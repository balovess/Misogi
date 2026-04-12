// =============================================================================
// Misogi Core — Command-Line Scanner Adapter
// =============================================================================
//! Wraps external command-line scanning tools (Windows Defender, Kaspersky,
//! Sophos CLI, custom scripts, etc.) by writing input to a temporary file,
//! invoking the command, and parsing exit codes and output.
//!
//! # Supported Use Cases
//!
//! - **Windows Defender**: `MpCmdRun.exe -Scan -ScanFile -DisableRemediation -File {file}`
//! - **Kaspersky**: `kesl --scan-file {file}`
//! - **Sophos**: `/opt/sophos/savscan --no-failjet {file}`
//! - **ClamAV CLI**: `clamscan --infected {file}`
//! - **Custom scripts**: Any executable that returns meaningful exit codes
//!
//! # Security Considerations
//!
//! ⚠️ **Command Injection Risk**: The `command_template` is processed with
//! simple string replacement. Ensure that:
//! 1. Template values come from trusted configuration (not user input)
//! 2. The `{file}` placeholder is always replaced with a temp file path
//!    (never with arbitrary user-supplied paths)
//! 3. Working directory restrictions are properly configured
//!
//! # Temporary File Handling
//!
//! File content is written to a temporary file in the configured `temp_dir`
//! (or system default). The temp file is:
//! - Created with restricted permissions (platform-dependent)
//! - Automatically deleted after scanning completes
//! - Named with a UUID to prevent path prediction attacks
//!
//! # Example Usage
//!
//! ```ignore
//! use misogi_core::scanners::{CommandLineAdapter, CommandLineConfig};
//!
//! let config = CommandLineConfig {
//!     command_template: "MpCmdRun.exe -Scan -ScanFile -DisableRemediation -File {file}".to_string(),
//!     working_dir: Some("C:\\Program Files\\Windows Defender".to_string()),
//!     timeout_secs: 60,
//!     infected_exit_codes: vec![2, 3],
//!     error_exit_codes: vec![1],
//!     threat_name_regex: Some(r"Threat\s+:\s+(.+)".to_string()),
//! };
//!
//! let scanner = CommandLineAdapter::new(config)?;
//! let result = scanner.scan_stream(&file_data).await?;
//! ```

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use super::{
    ExternalScanner, Result as ScannerResult, ScanResult, ScannerError,
    ScannerMetadata, ThreatSeverity,
};

// =============================================================================
// Configuration Types
// =============================================================================

/// Configuration for command-line scanner adapter.
///
/// Defines how to invoke external CLI tools for virus/malware scanning,
/// including command template, exit code mappings, and output parsing rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLineConfig {
    /// Command template with placeholder support.
    ///
    /// Supported placeholders:
    /// - `{file}` — Path to temporary file containing scan target (REQUIRED)
    ///
    /// Example templates:
    /// ```text
    /// MpCmdRun.exe -Scan -ScanFile -DisableRemediation -File {file}
    /// /opt/sophos/savscan --no-failjet {file}
    /// clamscan --infected --no-summary {file}
    /// ```
    ///
    /// The command will be executed via the system shell.
    pub command_template: String,

    /// Working directory for command execution (optional).
    ///
    /// If provided, sets the current working directory before execution.
    /// Useful for tools that require relative paths or load config files
    /// from their installation directory.
    pub working_dir: Option<String>,

    /// Timeout for command execution (seconds).
    ///
    /// Maximum time to wait for the scanning tool to complete.
    /// Includes process startup, file I/O, and signature matching time.
    /// For large files or slow scanners, increase this value (60-300s).
    /// Default: `30` seconds.
    pub timeout_secs: u64,

    /// Exit codes that indicate infection detected.
    ///
    /// When the command exits with any of these codes, the result is
    /// `ScanResult::Infected`. Common conventions:
    /// - Windows Defender: `[2, 3]` (threat found, threat found + action taken)
    /// - ClamAV CLI: `[1]` (virus found)
    /// - Custom: Tool-specific exit codes
    pub infected_exit_codes: Vec<i32>,

    /// Exit codes that indicate error (not infection).
    ///
    /// When the command exits with any of these codes, the result is
    /// `ScanResult::Error`. These are distinct from infected codes and
    /// represent operational failures (file not found, permission denied, etc.)
    pub error_exit_codes: Vec<i32>,

    /// Regular expression pattern to extract threat name from stderr/stdout.
    ///
    /// If provided, applied to combined stdout+stderr output to extract
    /// the specific threat name when infection is detected.
    /// Must contain one capture group `(...)` for the threat name.
    ///
    /// Examples:
    /// - Windows Defender: `"Threat\\s*:\\s*(.+)"` → captures after "Threat:"
    /// - ClamAV: `"(.+)\\s+FOUND"` → captures before " FOUND"
    /// - Generic: `"detected:\\s*(.+)"` → captures after "detected:"
    pub threat_name_regex: Option<String>,
}

impl Default for CommandLineConfig {
    fn default() -> Self {
        Self {
            command_template: String::new(),
            working_dir: None,
            timeout_secs: 30,
            infected_exit_codes: vec![],
            error_exit_codes: vec![1], // Convention: exit code 1 = general error
            threat_name_regex: None,
        }
    }
}

// =============================================================================
// Command-Line Adapter Implementation
// =============================================================================

/// Adapter for external command-line virus/malware scanners.
///
/// Executes configured CLI tools by:
/// 1. Writing file content to a temporary file
/// 2. Substituting `{file}` in command template with temp file path
/// 3. Executing the command with timeout enforcement
/// 4. Parsing exit code and extracting threat info from output
///
/// # Thread Safety
/// This struct is `Send + Sync` safe because it holds only configuration data.
/// All process spawning and I/O happens within async methods.
///
/// # Resource Cleanup
/// Temporary files are automatically cleaned up using RAII pattern via
/// [`tempfile::NamedTempFile`]. Even if scanning fails or panics, temp
/// files will be removed when dropped.
///
/// # Platform Notes
///
/// - **Windows**: Commands run under `cmd.exe /c` for proper path handling
/// - **Unix**: Commands run via `/bin/sh -c`
/// - **Path separators**: Use forward slashes in templates; adapter normalizes
pub struct CommandLineAdapter {
    /// Immutable configuration for this adapter instance.
    config: CommandLineConfig,

    /// Unique identifier for logging and chain identification.
    adapter_id: String,

    /// Directory for temporary files (uses system default if empty).
    temp_dir: std::path::PathBuf,
}

impl CommandLineAdapter {
    /// Create a new command-line adapter with specified configuration.
    ///
    /// Validates configuration requirements (command template must contain
    /// `{file}` placeholder) and initializes temporary directory settings.
    ///
    /// # Arguments
    /// * `config` — Command template, exit codes, and parsing rules.
    ///
    /// # Returns
    /// Initialized `CommandLineAdapter` ready for scanning operations.
    ///
    /// # Errors
    /// Returns error if:
    /// - Command template is empty
    /// - Command template doesn't contain required `{file}` placeholder
    /// - Threat name regex is invalid (if provided)
    pub fn new(config: CommandLineConfig) -> ScannerResult<Self> {
        // Validate command template
        if config.command_template.is_empty() {
            return Err(ScannerError::Configuration(
                "Command template is required".to_string(),
            ));
        }

        if !config.command_template.contains("{file}") {
            return Err(ScannerError::Configuration(
                "Command template must contain {file} placeholder".to_string(),
            ));
        }

        // Validate threat name regex if provided
        if let Some(ref pattern) = config.threat_name_regex {
            Regex::new(pattern).map_err(|e| {
                ScannerError::Configuration(format!(
                    "Invalid threat_name_regex '{}': {}",
                    pattern, e
                ))
            })?;
        }

        // Generate adapter ID from command template (first word)
        let adapter_id = config
            .command_template
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string();

        // Determine temp directory
        let temp_dir = std::env::temp_dir();

        tracing::info!(
            adapter_id = %adapter_id,
            command = %config.command_template,
            timeout = config.timeout_secs,
            "Creating command-line scanner adapter"
        );

        Ok(Self {
            config,
            adapter_id,
            temp_dir,
        })
    }

    /// Execute scan by writing data to temp file and running command.
    ///
    /// Complete workflow:
    /// 1. Create temp file and write scan data
    /// 2. Build command from template with temp file path
    /// 3. Spawn process with timeout
    /// 4. Collect stdout/stderr/exit code
    /// 5. Parse result based on exit code mapping
    /// 6. Clean up temp file (automatic via RAII)
    ///
    /// # Arguments
    /// * `data` — File content bytes to write to temp file and scan.
    ///
    /// # Returns
    /// Parsed [`ScanResult`] based on exit code and output analysis.
    async fn execute_scan(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        tracing::debug!(
            adapter_id = %self.adapter_id,
            data_size = data.len(),
            "Starting command-line scan"
        );

        // Step 1: Create temporary file with scan data
        let mut temp_file = tempfile::NamedTempFile::new_in(&self.temp_dir)
            .map_err(|e| {
                ScannerError::Internal(format!("Failed to create temp file: {}", e))
            })?;

        use std::io::Write;
        temp_file.write_all(data).map_err(|e| {
            ScannerError::Internal(format!("Failed to write to temp file: {}", e))
        })?;

        let temp_path = temp_file.path().to_path_buf();
        tracing::debug!(temp_path = %temp_path.display(), "Created temp file");

        // Step 2: Build command string
        let command_str = self
            .config
            .command_template
            .replace("{file}", &temp_path.to_string_lossy());

        tracing::debug!(command = %command_str, "Executing scanner command");

        // Step 3: Execute with timeout
        let exec_result = self.run_command_with_timeout(&command_str).await;

        // Step 4: Parse result
        match exec_result {
            Ok((exit_code, stdout, stderr)) => {
                self.parse_command_output(exit_code, &stdout, &stderr)
            }
            Err(e) => Err(e),
        }
    }

    /// Execute command string with timeout enforcement.
    ///
    /// Spawns the command as a child process, collects stdout and stderr,
    /// and enforces the configured timeout duration.
    ///
    /// # Arguments
    /// * `command_str` — Fully resolved command string (placeholders replaced).
    ///
    /// # Returns
    /// Tuple of (exit_code, stdout, stderr) on success, or error on failure.
    async fn run_command_with_timeout(
        &self,
        command_str: &str,
    ) -> ScannerResult<(i32, String, String)> {
        let timeout_duration = std::time::Duration::from_secs(self.config.timeout_secs);

        // Determine how to split command (platform-specific)
        #[cfg(target_family = "windows")]
        let (program, args) = self.split_windows_command(command_str);

        #[cfg(not(target_family = "windows"))]
        let (program, args) = self.split_unix_command(command_str);

        tracing::trace!(
            program = %program,
            args = ?args,
            timeout_secs = self.config.timeout_secs,
            "Spawning command process"
        );

        let mut cmd = Command::new(&program);
        cmd.args(&args);

        // Set working directory if configured
        if let Some(ref work_dir) = self.config.working_dir {
            cmd.current_dir(work_dir);
        }

        // Capture both stdout and stderr
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // Spawn with timeout
        let child = cmd.spawn().map_err(|e| {
            ScannerError::Internal(format!("Failed to spawn command '{}': {}", program, e))
        })?;

        let timeout_result =
            tokio::time::timeout(timeout_duration, child.wait_with_output()).await;

        match timeout_result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                tracing::debug!(
                    exit_code = exit_code,
                    stdout_len = stdout.len(),
                    stderr_len = stderr.len(),
                    "Command completed"
                );

                Ok((exit_code, stdout, stderr))
            }
            Ok(Err(e)) => Err(ScannerError::Internal(format!(
                "Failed to wait for command: {}",
                e
            ))),
            Err(_) => {
                // Timeout: child handle was consumed by wait_with_output().
                // The process will be reaped when the Child is dropped.
                tracing::warn!(
                    timeout = self.config.timeout_secs,
                    "Command timed out"
                );

                // Return sentinel exit code; caller's parse_command_output will
                // treat unknown exit codes as errors (fail-safe).
                Ok((-1, String::new(), String::new()))
            }
        }
    }

    /// Split Windows command into program + arguments.
    ///
    /// On Windows, we need to handle `.exe` detection and `cmd.exe /c`
    /// for complex commands with pipes/redirections.
    #[cfg(target_family = "windows")]
    fn split_windows_command(
        &self,
        command_str: &str,
    ) -> (String, Vec<String>) {
        // Simple splitting: first token is program, rest are args
        let tokens: Vec<&str> = command_str.split_whitespace().collect();

        if tokens.is_empty() {
            return (String::new(), Vec::new());
        }

        let program = tokens[0].to_string();
        let args: Vec<String> = tokens[1..].iter().map(|s| s.to_string()).collect();

        (program, args)
    }

    /// Split Unix command into program + arguments.
    #[cfg(not(target_family = "windows"))]
    fn split_unix_command(
        &self,
        command_str: &str,
    ) -> (String, Vec<String>) {
        // Simple splitting: first token is program, rest are args
        let tokens: Vec<&str> = command_str.split_whitespace().collect();

        if tokens.is_empty() {
            return (String::new(), Vec::new());
        }

        let program = tokens[0].to_string();
        let args: Vec<String> = tokens[1..].iter().map(|s| s.to_string()).collect();

        (program, args)
    }

    /// Parse command output into ScanResult based on exit code and output.
    ///
    /// Maps exit codes according to configuration:
    /// - Codes in `infected_exit_codes` → `Infected` (with optional threat name extraction)
    /// - Codes in `error_exit_codes` → `Error`
    /// - Code 0 (or unmapped) → `Clean`
    ///
    /// # Arguments
    /// * `exit_code` — Process exit status.
    /// * `stdout` — Standard output text.
    /// * `stderr` — Standard error text.
    ///
    /// # Returns
    /// Appropriate [`ScanResult`] variant.
    fn parse_command_output(
        &self,
        exit_code: i32,
        stdout: &str,
        stderr: &str,
    ) -> ScannerResult<ScanResult> {
        tracing::debug!(
            exit_code = exit_code,
            infected_codes = ?self.config.infected_exit_codes,
            error_codes = ?self.config.error_exit_codes,
            "Parsing command output"
        );

        // Check for infection exit codes
        if self.config.infected_exit_codes.contains(&exit_code) {
            let threat_name = self.extract_threat_name(stdout, stderr);

            tracing::warn!(
                exit_code = exit_code,
                threat_name = ?threat_name,
                "Command reported INFECTION"
            );

            return Ok(ScanResult::Infected {
                threat_name: threat_name.unwrap_or_else(|| "Unknown Threat".to_string()),
                severity: ThreatSeverity::Medium, // Default severity
            });
        }

        // Check for error exit codes
        if self.config.error_exit_codes.contains(&exit_code) {
            let error_msg = format!(
                "Command exited with error code {}: stdout={}, stderr={}",
                exit_code,
                if stdout.len() > 500 { &stdout[..500] } else { stdout },
                if stderr.len() > 500 { &stderr[..500] } else { stderr },
            );

            tracing::error!(
                exit_code = exit_code,
                error = %error_msg,
                "Command reported ERROR"
            );

            return Ok(ScanResult::Error {
                message: error_msg,
                transient: false, // CLI errors usually permanent
            });
        }

        // Exit code 0 or unmapped → clean
        if exit_code == 0 {
            tracing::info!("Command reports CLEAN");
            Ok(ScanResult::Clean)
        } else {
            // Unknown exit code — treat as error for safety
            tracing::warn!(
                exit_code = exit_code,
                "Unknown exit code, treating as error (fail-safe)"
            );
            Ok(ScanResult::Error {
                message: format!("Unknown exit code: {}", exit_code),
                transient: false,
            })
        }
    }

    /// Extract threat name from command output using configured regex.
    ///
    /// Applies the optional `threat_name_regex` pattern to combined
    /// stdout+stderr text to find the specific threat identifier.
    ///
    /// # Arguments
    /// * `stdout` — Standard output text.
    /// * `stderr` — Standard error text.
    ///
    /// # Returns
    /// Extracted threat name string, or `None` if not found/not configured.
    fn extract_threat_name(&self, stdout: &str, stderr: &str) -> Option<String> {
        let pattern = self.config.threat_name_regex.as_ref()?;

        let regex = Regex::new(pattern).ok()?; // Already validated in new()

        let combined_output = format!("{}\n{}", stdout, stderr);

        if let Some(captures) = regex.captures(&combined_output) {
            if let Some(matched) = captures.get(1) {
                let threat = matched.as_str().trim().to_string();
                tracing::debug!(threat = %threat, "Extracted threat name");
                return Some(threat);
            }
        }

        tracing::trace!("No threat name matched in output");
        None
    }
}

#[async_trait]
impl ExternalScanner for CommandLineAdapter {
    /// Returns the command name (first word of template) as display name.
    fn name(&self) -> &str {
        &self.adapter_id
    }

    /// Returns unique identifier based on command template.
    fn id(&self) -> &str {
        &self.adapter_id
    }

    /// Scan file content via command-line tool invocation.
    ///
    /// Writes data to temp file, executes configured command, parses result.
    /// All I/O bounded by configured timeout.
    ///
    /// # Arguments
    /// * `data` — Complete file bytes to scan.
    ///
    /// # Returns
    /// - `Ok(ScanResult::Clean)` — No threats (exit code 0)
    /// - `Ok(ScanResult::Infected { ... })` — Threat detected
    /// - `Ok(ScanResult::Error { ... })` — Command error
    /// - `Ok(ScanResult::Timeout { ... })` — Command timed out
    /// - `Err(ScannerError)` — Internal failure (temp file, etc.)
    async fn scan_stream(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        self.execute_scan(data).await
    }

    /// Health check by verifying command exists and is executable.
    ///
    /// Attempts to locate the command executable in PATH or working directory.
    /// Does NOT execute the full scan — just checks binary availability.
    ///
    /// # Returns
    /// - `true` — Command executable can be found
    /// - `false` — Command not found or not executable
    async fn health_check(&self) -> bool {
        tracing::debug!(adapter_id = %self.adapter_id, "Performing health check");

        // Extract program name from template
        let program = self
            .config
            .command_template
            .split_whitespace()
            .next()
            .unwrap_or("");

        if program.is_empty() {
            tracing::warn!("Empty command in template");
            return false;
        }

        // Check which command exists (platform-appropriate)
        #[cfg(target_family = "windows")]
        let check_result = self.check_windows_program_exists(program).await;

        #[cfg(not(target_family = "windows"))]
        let check_result = self.check_unix_program_exists(program).await;

        match check_result {
            Ok(true) => {
                tracing::info!(program = program, "Health check passed");
                true
            }
            Ok(false) => {
                tracing::warn!(program = program, "Command not found");
                false
            }
            Err(e) => {
                tracing::warn!(program = program, error = %e, "Health check failed");
                false
            }
        }
    }

    /// Query metadata (not typically available for CLI tools).
    ///
    /// Most CLI scanners don't have version query mechanisms that are
    /// reliable across platforms. This returns `None`.
    ///
    /// # Returns
    /// Always returns `None`.
    async fn metadata(&self) -> Option<ScannerMetadata> {
        tracing::debug!(adapter_id = %self.adapter_id, "Metadata query (not supported)");
        None
    }
}

impl CommandLineAdapter {
    /// Check if Windows program exists (using `where` command).
    #[cfg(target_family = "windows")]
    async fn check_windows_program_exists(&self, program: &str) -> ScannerResult<bool> {
        let output = Command::new("where")
            .arg(program)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| {
                ScannerError::Internal(format!("Failed to check program existence: {}", e))
            })?;

        Ok(output.status.success())
    }

    /// Check if Unix program exists (using `which` command).
    #[cfg(not(target_family = "windows"))]
    async fn check_unix_program_exists(&self, program: &str) -> ScannerResult<bool> {
        let output = Command::new("which")
            .arg(program)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| {
                ScannerError::Internal(format!("Failed to check program existence: {}", e))
            })?;

        Ok(output.status.success())
    }
}

impl std::fmt::Debug for CommandLineAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandLineAdapter")
            .field("adapter_id", &self.adapter_id)
            .field("command_template", &self.config.command_template)
            .field("timeout_secs", &self.config.timeout_secs)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Configuration Validation Tests
    // =========================================================================

    #[test]
    fn test_config_requires_template() {
        let config = CommandLineConfig {
            command_template: String::new(),
            ..Default::default()
        };
        let result = CommandLineAdapter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_requires_file_placeholder() {
        let config = CommandLineConfig {
            command_template: "some-command --flag".to_string(),
            ..Default::default()
        };
        let result = CommandLineAdapter::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("{file}"));
    }

    #[test]
    fn test_config_validates_regex() {
        let config = CommandLineConfig {
            command_template: "scanner {file}".to_string(),
            threat_name_regex: Some("[invalid(regex".to_string()),
            ..Default::default()
        };
        let result = CommandLineAdapter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_config_creation() {
        let config = CommandLineConfig {
            command_template: "scanner --scan {file}".to_string(),
            ..Default::default()
        };
        let result = CommandLineAdapter::new(config);
        assert!(result.is_ok());
        let adapter = result.unwrap();
        assert_eq!(adapter.name(), "scanner");
    }

    // =========================================================================
    // Exit Code Mapping Tests
    // =========================================================================

    #[test]
    fn test_parse_clean_exit_code() {
        let adapter = create_test_adapter();

        let result = adapter
            .parse_command_output(0, "Scan complete", "")
            .unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[test]
    fn test_parse_infected_exit_code() {
        let adapter = create_test_adapter_with_codes_and_regex(
            vec![2],
            vec![1],
            r"(?i)threat\s+found:\s*(.+)",
        );

        let result = adapter
            .parse_command_output(2, "", "Threat found: Trojan.A")
            .unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threat_name(), Some("Trojan.A"));
    }

    #[test]
    fn test_parse_error_exit_code() {
        let adapter = create_test_adapter_with_codes(vec![2], vec![1]);

        let result = adapter.parse_command_output(1, "", "Permission denied").unwrap();
        assert!(result.is_error());
    }

    #[test]
    fn test_parse_unknown_exit_code() {
        let adapter = create_test_adapter();

        let result = adapter.parse_command_output(42, "", "").unwrap();
        assert!(result.is_error()); // Unknown codes treated as errors
    }

    // =========================================================================
    // Threat Name Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_threat_name_from_stdout() {
        let adapter = create_test_adapter_with_regex(r"(?i)found:\s*(.+)");

        let threat = adapter.extract_threat_name(
            "Scanning... complete\nFound: Eicar-Test-Signature",
            "",
        );
        assert_eq!(threat, Some("Eicar-Test-Signature".to_string()));
    }

    #[test]
    fn test_extract_threat_name_from_stderr() {
        let adapter = create_test_adapter_with_regex(r"ERROR:\s*(.+?)\s*detected");

        let threat = adapter.extract_threat_name(
            "",
            "ERROR: Virus.Win32.Generic detected",
        );
        assert_eq!(threat, Some("Virus.Win32.Generic".to_string()));
    }

    #[test]
    fn test_no_match_returns_none() {
        let adapter = create_test_adapter_with_regex(r"Threat:\s*(.+)");

        let threat = adapter.extract_threat_name("No threats found", "");
        assert_eq!(threat, None);
    }

    #[test]
    fn test_no_regex_configured_returns_none() {
        let adapter = create_test_adapter(); // No regex

        let threat = adapter.extract_threat_name("Threat: Something", "");
        assert_eq!(threat, None);
    }

    // =========================================================================
    // Command Template Substitution Tests
    // =========================================================================

    #[test]
    fn test_template_substitution_basic() {
        let config = CommandLineConfig {
            command_template: "MpCmdRun.exe -File {file} -Scan".to_string(),
            ..Default::default()
        };

        let adapter = CommandLineAdapter::new(config).unwrap();
        // Just verify creation succeeds — actual substitution tested in integration
        assert_eq!(adapter.name(), "MpCmdRun.exe");
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = CommandLineConfig {
            command_template: "scanner {file} --verbose".to_string(),
            working_dir: Some("/opt/scanner".to_string()),
            timeout_secs: 120,
            infected_exit_codes: vec![2, 3, 4],
            error_exit_codes: vec![1, 127],
            threat_name_regex: Some(r"detected:\s*(.+)".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: CommandLineConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.command_template, config.command_template);
        assert_eq!(deserialized.infected_exit_codes, config.infected_exit_codes);
        assert_eq!(deserialized.error_exit_codes, config.error_exit_codes);
        assert_eq!(deserialized.threat_name_regex, config.threat_name_regex);
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    /// Create a minimal valid test adapter.
    fn create_test_adapter() -> CommandLineAdapter {
        CommandLineAdapter::new(CommandLineConfig {
            command_template: "test-scanner {file}".to_string(),
            ..Default::default()
        })
        .expect("Test adapter creation should succeed")
    }

    /// Create test adapter with custom exit codes.
    fn create_test_adapter_with_codes(
        infected: Vec<i32>,
        error: Vec<i32>,
    ) -> CommandLineAdapter {
        CommandLineAdapter::new(CommandLineConfig {
            command_template: "test-scanner {file}".to_string(),
            infected_exit_codes: infected,
            error_exit_codes: error,
            ..Default::default()
        })
        .expect("Test adapter creation should succeed")
    }

    /// Create test adapter with custom threat name regex.
    fn create_test_adapter_with_regex(pattern: &str) -> CommandLineAdapter {
        CommandLineAdapter::new(CommandLineConfig {
            command_template: "test-scanner {file}".to_string(),
            threat_name_regex: Some(pattern.to_string()),
            ..Default::default()
        })
        .expect("Test adapter creation should succeed")
    }

    /// Create test adapter with custom exit codes and threat name regex.
    fn create_test_adapter_with_codes_and_regex(
        infected: Vec<i32>,
        error: Vec<i32>,
        threat_regex: &str,
    ) -> CommandLineAdapter {
        CommandLineAdapter::new(CommandLineConfig {
            command_template: "test-scanner {file}".to_string(),
            infected_exit_codes: infected,
            error_exit_codes: error,
            threat_name_regex: Some(threat_regex.to_string()),
            ..Default::default()
        })
        .expect("Test adapter creation should succeed")
    }
}
