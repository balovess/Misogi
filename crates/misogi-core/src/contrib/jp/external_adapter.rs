//! External Sanitizer Adapter — Integration with third-party file sanitization tools.
//!
//! This module provides a generic adapter pattern for invoking external command-line
//! sanitization tools as part of the CDR (Content Disarm & Reconstruction) pipeline.
//!
//! # Use Cases
//!
//! Some file formats cannot be safely sanitized using pure Rust libraries and require
//! specialized commercial or open-source tools:
//!
//! | File Format   | Example Tool              | Purpose                          |
//! |---------------|---------------------------|----------------------------------|
//! | `.jtd`        | JTD Sanitizer (proprietary)| Japanese CAD drawing cleanup     |
//! | `.dwg`        | ODA File Converter        | AutoCAD drawing macro removal    |
//! | `.dxf`        | LibreOffice headless      | Drawing format flattening        |
//! | `.vsdx`       | pptx2txt / custom tool    | Visio diagram text extraction    |
//! | `.rpt`        | Crystal Reports exporter  | Report format conversion         |
//!
//! # Architecture
//!
//! ```
//! ┌─────────────────┐     ┌──────────────────────┐     ┌──────────────┐
//! │ Input File      │────▶│ ExternalSanitizer     │────▶│ Output File  │
//! │ (untrusted)     │     │ Adapter               │     │ (sanitized)  │
//! └─────────────────┘     └──────────────────────┘     └──────────────┘
//!                                │
//!                    ┌───────────┼───────────┐
//!                    ▼           ▼           ▼
//!              [Config: .jtd] [Config: .dwg] [Config: .dxf]
//!                    │           │           ▼
//!                    ▼           ▼     jtd_clean --input {{input_path}} --output {{output_path}}
//!              dwg_filter          oda_convert -i {{input_path}} -o {{output_path}}
//! ```
//!
//! # Security Considerations
//!
//! - All external commands run in a **temporary working directory** (not the source directory).
//! - Commands are subject to **configurable timeout** to prevent indefinite hangs.
//! - **Template injection** is prevented by only allowing `{{input_path}}` and `{{output_path}}`.
//! - Exit codes are checked; non-zero exits trigger configured failure actions.
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_core::contrib::jp::external_adapter::{
//!     ExternalSanitizerAdapter,
//!     ExternalSanitizerConfig,
//!     ExternalSuccessAction,
//!     ExternalFailureAction,
//! };
//! use std::path::PathBuf;
//!
//! let mut adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/misogi_work"));
//!
//! let config = ExternalSanitizerConfig {
//!     extension: ".jtd".to_string(),
//!     command: "/usr/local/bin/jtd_clean".to_string(),
//!     args: vec![
//!         "--input".to_string(),
//!         "{{input_path}}".to_string(),
//!         "--output".to_string(),
//!         "{{output_path}}".to_string(),
//!     ],
//!     timeout_secs: 30,
//!     on_success: ExternalSuccessAction::VerifyHash,
//!     on_failure: ExternalFailureAction::BlockAndLog,
//! };
//!
//! adapter.register(config)?;
//! let result = adapter.sanitize(
//!     &PathBuf::from("/data/input.drawing.jtd"),
//!     &PathBuf::from("/data/output.sanitized.jtd"),
//!     ".jtd",
//! ).await?;
//! ```

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use tokio::process::Command;
use tracing::{error, info, warn};

use crate::error::{MisogiError, Result};
use crate::hash;

// =============================================================================
// Enums for Success/Failure Actions
// =============================================================================

/// Action to take when an external sanitizer completes successfully (exit code 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSuccessAction {
    /// Trust the output without additional verification.
    ///
    /// Use this when the external tool is well-vetted and known to produce safe output.
    /// This is faster but provides less defense-in-depth.
    TrustOutput,

    /// Verify that the output hash differs from the input hash (confirming modification).
    ///
    /// A successful sanitizer **must** alter the file (remove macros, sanitize content, etc.).
    /// If the hashes are identical, it suggests the tool did nothing, which may indicate
    /// a misconfiguration or bypass attempt.
    VerifyHash,
}

impl Default for ExternalSuccessAction {
    fn default() -> Self {
        Self::TrustOutput // Safer default for production reliability
    }
}

/// Action to take when an external sanitizer fails (non-zero exit code or timeout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalFailureAction {
    /// Block the file transfer entirely and log the failure for security review.
    ///
    /// **Recommended** for high-security environments where any sanitization failure
    /// could indicate an attack or malformed payload designed to crash the tool.
    BlockAndLog,

    /// Allow the transfer to proceed but emit a warning log entry.
    ///
    /// Use this in development/testing environments or for low-risk file types where
    /// availability is prioritized over strict security.
    WarnAndPass,
}

impl Default for ExternalFailureAction {
    fn default() -> Self {
        Self::BlockAndLog // Safer default: fail secure
    }
}

// =============================================================================
// ExternalSanitizerConfig
// =============================================================================

/// Configuration for a single external sanitizer tool bound to a file extension.
///
/// Each config maps one file extension (e.g., `.jtd`, `.dwg`) to an external
/// command-line tool with its arguments and behavior policies.
///
/// # Template Variables
///
/// The `args` field supports two template variables that are replaced at runtime:
///
/// | Variable         | Replaced With                                    |
/// |------------------|--------------------------------------------------|
/// | `{{input_path}}` | Absolute path to the untrusted input file         |
/// | `{{output_path}}`| Absolute path where sanitized output should be written |
///
/// # Example Configuration
///
/// ```ignore
/// ExternalSanitizerConfig {
///     extension: ".dwg".to_string(),
///     command: "C:\\tools\\oda_converter.exe".to_string(),
///     args: vec![
///         "-i".to_string(), "{{input_path}}".to_string(),
///         "-o".to_string(), "{{output_path}}".to_string(),
///         "--flatten".to_string(),
///     ],
///     timeout_secs: 60,
///     on_success: ExternalSuccessAction::VerifyHash,
///     on_failure: ExternalFailureAction::BlockAndLog,
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ExternalSanitizerConfig {
    /// File extension this sanitizer handles (including the dot, e.g., `.jtd`).
    pub extension: String,

    /// Absolute or relative path to the external sanitizer executable.
    ///
    /// Must be accessible from the Misogi process's PATH environment, or be an
    /// absolute filesystem path. Relative paths are resolved against the current
    /// working directory of the Misogi process.
    pub command: String,

    /// Command-line arguments for the external tool.
    ///
    /// May contain template variables `{{input_path}}` and `{{output_path}}`
    /// which are replaced with actual paths at invocation time.
    pub args: Vec<String>,

    /// Maximum execution time in seconds before the process is killed.
    ///
    /// Prevents hung or maliciously slow external tools from blocking the CDR
    /// pipeline indefinitely. Recommended values:
    /// - Simple text extractors: 10–30 seconds
    /// - CAD/drawing converters: 60–300 seconds
    /// - Complex document processors: 300–600 seconds
    pub timeout_secs: u64,

    /// Policy for handling successful completion (exit code 0).
    pub on_success: ExternalSuccessAction,

    /// Policy for handling failures (non-zero exit code, timeout, crash).
    pub on_failure: ExternalFailureAction,
}

impl Default for ExternalSanitizerConfig {
    fn default() -> Self {
        Self {
            extension: String::new(),
            command: String::new(),
            args: Vec::new(),
            timeout_secs: 60, // Reasonable default
            on_success: ExternalSuccessAction::default(),
            on_failure: ExternalFailureAction::default(),
        }
    }
}

// =============================================================================
// ExternalSanitizeResult
// =============================================================================

/// Detailed result of an external sanitization operation.
///
/// Carries all metadata needed for audit logging, debugging, and downstream
/// decision-making about whether to accept or reject the sanitized output.
#[derive(Debug, Clone)]
pub struct ExternalSanitizeResult {
    /// Whether the overall operation was considered successful.
    ///
    /// This combines the process exit code check with the configured
    /// `on_success`/`on_failure` policy evaluation.
    pub success: bool,

    /// Process exit code if the process terminated normally.
    /// `None` if the process was killed by timeout or signal.
    pub exit_code: Option<i32>,

    /// Captured stdout output from the external process (truncated to last 64KB).
    pub stdout: String,

    /// Captured stderr output from the external process (truncated to last 64KB).
    pub stderr: String,

    /// Size of the output file in bytes (if produced), `None` otherwise.
    pub output_size: Option<u64>,

    /// SHA-256 hash of the output file (hex-encoded) if verification was performed.
    pub output_hash: Option<String>,

    /// Wall-clock duration of the operation in milliseconds.
    pub duration_ms: u64,
}

impl ExternalSanitizeResult {
    /// Create a success result with minimal information.
    #[cfg(test)]
    fn success_basic(exit_code: i32, duration_ms: u64) -> Self {
        Self {
            success: true,
            exit_code: Some(exit_code),
            stdout: String::new(),
            stderr: String::new(),
            output_size: None,
            output_hash: None,
            duration_ms,
        }
    }

    /// Create a failure result indicating the tool was not found.
    #[cfg(test)]
    fn tool_not_found(command: &str, duration_ms: u64) -> Self {
        Self {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("Command not found: {}", command),
            output_size: None,
            output_hash: None,
            duration_ms,
        }
    }

    /// Create a failure result for timeout.
    #[cfg(test)]
    fn timeout_result(duration_ms: u64) -> Self {
        Self {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::from("Process timed out"),
            output_size: None,
            output_hash: None,
            duration_ms,
        }
    }
}

// =============================================================================
// ExternalSanitizerAdapter
// =============================================================================

/// Manages a registry of external sanitizer configurations and executes them.
///
/// Acts as the bridge between Misogi's CDR pipeline and third-party sanitization
/// tools. Each file extension can have at most one registered sanitizer (last
/// registration wins if duplicates occur).
///
/// # Thread Safety
///
/// This struct is **not** thread-safe by design. In async contexts, it should be
/// wrapped in `Arc<RwLock<>>` or used within a single async task. The [`sanitize()`]
/// method spawns subprocesses via Tokio's async runtime.
///
/// # Working Directory
///
/// All external commands execute in the configured `work_dir`. Input files are
/// expected to already exist at `input_path`; output files are written to
/// `output_path`. Neither path needs to be inside `work_dir`.

pub struct ExternalSanitizerAdapter {
    /// Registered sanitizer configurations keyed by file extension.
    configs: Vec<ExternalSanitizerConfig>,

    /// Working directory for spawned processes (used as CWD for external commands).
    work_dir: PathBuf,
}

impl ExternalSanitizerAdapter {
    /// Create a new adapter with the specified working directory.
    ///
    /// # Arguments
    /// * `work_dir` - Directory that will be used as the current working directory
    ///   for all spawned external sanitizer processes. Should be a dedicated temp
    ///   directory (e.g., `/tmp/misogi_external_sanitizers/`).
    ///
    /// # Note
    /// The working directory is **not** created automatically. Callers must ensure
    /// it exists before invoking [`sanitize()`](Self::sanitize).
    pub fn new(work_dir: PathBuf) -> Self {
        Self {
            configs: Vec::new(),
            work_dir,
        }
    }

    /// Register (or update) a sanitizer configuration for a file extension.
    ///
    /// If a configuration for the same extension already exists, it is replaced
    /// with the new configuration (last-write-wins semantics).
    ///
    /// # Arguments
    /// * `config` - Complete sanitizer configuration including command, args, and policies.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if `extension` is empty or `command` is empty.
    ///
    /// # Example
    ///
    /// ```ignore
    /// adapter.register(ExternalSanitizerConfig {
    ///     extension: ".dwg".to_string(),
    ///     command: "/opt/oda/oda_converter".to_string(),
    ///     args: vec!["-i".into(), "{{input_path}}".into()],
    ///     ..Default::default()
    /// })?;
    /// ```
    pub fn register(&mut self, config: ExternalSanitizerConfig) -> Result<()> {
        if config.extension.is_empty() {
            return Err(MisogiError::Protocol(
                "ExternalSanitizerConfig.extension must not be empty".to_string(),
            ));
        }

        if config.command.is_empty() {
            return Err(MisogiError::Protocol(
                "ExternalSanitizerConfig.command must not be empty".to_string(),
            ));
        }

        // Remove existing config for same extension (if any)
        self.configs.retain(|c| c.extension != config.extension);

        // Add new config
        self.configs.push(config);

        info!(
            extension = %self.configs.last().unwrap().extension,
            command = %self.configs.last().unwrap().command,
            "External sanitizer registered"
        );

        Ok(())
    }

    /// Find the registered configuration for a given file extension.
    ///
    /// # Arguments
    /// * `extension` - File extension to look up (e.g., `.jtd`, `.dwg`).
    ///
    /// # Returns
    /// - `Some(&ExternalSanitizerConfig)` if a sanitizer is registered for this extension.
    /// - `None` if no sanitizer is configured for this extension.
    pub fn find_adapter(&self, extension: &str) -> Option<&ExternalSanitizerConfig> {
        self.configs.iter().find(|c| c.extension == extension)
    }

    /// Get the number of currently registered sanitizer configurations.
    #[cfg(test)]
    fn config_count(&self) -> usize {
        self.configs.len()
    }

    /// Execute the registered external sanitizer for a given file.
    ///
    /// This is the primary entry point for the CDR pipeline. It:
    /// 1. Looks up the appropriate sanitizer configuration for the file extension.
    /// 2. Renders template variables (`{{input_path}}`, `{{output_path}}`) in the argument list.
    /// 3. Spawns the external process with stdin/stdout/stderr captured.
    /// 4. Waits for completion (with timeout).
    /// 5. Evaluates the result based on configured success/failure policies.
    /// 6. Optionally verifies that the output differs from the input (hash check).
    ///
    /// # Arguments
    /// * `input_path` - Path to the untrusted input file (must exist).
    /// * `output_path` - Path where the sanitized output should be written.
    /// * `extension` - File extension used to select the appropriate sanitizer config.
    ///
    /// # Returns
    /// Detailed [`ExternalSanitizeResult`] with success/failure status and metadata.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if no sanitizer is registered for the given extension.
    /// - [`MisogiError::Io`] if the process cannot be spawned or output files cannot be read.
    pub async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        extension: &str,
    ) -> Result<ExternalSanitizeResult> {
        let start_time = Instant::now();

        // Step 1: Find configuration for this extension
        let config = self.find_adapter(extension).ok_or_else(|| {
            MisogiError::NotFound(format!(
                "No external sanitizer registered for extension '{}'",
                extension
            ))
        })?;

        // Step 2: Compute input hash (for later verification if needed)
        let input_hash = if config.on_success == ExternalSuccessAction::VerifyHash {
            Some(hash::compute_file_sha256(input_path).await?)
        } else {
            None
        };

        // Step 3: Render template variables in arguments
        let rendered_args = render_args(&config.args, input_path, output_path);

        // Step 4: Spawn external process
        tracing::debug!(
            command = %config.command,
            args = ?rendered_args,
            timeout_secs = config.timeout_secs,
            work_dir = %self.work_dir.display(),
            "Spawning external sanitizer"
        );

        let output = Command::new(&config.command)
            .args(&rendered_args)
            .current_dir(&self.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                error!(
                    command = %config.command,
                    error = %e,
                    "Failed to spawn external sanitizer"
                );
                MisogiError::Io(e)
            })?;

        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

        // Step 5: Check exit status
        let exit_code = output.status.code();
        let process_success = output.status.success();

        // Step 6: Build base result
        let mut result = ExternalSanitizeResult {
            success: false, // Default to false until verified
            exit_code,
            stdout: stdout_str,
            stderr: stderr_str.clone(),
            output_size: None,
            output_hash: None,
            duration_ms: elapsed_ms,
        };

        // Step 7: Evaluate based on exit status
        if process_success {
            // Success path
            match &config.on_success {
                ExternalSuccessAction::TrustOutput => {
                    result.success = true;
                    info!(
                        extension = %extension,
                        command = %config.command,
                        duration_ms = elapsed_ms,
                        "External sanitizer completed successfully (trust mode)"
                    );
                }
                ExternalSuccessAction::VerifyHash => {
                    // Check if output file exists and compute its hash
                    if output_path.exists() {
                        let output_hash_val = hash::compute_file_sha256(output_path).await?;
                        result.output_size = Some(
                            std::fs::metadata(output_path)
                                .map(|m| m.len())
                                .unwrap_or(0),
                        );
                        result.output_hash = Some(output_hash_val.clone());

                        // Verify that output differs from input
                        if let Some(ref input_h) = input_hash {
                            if output_hash_val != *input_h {
                                result.success = true;
                                info!(
                                    extension = %extension,
                                    command = %config.command,
                                    duration_ms = elapsed_ms,
                                    "External sanitizer completed successfully (hash verified, file changed)"
                                );
                            } else {
                                warn!(
                                    extension = %extension,
                                    command = %config.command,
                                    "External sanitizer output identical to input (possible no-op)"
                                );
                                // Hash verification failed — treat as failure
                                result.success = false;
                            }
                        } else {
                            // No input hash available (shouldn't happen, but handle gracefully)
                            result.success = true;
                        }
                    } else {
                        warn!(
                            extension = %extension,
                            output_path = %output_path.display(),
                            "External sanitizer succeeded but output file does not exist"
                        );
                        result.success = false;
                    }
                }
            }
        } else {
            // Failure path
            match &config.on_failure {
                ExternalFailureAction::BlockAndLog => {
                    result.success = false;
                    error!(
                        extension = %extension,
                        command = %config.command,
                        exit_code = ?exit_code,
                        stderr = %stderr_str,
                        "External sanitizer failed (block mode)"
                    );
                }
                ExternalFailureAction::WarnAndPass => {
                    result.success = true; // Allow despite failure
                    warn!(
                        extension = %extension,
                        command = %config.command,
                        exit_code = ?exit_code,
                        stderr = %stderr_str,
                        "External sanitizer failed but passing through (warn mode)"
                    );
                }
            }
        }

        Ok(result)
    }
}

// =============================================================================
// Template Variable Rendering
// =============================================================================

/// Replace template placeholders in argument list with actual file paths.
///
/// Supported template variables:
/// - `{{input_path}}` → Absolute path string of the input file
/// - `{{output_path}}` → Absolute path string of the output file
///
/// # Arguments
/// * `args` - Original argument list potentially containing templates.
/// * `input_path` - Path to the input file.
/// * `output_path` - Path to the output file.
///
/// # Returns
/// New argument vector with all template variables replaced.
///
/// # Example
///
/// ```
/// # use std::path::PathBuf;
/// # use misogi_core::contrib::jp::external_adapter::render_args;
/// let args = vec![
///     "--input".to_string(),
///     "{{input_path}}".to_string(),
///     "--output".to_string(),
///     "{{output_path}}".to_string(),
/// ];
/// let rendered = render_args(
///     &args,
///     &PathBuf::from("/data/input.txt"),
///     &PathBuf::from("/data/output.txt"),
/// );
/// assert_eq!(rendered[1], "/data/input.txt");
/// assert_eq!(rendered[3], "/data/output.txt");
/// ```
pub fn render_args(
    args: &[String],
    input_path: &Path,
    output_path: &Path,
) -> Vec<String> {
    let input_str = input_path.to_string_lossy().to_string();
    let output_str = output_path.to_string_lossy().to_string();

    args.iter()
        .map(|arg| {
            arg.replace("{{input_path}}", &input_str)
                .replace("{{output_path}}", &output_str)
        })
        .collect()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: Config Registration and Lookup
    // =========================================================================

    #[test]
    fn test_register_and_find_config() {
        let mut adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/test_work"));

        let config = ExternalSanitizerConfig {
            extension: ".jtd".to_string(),
            command: "/usr/bin/jtd_clean".to_string(),
            args: vec![
                "--input".to_string(),
                "{{input_path}}".to_string(),
                "--output".to_string(),
                "{{output_path}}".to_string(),
            ],
            timeout_secs: 30,
            on_success: ExternalSuccessAction::VerifyHash,
            on_failure: ExternalFailureAction::BlockAndLog,
        };

        assert!(adapter.register(config).is_ok());
        assert_eq!(adapter.config_count(), 1);

        let found = adapter.find_adapter(".jtd");
        assert!(found.is_some());
        assert_eq!(found.unwrap().command, "/usr/bin/jtd_clean");
    }

    #[test]
    fn test_register_replaces_existing() {
        let mut adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/test_work"));

        // First registration
        let config1 = ExternalSanitizerConfig {
            extension: ".dwg".to_string(),
            command: "/old/path/tool.exe".to_string(),
            ..Default::default()
        };
        adapter.register(config1).unwrap();
        assert_eq!(adapter.config_count(), 1);

        // Second registration with same extension (should replace)
        let config2 = ExternalSanitizerConfig {
            extension: ".dwg".to_string(),
            command: "/new/path/tool_v2.exe".to_string(),
            ..Default::default()
        };
        adapter.register(config2).unwrap();
        assert_eq!(adapter.config_count(), 1); // Still 1, not 2

        let found = adapter.find_adapter(".dwg").unwrap();
        assert_eq!(found.command, "/new/path/tool_v2.exe");
    }

    #[test]
    fn test_register_empty_extension_fails() {
        let mut adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/test_work"));

        let config = ExternalSanitizerConfig {
            extension: String::new(), // Empty!
            command: "/bin/test".to_string(),
            ..Default::default()
        };

        let result = adapter.register(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("extension must not be empty"));
    }

    #[test]
    fn test_register_empty_command_fails() {
        let mut adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/test_work"));

        let config = ExternalSanitizerConfig {
            extension: ".test".to_string(),
            command: String::new(), // Empty!
            ..Default::default()
        };

        let result = adapter.register(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("command must not be empty"));
    }

    // =========================================================================
    // Test: Template Variable Replacement
    // =========================================================================

    #[test]
    fn test_template_variable_replacement() {
        let args = vec![
            "--input".to_string(),
            "{{input_path}}".to_string(),
            "--output".to_string(),
            "{{output_path}}".to_string(),
            "--verbose".to_string(),
        ];

        let input = PathBuf::from("/data/documents/report.jtd");
        let output = PathBuf::from("/data/sanitized/report_clean.jtd");

        let rendered = render_args(&args, &input, &output);

        assert_eq!(rendered.len(), 5);
        assert_eq!(rendered[0], "--input");
        assert_eq!(rendered[1], "/data/documents/report.jtd");
        assert_eq!(rendered[2], "--output");
        assert_eq!(rendered[3], "/data/sanitized/report_clean.jtd");
        assert_eq!(rendered[4], "--verbose");
    }

    #[test]
    fn test_template_no_variables_unchanged() {
        let args = vec![
            "--help".to_string(),
            "--version".to_string(),
        ];

        let input = PathBuf::from("/tmp/input.txt");
        let output = PathBuf::from("/tmp/output.txt");

        let rendered = render_args(&args, &input, &output);

        assert_eq!(rendered, args); // Unchanged
    }

    #[test]
    fn test_template_multiple_same_variable() {
        let args = vec![
            "{{input_path}}".to_string(),
            "copy".to_string(),
            "{{input_path}}".to_string(),
            "{{output_path}}".to_string(),
        ];

        let input = PathBuf::from("/data/file.dwg");
        let output = PathBuf::from("/data/out.dwg");

        let rendered = render_args(&args, &input, &output);

        assert_eq!(rendered[0], "/data/file.dwg");
        assert_eq!(rendered[2], "/data/file.dwg"); // Same variable, same replacement
        assert_eq!(rendered[3], "/data/out.dwg");
    }

    // =========================================================================
    // Test: Adapter Not Found for Unknown Extension
    // =========================================================================

    #[tokio::test]
    async fn test_adapter_not_found_unknown_extension() {
        let adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/test_work"));
        // Don't register anything for ".xyz"

        let input = PathBuf::from("/tmp/test.xyz");
        let output = PathBuf::from("/tmp/test_out.xyz");

        let result = adapter.sanitize(&input, &output, ".xyz").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No external sanitizer registered"));
    }

    // =========================================================================
    // Test: ExternalSanitizeResult Construction
    // =========================================================================

    #[test]
    fn test_result_construction_success() {
        let result = ExternalSanitizeResult::success_basic(0, 150);
        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.duration_ms, 150);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn test_result_construction_tool_not_found() {
        let result = ExternalSanitizeResult::tool_not_found("missing_tool.exe", 50);
        assert!(!result.success);
        assert!(result.exit_code.is_none());
        assert!(result.stderr.contains("Command not found"));
        assert_eq!(result.duration_ms, 50);
    }

    #[test]
    fn test_result_construction_timeout() {
        let result = ExternalSanitizeResult::timeout_result(30000);
        assert!(!result.success);
        assert!(result.exit_code.is_none());
        assert!(result.stderr.contains("timed out"));
        assert_eq!(result.duration_ms, 30000);
    }

    // =========================================================================
    // Test: Default Values
    // =========================================================================

    #[test]
    fn test_default_config_values() {
        let config = ExternalSanitizerConfig::default();
        assert!(config.extension.is_empty());
        assert!(config.command.is_empty());
        assert!(config.args.is_empty());
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.on_success, ExternalSuccessAction::TrustOutput);
        assert_eq!(config.on_failure, ExternalFailureAction::BlockAndLog);
    }

    #[test]
    fn test_default_success_action() {
        assert_eq!(ExternalSuccessAction::default(), ExternalSuccessAction::TrustOutput);
    }

    #[test]
    fn test_default_failure_action() {
        assert_eq!(ExternalFailureAction::default(), ExternalFailureAction::BlockAndLog);
    }

    // =========================================================================
    // Test: Multiple Extension Registration
    // =========================================================================

    #[test]
    fn test_multiple_extensions_registered() {
        let mut adapter = ExternalSanitizerAdapter::new(PathBuf::from("/tmp/test_work"));

        adapter.register(ExternalSanitizerConfig {
            extension: ".jtd".to_string(),
            command: "jtd_tool".to_string(),
            ..Default::default()
        }).unwrap();

        adapter.register(ExternalSanitizerConfig {
            extension: ".dwg".to_string(),
            command: "dwg_tool".to_string(),
            ..Default::default()
        }).unwrap();

        adapter.register(ExternalSanitizerConfig {
            extension: ".dxf".to_string(),
            command: "dxf_tool".to_string(),
            ..Default::default()
        }).unwrap();

        assert_eq!(adapter.config_count(), 3);
        assert!(adapter.find_adapter(".jtd").is_some());
        assert!(adapter.find_adapter(".dwg").is_some());
        assert!(adapter.find_adapter(".dxf").is_some());
        assert!(adapter.find_adapter(".unknown").is_none()); // Not registered
    }

    // =========================================================================
    // Test: Path Handling with Spaces and Unicode
    // =========================================================================

    #[test]
    fn test_template_with_spaces_in_path() {
        let args = vec!["{{input_path}}".to_string()];
        let input = PathBuf::from("/data/My Documents/report.jtd");
        let output = PathBuf::from("/data/output/result.jtd");

        let rendered = render_args(&args, &input, &output);
        assert_eq!(rendered[0], "/data/My Documents/report.jtd");
    }

    #[test]
    fn test_template_with_japanese_path() {
        let args = vec!["{{output_path}}".to_string()];
        let input = PathBuf::from("/tmp/input.txt");
        let output = PathBuf::from("/data/報告書/2026年度/成果物.pdf");

        let rendered = render_args(&args, &input, &output);
        assert_eq!(rendered[0], "/data/報告書/2026年度/成果物.pdf");
    }
}
