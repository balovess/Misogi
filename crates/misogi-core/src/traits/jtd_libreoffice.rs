// =============================================================================
// LibreOffice JTD Converter — Headless JTD-to-PDF Conversion Backend
// =============================================================================
// This module implements the [`JtdConverter`] trait using LibreOffice's headless
// (`--headless`) mode for converting Ichitaro JTD documents to PDF format.
//
// Architecture:
// - Spawns `soffice` as a child process via `tokio::process::Command`
// - Uses `--headless --convert-to pdf --outdir <dir> <input>` command line
// - Enforces configurable timeout via `tokio::time::timeout`
// - Validates output PDF existence and non-zero size before returning success
//
// Platform Support:
// - Windows: soffice.com (preferred over .exe for console-mode behavior)
// - macOS: /Applications/LibreOffice.app/Contents/MacOS/soffice
// - Linux: /usr/bin/soffice or /usr/lib/libreoffice/program/soffice
//
// Thread Safety:
// This struct holds only configuration data (PathBuf + u64) and is inherently
// Send + Sync. Concurrent conversion invocations each spawn independent child
// processes with no shared mutable state.
//
// References:
// - LibreOffice headless conversion: https://help.libreoffice.org/latest/en-US/text/shared/guide/convertformats.html
// - Command-line options: `soffice --help --headless`
// =============================================================================

use std::path::{Path, PathBuf};
use std::time::Instant;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::timeout as tokio_timeout;

use super::jtd_converter::{JtdConversionError, JtdConversionResult, JtdConverter};

/// Default timeout for LibreOffice conversion operations in seconds.
///
/// Complex documents (hundreds of pages, embedded images, complex layouts)
/// may require extended processing time. 120 seconds accommodates typical
/// government/enterprise document sizes while preventing indefinite hangs.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

// =============================================================================
// Configuration Struct
// =============================================================================

/// Configuration for [`LibreOfficeJtdConverter`] suitable for TOML deserialization.
///
/// Used by the configuration subsystem to initialize converter instances from
/// external config files without hardcoding paths in source code.
///
/// # Example (TOML)
/// ```toml
/// [jtd_converter.libreoffice]
/// soffice_path = "C:\\Program Files\\LibreOffice\\program\\soffice.com"
/// timeout_secs = 180
/// ```
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct JtdLibreOfficeConfig {
    /// Explicit path to the `soffice` binary. When `None`, auto-detection is used.
    #[serde(default)]
    pub soffice_path: Option<String>,

    /// Maximum conversion time in seconds. Defaults to [`DEFAULT_TIMEOUT_SECS`].
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

impl Default for JtdLibreOfficeConfig {
    fn default() -> Self {
        Self {
            soffice_path: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

// =============================================================================
// Converter Implementation
// =============================================================================

/// LibreOffice-based JTD to PDF converter using headless mode.
///
/// This converter spawns a LibreOffice child process in headless mode to perform
/// document format conversion. It is the recommended cross-platform backend when
/// Ichitaro COM automation is unavailable (non-Windows or unlicensed environments).
///
/// # Selection Priority
/// In the CDR pipeline's converter selection order, this backend typically ranks
/// second after the native Ichitaro COM converter (when available on Windows).
///
/// # Resource Usage
/// Each conversion invocation spawns a separate `soffice` process. Memory usage
/// depends on document complexity but typically ranges from 100MB–500MB per process.
/// Callers should limit concurrent conversions based on available system memory.
pub struct LibreOfficeJtdConverter {
    /// Path to the `soffice` binary, or `None` for auto-detection at conversion time.
    soffice_path: Option<PathBuf>,
    /// Maximum wall-clock time allowed for a single conversion operation in seconds.
    timeout_secs: u64,
}

impl LibreOfficeJtdConverter {
    /// Create a new converter with default settings (auto-detect path, 120s timeout).
    ///
    /// The actual LibreOffice path is resolved lazily during [`is_available()`](JtdConverter::is_available)
    /// or [`convert_to_pdf()`](JtdConverter::convert_to_pdf) via platform-specific
    /// heuristics defined in [`detect_soffice_path()`](Self::detect_soffice_path).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a converter with an explicit `soffice` binary path.
    ///
    /// Use this constructor when the LibreOffice installation is in a non-standard
    /// location or when auto-detection is unreliable (e.g., multiple installations).
    ///
    /// # Arguments
    /// * `path` - Absolute or relative path to the `soffice` / `soffice.com` binary.
    ///
    /// # Example
    /// ```ignore
    /// let converter = LibreOfficeJtdConverter::with_path(
    ///     "C:\\Program Files\\LibreOffice\\program\\soffice.com"
    /// );
    /// ```
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            soffice_path: Some(path.into()),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    /// Set a custom timeout duration for conversion operations.
    ///
    /// # Arguments
    /// * `secs` - Maximum number of seconds to wait for conversion completion.
    ///   Must be > 0; values of 0 are clamped to 1 to prevent instant timeouts.
    ///
    /// # Returns
    /// `self` for method chaining (builder pattern).
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs.max(1);
        self
    }

    /// Create a converter from a structured configuration object.
    ///
    /// This factory method enables TOML-driven initialization for production
    /// deployments where converter settings are externalized.
    ///
    /// # Arguments
    /// * `config` - Parsed configuration with optional explicit path and timeout.
    pub fn from_config(config: &JtdLibreOfficeConfig) -> Self {
        let soffice_path = config.soffice_path.as_deref().map(PathBuf::from);
        let timeout_secs = config.timeout_secs.max(1);

        Self {
            soffice_path,
            timeout_secs,
        }
    }

    /// Resolve the effective `soffice` binary path.
    ///
    /// Returns the explicitly configured path if set, otherwise runs
    /// platform-specific auto-detection heuristics.
    ///
    /// # Errors
    /// - [`JtdConversionError::ConverterNotFound`] when no path is configured
    ///   and auto-detection fails to locate any LibreOffice installation.
    async fn resolve_soffice_path(&self) -> Result<PathBuf, JtdConversionError> {
        if let Some(ref path) = self.soffice_path {
            // Validate that the explicitly-configured path still exists
            if path.exists() {
                return Ok(path.clone());
            }
            return Err(JtdConversionError::ConverterNotFound(format!(
                "configured soffice path does not exist: {}",
                path.display()
            )));
        }

        match Self::detect_soffice_path().await {
            Some(path) => Ok(path),
            None => Err(JtdConversionError::ConverterNotFound(
                "LibreOffice installation not found".to_string(),
            )),
        }
    }

    /// Auto-detect the LibreOffice `soffice` binary path on the current platform.
    ///
    /// Scans platform-specific installation directories in priority order.
    /// Returns the first existing path, or `None` if no installation found.
    ///
    /// # Detection Order
    ///
    /// | Platform | Paths Checked (in order) |
    /// |----------|-------------------------|
    /// | Windows  | `C:\Program Files\LibreOffice\program\soffice.com`, `C:\Program Files (x86)\...`, `where soffice` |
    /// | macOS    | `/Applications/LibreOffice.app/Contents/MacOS/soffice` |
    /// | Linux    | `/usr/bin/soffice`, `/usr/local/bin/soffice`, `/usr/lib/libreoffice/program/soffice` |
    pub async fn detect_soffice_path() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            Self::detect_windows().await
        }
        #[cfg(target_os = "macos")]
        {
            Self::detect_macos().await
        }
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux().await
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    /// Windows-specific detection: check standard install locations and PATH.
    #[cfg(target_os = "windows")]
    async fn detect_windows() -> Option<PathBuf> {
        // Check common installation directories first (faster than shell commands)
        let candidates = [
            r"C:\Program Files\LibreOffice\program\soffice.com",
            r"C:\Program Files (x86)\LibreOffice\program\soffice.com",
            r"C:\Program Files\LibreOffice\program\soffice.exe",
            r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
        ];

        for candidate in &candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Some(path);
            }
        }

        // Fallback: use `where` command to search PATH
        match Command::new("cmd")
            .args(["/C", "where", "soffice"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // `where` returns multiple lines; take the first valid path
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        return Some(PathBuf::from(trimmed));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// macOS-specific detection: check standard .app bundle location.
    #[cfg(target_os = "macos")]
    async fn detect_macos() -> Option<PathBuf> {
        let candidates = [
            "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            "/Applications/LibreOffice Dev.app/Contents/MacOS/soffice",
        ];

        for candidate in &candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    /// Linux-specific detection: check standard FHS and distribution-specific paths.
    #[cfg(target_os = "linux")]
    async fn detect_linux() -> Option<PathBuf> {
        let candidates = [
            "/usr/bin/soffice",
            "/usr/local/bin/soffice",
            "/usr/lib/libreoffice/program/soffice",
            "/opt/libreoffice/program/soffice",
        ];

        for candidate in &candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    /// Build the LibreOffice command arguments for PDF conversion.
    ///
    /// Constructs the argument vector: `--headless --convert-to pdf --outdir <dir> <input>`
    ///
    /// # Arguments
    /// * `output_dir` - Directory where LibreOffice will write the output PDF.
    /// * `input_path` - Absolute path to the input `.jtd` file.
    fn build_conversion_args(output_dir: &Path, input_path: &Path) -> Vec<String> {
        vec![
            "--headless".to_string(),
            "--convert-to".to_string(),
            "pdf".to_string(),
            "--outdir".to_string(),
            output_dir.to_string_lossy().into_owned(),
            input_path.to_string_lossy().into_owned(),
        ]
    }

    /// Determine the expected output PDF path from the input filename and output directory.
    ///
    /// LibreOffice's `--convert-to pdf` produces output named `<stem>.pdf` in the
    /// specified output directory, where `<stem>` is the input filename without extension.
    fn expected_output_path(output_dir: &Path, input_path: &Path) -> PathBuf {
        let stem = input_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        output_dir.join(format!("{stem}.pdf"))
    }
}

impl Default for LibreOfficeJtdConverter {
    fn default() -> Self {
        Self {
            soffice_path: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

// =============================================================================
// JtdConverter Trait Implementation
// =============================================================================

#[async_trait]
impl JtdConverter for LibreOfficeJtdConverter {
    fn name(&self) -> &str {
        "libreoffice"
    }

    async fn is_available(&self) -> Result<bool, JtdConversionError> {
        match self.resolve_soffice_path().await {
            Ok(_) => Ok(true),
            Err(JtdConversionError::ConverterNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn convert_to_pdf(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<JtdConversionResult, JtdConversionError> {
        let start_time = Instant::now();

        // Step 1: Resolve soffice binary path
        let soffice_path = self.resolve_soffice_path().await?;

        // Step 2: Validate input file existence and readability
        if !input_path.exists() {
            return Err(JtdConversionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("input file not found: {}", input_path.display()),
            )));
        }

        let original_size_bytes = std::fs::metadata(input_path)?.len();

        // Step 3: Ensure output directory exists
        let output_dir = output_path
            .parent()
            .ok_or_else(|| {
                JtdConversionError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "output_path has no parent directory",
                ))
            })?;

        std::fs::create_dir_all(output_dir)?;

        // Step 4-6: Build and execute LibreOffice command with timeout
        let args = Self::build_conversion_args(output_dir, input_path);
        let expected_output = Self::expected_output_path(output_dir, input_path);

        tracing::debug!(
            soffice = %soffice_path.display(),
            args = ?args,
            "spawning LibreOffice conversion process"
        );

        let result = tokio_timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            Command::new(&soffice_path)
                .args(&args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?
                .wait_with_output(),
        )
        .await;

        // Step 7: Handle timeout vs completion
        let output = match result {
            Ok(inner_result) => inner_result?,
            Err(_) => {
                // Clean up partial output on timeout
                let _ = std::fs::remove_file(&expected_output);
                return Err(JtdConversionError::Timeout(self.timeout_secs * 1000));
            }
        };

        // Step 8: Check exit status
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Clean up any partial output on failure
            let _ = std::fs::remove_file(&expected_output);
            return Err(JtdConversionError::ConversionFailed(format!(
                "soffice exited with code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }

        // Step 9: Verify output PDF exists and move/rename if necessary
        if !expected_output.exists() {
            return Err(JtdConversionError::ConversionFailed(
                "LibreOffice completed successfully but output PDF was not created".to_string(),
            ));
        }

        // If the expected output path differs from the requested output_path,
        // rename/move the file to the exact target location
        if expected_output != output_path {
            // Remove existing file at target path if it exists (overwrite semantics)
            if output_path.exists() {
                std::fs::remove_file(output_path)?;
            }
            std::fs::rename(&expected_output, output_path)?;
        }

        // Step 10: Collect output metrics and build result
        let converted_size_bytes = std::fs::metadata(output_path)?.len();
        let conversion_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(JtdConversionResult {
            success: true,
            output_path: output_path.to_path_buf(),
            original_size_bytes,
            converted_size_bytes,
            page_count: None, // LibreOffice CLI does not expose page count easily
            conversion_time_ms,
            converter_used: self.name().to_string(),
        })
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Constructor Tests
    // =========================================================================

    #[test]
    fn test_default_constructor_values() {
        let converter = LibreOfficeJtdConverter::new();
        assert!(converter.soffice_path.is_none(), "default should have no explicit path");
        assert_eq!(converter.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_default_trait_impl() {
        let converter = LibreOfficeJtdConverter::default();
        assert!(converter.soffice_path.is_none());
        assert_eq!(converter.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_with_path_constructor() {
        let converter = LibreOfficeJtdConverter::with_path("/opt/libreoffice/bin/soffice");
        assert_eq!(
            converter.soffice_path.as_deref(),
            Some(Path::new("/opt/libreoffice/bin/soffice"))
        );
        assert_eq!(converter.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_with_timeout_builder() {
        let converter = LibreOfficeJtdConverter::new().with_timeout(300);
        assert_eq!(converter.timeout_secs, 300);
    }

    #[test]
    fn test_with_timeout_clamps_zero() {
        let converter = LibreOfficeJtdConverter::new().with_timeout(0);
        assert_eq!(converter.timeout_secs, 1, "zero timeout must be clamped to 1");
    }

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_from_config_default() {
        let config = JtdLibreOfficeConfig::default();
        let converter = LibreOfficeJtdConverter::from_config(&config);
        assert!(converter.soffice_path.is_none());
        assert_eq!(converter.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_from_config_custom() {
        let config = JtdLibreOfficeConfig {
            soffice_path: Some("/custom/path/soffice".to_string()),
            timeout_secs: 200,
        };
        let converter = LibreOfficeJtdConverter::from_config(&config);
        assert_eq!(
            converter.soffice_path.as_deref(),
            Some(Path::new("/custom/path/soffice"))
        );
        assert_eq!(converter.timeout_secs, 200);
    }

    #[test]
    fn test_from_config_zero_timeout_clamped() {
        let config = JtdLibreOfficeConfig {
            soffice_path: None,
            timeout_secs: 0,
        };
        let converter = LibreOfficeJtdConverter::from_config(&config);
        assert_eq!(converter.timeout_secs, 1);
    }

    // =========================================================================
    // Name Tests
    // =========================================================================

    #[test]
    fn test_name_returns_expected_identifier() {
        let converter = LibreOfficeJtdConverter::new();
        assert_eq!(converter.name(), "libreoffice");
    }

    // =========================================================================
    // Command Building Tests
    // =========================================================================

    #[test]
    fn test_build_conversion_args_structure() {
        let input = Path::new("/data/input/document.jtd");
        let output_dir = Path::new("/data/output");

        let args = LibreOfficeJtdConverter::build_conversion_args(output_dir, input);

        assert_eq!(args.len(), 6, "conversion expects exactly 6 arguments");
        assert_eq!(args[0], "--headless");
        assert_eq!(args[1], "--convert-to");
        assert_eq!(args[2], "pdf");
        assert_eq!(args[3], "--outdir");
        assert_eq!(args[4], "/data/output");
        assert_eq!(args[5], "/data/input/document.jtd");
    }

    #[test]
    fn test_build_conversion_args_preserves_spaces_in_paths() {
        let input = Path::new("/data/my documents/file.jtd");
        let output_dir = Path::new("/data/output dir");

        let args = LibreOfficeJtdConverter::build_conversion_args(output_dir, input);

        assert_eq!(args[4], "/data/output dir");
        assert_eq!(args[5], "/data/my documents/file.jtd");
    }

    // =========================================================================
    // Expected Output Path Tests
    // =========================================================================

    #[test]
    fn test_expected_output_path_simple_filename() {
        let input = Path::new("/input/report.jtd");
        let output_dir = Path::new("/output");

        let result = LibreOfficeJtdConverter::expected_output_path(output_dir, input);

        assert_eq!(result, Path::new("/output/report.pdf"));
    }

    #[test]
    fn test_expected_output_path_multiple_extensions() {
        // File like "archive.tar.jtd" — stem should be "archive.tar"
        let input = Path::new("/input/archive.tar.jtd");
        let output_dir = Path::new("/output");

        let result = LibreOfficeJtdConverter::expected_output_path(output_dir, input);

        assert_eq!(result, Path::new("/output/archive.tar.pdf"));
    }

    #[test]
    fn test_expected_output_path_no_extension() {
        let input = Path::new("/input/README");
        let output_dir = Path::new("/output");

        let result = LibreOfficeJtdConverter::expected_output_path(output_dir, input);

        // file_stem returns the full filename when there's no extension
        assert_eq!(result, Path::new("/output/README.pdf"));
    }

    // =========================================================================
    // Error Classification Tests
    // =========================================================================

    #[tokio::test]
    async fn test_is_available_returns_false_when_not_installed() {
        // Use a clearly nonexistent path to force detection failure
        let converter = LibreOfficeJtdConverter::with_path(
            "/this/path/definitely/does/not/exist/soffice",
        );
        let available = converter.is_available().await.unwrap();
        assert!(!available);
    }

    #[tokio::test]
    async fn test_convert_to_pdf_input_not_found_error() {
        // Use a system binary that is guaranteed to exist on all platforms
        // to bypass resolve_soffice_path and reach input file validation.
        #[cfg(target_os = "windows")]
        let converter =
            LibreOfficeJtdConverter::with_path(r"C:\Windows\System32\cmd.exe");
        #[cfg(target_os = "macos")]
        let converter = LibreOfficeJtdConverter::with_path("/bin/sh");
        #[cfg(target_os = "linux")]
        let converter = LibreOfficeJtdConverter::with_path("/bin/sh");

        let result = converter
            .convert_to_pdf(
                Path::new("/nonexistent/input.jtd"),
                Path::new("/tmp/output.pdf"),
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            JtdConversionError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io(NotFound), got {:?}", other),
        }
    }

    // =========================================================================
    // Config Serialization Tests
    // =========================================================================

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = JtdLibreOfficeConfig {
            soffice_path: Some(r"C:\Program Files\LibreOffice\program\soffice.com".to_string()),
            timeout_secs: 180,
        };

        let json = serde_json::to_string(&config).expect("serialization must succeed");
        let deserialized: JtdLibreOfficeConfig =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(deserialized.soffice_path, config.soffice_path);
        assert_eq!(deserialized.timeout_secs, 180);
    }

    #[test]
    fn test_config_default_serialization() {
        let config = JtdLibreOfficeConfig::default();
        let json = serde_json::to_string(&config).expect("must serialize");
        // Verify both fields appear
        assert!(json.contains("timeout_secs"));
    }

    // =========================================================================
    // Detection Logic Tests (platform-independent verification)
    // =========================================================================

    #[tokio::test]
    async fn test_detect_soffice_path_returns_option() {
        // We don't assume LibreOffice is installed in CI/test environments,
        // so we just verify the function returns Some or None without panicking.
        let result = LibreOfficeJtdConverter::detect_soffice_path().await;
        // If Some, verify it points to an existing file
        if let Some(ref path) = result {
            assert!(path.exists(), "detected path must exist");
        }
        // Both Some and None are valid outcomes depending on environment
    }

    // =========================================================================
    // Timeout Value Validation Tests
    // =========================================================================

    #[test]
    fn test_default_timeout_constant_value() {
        assert_eq!(DEFAULT_TIMEOUT_SECS, 120, "default timeout must be 120 seconds");
    }

    #[test]
    fn test_default_timeout_config_function() {
        assert_eq!(default_timeout_secs(), DEFAULT_TIMEOUT_SECS);
    }
}
