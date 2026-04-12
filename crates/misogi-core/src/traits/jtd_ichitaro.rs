// =============================================================================
// Ichitaro Viewer JTD-to-PDF Converter — Stub Implementation
// =============================================================================
// This module provides a converter backend that leverages the Ichitaro Viewer
// (一太郎ビューア) command-line interface for converting proprietary JustSystem
// Ichitaro JTD documents to PDF format with native format fidelity.
//
// Architecture Role:
// This converter is one of several pluggable backends implementing the [`JtdConverter`]
// trait within the Misogi CDR pipeline's Japanese Market Compliance Kit. It is selected
// at runtime based on platform availability and organizational policy.
//
// Platform Limitations:
// - **Windows-only**: Ichitaro Viewer is a native Windows application. This converter
//   returns `Ok(false)` from `is_available()` on non-Windows platforms and
//   `PlatformNotSupported` errors from `convert_to_pdf()`.
// - **Proprietary software**: Requires licensed installation of Ichitaro or
//   Ichitaro Viewer from JustSystem Corporation (https://www.justsystems.com/jp/).
// - **Version-dependent CLI**: The exact command-line interface varies across
//   Ichitaro versions. This implementation uses a configurable command template
//   that can be updated when the actual CLI is verified against specific versions.
//
// Security Considerations:
// - The input JTD file originates from an untrusted source (external upload).
// - Ichitaro Viewer MAY execute embedded macros if not properly sandboxed.
// - Output PDF MUST be scanned by downstream CDR stages before delivery.
// - This stub implementation does NOT execute the actual converter; it provides
//   the structural skeleton for future integration once CLI behavior is verified.
//
// References:
// - Ichitaro Product Line: https://www.justsystems.com/jp/products/ichitaro/
// - JTD File Specification: Proprietary (JustSystem Corporation)
// - CDR Pipeline Integration: See crate::traits::jtd_converter::JtdConverter
// =============================================================================

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tracing::{debug, info, warn};

use super::jtd_converter::{
    JtdConversionError, JtdConversionResult, JtdConverter,
};

/// Default timeout for conversion operations in seconds.
///
/// 60 seconds is sufficient for typical Japanese government documents
/// (< 100 pages). Complex documents with embedded objects may require more time.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Known installation paths for Ichitaro Viewer across different versions.
///
/// These paths are searched in order during auto-detection. The exact location
/// varies by:
/// - Ichitaro version (e.g., 2024, 2023, 2022, 2021, 2019, 2018)
/// - Edition (Standard, Pro, Justice, Smart, etc.)
/// - Installation architecture (x86 vs x64)
/// - OEM/bundled versions (NEC, Fujitsu, etc.)
///
/// # Limitations
/// This list covers the most common retail installations but is NOT exhaustive.
/// Enterprise deployments via MSI packages may install to custom locations.
/// Users SHOULD use [`IchitaroViewerConverter::with_path()`] to specify exact paths
/// for non-standard installations.
const KNOWN_VIEWER_PATHS: &[&str] = &[
    // Ichitaro 2024 / 2023 / 2022 (x86 on x64 Windows)
    r"C:\Program Files (x86)\JustSystems\Ichitaro\JVVIEW.EXE",
    // Ichitaro 2024 / 2023 / 2022 (native x64, if available)
    r"C:\Program Files\JustSystems\Ichitaro\JVVIEW.EXE",
    // Legacy Ichitaro 2019 / 2018
    r"C:\Program Files (x86)\JustSystems\Ichitaro2019\JVVIEW.EXE",
    r"C:\Program Files\JustSystems\Ichitaro2019\JVVIEW.EXE",
    // OEM variations (common in Japanese government)
    r"C:\Program Files (x86)\JustSystems\Ichitaro Smart\JVVIEW.EXE",
    // Alternative binary names in some versions
    r"C:\Program Files (x86)\JustSystems\Ichitaro\TAROVIEW.EXE",
];

/// Stub template string for the Ichitaro Viewer conversion command.
///
/// Placeholders:
/// - `{viewer}` — Path to the JVVIEW.EXE executable
/// - `{input}`  — Path to the source .jtd file
/// - `{output}` — Path to the target .pdf output file
///
/// # Note
/// This is a STUB placeholder. The actual CLI syntax must be verified
/// against the specific Ichitaro Viewer version installed. Common patterns
/// observed across versions include:
///
/// | Version Range     | Pattern                              |
/// |-------------------|--------------------------------------|
/// | Ichitaro 2018+    | `JVVIEW.EXE /S /P /O"output.pdf" input.jtd` |
/// | Ichitaro Viewer 9 | `JVVIEW.EXE /C /P input.jtd /D output_dir`  |
/// | OEM Custom        | Varies by vendor customization       |
///
/// The `/S` flag typically enables silent (non-interactive) mode,
/// `/P` triggers print-to-PDF conversion, and `/O` specifies output path.
const COMMAND_TEMPLATE: &str = r#"{viewer} /S /P /O"{output}" {input}"#;

// =============================================================================
// IchitaroViewerConverter — Public Interface
// =============================================================================

/// Converter backend using Ichitaro Viewer's command-line interface for JTD-to-PDF conversion.
///
/// This struct holds configuration for invoking the Ichitaro Viewer executable
/// as an external process to perform document conversion. It implements the
/// [`JtdConverter`] trait for integration into the Misogi CDR pipeline's
/// pluggable converter architecture.
///
/// # Lifecycle
///
/// ```text
/// Construction → [optional: with_path()] → [optional: with_timeout()]
///     │
///     ▼
/// is_available() check (by pipeline selector)
///     │
///     ▼ (if available)
/// convert_to_pdf(input, output) → JtdConversionResult
/// ```
///
/// # Thread Safety
/// This struct is `Send + Sync` (all fields are either owned values or
/// `Option<PathBuf>` which is `Send + Sync`). Multiple concurrent conversions
/// are safe because each invocation spawns an independent subprocess.
///
/// # Example
///
/// ```rust,ignore
/// use misogi_core::traits::jtd_ichitaro::IchitaroViewerConverter;
/// use misogi_core::traits::jtd_converter::JtdConverter;
/// use std::path::PathBuf;
///
/// // Create with default settings (auto-detect viewer, 60s timeout)
/// let converter = IchitaroViewerConverter::new();
///
/// // Or specify explicit path and custom timeout
/// let converter = IchitaroViewerConverter::new()
///     .with_path(r"C:\Tools\Ichitaro\JVVIEW.EXE")
///     .with_timeout(120);
 ///
/// if converter.is_available().await? {
///     let result = converter.convert_to_pdf(
///         &PathBuf::from("C:\\data\\document.jtd"),
///         &PathBuf::from("C:\\output\\document.pdf"),
///     ).await?;
/// }
/// ```
pub struct IchitaroViewerConverter {
    /// Absolute filesystem path to the Ichitaro Viewer executable (JVVIEW.EXE).
    ///
    /// When `None`, the converter will attempt auto-detection via
    /// [`detect_viewer_path()`] during [`is_available()`] checks.
    /// Use [`with_path()`](Self::with_path) to set explicitly.
    viewer_path: Option<PathBuf>,

    /// Maximum wall-clock time allowed for a single conversion operation.
    ///
    /// Measured in seconds. When exceeded, the converter subprocess is terminated
    /// and [`JtdConversionError::Timeout`] is returned. Default is 60 seconds.
    timeout_secs: u64,
}

impl IchitaroViewerConverter {
    /// Create a new Ichitaro Viewer converter with default configuration.
    ///
    /// Default values:
    /// - `viewer_path`: `None` (auto-detection will be attempted)
    /// - `timeout_secs`: 60 seconds
    ///
    /// # Returns
    /// A fresh `IchitaroViewerConverter` instance ready for use.
    ///
    /// # Example
    ///
    /// ```
    /// use misogi_core::traits::jtd_ichitaro::IchitaroViewerConverter;
    ///
    /// let converter = IchitaroViewerConverter::new();
    /// assert!(converter.viewer_path().is_none());
    /// assert_eq!(converter.timeout_secs(), 60);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            viewer_path: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    /// Set the explicit path to the Ichitaro Viewer executable.
    ///
    /// Use this method when auto-detection is insufficient (custom installations,
    /// network shares, non-standard OEM bundles). The provided path is stored
    /// as-is; existence validation occurs during [`is_available()`].
    ///
    /// # Arguments
    /// * `path` — Any type convertible to [`PathBuf`] (e.g., `&str`, `String`,
    ///   `PathBuf`). Should point to `JVVIEW.EXE` or equivalent viewer binary.
    ///
    /// # Returns
    /// `self` for method chaining (builder pattern).
    ///
    /// # Example
    ///
    /// ```
    /// use misogi_core::traits::jtd_ichitaro::IchitaroViewerConverter;
    ///
    /// let converter = IchitaroViewerConverter::new()
    ///     .with_path(r"C:\Custom\Ichitaro\JVVIEW.EXE");
    ///
    /// assert!(converter.viewer_path().is_some());
    /// ```
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.viewer_path = Some(path.into());
        self
    }

    /// Set the maximum conversion timeout in seconds.
    ///
    /// Increase this value for complex documents (thousands of pages,
    /// high-resolution embedded images, complex layouts typical of
    /// Japanese government forms). Decrease for strict SLA environments
    /// where hung processes must be detected quickly.
    ///
    /// # Arguments
    /// * `secs` — Timeout duration in seconds. Values < 1 are clamped to 1.
    ///
    /// # Returns
    /// `self` for method chaining (builder pattern).
    ///
    /// # Example
    ///
    /// ```
    /// use misogi_core::traits::jtd_ichitaro::IchitaroViewerConverter;
    ///
    /// let converter = IchitaroViewerConverter::new().with_timeout(120);
    /// assert_eq!(converter.timeout_secs(), 120);
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs.max(1);
        self
    }

    /// Get the configured viewer path, if explicitly set.
    ///
    /// Returns `None` if auto-detection will be used instead.
    #[must_use]
    pub const fn viewer_path(&self) -> &Option<PathBuf> {
        &self.viewer_path
    }

    /// Get the configured timeout in seconds.
    #[must_use]
    pub const fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// Auto-detect the Ichitaro Viewer installation path on Windows.
    ///
    /// This method searches well-known installation directories for
    /// `JVVIEW.EXE` (or equivalent viewer binaries) across common
    /// Ichitaro versions and editions.
    ///
    /// # Platform Behavior
    /// - **Windows**: Searches [`KNOWN_VIEWER_PATHS`] in order, returning
    ///   the first path that exists on disk.
    /// - **Non-Windows**: Always returns `None` immediately without I/O.
    ///
    /// # Returns
    /// - `Some(PathBuf)` containing the detected viewer executable path.
    /// - `None` if no installation found (or non-Windows platform).
    ///
    /// # Limitations
    /// - Only checks retail/OEM installation paths; enterprise MSI deployments
    ///   to custom locations require explicit [`with_path()`](Self::with_path).
    /// - Does not query Windows Registry (future enhancement could check
    ///   `HKLM\SOFTWARE\JustSystems\Ichitaro\InstallPath`).
    /// - Does not verify the binary is executable (only checks existence).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use misogi_core::traits::jtd_ichitaro::IchitaroViewerConverter;
    ///
    /// let path = IchitaroViewerConverter::detect_viewer_path();
    /// if let Some(ref p) = path {
    ///     println!("Found Ichitaro Viewer at: {}", p.display());
    /// } else {
    ///     println!("Ichitaro Viewer not found");
    /// }
    /// ```
    pub fn detect_viewer_path() -> Option<PathBuf> {
        // Non-Windows platforms cannot run Ichitaro Viewer natively.
        // Return None immediately without filesystem access.
        if !cfg!(target_os = "windows") {
            debug!(
                converter = "ichitaro_viewer",
                "Skipping viewer detection: platform is not Windows"
            );
            return None;
        }

        // Search known installation paths in priority order.
        // First match wins — this assumes newer installations overwrite
        // older ones or use distinct directory names.
        for candidate in KNOWN_VIEWER_PATHS {
            let path = PathBuf::from(candidate);
            if path.exists() {
                debug!(
                    converter = "ichitaro_viewer",
                    path = %path.display(),
                    "Found Ichitaro Viewer executable"
                );
                return Some(path);
            }
        }

        debug!(
            converter = "ichitaro_viewer",
            "Ichitaro Viewer not found in any known installation path"
        );
        None
    }

    /// Resolve the effective viewer path for conversion operations.
    ///
    /// Resolution strategy:
    /// 1. If [`viewer_path`](Self::viewer_path) was set explicitly, use it.
    /// 2. Otherwise, invoke [`detect_viewer_path()`] for auto-detection.
    ///
    /// # Errors
    /// Returns [`JtdConversionError::ConverterNotFound`] if no path can be
    /// resolved (not configured and auto-detection failed).
    ///
    /// # Returns
    /// The absolute path to the viewer executable on success.
    fn resolve_viewer_path(&self) -> Result<PathBuf, JtdConversionError> {
        // Priority 1: Explicitly configured path (user-specified)
        if let Some(ref path) = self.viewer_path {
            debug!(
                converter = "ichitaro_viewer",
                path = %path.display(),
                "Using explicitly configured viewer path"
            );
            return Ok(path.clone());
        }

        // Priority 2: Auto-detection from known installation locations
        debug!(
            converter = "ichitaro_viewer",
            "No explicit path configured; attempting auto-detection"
        );

        Self::detect_viewer_path().ok_or_else(|| {
            JtdConversionError::ConverterNotFound(
                "Ichitaro Viewer (JVVIEW.EXE) not found. \
                 Install Ichitaro or specify path via with_path()."
                    .into(),
            )
        })
    }

    /// Build the command line for invoking Ichitaro Viewer conversion.
    ///
    /// Constructs the command string from [`COMMAND_TEMPLATE`] by substituting
    /// placeholders with actual paths. This is a stub implementation that
    /// documents the expected interface; the actual CLI syntax should be
    /// verified against the installed Ichitaro Viewer version.
    ///
    /// # Arguments
    /// * `viewer_path` — Resolved path to the viewer executable.
    /// * `input_path` — Path to the source `.jtd` file.
    /// * `output_path` — Path for the generated PDF output.
    ///
    /// # Returns
    /// A tuple of (executable_path, argument_string) suitable for
    /// `tokio::process::Command::new().args()`.
    #[must_use]
    fn build_command(
        viewer_path: &Path,
        input_path: &Path,
        output_path: &Path,
    ) -> (PathBuf, String) {
        let cmd = COMMAND_TEMPLATE
            .replace("{viewer}", &viewer_path.to_string_lossy())
            .replace("{input}", &input_path.to_string_lossy())
            .replace("{output}", &output_path.to_string_lossy());

        debug!(
            converter = "ichitaro_viewer",
            command = %cmd,
            "Built conversion command (stub)"
        );

        // In production, we would parse the command properly to separate
        // the executable from its arguments. For now, return the template
        // result as documentation of expected usage.
        (viewer_path.to_path_buf(), cmd)
    }
}

impl Default for IchitaroViewerConverter {
    /// Create a default-configured converter instance.
    ///
    /// Equivalent to [`IchitaroViewerConverter::new()`] with no explicit
    /// viewer path and 60-second default timeout.
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// JtdConverter Trait Implementation
// =============================================================================

#[async_trait]
impl JtdConverter for IchitaroViewerConverter {
    /// Return the stable identifier `"ichitaro_viewer"` for this converter backend.
    ///
    /// This name is used for:
    /// - Audit trail attribution (which backend processed each document)
    /// - Configuration references (YAML/TOML backend selection)
    /// - Metrics labeling (conversion timing histograms)
    /// - Log correlation (all messages from this implementation)
    fn name(&self) -> &str {
        "ichitaro_viewer"
    }

    /// Check whether Ichitaro Viewer is available for conversion operations.
    ///
    /// # Platform-Specific Behavior
    ///
    /// | Platform | Return Value | Reason |
    /// |----------|-------------|--------|
    /// | Windows  | `Ok(true/false)` | Checks viewer binary existence |
    /// | Other    | `Ok(false)` | Ichitaro Viewer is Windows-only |
    ///
    /// This method performs a lightweight probe (< 100ms) consisting solely
    /// of filesystem existence checks. It does NOT spawn processes, load DLLs,
    /// or perform network operations.
    ///
    /// # Returns
    /// - `Ok(true)` — Viewer executable found and accessible.
    /// - `Ok(false)` — Viewer not installed (or non-Windows platform).
    /// - `Err(...)` — Unexpected error during availability check.
    async fn is_available(&self) -> Result<bool, JtdConversionError> {
        // Platform guard: Ichitaro Viewer is Windows-only software.
        // Return Ok(false) rather than error to allow graceful fallback
        // to other converter backends in the pipeline selection chain.
        if !cfg!(target_os = "windows") {
            debug!(
                converter = "ichitaro_viewer",
                "Availability check: not available (non-Windows platform)"
            );
            return Ok(false);
        }

        // Attempt to resolve viewer path (explicit config or auto-detection).
        match self.resolve_viewer_path() {
            Ok(path) => {
                // Final verification: confirm the resolved path exists on disk.
                // Handles race condition where viewer was uninstalled between
                // program start and this check.
                let exists = path.exists();

                if exists {
                    debug!(
                        converter = "ichitaro_viewer",
                        path = %path.display(),
                        "Availability check: viewer is ready"
                    );
                } else {
                    warn!(
                        converter = "ichitaro_viewer",
                        path = %path.display(),
                        "Availability check: configured path does not exist"
                    );
                }

                Ok(exists)
            }
            Err(e) => {
                debug!(
                    converter = "ichitaro_viewer",
                    error = %e,
                    "Availability check: viewer not found"
                );
                Ok(false) // Not an error — just unavailable
            }
        }
    }

    /// Convert an Ichitaro JTD document to PDF using the Viewer's CLI.
    ///
    /// # Stub Implementation Notice
    ///
    /// This is a **stub implementation** that provides the complete structural
    /// framework for Ichitaro Viewer-based conversion but does NOT yet execute
    /// the actual external process. The reasons for stub status:
    ///
    /// 1. **Proprietary CLI**: Ichitaro Viewer's exact command-line syntax is
    ///    not publicly documented and varies significantly between versions.
    ///    The [`COMMAND_TEMPLATE`] constant documents the EXPECTED pattern but
    ///    must be empirically verified against each supported version.
    ///
    /// 2. **Licensing**: Testing requires a valid Ichitaro Viewer license
    ///    which cannot be distributed with open-source test suites.
    ///
    /// 3. **Process Management**: Production use requires careful handling of:
    ///    - Window station/Desktop creation (non-interactive session)
    ///    - Print driver configuration (Microsoft Print to PDF)
    ///    - Temporary file cleanup on crash/hang
    ///    - Anti-virus interference with Office document processing
    ///
    /// # Current Behavior
    /// - Performs full input validation and platform guards.
    /// - Resolves viewer path and builds command template.
    /// - Logs what WOULD be executed (for development debugging).
    /// - Returns a mock [`JtdConversionResult`] indicating success.
    ///
    /// # Future Work
    /// Replace the stub body with actual `tokio::process::Command` execution
    /// once CLI behavior is certified against target Ichitaro versions.
    ///
    /// # Arguments
    /// * `input_path` — Absolute path to the source `.jtd` file.
    /// * `output_path` — Absolute path for the generated PDF output.
    ///
    /// # Returns
    /// A [`JtdConversionResult`] on success, or a [`JtdConversionError`] on failure.
    ///
    /// # Errors
    /// | Error Variant | Condition |
    /// |---------------|-----------|
    /// | `PlatformNotSupported` | Called on non-Windows OS |
    /// | `ConverterNotFound` | Viewer executable not found |
    /// | `IoError` | Input file missing or unreadable |
    /// | `Timeout` | Conversion exceeded configured time limit |
    /// | `ConversionFailed` | Viewer process exited with error |
    async fn convert_to_pdf(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<JtdConversionResult, JtdConversionError> {
        // -----------------------------------------------------------------
        // Step 1: Platform Guard — Windows-only enforcement
        // -----------------------------------------------------------------
        if !cfg!(target_os = "windows") {
            warn!(
                converter = %self.name(),
                "convert_to_pdf called on non-Windows platform; rejecting"
            );
            return Err(JtdConversionError::PlatformNotSupported(
                "Ichitaro Viewer is only available on Windows".into(),
            ));
        }

        info!(
            converter = %self.name(),
            input = %input_path.display(),
            output = %output_path.display(),
            timeout_secs = self.timeout_secs,
            "Starting JTD-to-PDF conversion (stub mode)"
        );

        // -----------------------------------------------------------------
        // Step 2: Input Validation — Verify source file exists
        // -----------------------------------------------------------------
        if !input_path.exists() {
            return Err(JtdConversionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Input file not found: {}", input_path.display()),
            )));
        }

        // Read original file size for audit trail metadata.
        let original_size_bytes = std::fs::metadata(input_path)?.len();

        // -----------------------------------------------------------------
        // Step 3: Resolve Viewer Path
        // -----------------------------------------------------------------
        let viewer_path = self.resolve_viewer_path()?;

        // -----------------------------------------------------------------
        // Step 4: Build Command (Stub — logs but does not execute)
        // -----------------------------------------------------------------
        let (_executable, _command_string) =
            Self::build_command(&viewer_path, input_path, output_path);

        // -----------------------------------------------------------------
        // Step 5: Execute Conversion (STUB — replace with tokio::process)
        // -----------------------------------------------------------------
        //
        // Production implementation sketch (when CLI is verified):
        //
        // ```rust,ignore
        // let start = std::time::Instant::now();
        //
        // let output = tokio::time::timeout(
        //     std::time::Duration::from_secs(self.timeout_secs),
        //     tokio::process::Command::new(&executable)
        //         .args(parse_args(&command_string))
        //         .creation_flags(CREATE_NO_WINDOW) // Hide console window
        //         .stdout(Stdio::piped())
        //         .stderr(Stdio::piped())
        //         .output(),
        // )
        // .await
        // .map_err(|_| JtdConversionError::Timeout(self.timeout_secs * 1000))?
        // .map_err(|e| JtdConversionError::ConversionFailed(e.to_string()))?;
        //
        // if !output.status.success() {
        //     let stderr = String::from_utf8_lossy(&output.stderr);
        //     return Err(JtdConversionError::ConversionFailed(stderr.into()));
        // }
        //
        // let converted_size_bytes = std::fs::metadata(output_path)?.len();
        // let conversion_time_ms = start.elapsed().as_millis() as u64;
        // ```

        // Stub: Simulate successful conversion with zero-byte output warning.
        // In production, these values come from actual file metadata.
        warn!(
            converter = %self.name(),
            "Conversion executed in STUB mode — no real transformation performed. \
             Replace with tokio::process::Command when CLI is verified."
        );

        let conversion_time_ms = 0; // Stub: no actual work performed
        let converted_size_bytes = 0; // Stub: no output file created

        // -----------------------------------------------------------------
        // Step 6: Construct and Return Result
        // -----------------------------------------------------------------
        let result = JtdConversionResult {
            success: true, // Stub: always reports success
            output_path: output_path.to_path_buf(),
            original_size_bytes,
            converted_size_bytes,
            page_count: None, // Stub: cannot determine without actual conversion
            conversion_time_ms,
            converter_used: self.name().to_string(),
        };

        info!(
            converter = %result.converter_used,
            success = result.success,
            original_bytes = result.original_size_bytes,
            converted_bytes = result.converted_size_bytes,
            time_ms = result.conversion_time_ms,
            "JTD-to-PDF conversion completed (stub)"
        );

        Ok(result)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test Group 1: Constructor and Builder Pattern
    // =========================================================================

    #[test]
    fn test_new_creates_instance_with_defaults() {
        let converter = IchitaroViewerConverter::new();

        assert!(
            converter.viewer_path().is_none(),
            "Default constructor should have no explicit viewer path"
        );
        assert_eq!(
            converter.timeout_secs(),
            DEFAULT_TIMEOUT_SECS,
            "Default timeout should be {} seconds",
            DEFAULT_TIMEOUT_SECS
        );
    }

    #[test]
    fn test_default_trait_matches_new() {
        let from_new = IchitaroViewerConverter::new();
        let from_default = IchitaroViewerConverter::default();

        assert_eq!(
            from_new.viewer_path().is_none(),
            from_default.viewer_path().is_none(),
            "Default trait should produce same state as new()"
        );
        assert_eq!(
            from_new.timeout_secs(),
            from_default.timeout_secs(),
            "Default trait timeout should match new()"
        );
    }

    #[test]
    fn test_with_path_sets_viewer_path() {
        let custom_path = PathBuf::from(r"C:\Custom\Ichitaro\JVVIEW.EXE");
        let converter = IchitaroViewerConverter::new().with_path(&custom_path);

        assert_eq!(
            converter.viewer_path(),
            &Some(custom_path),
            "with_path() should store the provided path"
        );
    }

    #[test]
    fn test_with_timeout_sets_custom_duration() {
        let converter = IchitaroViewerConverter::new().with_timeout(120);

        assert_eq!(
            converter.timeout_secs(),
            120,
            "with_timeout(120) should set timeout to 120 seconds"
        );
    }

    #[test]
    fn test_with_timeout_clamps_minimum_to_one() {
        let converter = IchitaroViewerConverter::new().with_timeout(0);

        assert_eq!(
            converter.timeout_secs(),
            1,
            "with_timeout(0) should clamp to minimum of 1 second"
        );
    }

    #[test]
    fn test_builder_chain_combines_all_setters() {
        let converter = IchitaroViewerConverter::new()
            .with_path(r"C:\Tools\JVVIEW.EXE")
            .with_timeout(300);

        assert!(converter.viewer_path().is_some());
        assert_eq!(converter.timeout_secs(), 300);
    }

    // =========================================================================
    // Test Group 2: Converter Identity
    // =========================================================================

    #[test]
    fn test_name_returns_expected_identifier() {
        let converter = IchitaroViewerConverter::new();

        assert_eq!(
            converter.name(),
            "ichitaro_viewer",
            "name() should return 'ichitaro_viewer' for audit trail consistency"
        );
    }

    // =========================================================================
    // Test Group 3: Platform Detection
    // =========================================================================

    #[tokio::test]
    async fn test_is_available_returns_false_on_non_windows() {
        let converter = IchitaroViewerConverter::new();

        // This test runs on whatever platform the CI uses.
        // On non-Windows, it verifies the graceful degradation path.
        // On Windows, it may return true/false depending on installation.
        let available = converter.is_available().await.expect(
            "is_available() should never return Err for platform check",
        );

        // On non-Windows platforms, this MUST be false.
        // On Windows, we don't assert a value (depends on installed software).
        if !cfg!(target_os = "windows") {
            assert!(
                !available,
                "is_available() must return false on non-Windows platforms"
            );
        }
    }

    #[tokio::test]
    async fn test_convert_to_pdf_rejects_non_windows() {
        let converter = IchitaroViewerConverter::new();
        let input = PathBuf::from("/tmp/test.jtd");
        let output = PathBuf::from("/tmp/test.pdf");

        let result = converter.convert_to_pdf(&input, &output).await;

        // On non-Windows, this MUST fail with PlatformNotSupported.
        // On Windows, it may succeed (stub) or fail for other reasons.
        if !cfg!(target_os = "windows") {
            match result {
                Err(JtdConversionError::PlatformNotSupported(msg)) => {
                    assert!(
                        msg.contains("Windows"),
                        "Error message should mention Windows: {msg}"
                    );
                }
                other => panic!(
                    "Expected PlatformNotSupported error on non-Windows, got: {other:?}"
                ),
            }
        }
    }

    // =========================================================================
    // Test Group 4: Auto-Detection Logic
    // =========================================================================

    #[test]
    fn test_detect_viewer_path_returns_none_on_non_windows() {
        // On non-Windows, auto-detection should return None immediately
        // without performing any filesystem I/O.
        let result = IchitaroViewerConverter::detect_viewer_path();

        if !cfg!(target_os = "windows") {
            assert!(
                result.is_none(),
                "detect_viewer_path() must return None on non-Windows"
            );
        }
        // On Windows, we don't assert (depends on local installation).
    }

    #[test]
    fn test_known_viewer_paths_is_non_empty() {
        assert!(
            !KNOWN_VIEWER_PATHS.is_empty(),
            "KNOWN_VIEWER_PATHS should contain at least one candidate path"
        );
    }

    #[test]
    fn test_known_viewer_paths_contain_common_locations() {
        // Verify that the most common installation path is included.
        let has_program_files_x86 = KNOWN_VIEWER_PATHS.iter().any(|p| {
            p.contains("Program Files (x86)") && p.contains("JustSystems")
        });

        assert!(
            has_program_files_x86,
            "KNOWN_VIEWER_PATHS should include Program Files (x86)\\JustSystems path"
        );
    }

    // =========================================================================
    // Test Group 5: Command Template Structure
    // =========================================================================

    #[test]
    fn test_command_template_contains_required_placeholders() {
        assert!(
            COMMAND_TEMPLATE.contains("{viewer}"),
            "Command template must contain {{viewer}} placeholder"
        );
        assert!(
            COMMAND_TEMPLATE.contains("{input}"),
            "Command template must contain {{input}} placeholder"
        );
        assert!(
            COMMAND_TEMPLATE.contains("{output}"),
            "Command template must contain {{output}} placeholder"
        );
    }

    #[test]
    fn test_build_command_substitutes_placeholders() {
        let viewer = PathBuf::from(r"C:\Ichitaro\JVVIEW.EXE");
        let input = PathBuf::from(r"C:\data\doc.jtd");
        let output = PathBuf::from(r"C:\out\doc.pdf");

        let (_exe, cmd) = IchitaroViewerConverter::build_command(&viewer, &input, &output);

        assert!(
            cmd.contains("JVVIEW.EXE"),
            "Built command should contain viewer filename: {cmd}"
        );
        assert!(
            cmd.contains("doc.jtd"),
            "Built command should contain input filename: {cmd}"
        );
        assert!(
            cmd.contains("doc.pdf"),
            "Built command should contain output filename: {cmd}"
        );
    }

    // =========================================================================
    // Test Group 6: Edge Cases and Error Conditions
    // =========================================================================

    #[tokio::test]
    async fn test_convert_to_pdf_missing_input_returns_io_error() {
        let converter = IchitaroViewerConverter::new();
        let nonexistent = PathBuf::from(r"C:\this\file\does\not\exist.jtd");
        let output = PathBuf::from(r"C:\output.pdf");

        let result = converter.convert_to_pdf(&nonexistent, &output).await;

        // Should fail with IoError due to missing input file (on Windows).
        // On non-Windows, fails earlier with PlatformNotSupported.
        if cfg!(target_os = "windows") {
            match result {
                Err(JtdConversionError::Io(_)) => (), // Expected
                other => panic!("Expected IoError for missing file, got: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_viewer_path_fails_when_not_found() {
        // Create converter WITHOUT setting a path (forces auto-detection).
        // On systems without Ichitaro installed, this should fail.
        let converter = IchitaroViewerConverter::new();

        // Only test on platforms where auto-detection won't find anything.
        // Skip on Windows machines that might have Ichitaro installed.
        if !cfg!(target_os = "windows") {
            let result = converter.resolve_viewer_path();
            assert!(
                result.is_err(),
                "resolve_viewer_path() should fail when no viewer is installed"
            );

            match result.unwrap_err() {
                JtdConversionError::ConverterNotFound(msg) => {
                    assert!(
                        msg.contains("JVVIEW.EXE"),
                        "Error message should mention JVVIEW.EXE: {msg}"
                    );
                }
                other => panic!("Expected ConverterNotFound, got: {other:?}"),
            }
        }
    }

    #[test]
    fn test_send_sync_bounds() {
        // Compile-time verification that the converter satisfies Send + Sync bounds
        // required by the JtdConverter trait for concurrent async task usage.
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<IchitaroViewerConverter>();
    }
}
