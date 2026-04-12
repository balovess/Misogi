// =============================================================================
// JtdConverter Trait — Ichitaro .jtd to PDF Conversion
// =============================================================================
// This module defines the trait interface for converting Ichitaro JTD (JustSystem
// Text Document) format files to Portable Document Format (PDF). The conversion
// capability is essential for the Japanese Market Compliance Kit, enabling
// Content Disarm & Reconstruction (CDR) pipelines to sanitize Japanese
// government/enterprise documents in their native format.
//
// Design Rationale:
// - Ichitaro (ジャストシステム 一太郎) holds ~20% market share in Japanese
//   government agencies and enterprises, making JTD support non-optional.
// - The trait abstracts multiple possible backend implementations:
//   * JustSystem COM/OLE automation (Windows-only, requires installed Ichitaro)
//   * LibreOffice headless conversion (cross-platform, format fidelity varies)
//   * Cloud-based conversion services (API-driven, network dependency)
//   * Custom native parser (maximum control, highest development cost)
// - Each implementation is selected at runtime based on platform availability,
//   licensing constraints, and organizational policy requirements.
//
// Thread Safety Guarantee:
// All implementors MUST be Send + Sync. Conversion operations are typically
// long-running (seconds to minutes for complex documents) and MUST be safe
// to invoke concurrently from multiple tokio tasks without data races.
// Implementations that wrap stateful converter processes MUST use internal
// synchronization (Arc<Mutex<T>>, channel-based serialization, or process pools).
//
// References:
// - JTD File Specification: Proprietary (JustSystem Corporation)
// - Ichitaro Product Line: https://www.justsystems.com/jp/products/
// - CDR Pipeline Integration: See crate::cdr_strategies::format_downgrade
// =============================================================================

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Result structure returned by [`JtdConverter::convert_to_pdf()`] upon completion.
///
/// This structure captures all observable outcomes of a single conversion operation,
/// forming part of the immutable audit chain of custody required by Japanese
//  government compliance frameworks (e-Gov Act, APPI audit trails).
///
/// All fields are serialized via `serde::Serialize` for JSONL audit log output
/// and structured monitoring pipeline consumption.
///
/// # Lifecycle
/// An instance of this struct is created exclusively by [`JtdConverter`] implementations
/// and consumed by the CDR pipeline's reporting subsystem. It MUST NOT be modified
/// after construction — all fields are public for serialization convenience but
/// semantically immutable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JtdConversionResult {
    /// Whether the conversion completed successfully without errors.
    ///
    /// When `false`, the caller SHOULD inspect error context from the
    /// `Result<JtdConversionError>` return rather than relying solely on this flag.
    /// This field exists for quick boolean checks in monitoring dashboards.
    pub success: bool,

    /// Absolute filesystem path to the generated PDF output file.
    ///
    /// This path points to a file that has been validated for existence and
    /// basic structural integrity (non-zero size, valid PDF header bytes).
    /// The file is owned by the caller after this result is returned; the
    /// converter implementation MUST NOT hold any references to it.
    pub output_path: PathBuf,

    /// Size of the original input `.jtd` file in bytes.
    ///
    /// Recorded before conversion begins for audit trail completeness.
    /// Used for compression ratio calculation: `converted_size / original_size`.
    /// A ratio significantly < 1.0 may indicate content loss during conversion.
    pub original_size_bytes: u64,

    /// Size of the converted PDF output file in bytes.
    ///
    /// Measured after conversion completes and before this result is returned.
    /// Used together with `original_size_bytes` for integrity verification and
    /// storage quota accounting in downstream processing stages.
    pub converted_size_bytes: u64,

    /// Number of pages in the generated PDF document, if determinable.
    ///
    /// `None` indicates that page count extraction was not attempted or failed.
    /// Implementations SHOULD populate this field when the converter provides
    /// page count metadata (e.g., via PDF info dictionary or printer driver API).
    ///
    /// Page count is critical for:
    /// - Cost estimation (per-page printing quotas in government offices)
    /// - Processing time prediction (larger documents need more sanitization time)
    /// - Compliance verification (page count preservation across conversions)
    pub page_count: Option<u32>,

    /// Wall-clock duration of the conversion operation in milliseconds.
    ///
    /// Measured from the start of input file parsing to the completion of
    /// PDF output writing. Does not include file I/O overhead outside the
    /// converter process itself (e.g., network latency for cloud converters).
    ///
    /// Used for:
    /// - SLA monitoring (conversion timeout enforcement)
    /// - Performance regression detection across converter versions
    /// - Capacity planning (throughput calculations for batch jobs)
    pub conversion_time_ms: u64,

    /// Human-readable identifier of the converter implementation used.
    ///
    /// Matches the value returned by [`JtdConverter::name()`] for the concrete
    /// implementation that performed this conversion. Used for audit trail
    /// attribution and A/B testing of different converter backends.
    ///
    /// # Examples
    /// - `"ichitaro-com-converter"` — Windows COM automation via installed Ichitaro
    /// - `"libreoffice-headless"` — Cross-platform LibreOffice conversion
    /// - `"cloud-jtd-service"` — Third-party cloud conversion API
    pub converter_used: String,
}

impl JtdConversionResult {
    /// Calculate the size change ratio between original and converted file.
    ///
    /// Returns `None` if `original_size_bytes` is zero (division by zero guard).
    /// Values > 1.0 indicate size increase (common when embedding fonts);
    /// values < 1.0 indicate size reduction (content stripping occurred).
    ///
    /// # Examples
    ///
    /// ```
    /// // Typical range: 0.3 (heavy reduction) to 2.5 (font embedding)
    /// let ratio = result.size_ratio().unwrap_or(1.0);
    /// if ratio < 0.5 {
    ///     tracing::warn!("Significant size reduction detected — possible content loss");
    /// }
    /// ```
    pub fn size_ratio(&self) -> Option<f64> {
        if self.original_size_bytes == 0 {
            return None;
        }
        Some(self.converted_size_bytes as f64 / self.original_size_bytes as f64)
    }

    /// Check whether this result indicates a successful conversion with valid output.
    ///
    /// A result is considered fully valid when:
    /// - `success` is true
    /// - Output file exists on disk (checked at construction time)
    /// - Converted size is greater than zero (non-empty PDF)
    pub fn is_valid(&self) -> bool {
        self.success && self.converted_size_bytes > 0
    }
}

/// Error type for JTD-to-PDF conversion operations.
///
/// This enum categorizes all failure modes that can occur during the conversion
/// lifecycle, from initial availability checking through final output validation.
/// Each variant carries sufficient diagnostic context for operator troubleshooting
/// and automated retry decision-making.
///
/// # Error Hierarchy
///
/// | Category        | Variants                  | Recovery Strategy          |
/// |-----------------|---------------------------|----------------------------|
/// | Infrastructure  | `ConverterNotFound`       | Install/configure converter|
/// |                 | `PlatformNotSupported`    | Switch to compatible backend|
/// | Runtime         | `ConversionFailed`        | Retry with exponential backoff|
/// |                 | `Timeout`                 | Increase timeout, retry     |
/// | I/O             | `IoError`                 | Check permissions, disk space|
///
/// # Conversion to MisogiError
/// Implementations of [`JtdConverter`] SHOULD convert these errors into
/// [`crate::error::MisogiError`] via appropriate `From` implementations
/// before returning to the CDR pipeline layer.
#[derive(Debug, thiserror::Error)]
pub enum JtdConversionError {
    /// The required converter tool or library is not available on this system.
    ///
    /// This error indicates a configuration or installation prerequisite failure:
    /// - Ichitaro COM server not registered (Windows)
    /// - LibreOffice `soffice` binary not found in PATH
    /// - Cloud service credentials missing or expired
    /// - Required native library (.dll/.so/.dylib) not loadable
    ///
    /// The enclosed string identifies which specific component is missing.
    #[error("converter tool not found: {0}")]
    ConverterNotFound(String),

    /// The conversion process itself failed after starting successfully.
    ///
    /// This variant covers failures that occur during the actual document
    /// transformation phase, distinct from setup/teardown issues:
    /// - Document parsing errors (corrupt JTD, unsupported features)
    /// - PDF generation errors (font embedding failures, image encoding issues)
    /// - Process crashes (converter segfaulted, OOM killed)
    /// - Output validation failures (produced invalid PDF bytes)
    ///
    /// The enclosed string contains error details from the converter's
    /// stderr output or error API return value.
    #[error("conversion process failed: {0}")]
    ConversionFailed(String),

    /// The conversion operation exceeded the allowed time limit.
    ///
    /// Long-running conversions are terminated proactively to prevent resource
    /// exhaustion in multi-tenant environments. The enclosed value is the
    /// configured timeout duration in milliseconds.
    ///
    /// # Common Causes
    /// - Extremely large or complex documents (thousands of pages)
    /// - Converter process hung waiting for user interaction (dialog boxes)
    /// - Resource contention (CPU/memory starvation on shared infrastructure)
    /// - Network timeouts (for cloud-based converter backends)
    #[error("conversion timed out after {0}ms")]
    Timeout(u64),

    /// A filesystem I/O error occurred during conversion.
    ///
    /// Wraps standard I/O errors encountered when:
    /// - Reading the input `.jtd` file (permissions, file locking)
    /// - Writing the output PDF file (disk full, read-only filesystem)
    /// - Creating temporary working directories
    /// - Accessing converter-specific cache or profile directories
    #[error("I/O error during JTD conversion: {0}")]
    Io(#[from] std::io::Error),

    /// The current operating system or architecture does not support conversion.
    ///
    /// Certain converter backends have hard platform dependencies:
    /// - Ichitaro COM automation requires Windows with DCOM support
    /// - Native parsers may be compiled only for specific architectures
    /// - Some cloud converters restrict by geographic region
    ///
    /// The enclosed string describes the unsupported platform constraint.
    #[error("platform not supported for JTD conversion: {0}")]
    PlatformNotSupported(String),
}

impl JtdConversionError {
    /// Determine whether this error is potentially recoverable via retry.
    ///
    /// Transient errors (`ConversionFailed`, `Timeout`) may succeed on retry
    /// if the underlying cause was temporary (resource contention, network glitch).
    /// Permanent errors (`ConverterNotFound`, `PlatformNotSupported`, certain
    /// `IoError` variants) will not resolve through retry alone.
    ///
    /// # Returns
    /// `true` if the caller should consider retrying the operation with
    /// exponential backoff; `false` if the error requires human intervention
    /// or configuration changes before retry is meaningful.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            JtdConversionError::ConversionFailed(_) | JtdConversionError::Timeout(_)
        )
    }

    /// Extract a machine-readable error code for logging/metrics systems.
    ///
    /// Returns a stable string identifier matching the variant name,
    /// suitable for use in Prometheus label values, structured log fields,
    /// and alert routing rules.
    pub fn error_code(&self) -> &'static str {
        match self {
            JtdConversionError::ConverterNotFound(_) => "CONVERTER_NOT_FOUND",
            JtdConversionError::ConversionFailed(_) => "CONVERSION_FAILED",
            JtdConversionError::Timeout(_) => "TIMEOUT",
            JtdConversionError::Io(_) => "IO_ERROR",
            JtdConversionError::PlatformNotSupported(_) => "PLATFORM_NOT_SUPPORTED",
        }
    }
}

/// Trait abstraction for Ichitaro JTD document to PDF conversion.
///
/// [`JtdConverter`] defines the contract that all JTD-to-PDF converter backends
/// must fulfill within the Misogi CDR pipeline. Multiple implementations coexist
/// and are selected at runtime based on availability, policy, and performance
/// requirements.
///
/// # Architecture Overview
///
/// ```text
/// ┌─────────────────────────────────────────────────────┐
/// │                   CDR Pipeline                       │
/// │                                                     │
/// │  Input: .jtd file                                    │
/// │      │                                              │
/// │      ▼                                              │
/// │  ┌─────────────────┐                                │
/// │  │  JtdConverter   │ ◄── Trait (this module)         │
/// │  │  (dyn object)   │                                │
/// │  └────────┬────────┘                                │
/// │           │                                         │
/// │     ┌─────┼─────┬──────────────┐                    │
/// │     ▼     ▼     ▼              ▼                    │
/// │  Ichitaro  LibreOffice  Cloud API  Native Parser     │
/// │  COM       Headless    Backend      (future)         │
/// └─────────────────────────────────────────────────────┘
/// ```
///
/// # Selection Strategy
/// The CDR pipeline maintains an ordered list of registered [`JtdConverter`]
/// implementations. At conversion time, each candidate's [`is_available()`]
/// method is called in priority order. The first implementation returning
/// `Ok(true)` is used for the actual conversion.
///
/// # Implementation Guidelines
///
/// ## Required Behavior
/// - [`name()`](JtdConverter::name): Return a stable, unique identifier string.
/// - [`is_available()`](JtdConverter::is_available): Perform lightweight
///   availability check without side effects (no file modifications).
/// - [`convert_to_pdf()`](JtdConverter::convert_to_pdf): Perform the actual
///   conversion with comprehensive error handling and result reporting.
///
/// ## Safety Requirements
/// - Input file MUST NOT be modified during or after conversion.
/// - Output file MUST be written to the specified `output_path` exactly.
/// - On error, `output_path` MUST NOT contain partial/corrupt data.
/// - Temporary files MUST be cleaned up in both success and error paths.
/// - Resource limits (memory, CPU, wall-clock time) MUST be enforced internally.
///
/// ## Performance Expectations
/// - `is_available()`: < 100ms (typically just binary existence check).
/// - `convert_to_pdf()`: Variable, but typical documents (< 100 pages)
///   should complete within 30 seconds. Implementations MUST enforce configurable
///   timeout limits and return [`JtdConversionError::Timeout`] when exceeded.
///
/// # Example Implementation Sketch
///
/// ```rust,ignore
/// use misogi_core::traits::jtd_converter::*;
/// use async_trait::async_trait;
///
/// pub struct LibreOfficeJtdConverter;
///
/// #[async_trait]
/// impl JtdConverter for LibreOfficeJtdConverter {
///     fn name(&self) -> &str {
///         "libreoffice-headless"
///     }
///
///     async fn is_available(&self) -> Result<bool, JtdConversionError> {
///         // Check if soffice binary exists in PATH
///         Ok(which::which("soffice").is_ok())
///     }
///
///     async fn convert_to_pdf(
///         &self,
///         input_path: &Path,
///         output_path: &Path,
///     ) -> Result<JtdConversionResult, JtdConversionError> {
///         // Execute: soffice --headless --convert-to pdf --outdir ...
///         // Validate output, collect metrics, return JtdConversionResult
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait JtdConverter: Send + Sync {
    /// Return the human-readable identifier of this converter implementation.
    ///
    /// This name serves multiple purposes:
    /// - **Audit trail attribution**: Records which backend processed each document.
    /// - **Configuration references**: Used in YAML/TOML config to select backends.
    /// - **Metrics labeling**: Attached as a label to conversion timing histograms.
    /// - **Log correlation**: Appears in all log messages from this implementation.
    ///
    /// # Contract
    /// - MUST be unique across all registered implementations in a single runtime.
    /// - SHOULD be stable across version upgrades (avoid changing names).
    /// - MUST be lowercase kebab-case for consistency with other Misogi identifiers.
    /// - Recommended length: 15-40 characters.
    ///
    /// # Examples
    /// - `"ichitaro-com-converter"`
    /// - `"libreoffice-jtd-converter"`
    /// - `"cloud-jtd-api-v1"`
    /// - `"native-jtd-parser"`
    fn name(&self) -> &str;

    /// Check whether this converter backend is operational and ready to use.
    ///
    /// This method performs a lightweight probe to determine if all prerequisites
    /// for conversion are satisfied, WITHOUT actually converting any document.
    /// It is called by the CDR pipeline's converter selection logic before
    /// attempting [`convert_to_pdf()`](JtdConverter::convert_to_pdf).
    ///
    /// # Probe Operations (Implementation-Specific)
    ///
    /// | Backend Type           | Typical Probe                          |
    /// |------------------------|----------------------------------------|
    /// | Ichitaro COM           | Query COM server registration via regsvr32 |
    /// | LibreOffice           | Check `soffice --version` exits cleanly |
    /// | Cloud API              | Health-check endpoint / credential validation |
    /// | Native parser          | Load shared library, verify ABI compatibility |
    ///
    /// # Returns
    /// - `Ok(true)` — Converter is available and ready for conversion tasks.
    /// - `Ok(false)` — Converter is intentionally unavailable (not installed,
    ///   disabled by policy, license exhausted). Caller should try next backend.
    /// - `Err(JtdConversionError::ConverterNotFound)` — Prerequisite missing
    ///   with diagnostic details.
    /// - `Err(JtdConversionError::PlatformNotSupported)` — Current OS/arch
    ///   cannot run this converter.
    ///
    /// # Performance
    /// This method MUST complete within 100ms under normal conditions.
    /// Expensive operations (network calls, process spawning) are prohibited.
    async fn is_available(&self) -> Result<bool, JtdConversionError>;

    /// Convert an Ichitaro JTD document file to PDF format.
    ///
    /// This is the primary operation of the trait. It reads the source `.jtd`
    /// file, transforms it through the converter backend's document processing
    /// engine, and writes the resulting PDF to the specified output path.
    ///
    /// # Arguments
    /// * `input_path` — Absolute path to the source `.jtd` file to convert.
    ///   The file MUST exist and be readable by the current process.
    ///   The file MUST NOT be modified by this method (read-only access).
    ///
    /// * `output_path` — Absolute path where the converted PDF will be written.
    ///   Parent directories MUST exist; this method creates (or overwrites)
    ///   the file at this exact path. If conversion fails, no partial file
    ///   MUST remain at this path (atomic write pattern recommended).
    ///
    /// # Returns
    /// A [`JtdConversionResult`] containing conversion metadata on success,
    /// or a [`JtdConversionError`] describing the failure mode on error.
    ///
    /// # Errors
    ///
    /// | Error Variant              | When It Occurs                              |
    /// |----------------------------|---------------------------------------------|
    /// | `ConverterNotFound`        | Converter became unavailable between `is_available()` check and conversion start |
    /// | `ConversionFailed`         | Document parsing, rendering, or PDF generation failed |
    /// | `Timeout`                  | Conversion exceeded configured time limit   |
    /// | `IoError`                  | File read/write/permission failures         |
    /// | `PlatformNotSupported`     | Runtime platform check failed unexpectedly  |
    ///
    /// # Implementation Requirements
    ///
    /// 1. **Input Validation**: Verify `input_path` exists and has `.jtd` extension
    ///    (or compatible magic bytes) before invoking the converter.
    ///
    /// 2. **Output Atomicity**: Write to a temporary file in the same directory,
    ///    then rename to `output_path` on success. This prevents partial writes
    ///    on crash/failure.
    ///
    /// 3. **Resource Limits**: Enforce maximum conversion time (configurable,
    ///    default 120 seconds). Kill converter subprocesses that exceed the limit.
    ///
    /// 4. **Cleanup**: Remove ALL temporary files (working directories, intermediate
    ///    formats, lock files) in both success and error code paths.
    ///
    /// 5. **Metrics Collection**: Record `original_size_bytes`, `converted_size_bytes`,
    ///    `page_count` (if available), and `conversion_time_ms` accurately.
    ///
    /// # Security Considerations
    /// - The input file originates from an untrusted source (external upload).
    /// - Converter backends MAY execute embedded scripts/macros if not properly
    ///   sandboxed. Implementations using desktop office suites (Ichitaro, LibreOffice)
    ///   SHOULD disable macro execution via command-line flags or security settings.
    /// - Output PDF MUST be scanned by downstream CDR stages before delivery.
    ///
    /// # Example Usage
    ///
    /// ```rust,ignore
    /// use std::path::PathBuf;
    /// use misogi_core::traits::jtd_converter::*;
    ///
    /// let converter = LibreOfficeJtdConverter;
    ///
    /// // Check availability first
    /// if !converter.is_available().await? {
    ///     return Err(JtdConversionError::ConverterNotFound(
    ///         "LibreOffice not installed".into(),
    ///     ));
    /// }
    ///
    /// // Perform conversion
    /// let result = converter
    ///     .convert_to_pdf(
    ///         &PathBuf::from("/tmp/input/document.jtd"),
    ///         &PathBuf::from("/tmp/output/document.pdf"),
    ///     )
    ///     .await?;
    ///
    /// assert!(result.is_valid());
    /// tracing::info!(
    ///     converter = %result.converter_used,
    ///     pages = ?result.page_count,
    ///     time_ms = result.conversion_time_ms,
    ///     "JTD conversion completed successfully"
    /// );
    /// ```
    async fn convert_to_pdf(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<JtdConversionResult, JtdConversionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Unit Tests: JtdConversionResult
    // =========================================================================

    #[test]
    fn test_result_size_ratio_normal() {
        let result = JtdConversionResult {
            success: true,
            output_path: PathBuf::from("/tmp/output.pdf"),
            original_size_bytes: 1_000_000,
            converted_size_bytes: 500_000,
            page_count: Some(10),
            conversion_time_ms: 1500,
            converter_used: "test-converter".to_string(),
        };

        let ratio = result.size_ratio();
        assert!(ratio.is_some());
        assert!((ratio.unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_result_size_ratio_zero_original() {
        let result = JtdConversionResult {
            success: true,
            output_path: PathBuf::from("/tmp/output.pdf"),
            original_size_bytes: 0,
            converted_size_bytes: 100,
            page_count: None,
            conversion_time_ms: 0,
            converter_used: "test-converter".to_string(),
        };

        assert!(result.size_ratio().is_none());
    }

    #[test]
    fn test_result_is_valid_success_with_content() {
        let result = JtdConversionResult {
            success: true,
            output_path: PathBuf::from("/tmp/output.pdf"),
            original_size_bytes: 1000,
            converted_size_bytes: 800,
            page_count: Some(5),
            conversion_time_ms: 1200,
            converter_used: "test".into(),
        };
        assert!(result.is_valid());
    }

    #[test]
    fn test_result_is_valid_failure_returns_false() {
        let result = JtdConversionResult {
            success: false,
            output_path: PathBuf::from("/tmp/output.pdf"),
            original_size_bytes: 1000,
            converted_size_bytes: 0,
            page_count: None,
            conversion_time_ms: 0,
            converter_used: "test".into(),
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_result_is_valid_zero_converted_size() {
        let result = JtdConversionResult {
            success: true,
            output_path: PathBuf::from("/tmp/output.pdf"),
            original_size_bytes: 1000,
            converted_size_bytes: 0,
            page_count: None,
            conversion_time_ms: 100,
            converter_used: "test".into(),
        };
        assert!(!result.is_valid());
    }

    // =========================================================================
    // Unit Tests: JtdConversionError
    // =========================================================================

    #[test]
    fn test_error_is_recoverable_conversion_failed() {
        let err = JtdConversionError::ConversionFailed("parse error".into());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_is_recoverable_timeout() {
        let err = JtdConversionError::Timeout(30000);
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_is_recoverable_not_found_not_recoverable() {
        let err = JtdConversionError::ConverterNotFound("soffice".into());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_error_is_recoverable_platform_not_supported() {
        let err = JtdConversionError::PlatformNotSupported("macOS".into());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_error_code_stability() {
        assert_eq!(
            JtdConversionError::ConverterNotFound("x".into()).error_code(),
            "CONVERTER_NOT_FOUND"
        );
        assert_eq!(
            JtdConversionError::ConversionFailed("x".into()).error_code(),
            "CONVERSION_FAILED"
        );
        assert_eq!(JtdConversionError::Timeout(0).error_code(), "TIMEOUT");
        assert_eq!(
            JtdConversionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                ""
            ))
            .error_code(),
            "IO_ERROR"
        );
        assert_eq!(
            JtdConversionError::PlatformNotSupported("x".into()).error_code(),
            "PLATFORM_NOT_SUPPORTED"
        );
    }

    #[test]
    fn test_error_display_messages() {
        use std::fmt::Write;

        let mut buf = String::new();
        write!(&mut buf, "{}", JtdConversionError::ConverterNotFound("tool".into()))
            .unwrap();
        assert!(buf.contains("tool"));

        buf.clear();
        write!(&mut buf, "{}", JtdConversionError::Timeout(5000)).unwrap();
        assert!(buf.contains("5000"));
    }

    // =========================================================================
    // Serialization Tests: JtdConversionResult
    // =========================================================================

    #[test]
    fn test_result_serialization_roundtrip() {
        let result = JtdConversionResult {
            success: true,
            output_path: PathBuf::from("C:\\data\\output.pdf"),
            original_size_bytes: 2048576,
            converted_size_bytes: 1024000,
            page_count: Some(42),
            conversion_time_ms: 5678,
            converter_used: "ichitaro-com-converter".to_string(),
        };

        let json = serde_json::to_string(&result).expect("serialization must succeed");
        let deserialized: JtdConversionResult =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(result, deserialized);
        assert_eq!(deserialized.page_count, Some(42));
        assert_eq!(deserialized.converter_used, "ichitaro-com-converter");
    }

    #[test]
    fn test_result_serialization_includes_all_fields() {
        let result = JtdConversionResult {
            success: false,
            output_path: PathBuf::from("/tmp/test.pdf"),
            original_size_bytes: 999,
            converted_size_bytes: 0,
            page_count: None,
            conversion_time_ms: 100,
            converter_used: "test-backend".to_string(),
        };

        let json = serde_json::to_string_pretty(&result).expect("must serialize");

        // Verify all expected fields appear in JSON output
        assert!(json.contains("\"success\""));
        assert!(json.contains("\"output_path\""));
        assert!(json.contains("\"original_size_bytes\""));
        assert!(json.contains("\"converted_size_bytes\""));
        assert!(json.contains("\"page_count\""));
        assert!(json.contains("\"conversion_time_ms\""));
        assert!(json.contains("\"converter_used\""));
    }
}
