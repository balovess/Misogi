// =============================================================================
// DummyJtdConverter — Placeholder JTD-to-PDF Converter for Testing
// =============================================================================
// This module provides a no-dependency implementation of the [`JtdConverter`]
// trait that generates minimal valid PDF files without requiring any external
// converter tools (Ichitaro, LibreOffice, etc.). It serves two primary purposes:
//
// 1. **Development/Testing**: Allows the CDR pipeline to be tested end-to-end
//    without installing proprietary Japanese word processor software.
// 2. **Fallback Stub**: Provides a known-good baseline converter for integration
//    testing and benchmarking of the conversion infrastructure.
//
// Design Decisions:
// - The [`DummyAction`] enum controls converter behavior at construction time,
//   enabling both happy-path and error-path testing from the same codebase.
// - PDF generation uses raw bytes (no external crates) to maintain the
//   zero-dependency invariant of this module.
// - All operations are synchronous internally but exposed via async trait
//   methods to satisfy the [`JtdConverter`] interface contract.
//
// Security Considerations:
// - Generated PDFs contain no executable content, scripts, or active elements.
// - Output is written atomically (write to temp, then rename) to prevent
//   partial file corruption on failure.
// - Input files are read-only; no modification occurs during conversion.
//
// References:
// - PDF Reference 1.7: https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf
// - ISO 32000-1: Portable Document Format specification
// =============================================================================

use std::path::{Path, PathBuf};
use std::time::Instant;

use async_trait::async_trait;

use super::jtd_converter::{JtdConversionError, JtdConversionResult, JtdConverter};

// =============================================================================
// DummyAction Enum — Behavior Configuration
// =============================================================================

/// Controls the operational mode of [`DummyJtdConverter`].
///
/// This enum enables test code to exercise both success and error paths
/// of the conversion pipeline without requiring external dependencies or
/// mock frameworks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum DummyAction {
    /// Generate a minimal valid blank PDF (single A4 page).
    #[serde(rename = "placeholder_pdf")]
    PlaceholderPdf,

    /// Simulate a conversion failure by returning an error.
    #[serde(rename = "error")]
    Error,
}

impl Default for DummyAction {
    /// Returns [`DummyAction::PlaceholderPdf`] as the default behavior.
    fn default() -> Self {
        Self::PlaceholderPdf
    }
}

// =============================================================================
// DummyJtdConverter Struct — No-Dependency Converter Implementation
// =============================================================================

/// A placeholder [`JtdConverter`] implementation that generates minimal PDFs.
///
/// This converter does not perform actual JTD-to-PDF transformation. Instead,
/// it produces a minimal valid PDF document (single blank A4 page) regardless
/// of input content. It is designed for:
///
/// - **Unit testing** of CDR pipeline components without external tooling.
/// - **Integration testing** of converter selection and fallback logic.
/// - **Development environments** where Ichitaro/LibreOffice are unavailable.
/// - **Benchmarking** of pipeline overhead independent of conversion time.
///
/// # Thread Safety
/// This struct contains no internal mutable state and is freely `Send + Sync`.
/// Multiple concurrent conversions are safe and do not share any resources.
///
/// # Example
///
/// ```rust,ignore
/// use misogi_core::traits::jtd_dummy::{DummyJtdConverter, DummyAction};
///
/// // Create converter in placeholder mode (default)
/// let converter = DummyJtdConverter::default();
///
/// // Or explicitly specify error mode for testing error paths
/// let failing_converter = DummyJtdConverter::new(DummyAction::Error);
/// ```
#[derive(Debug, Clone)]
pub struct DummyJtdConverter {
    /// Configured behavior for this converter instance.
    dummy_action: DummyAction,
}

impl Default for DummyJtdConverter {
    /// Creates a converter with [`DummyAction::PlaceholderPdf`] behavior.
    fn default() -> Self {
        Self {
            dummy_action: DummyAction::PlaceholderPdf,
        }
    }
}

impl DummyJtdConverter {
    /// Create a new `DummyJtdConverter` with the specified action mode.
    ///
    /// # Arguments
    /// * `action` — The [`DummyAction`] controlling conversion behavior.
    ///
    /// # Returns
    /// A new `DummyJtdConverter` instance ready for use.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use misogi_core::traits::jtd_dummy::{DummyJtdConverter, DummyAction};
    ///
    /// let converter = DummyJtdConverter::new(DummyAction::PlaceholderPdf);
    /// ```
    pub fn new(action: DummyAction) -> Self {
        Self { dummy_action: action }
    }

    // -----------------------------------------------------------------------
    // Minimal PDF Generation
    // -----------------------------------------------------------------------

    /// Generate a minimal valid PDF document as a byte vector.
    ///
    /// The produced PDF conforms to PDF 1.4 specification with:
    /// - Valid `%PDF-1.4` header with binary comment marker
    /// - Single page object referencing an A4-sized media box (595 × 842 pt)
    /// - Required objects: Catalog, Pages, Page, MediaBox, Font, Contents
    /// - Cross-reference table with correct byte offsets
    /// - Trailer dictionary with Size and Root entries
    /// - `%%EOF` marker at file end
    ///
    /// Total size is approximately 750-850 bytes depending on object offsets.
    ///
    /// # Returns
    /// A `Vec<u8>` containing a complete, parseable PDF document.
    fn generate_minimal_pdf() -> Vec<u8> {
        // PDF structure overview:
        //
        // Object 1: Catalog (type/Catalog,Pages ref)
        // Object 2: Pages (type/Pages,Kids[],Count 1)
        // Object 3: Page (type/Page,Parent ref,MediaBox,Contents ref,Resources/Font ref)
        // Object 4: Font (type/Font,Subtype/Type1,BaseFont/Helvetica)
        // Object 5: Contents (stream with empty content "BT ET")
        //
        // We build the PDF incrementally, tracking byte offsets for xref.

        let mut pdf = Vec::with_capacity(1024);

        // ---- Header ----
        pdf.extend_from_slice(b"%PDF-1.4\n");
        // Binary comment (bytes 128-255) to declare binary content
        pdf.extend_from_slice(b"%\xe2\xe3\xcf\xd3\n");

        // We'll track object positions after writing each one
        let obj1_pos = pdf.len() as u64;
        // Object 1: Catalog
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        let obj2_pos = pdf.len() as u64;
        // Object 2: Pages
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        let obj3_pos = pdf.len() as u64;
        // Object 3: Page (A4 size: 595 x 842 points)
        pdf.extend_from_slice(
            b"3 0 obj\n\
             << /Type /Page \
             /Parent 2 0 R \
             /MediaBox [0 0 595 842] \
             /Contents 5 0 R \
             /Resources << /Font << /F1 4 0 R >> >> \
             >>\n\
             endobj\n",
        );

        let obj4_pos = pdf.len() as u64;
        // Object 4: Font (Type1 Helvetica — one of the 14 standard fonts)
        pdf.extend_from_slice(
            b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        );

        let obj5_pos = pdf.len() as u64;
        // Object 5: Content stream (empty page — just begin/end text)
        let content_stream = b"BT ET";
        pdf.extend_from_slice(b"5 0 obj\n<< /Length ");
        pdf.extend_from_slice(content_stream.len().to_string().as_bytes());
        pdf.extend_from_slice(b" >>\nstream\n");
        pdf.extend_from_slice(content_stream);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        // ---- Cross-Reference Table ----
        let xref_pos = pdf.len() as u64;
        pdf.extend_from_slice(b"xref\n");
        pdf.extend_from_slice(b"0 6\n");
        // Entry 0: free object head (always present)
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        // Entries 1-5: used objects with their byte offsets
        pdf.extend_from_slice(format!("{:010} 00000 n \n", obj1_pos).as_bytes());
        pdf.extend_from_slice(format!("{:010} 00000 n \n", obj2_pos).as_bytes());
        pdf.extend_from_slice(format!("{:010} 00000 n \n", obj3_pos).as_bytes());
        pdf.extend_from_slice(format!("{:010} 00000 n \n", obj4_pos).as_bytes());
        pdf.extend_from_slice(format!("{:010} 00000 n \n", obj5_pos).as_bytes());

        // ---- Trailer ----
        pdf.extend_from_slice(b"trailer\n");
        pdf.extend_from_slice(b"<< /Size 6 /Root 1 0 R >>\n");
        pdf.extend_from_slice(b"startxref\n");
        pdf.extend_from_slice(xref_pos.to_string().as_bytes());
        pdf.extend_from_slice(b"\n%%EOF\n");

        pdf
    }
}

// =============================================================================
// JtdConverter Trait Implementation
// =============================================================================

#[async_trait]
impl JtdConverter for DummyJtdConverter {
    /// Returns the constant identifier `"dummy"` for this converter.
    ///
    /// This name appears in audit logs, metrics labels, and configuration
    /// references. It is stable across versions and unique among all
    /// registered converter implementations.
    fn name(&self) -> &str {
        "dummy"
    }

    /// Always reports availability — no external dependency checking needed.
    ///
    /// Unlike real converters that must probe for installed software
    /// (Ichitaro COM server, LibreOffice binary, cloud credentials),
    /// the dummy converter has zero prerequisites and is always ready.
    ///
    /// # Returns
    /// Always `Ok(true)` immediately (synchronous, no I/O).
    async fn is_available(&self) -> Result<bool, JtdConversionError> {
        Ok(true)
    }

    /// Convert a `.jtd` file to PDF using the configured [`DummyAction`] mode.
    ///
    /// # Behavior by Mode
    ///
    /// | Mode              | Action                                      |
    /// |-------------------|---------------------------------------------|
    /// | `PlaceholderPdf`  | Generate minimal valid PDF to `output_path`  |
    /// | `Error`           | Return `Err(JtdConversionError::ConversionFailed)` |
    ///
    /// # PlaceholderPdf Mode Details
    ///
    /// When configured with [`DummyAction::PlaceholderPdf`], this method:
    /// 1. Reads the input file to determine `original_size_bytes`.
    /// 2. Generates a minimal valid PDF (single blank A4 page).
    /// 3. Writes the PDF to `output_path` atomically.
    /// 4. Records wall-clock timing for the operation.
    /// 5. Returns a [`JtdConversionResult`] with complete metadata.
    ///
    /// # Atomic Write Guarantee
    /// The output file is written to a temporary location first, then renamed
    /// to the target path on success. On failure, no partial file remains.
    ///
    /// # Errors
    ///
    /// | Condition                          | Error Variant               |
    /// |-------------------------------------|-----------------------------|
    /// | `dummy_action` is `Error`           | `ConversionFailed`           |
    /// | Input file cannot be read           | `IoError`                   |
    /// | Output file cannot be written       | `IoError`                   |
    ///
    /// # Arguments
    /// * `input_path` — Path to the source `.jtd` file (read for size only).
    /// * `output_path` — Path where the generated PDF will be written.
    ///
    /// # Returns
    /// A [`JtdConversionResult`] on success, or a [`JtdConversionError`] on failure.
    async fn convert_to_pdf(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<JtdConversionResult, JtdConversionError> {
        // Check configured action mode
        if self.dummy_action == DummyAction::Error {
            return Err(JtdConversionError::ConversionFailed(
                "Dummy converter configured to error".into(),
            ));
        }

        // Record start time for conversion timing
        let start_time = Instant::now();

        // Read input file metadata (size only — we don't parse JTD content)
        let original_size_bytes = std::fs::metadata(input_path)?.len();

        // Generate minimal valid PDF bytes
        let pdf_bytes = Self::generate_minimal_pdf();

        // Atomic write pattern: write to temp file, then rename
        let output_dir = output_path
            .parent()
            .ok_or_else(|| {
                JtdConversionError::ConversionFailed(
                    "Output path has no parent directory".into(),
                )
            })?;

        // Ensure output directory exists
        std::fs::create_dir_all(output_dir)?;

        // Write PDF to temporary file in same directory (same filesystem = atomic rename)
        let temp_path = output_path.with_extension("pdf.tmp");
        std::fs::write(&temp_path, &pdf_bytes)?;

        // Atomically rename temp file to final output path
        std::fs::rename(&temp_path, output_path)?;

        // Calculate conversion time
        let conversion_time_ms = start_time.elapsed().as_millis() as u64;

        // Build and return result
        Ok(JtdConversionResult {
            success: true,
            output_path: PathBuf::from(output_path),
            original_size_bytes,
            converted_size_bytes: pdf_bytes.len() as u64,
            page_count: Some(1), // Single blank A4 page
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
    // Test Utilities
    // =========================================================================

    /// Create a temporary directory with automatic cleanup scope.
    ///
    /// Returns the path to a newly created empty temp directory.
    /// Caller is responsible for cleanup (or rely on OS temp cleaner).
    fn setup_temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("misogi_dummy_jtd_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir creation must succeed");
        dir
    }

    /// Create a dummy input file with specified size at the given path.
    fn create_dummy_input(path: &Path, size_bytes: usize) {
        let data = vec![0x41u8; size_bytes]; // Fill with 'A' bytes
        std::fs::write(path, &data).expect("dummy input creation must succeed");
    }

    // =========================================================================
    // Test 1: is_available() returns true
    // =========================================================================

    #[tokio::test]
    async fn test_is_available_returns_true() {
        let converter = DummyJtdConverter::default();
        let result = converter.is_available().await;

        assert!(result.is_ok(), "is_available() must return Ok");
        assert!(
            result.unwrap(),
            "is_available() must return true for dummy converter"
        );
    }

    // =========================================================================
    // Test 2: convert_to_pdf() with PlaceholderPdf produces valid output
    // =========================================================================

    #[tokio::test]
    async fn test_convert_placeholder_produces_output_file() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("test_input.jtd");
        let output_path = temp_dir.join("test_output.pdf");

        create_dummy_input(&input_path, 1024);

        let converter = DummyJtdConverter::new(DummyAction::PlaceholderPdf);
        let result = converter.convert_to_pdf(&input_path, &output_path).await;

        assert!(
            result.is_ok(),
            "convert_to_pdf must succeed in PlaceholderPdf mode: {:?}",
            result.err()
        );

        let conv_result = result.unwrap();
        assert!(conv_result.success, "result.success must be true");
        assert!(
            output_path.exists(),
            "output file must exist on disk"
        );
        assert!(
            conv_result.converted_size_bytes > 0,
            "converted_size_bytes must be greater than zero"
        );
        assert_eq!(
            conv_result.page_count,
            Some(1),
            "page_count must be Some(1) for single-page PDF"
        );
        assert_eq!(
            conv_result.converter_used,
            "dummy",
            "converter_used must be 'dummy'"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // Test 3: convert_to_pdf() with Error mode returns error
    // =========================================================================

    #[tokio::test]
    async fn test_convert_error_mode_returns_conversion_failed() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("test_input.jtd");
        let output_path = temp_dir.join("test_output.pdf");

        create_dummy_input(&input_path, 512);

        let converter = DummyJtdConverter::new(DummyAction::Error);
        let result = converter.convert_to_pdf(&input_path, &output_path).await;

        assert!(
            result.is_err(),
            "convert_to_pdf must fail in Error mode"
        );

        match result.unwrap_err() {
            JtdConversionError::ConversionFailed(msg) => {
                assert!(
                    msg.contains("configured to error"),
                    "error message must indicate intentional error: {}",
                    msg
                );
            }
            other => panic!("expected ConversionFailed variant, got: {:?}", other),
        }

        // Verify no partial output was created
        assert!(
            !output_path.exists(),
            "no output file should exist after error mode conversion"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // Test 4: Output file starts with %PDF header
    // =========================================================================

    #[tokio::test]
    async fn test_output_starts_with_pdf_header() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("test.jtd");
        let output_path = temp_dir.join("output.pdf");

        create_dummy_input(&input_path, 256);

        let converter = DummyJtdConverter::default();
        converter
            .convert_to_pdf(&input_path, &output_path)
            .await
            .expect("conversion must succeed");

        let output_bytes = std::fs::read(&output_path).expect("output must be readable");
        assert!(
            output_bytes.starts_with(b"%PDF"),
            "output must start with %PDF header, got: {:?}",
            &output_bytes[..std::cmp::min(10, output_bytes.len())]
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // Test 5: name() returns "dummy"
    // =========================================================================

    #[test]
    fn test_name_returns_dummy() {
        let converter = DummyJtdConverter::default();
        assert_eq!(converter.name(), "dummy", "name() must return 'dummy'");
    }

    // =========================================================================
    // Test 6: Default trait produces PlaceholderPdf variant
    // =========================================================================

    #[test]
    fn test_default_creates_placeholder_mode() {
        let converter = DummyJtdConverter::default();
        assert_eq!(
            converter.dummy_action,
            DummyAction::PlaceholderPdf,
            "Default must create PlaceholderPdf variant"
        );
    }

    // =========================================================================
    // Test 7: Generated PDF ends with %%EOF marker
    // =========================================================================

    #[tokio::test]
    async fn test_output_ends_with_eof_marker() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("test.jtd");
        let output_path = temp_dir.join("output.pdf");

        create_dummy_input(&input_path, 128);

        let converter = DummyJtdConverter::default();
        converter
            .convert_to_pdf(&input_path, &output_path)
            .await
            .expect("conversion must succeed");

        let output_bytes = std::fs::read(&output_path).expect("output must be readable");
        assert!(
            output_bytes.ends_with(b"%%EOF\n"),
            "output must end with %%EOF marker"
        );

        // Verify PDF is within expected size range (500-1000 bytes for minimal PDF)
        let size = output_bytes.len();
        assert!(
            size >= 500 && size <= 1000,
            "PDF size {} bytes outside expected range [500, 1000]",
            size
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // Test 8: Conversion timing is recorded correctly
    // =========================================================================

    #[tokio::test]
    async fn test_conversion_records_timing() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("timing_test.jtd");
        let output_path = temp_dir.join("timing_test.pdf");

        create_dummy_input(&input_path, 2048);

        let converter = DummyJtdConverter::default();
        let result = converter
            .convert_to_pdf(&input_path, &output_path)
            .await
            .expect("conversion must succeed");

        // Timing should be non-negative and reasonably small (< 1 second for dummy)
        assert!(
            result.conversion_time_ms < 1000,
            "conversion_time_ms should be < 1000ms for dummy converter, got: {}",
            result.conversion_time_ms
        );

        // Original size should match what we wrote
        assert_eq!(
            result.original_size_bytes, 2048,
            "original_size_bytes must match input file size"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // Test 9: Input file size is recorded accurately
    // =========================================================================

    #[tokio::test]
    async fn test_original_size_recorded_correctly() {
        let temp_dir = setup_temp_dir();

        // Test with various sizes
        for size in [0u64, 100, 999, 65536] {
            let input_path = temp_dir.join(format!("size_{}.jtd", size));
            let output_path = temp_dir.join(format!("size_{}.pdf", size));

            if size > 0 {
                create_dummy_input(&input_path, size as usize);
            } else {
                // Create empty file
                std::fs::write(&input_path, b"").unwrap();
            }

            let converter = DummyJtdConverter::default();
            let result = converter
                .convert_to_pdf(&input_path, &output_path)
                .await
                .expect("conversion must succeed");

            assert_eq!(
                result.original_size_bytes, size,
                "original_size_bytes must match for input size {}",
                size
            );
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // Test 10: Error mode error is recoverable (per JtdConversionError spec)
    // =========================================================================

    #[tokio::test]
    async fn test_error_mode_is_recoverable() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("recoverable.jtd");
        let output_path = temp_dir.join("recoverable.pdf");

        create_dummy_input(&input_path, 100);

        let converter = DummyJtdConverter::new(DummyAction::Error);
        let result = converter.convert_to_pdf(&input_path, &output_path).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.is_recoverable(),
            "ConversionFailed errors should be recoverable per JtdConversionError spec"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
