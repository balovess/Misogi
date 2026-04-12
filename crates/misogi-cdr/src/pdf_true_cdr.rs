//! PDF True CDR (Content Disarm & Reconstruction) Engine
//!
//! Implements parse → extract → rebuild pipeline for PDF documents.
//! Unlike simple NOP remediation, True CDR guarantees **zero bytes** from
//! the original file survive in the output — eliminating all hidden payloads,
//! obfuscated threats, and structural exploits.
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────┐    ┌──────────────────┐    ┌────────────────┐    ┌──────────────┐
//! │  Input PDF  │───▶│  1. Parse Phase  │───▶│ 2. Analyze     │───▶│ 3. Extract   │
//! │  (raw bytes)│    │  (lopdf parser)  │    │  (classify)    │    │  (whitelist) │
//! └─────────────┘    └──────────────────┘    └────────────────┘    └──────────────┘
//!                                                                  │
//!                                                                  ▼
//!                                                             ┌──────────────┐
//!                                                             │ 4. Rebuild   │
//!                                                             │(clean template│
//!                                                             └──────┬────────┘
//!                                                                    │
//!                                                                    ▼
//!                                                             ┌──────────────┐
//!                                                             │ Output PDF   │
//!                                                             │(zero orig.)  │
//!                                                             └──────────────┘
//! ```
//!
//! ## Security Guarantees
//!
//! - **Zero-byte survival**: No byte from input appears in output
//! - **Structural sanitization**: Catalog, pages, xref rebuilt from scratch
//! - **Content whitelisting**: Only safe PDF operators preserved
//! - **Threat elimination**: JS, OpenAction, AA, EmbeddedFile always removed
//!
//! # Feature Flag
//!
//! This module is only available when the `pdf-cdr` feature is enabled:
//! ```toml
//! [dependencies]
//! misogi-cdr = { version = "0.1", features = ["pdf-cdr"] }
//! ```

// =============================================================================
// Sub-module declarations
// =============================================================================

mod types;
mod constants;

#[cfg(feature = "pdf-cdr")]
mod parse;

#[cfg(feature = "pdf-cdr")]
mod analyze;

#[cfg(feature = "pdf-cdr")]
mod extract;

#[cfg(feature = "pdf-cdr")]
mod rebuild;

// =============================================================================
// Public re-exports (backward compatible API)
// =============================================================================

pub use types::{
    BlockedItemType,
    BlockedItemRecord,
    FontPolicy,
    ImageExtractionPolicy,
    PdfCdrError,
    PdfCdrReport,
    PdfTrueCdrConfig,
    PdfTrueCdrResult,
    ThreatRemovalRecord,
    ThreatType,
};

// =============================================================================
// Main Engine — Thin Orchestrator
// =============================================================================

/// PDF True CDR Engine — implements full parse→extract→rebuild pipeline.
///
/// This engine provides **guaranteed zero-byte survival** CDR for PDF documents,
/// making it suitable for high-security environments (government, military, finance)
/// where even theoretical attack vectors must be eliminated.
///
/// ## Usage
///
/// ```ignore
/// use misogi_cdr::pdf_true_cdr::*;
///
/// // Japanese government-safe defaults
/// let engine = PdfTrueCdrEngine::with_jp_defaults();
///
/// let input_pdf = std::fs::read("document.pdf")?;
/// let result = engine.reconstruct(&input_pdf)?;
///
/// if result.success {
///     std::fs::write("sanitized.pdf", &result.output)?;
///     println!("Removed {} threats", result.report.threats_removed.len());
/// }
/// ```
///
/// ## Pipeline Phases
///
/// 1. **Parse**: Load PDF into memory using lopdf, extract structure
/// 2. **Analyze**: Classify every object as keep/remove/block
/// 3. **Extract**: Pull whitelisted content from kept objects
/// 4. **Rebuild**: Write new PDF from scratch using clean template
pub struct PdfTrueCdrEngine {
    /// Security configuration controlling behavior.
    pub config: PdfTrueCdrConfig,
}

impl PdfTrueCdrEngine {
    /// Create new engine with Japanese government-safe defaults.
    ///
    /// These defaults follow JIS (Japanese Industrial Standards) guidelines
    /// for secure document handling across network boundaries:
    ///
    /// - Block all embedded files
    /// - Disable forms (AcroForm)
    /// - Strip metadata (prevents information leakage)
    /// - Re-encode images (removes steganography)
    /// - Use only standard fonts (no custom font programs)
    pub fn with_jp_defaults() -> Self {
        Self {
            config: PdfTrueCdrConfig {
                max_embedded_file_size: None,
                allow_forms: false,
                allow_annotations: false,
                preserve_metadata: false,
                image_policy: ImageExtractionPolicy::ReEncode,
                font_policy: FontPolicy::StandardFontsOnly,
            },
        }
    }

    /// Create new engine with custom configuration.
    pub fn with_config(config: PdfTrueCdrConfig) -> Self {
        Self { config }
    }

    /// Execute full True CDR pipeline on raw PDF bytes.
    ///
    /// # Arguments
    /// * `input` - Raw bytes of the input PDF document.
    ///
    /// # Returns
    /// - `Ok(PdfTrueCdrResult)` on success (even with degradation/warnings)
    /// - `Err(PdfCdrError)` on fatal failure (corrupt PDF, encryption, etc.)
    #[cfg(feature = "pdf-cdr")]
    pub fn reconstruct(&self, input: &[u8]) -> Result<PdfTrueCdrResult, PdfCdrError> {
        tracing::info!(
            input_size = input.len(),
            "Starting PDF True CDR reconstruction"
        );

        // Phase 1: Parse
        let intermediates = parse::parse_pdf(input)?;

        // Phase 2: Analyze
        let classification = analyze::analyze_objects(
            self.config.allow_forms,
            self.config.allow_annotations,
            &intermediates,
        );

        // Phase 3: Extract
        let content = extract::extract_content(
            self.config.preserve_metadata,
            &intermediates,
            &classification,
        )?;

        // Phase 4: Rebuild
        let output = rebuild::rebuild_pdf(&content, &classification)?;

        // Build report
        let mut report = PdfCdrReport::default();
        report.pages_extracted = content.page_contents.len();
        report.fonts_preserved = content.fonts.clone();
        report.images_extracted = content.images.len();
        report.is_linearized = intermediates.is_linearized;

        for (obj_id, class) in &classification {
            match class {
                analyze::ObjectClassification::Remove(threat_type) => {
                    report.threats_removed.push(ThreatRemovalRecord {
                        threat_type: threat_type.clone(),
                        location: format!("object {}", obj_id),
                        description: format!("{} threat removed", threat_type),
                    });
                }
                analyze::ObjectClassification::Warn(msg) => {
                    report.warnings.push(format!("Object {}: {}", obj_id, msg));
                }
                analyze::ObjectClassification::Block(item_type, reason) => {
                    report.blocked_items.push(BlockedItemRecord {
                        item_type: item_type.clone(),
                        reason: reason.clone(),
                        size_bytes: None,
                    });
                }
                _ => {}
            }
        }

        Ok(PdfTrueCdrResult {
            output,
            report,
            success: true,
        })
    }

    /// Stub implementation when `pdf-cdr` feature is disabled.
    #[cfg(not(feature = "pdf-cdr"))]
    pub fn reconstruct(&self, _input: &[u8]) -> Result<PdfTrueCdrResult, PdfCdrError> {
        Err(PdfCdrError::InternalError(
            "PDF True CDR requires 'pdf-cdr' feature flag. Enable with: cargo build --features pdf-cdr".to_string()
        ))
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Feature Gate Test
    // =========================================================================

    #[test]
    fn test_reconstruct_without_feature_returns_error() {
        #[cfg(not(feature = "pdf-cdr"))]
        {
            let engine = PdfTrueCdrEngine::with_jp_defaults();
            let fake_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj";
            let result = engine.reconstruct(fake_pdf);
            assert!(result.is_err());
            match result.unwrap_err() {
                PdfCdrError::InternalError(msg) => {
                    assert!(msg.contains("pdf-cdr feature flag"));
                }
                other => panic!("Expected InternalError, got {:?}", other),
            }
        }

        #[cfg(feature = "pdf-cdr")]
        {
            let engine = PdfTrueCdrEngine::with_jp_defaults();
            let minimal_pdf = create_minimal_test_pdf();
            let result = engine.reconstruct(&minimal_pdf);
            if let Err(e) = result {
                match e {
                    PdfCdrError::InternalError(msg) => {
                        panic!(
                            "Should not get feature gate error when feature is enabled: {}",
                            msg
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    /// Create a minimal valid PDF for testing (using lopdf for structural correctness).
    #[cfg(feature = "pdf-cdr")]
    fn create_minimal_test_pdf() -> Vec<u8> {
        use lopdf::{dictionary, Document, Object};

        let mut doc = Document::with_version("1.5");

        let page_dict = dictionary! {
            b"Type" => "Page",
            b"MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };

        let pages_dict = dictionary! {
            b"Type" => "Pages",
            b"Kids" => vec![Object::Reference(doc.add_object(page_dict))],
            b"Count" => 1i64,
        };

        let catalog_dict = dictionary! {
            b"Type" => "Catalog",
            b"Pages" => Object::Reference(doc.add_object(pages_dict)),
        };

        let catalog_id = doc.add_object(catalog_dict);
        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut buf = Vec::new();
        doc.save_to(&mut buf).expect("Failed to save test PDF");
        buf
    }

    #[cfg(feature = "pdf-cdr")]
    #[test]
    fn test_reconstruct_minimal_pdf() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let minimal_pdf = create_minimal_test_pdf();

        let result = engine.reconstruct(&minimal_pdf);

        assert!(result.is_ok(), "Minimal PDF reconstruction should succeed");

        let cdr_result = result.unwrap();
        assert!(cdr_result.success);
        assert_eq!(cdr_result.report.pages_extracted, 1);

        assert!(
            cdr_result.output.starts_with(b"%PDF"),
            "Output should be valid PDF"
        );

        let output_str = String::from_utf8_lossy(&cdr_result.output);
        assert!(
            !output_str.contains("/OpenAction"),
            "Output should not contain /OpenAction"
        );
        assert!(!output_str.contains("/JS"), "Output should not contain /JS");
    }

    #[cfg(feature = "pdf-cdr")]
    #[test]
    fn test_report_contains_linearized_flag_after_reconstruct() {
        let engine = PdfTrueCdrEngine::with_jp_defaults();
        let minimal_pdf = create_minimal_test_pdf();

        let result = engine.reconstruct(&minimal_pdf);
        assert!(result.is_ok());

        let cdr_result = result.unwrap();
        assert!(!cdr_result.report.is_linearized, "Minimal PDF should not be detected as linearized");
    }
}
