// =============================================================================
// Misogi Core — OCR PII Detector
// =============================================================================
// Combines OCR text extraction with PII regex scanning on image content.
//
// ## Pipeline
//
// ```
// Image Bytes → OcrProvider.extract_text() → Text Blocks
//                                              ↓
//                                    RegexPIIDetector.scan()
//                                              ↓
//                              Annotated PIIMatch[] with spatial info
// ```
//
// The detector reuses the existing [`RegexPIIDetector`] for PII pattern matching
// after OCR extracts text from images. Spatial annotation (bounding boxes) is
// preserved in results for downstream UI display or redaction.
// =============================================================================

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use super::ocr_provider::OcrProvider;
use super::types::{OcrBoundingBox, OcrExtractionResult, OcrImageMetadata, OcrTextBlock, OcrError};
use crate::pii::{PIIRule, RegexPIIDetector};
use crate::traits::{PIIAction, PIIMatch};

/// Configuration for [`OcrPiiDetector`] behavior.
#[derive(Debug, Clone)]
pub struct OcrDetectorConfig {
    /// Minimum OCR confidence to process a block [0.0, 1.0].
    pub min_ocr_confidence: f64,

    /// Include spatial (position) annotations in results.
    pub spatial_annotation: bool,

    /// Minimum image dimension in pixels.
    pub min_dimension_px: u32,

    /// Maximum image dimension in pixels.
    pub max_dimension_px: u32,

    /// Maximum image size in MB before rejection.
    pub max_size_mb: usize,
}

impl Default for OcrDetectorConfig {
    fn default() -> Self {
        Self {
            min_ocr_confidence: 0.7,
            spatial_annotation: true,
            min_dimension_px: 50,
            max_dimension_px: 10_000,
            max_size_mb: 10,
        }
    }
}

/// PII match result from OCR scanning with optional spatial annotation.
#[derive(Debug, Clone)]
pub struct OcrPiiMatch {
    /// Standard PII match data.
    pub match_data: PIIMatch,

    /// Bounding box of the text block containing this PII (if available).
    pub bbox: Option<OcrBoundingBox>,

    /// Confidence of the OCR block that contained this PII.
    pub ocr_block_confidence: f64,
}

/// Aggregated result of OCR-based PII detection.
#[derive(Debug, Clone)]
pub struct OcrPiiScanResult {
    /// Whether any PII was found.
    pub found: bool,

    /// All PII matches with optional spatial data.
    pub matches: Vec<OcrPiiMatch>,

    /// Overall strictest action.
    pub action: PIIAction,

    /// Original image size in bytes.
    pub image_size_bytes: u64,

    /// OCR extraction metadata.
    pub ocr_metadata: OcrImageMetadata,

    /// Scan duration in milliseconds.
    pub scan_duration_ms: u64,

    /// Total text characters extracted by OCR.
    pub total_chars_extracted: usize,
}

/// Combines OCR text extraction with PII pattern detection.
pub struct OcrPiiDetector {
    ocr_provider: Arc<dyn OcrProvider>,
    text_detector: Arc<RegexPIIDetector>,
    config: OcrDetectorConfig,
}

impl OcrPiiDetector {
    /// Create detector with given OCR provider and text PII detector.
    pub fn new(
        ocr_provider: Arc<dyn OcrProvider>,
        text_detector: Arc<RegexPIIDetector>,
        config: OcrDetectorConfig,
    ) -> Self {
        Self {
            ocr_provider,
            text_detector,
            config,
        }
    }

    /// Create detector with default config values.
    pub fn with_defaults(
        ocr_provider: Arc<dyn OcrProvider>,
        text_detector: Arc<RegexPIIDetector>,
    ) -> Self {
        Self::new(ocr_provider, text_detector, OcrDetectorConfig::default())
    }

    /// Scan an image for PII using OCR + regex pipeline.
    ///
    /// # Pipeline
    /// 1. Validate image constraints (size, format)
    /// 2. Call `OcrProvider.extract_text()` to get text blocks
    /// 3. For each block above confidence threshold:
    ///    a. Run `RegexPIIDetector.scan()` on block text
    ///    b. Collect matches with spatial annotation
    /// 4. Aggregate into [`OcrPiiScanResult`]
    ///
    /// # Arguments
    /// * `image_data` — Raw image bytes (PNG/JPEG/TIFF/BMP/WebP).
    /// * `file_id` — Correlation identifier for audit logging.
    ///
    /// # Returns
    /// Aggregated OCR-PII scan result with all findings.
    pub async fn scan_image(
        &self,
        image_data: &[u8],
        file_id: &str,
    ) -> crate::error::Result<OcrPiiScanResult> {
        let start = Instant::now();
        let image_size = image_data.len() as u64;

        if image_data.len() > self.config.max_size_mb * 1024 * 1024 {
            return Err(crate::error::MisogiError::Protocol(format!(
                "Image exceeds maximum size of {} MB",
                self.config.max_size_mb
            )));
        }

        let ocr_result = self.ocr_provider.extract_text(image_data).await.map_err(|e| {
            crate::error::MisogiError::Protocol(format!("OCR extraction failed: {}", e))
        })?;

        if ocr_result.full_text.is_empty() || ocr_result.blocks.is_empty() {
            return Ok(OcrPiiScanResult {
                found: false,
                matches: vec![],
                action: PIIAction::AlertOnly,
                image_size_bytes: image_size,
                ocr_metadata: ocr_result.metadata,
                scan_duration_ms: start.elapsed().as_millis() as u64,
                total_chars_extracted: 0,
            });
        }

        let mut all_matches: Vec<OcrPiiMatch> = Vec::new();

        for block in &ocr_result.blocks {
            if block.confidence < self.config.min_ocr_confidence {
                continue;
            }

            let scan_result = self
                .text_detector
                .scan(&block.text, file_id, "ocr-extracted")
                .await?;

            for m in scan_result.matches {
                all_matches.push(OcrPiiMatch {
                    match_data: m,
                    bbox: if self.config.spatial_annotation {
                        Some(block.bbox)
                    } else {
                        None
                    },
                    ocr_block_confidence: block.confidence,
                });
            }
        }

        let found = !all_matches.is_empty();
        let actions: Vec<&PIIAction> = all_matches.iter().map(|m| &m.match_data.action).collect();
        let action = Self::resolve_strictest_action(&actions);

        Ok(OcrPiiScanResult {
            found,
            matches: all_matches,
            action,
            image_size_bytes: image_size,
            ocr_metadata: ocr_result.metadata,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            total_chars_extracted: ocr_result.full_text.len(),
        })
    }

    fn resolve_strictest_action(actions: &[&PIIAction]) -> PIIAction {
        if actions.iter().any(|a| **a == PIIAction::Block) {
            PIIAction::Block
        } else if actions.iter().any(|a| **a == PIIAction::Mask) {
            PIIAction::Mask
        } else {
            PIIAction::AlertOnly
        }
    }
}
