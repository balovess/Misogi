// =============================================================================
// Misogi Core — OCR Provider Trait
// =============================================================================
// Standard interface for pluggable OCR (Optical Character Recognition) providers.
//
// ## Architecture
//
// Misogi does NOT bundle any OCR implementation. This trait defines the contract:
//
// - Tesseract (local open-source)
// - Azure Computer Vision
// - Google Cloud Vision
// - AWS Textract
// - Baidu OCR / Alibaba Cloud OCR
// - Custom self-hosted services
//
// Users implement this trait and inject it into [`OcrPiiDetector`].
// =============================================================================

use async_trait::async_trait;

use super::types::{OcrExtractionResult, OcrError};

/// Standard trait for OCR service providers.
///
/// Implementors receive raw image bytes and return structured text extraction
/// results with position and confidence metadata.
///
/// # Interface Contract
///
/// **Input**: Raw image bytes (PNG/JPEG/TIFF/BMP/WebP)
/// **Output**: Structured text with bounding boxes + confidence scores
///
/// # Example Implementation (Mock)
///
/// ```ignore
/// struct MockOcrProvider;
///
/// #[async_trait]
/// impl OcrProvider for MockOcrProvider {
///     async fn extract_text(&self, image_data: &[u8]) -> Result<OcrExtractionResult, OcrError> {
///         // Return pre-configured test data
///     }
/// }
/// ```
#[async_trait]
pub trait OcrProvider: Send + Sync {
    /// Extract text from an image.
    ///
    /// # Arguments
    /// * `image_data` — Raw bytes of the image file (PNG, JPEG, TIFF, BMP, WebP).
    ///
    /// # Returns
    /// Structured extraction result with text blocks and positions.
    async fn extract_text(
        &self,
        image_data: &[u8],
    ) -> Result<OcrExtractionResult, OcrError>;

    /// Human-readable name of this provider instance.
    fn provider_name(&self) -> &str;

    /// Check if this provider is currently available and healthy.
    async fn is_available(&self) -> bool;
}

/// Deterministic mock implementation of [`OcrProvider`] for testing.
///
/// Returns pre-configured extraction results without any actual OCR processing.
pub struct MockOcrProvider {
    name: String,
    available: bool,
    fixed_text: String,
    fixed_confidence: f64,
}

impl MockOcrProvider {
    /// Create a mock that returns specific text.
    pub fn with_text(text: impl Into<String>, confidence: f64) -> Self {
        Self {
            name: "mock-ocr".to_string(),
            available: true,
            fixed_text: text.into(),
            fixed_confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Create a mock that simulates "no text found".
    pub fn empty_result() -> Self {
        Self {
            name: "mock-ocr-empty".to_string(),
            available: true,
            fixed_text: String::new(),
            fixed_confidence: 0.0,
        }
    }

    /// Create an unavailable mock (simulates service down).
    pub fn unavailable() -> Self {
        Self {
            name: "mock-ocr-down".to_string(),
            available: false,
            fixed_text: String::new(),
            fixed_confidence: 0.0,
        }
    }
}

#[async_trait]
impl OcrProvider for MockOcrProvider {
    async fn extract_text(
        &self,
        _image_data: &[u8],
    ) -> Result<OcrExtractionResult, OcrError> {
        if !self.available {
            return Err(OcrError::ProviderUnavailable {
                provider: self.name.clone(),
                message: "Mock OCR provider configured as unavailable".to_string(),
            });
        }

        if self.fixed_text.is_empty() {
            return Err(OcrError::NoTextFound);
        }

        Ok(OcrExtractionResult {
            full_text: self.fixed_text.clone(),
            blocks: vec![super::types::OcrTextBlock {
                text: self.fixed_text.clone(),
                bbox: super::types::OcrBoundingBox::new(0.0, 0.0, 1.0, 1.0),
                confidence: self.fixed_confidence,
            }],
            metadata: super::types::OcrImageMetadata {
                format: "png".to_string(),
                ..Default::default()
            },
            overall_confidence: self.fixed_confidence,
        })
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    async fn is_available(&self) -> bool {
        self.available
    }
}
