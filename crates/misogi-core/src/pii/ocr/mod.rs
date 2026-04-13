// =============================================================================
// Misogi Core — PII OCR Detection Module
// =============================================================================
// Standard interface for image-based PII extraction via pluggable OCR providers.
//
// ## Submodules
//
// | Module | Description |
// |--------|-------------|
// | [`types`] | OcrExtractionResult, OcrTextBlock, OcrBoundingBox, OcrError |
// | [`ocr_provider`] | **OcrProvider trait** (standard OCR interface) + Mock |
// | [`ocr_detector`] | OcrPiiDetector (OCR + RegexPIIDetector pipeline) |

pub mod types;
pub mod ocr_provider;
pub mod ocr_detector;

pub use types::{
    OcrBoundingBox,
    OcrError,
    OcrExtractionResult,
    OcrImageMetadata,
    OcrTextBlock,
};

pub use ocr_provider::{
    OcrProvider,
    MockOcrProvider,
};

pub use ocr_detector::{
    OcrDetectorConfig,
    OcrPiiDetector,
    OcrPiiMatch,
    OcrPiiScanResult,
};
