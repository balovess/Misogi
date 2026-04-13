// =============================================================================
// Misogi Core — OCR PII Detection Types
// =============================================================================
// Data structures for OCR-based PII extraction from images.
//
// ## Design Philosophy
//
// Misogi does NOT include any OCR engine. This module defines:
// 1. Standard result types (OcrExtractionResult, OcrTextBlock, etc.)
// 2. Error types for OCR operations
//
// Actual OCR is performed by user-provided implementations of [`OcrProvider`].
// =============================================================================

/// Bounding box with normalized coordinates [0.0, 1.0].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OcrBoundingBox {
    /// Left edge (0 = left, 1 = right).
    pub x_min: f64,

    /// Top edge (0 = top, 1 = bottom).
    pub y_min: f64,

    /// Right edge.
    pub x_max: f64,

    /// Bottom edge.
    pub y_max: f64,
}

impl OcrBoundingBox {
    /// Create a new bounding box with validation (clamps to [0, 1]).
    pub fn new(x_min: f64, y_min: f64, x_max: f64, y_max: f64) -> Self {
        Self {
            x_min: x_min.clamp(0.0, 1.0),
            y_min: y_min.clamp(0.0, 1.0),
            x_max: x_max.clamp(0.0, 1.0),
            y_max: y_max.clamp(0.0, 1.0),
        }
    }

    /// Width of the bounding box.
    pub fn width(&self) -> f64 {
        (self.x_max - self.x_min).abs()
    }

    /// Height of the bounding box.
    pub fn height(&self) -> f64 {
        (self.y_max - self.y_min).abs()
    }

    /// Area of the bounding box.
    pub fn area(&self) -> f64 {
        self.width() * self.height()
    }
}

/// Single text block extracted by OCR with position information.
#[derive(Debug, Clone)]
pub struct OcrTextBlock {
    /// Extracted text content.
    pub text: String,

    /// Normalized bounding box coordinates [0,0,1,1].
    pub bbox: OcrBoundingBox,

    /// Confidence score from OCR engine [0.0, 1.0].
    pub confidence: f64,
}

/// Metadata about the source image.
#[derive(Debug, Clone, Default)]
pub struct OcrImageMetadata {
    /// Image format detected (png, jpeg, tiff, bmp, webp).
    pub format: String,

    /// Image width in pixels.
    pub width_px: Option<u32>,

    /// Image height in pixels.
    pub height_px: Option<u32>,

    /// File size in bytes.
    pub size_bytes: Option<u64>,
}

/// Complete OCR extraction result for a single image.
#[derive(Debug, Clone)]
pub struct OcrExtractionResult {
    /// Full concatenated text from all blocks.
    pub full_text: String,

    /// Individual text blocks with position data.
    pub blocks: Vec<OcrTextBlock>,

    /// Source image metadata.
    pub metadata: OcrImageMetadata,

    /// Overall confidence across all blocks.
    pub overall_confidence: f64,
}

impl OcrExtractionResult {
    /// Create an empty extraction result.
    pub fn empty() -> Self {
        Self {
            full_text: String::new(),
            blocks: Vec::new(),
            metadata: OcrImageMetadata::default(),
            overall_confidence: 0.0,
        }
    }

    /// Number of text blocks extracted.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Average confidence across all blocks.
    pub fn average_confidence(&self) -> f64 {
        if self.blocks.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.blocks.iter().map(|b| b.confidence).sum();
        sum / self.blocks.len() as f64
    }
}

/// Errors from OCR operations.
#[derive(Debug, thiserror::Error)]
pub enum OcrError {
    /// The configured OCR provider is unavailable or misconfigured.
    #[error("OCR provider '{provider}' unavailable: {message}")]
    ProviderUnavailable {
        provider: String,
        message: String,
    },

    /// Unsupported image format.
    #[error("Unsupported image format: {format}")]
    UnsupportedFormat {
        format: String,
    },

    /// Image too large or too small.
    #[error("Image size out of bounds: {width}x{height}px (min={min}, max={max})")]
    SizeOutOfBounds {
        width: u32,
        height: u32,
        min: u32,
        max: u32,
    },

    /// No text could be extracted from the image.
    #[error("No text found in image")]
    NoTextFound,

    /// Network or communication failure with external OCR service.
    #[error("OCR communication failed: {0}")]
    Communication(String),

    /// Rate limit or quota exceeded.
    #[error("Rate limited by OCR provider '{provider}'")]
    RateLimited {
        provider: String,
    },

    /// Authentication failure.
    #[error("OCR authentication failed for provider '{provider}': {0}")]
    Authentication {
        provider: String,
        message: String,
    },

    /// Timeout waiting for OCR response.
    #[error("OCR timeout after {timeout_ms}ms")]
    Timeout {
        timeout_ms: u64,
    },

    /// Internal processing error.
    #[error("Internal OCR error: {0}")]
    Internal(String),
}
