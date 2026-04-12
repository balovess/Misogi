//! Public type definitions for PDF True CDR engine.
//!
//! This module defines all user-facing types including configuration,
//! results, error types, and threat classification enums.
//!
//! All types in this module are `pub` and re-exported by the parent
//! `pdf_true_cdr` module for backward compatibility.

use std::fmt;

use thiserror::Error;

// =============================================================================
// Public Types - Configuration
// =============================================================================

/// Policy for handling image XObjects during CDR reconstruction.
///
/// Each variant represents a different security/performance trade-off:
/// - `KeepOriginal` is fastest but preserves any steganographic payloads
/// - `ReEncode` removes steganography but requires codec support
/// - `ResizeMaxDimensions` is most aggressive (destroys hidden data + limits DoS)
/// - `BlockAll` is safest for high-security environments
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageExtractionPolicy {
    /// Embed image bytes as-is (fastest, minimal risk for trusted sources).
    KeepOriginal,

    /// Decode → re-encode to normalize format (removes steganography, slower).
    ///
    /// Note: Requires image codec support for JPEG/PNG/etc.
    ReEncode,

    /// Decode → resize → re-encode (most aggressive, destroys hidden data).
    ///
    /// Arguments: `(max_width_pixels, max_height_pixels)`
    ResizeMaxDimensions(u32, u32),

    /// Remove all images, replace with placeholder rectangle (safest).
    BlockAll,
}

impl Default for ImageExtractionPolicy {
    fn default() -> Self {
        Self::KeepOriginal
    }
}

/// Policy for font embedding during CDR reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FontPolicy {
    /// Preserve embedded fonts as-is (may contain malicious font programs).
    KeepEmbedded,

    /// Subset fonts to only used glyphs (reduces attack surface).
    SubsetGlyphs,

    /// Remove all embedded fonts, use standard 14 PDF fonts only (safest).
    StandardFontsOnly,
}

impl Default for FontPolicy {
    fn default() -> Self {
        Self::SubsetGlyphs
    }
}

/// Configuration for PDF True CDR reconstruction.
///
/// Controls security policy, resource handling, and output constraints.
/// Use [`PdfTrueCdrEngine::with_jp_defaults()`] for Japanese government-safe defaults.
///
/// # Example
///
/// ```ignore
/// use misogi_cdr::pdf_true_cdr::*;
///
/// let config = PdfTrueCdrConfig {
///     max_embedded_file_size: None, // Block ALL attachments
///     allow_forms: false,
///     allow_annotations: true,
///     preserve_metadata: false,
///     image_policy: ImageExtractionPolicy::ReEncode,
///     font_policy: FontPolicy::StandardFontsOnly,
/// };
///
/// let engine = PdfTrueCdrEngine::with_config(config);
/// ```
#[derive(Debug, Clone)]
pub struct PdfTrueCdrConfig {
    /// Maximum allowed embedded file size (bytes). `None` = block all.
    pub max_embedded_file_size: Option<u64>,

    /// Allow form fields (AcroForm). Default: `false`.
    pub allow_forms: bool,

    /// Allow annotations (sticky notes, highlights). Default: `true`.
    pub allow_annotations: bool,

    /// Preserve metadata (author, title, etc.) or strip all. Default: `false`.
    pub preserve_metadata: bool,

    /// Image handling strategy. Default: `ImageExtractionPolicy::KeepOriginal`.
    pub image_policy: ImageExtractionPolicy,

    /// Font embedding policy. Default: `FontPolicy::SubsetGlyphs`.
    pub font_policy: FontPolicy,
}

impl Default for PdfTrueCdrConfig {
    fn default() -> Self {
        Self {
            max_embedded_file_size: None, // Block all by default
            allow_forms: false,
            allow_annotations: true,
            preserve_metadata: false,
            image_policy: ImageExtractionPolicy::default(),
            font_policy: FontPolicy::default(),
        }
    }
}

// =============================================================================
// Public Types - Results
// =============================================================================

/// Result of PDF True CDR reconstruction.
///
/// Contains both the rebuilt document bytes and detailed audit report.
#[derive(Debug, Clone)]
pub struct PdfTrueCdrResult {
    /// Rebuilt PDF document bytes (clean template, zero original bytes).
    pub output: Vec<u8>,

    /// Detailed report of what was extracted/removed/blocked.
    pub report: PdfCdrReport,

    /// Whether reconstruction was successful (vs downgraded/degraded).
    pub success: bool,
}

/// Detailed reconstruction report for audit logging.
///
/// Tracks every decision made during the CDR pipeline for compliance
/// and forensic analysis.
#[derive(Debug, Clone)]
pub struct PdfCdrReport {
    /// Number of pages successfully extracted and rebuilt.
    pub pages_extracted: usize,

    /// Names of fonts that were preserved/subset during reconstruction.
    pub fonts_preserved: Vec<String>,

    /// Number of images extracted and re-embedded.
    pub images_extracted: usize,

    /// Threats that were detected and removed.
    pub threats_removed: Vec<ThreatRemovalRecord>,

    /// Items that were blocked (too large, unsupported, etc.).
    pub blocked_items: Vec<BlockedItemRecord>,

    /// Non-fatal warnings (degraded content, missing resources, etc.).
    pub warnings: Vec<String>,

    /// Whether the input PDF was detected as linearized (optimized/FAST WEB VIEW).
    ///
    /// Linearized PDFs use cross-reference streams which can be abused for
    /// obfuscation. When `true`, the CDR engine has flattened the structure.
    pub is_linearized: bool,
}

impl Default for PdfCdrReport {
    fn default() -> Self {
        Self {
            pages_extracted: 0,
            fonts_preserved: Vec::new(),
            images_extracted: 0,
            threats_removed: Vec::new(),
            blocked_items: Vec::new(),
            warnings: Vec::new(),
            is_linearized: false,
        }
    }
}

/// Record of a threat that was removed during CDR processing.
#[derive(Debug, Clone)]
pub struct ThreatRemovalRecord {
    /// Classification of the threat type.
    pub threat_type: ThreatType,

    /// Location where threat was found (object number if available).
    pub location: String,

    /// Human-readable description of what was removed.
    pub description: String,
}

/// Classification of PDF threat types detectable by the True CDR engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    /// JavaScript action (`/JS`, `/JavaScript`).
    JavaScript,

    /// OpenAction entry in catalog (auto-executes on open).
    OpenAction,

    /// Additional Actions dictionary (`/AA`) on catalog/page.
    AdditionalActions,

    /// Embedded file attachment (`/EmbeddedFile`).
    EmbeddedFile,

    /// Form submission action (`/SubmitForm`).
    SubmitForm,

    /// Launch action (executes external program).
    LaunchAction,

    /// RichMedia annotation (Flash/SWF container).
    RichMedia,

    /// Object stream containing suspicious compressed content.
    SuspiciousObjectStream,

    /// Cross-reference stream with unusual filters.
    SuspiciousXrefStream,

    /// Embedded script or steganographic payload in inline image.
    ///
    /// Detected when inline images use blocked encodings (e.g., FlateDecode)
    /// or contain obfuscated content patterns.
    EmbeddedScript,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JavaScript => write!(f, "JavaScript"),
            Self::OpenAction => write!(f, "OpenAction"),
            Self::AdditionalActions => write!(f, "AdditionalActions"),
            Self::EmbeddedFile => write!(f, "EmbeddedFile"),
            Self::SubmitForm => write!(f, "SubmitForm"),
            Self::LaunchAction => write!(f, "LaunchAction"),
            Self::RichMedia => write!(f, "RichMedia"),
            Self::SuspiciousObjectStream => write!(f, "SuspiciousObjectStream"),
            Self::SuspiciousXrefStream => write!(f, "SuspiciousXrefStream"),
            Self::EmbeddedScript => write!(f, "EmbeddedScript"),
        }
    }
}

/// Record of an item that was blocked during CDR processing.
#[derive(Debug, Clone)]
pub struct BlockedItemRecord {
    /// Type of item that was blocked.
    pub item_type: BlockedItemType,

    /// Reason for blocking.
    pub reason: String,

    /// Original size in bytes (if applicable).
    pub size_bytes: Option<u64>,
}

/// Classification of blocked item types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedItemType {
    /// File attachment exceeding size limit.
    OversizedAttachment,

    /// Unsupported image format.
    UnsupportedImageFormat,

    /// Encrypted content (cannot process without key).
    EncryptedContent,

    /// Corrupted/unparseable object.
    CorruptedObject,

    /// Resource reference that could not be resolved.
    UnresolvedReference,
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during PDF True CDR processing.
///
/// These errors represent fatal failures that prevent reconstruction.
/// Non-fatal issues are recorded as warnings in [`PdfCdrReport`].
#[derive(Error, Debug)]
pub enum PdfCdrError {
    /// Input is not a valid PDF document (missing header, corrupt structure).
    #[error("Invalid PDF: {0}")]
    InvalidPdf(String),

    /// PDF is encrypted and no decryption key was provided.
    #[error("PDF is encrypted and cannot be processed without decryption key")]
    EncryptedPdf,

    /// Failed to parse PDF structure using lopdf library.
    #[error("PDF parsing failed: {0}")]
    ParseError(#[from] lopdf::Error),

    /// I/O error during reading/writing.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Internal error in the CDR pipeline (should not happen).
    #[error("Internal CDR error: {0}")]
    InternalError(String),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_jp_defaults_config() {
        let engine_config = PdfTrueCdrConfig {
            max_embedded_file_size: None,
            allow_forms: false,
            allow_annotations: false,
            preserve_metadata: false,
            image_policy: ImageExtractionPolicy::ReEncode,
            font_policy: FontPolicy::StandardFontsOnly,
        };
        assert!(engine_config.max_embedded_file_size.is_none()); // Block all
        assert!(!engine_config.allow_forms);
        assert!(!engine_config.allow_annotations);
        assert!(!engine_config.preserve_metadata);
        assert_eq!(engine_config.image_policy, ImageExtractionPolicy::ReEncode);
        assert_eq!(engine_config.font_policy, FontPolicy::StandardFontsOnly);
    }

    #[test]
    fn test_custom_config() {
        let config = PdfTrueCdrConfig {
            max_embedded_file_size: Some(1024 * 1024), // 1 MB
            allow_forms: true,
            allow_annotations: true,
            preserve_metadata: true,
            image_policy: ImageExtractionPolicy::KeepOriginal,
            font_policy: FontPolicy::KeepEmbedded,
        };

        assert_eq!(config.max_embedded_file_size, Some(1024 * 1024));
        assert!(config.allow_forms);
    }

    #[test]
    fn test_default_config() {
        let config = PdfTrueCdrConfig::default();
        assert!(config.max_embedded_file_size.is_none());
        assert!(!config.allow_forms);
        assert!(config.allow_annotations);
    }

    // =========================================================================
    // Type Tests
    // =========================================================================

    #[test]
    fn test_threat_type_display() {
        assert_eq!(ThreatType::JavaScript.to_string(), "JavaScript");
        assert_eq!(ThreatType::OpenAction.to_string(), "OpenAction");
        assert_eq!(ThreatType::RichMedia.to_string(), "RichMedia");
    }

    #[test]
    fn test_image_policy_default() {
        assert_eq!(
            ImageExtractionPolicy::default(),
            ImageExtractionPolicy::KeepOriginal
        );
    }

    #[test]
    fn test_font_policy_default() {
        assert_eq!(FontPolicy::default(), FontPolicy::SubsetGlyphs);
    }

    // =========================================================================
    // Report Tests
    // =========================================================================

    #[test]
    fn test_report_default() {
        let report = PdfCdrReport::default();
        assert_eq!(report.pages_extracted, 0);
        assert!(report.fonts_preserved.is_empty());
        assert!(report.threats_removed.is_empty());
        assert!(report.blocked_items.is_empty());
        assert!(report.warnings.is_empty());
    }
}
