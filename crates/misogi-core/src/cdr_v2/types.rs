// =============================================================================
// CDR Engine v2 — Core Type Definitions
// =============================================================================
// This module defines the fundamental type system for the Content Disarm &
// Reconstruction (CDR) Engine v2. Every type here is designed for:
//
// 1. Zero-copy semantics where possible (String over &str for ownership).
// 2. Serde serializability for audit trail persistence.
// 3. Ord/PartialOrd on severity for deterministic policy decisions.
// 4. thiserror-based error hierarchy for structured error propagation.
//
// Design Rationale:
// - DocumentFormat covers all formats the CDR engine can process, including
//   legacy binary formats (Doc/Xls/Ppt) and modern XML-based Office formats.
// - ActiveContentType enumerates every known vector for executable content
//   within documents — this is the threat model foundation.
// - ThreatSeverity uses numeric levels so that max_severity() can use
//   Ord::max() for deterministic worst-case aggregation.
// =============================================================================

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported document formats for CDR processing.
///
/// Each variant represents a file format family that the CDR engine can
/// parse, sanitize, and reconstruct. The distinction between legacy binary
/// formats (Doc, Xls, Ppt) and modern OOXML formats (Docx, Xlsx, Pptx)
/// is critical because they require completely different parsing strategies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DocumentFormat {
    /// Portable Document Format — may contain JavaScript, forms, embedded files.
    Pdf,

    /// Office Open XML Word document — ZIP container with XML parts.
    Docx,

    /// Office Open XML Spreadsheet — may contain macros, external data connections.
    Xlsx,

    /// Office Open XML Presentation — may contain embedded OLE objects, VBA.
    Pptx,

    /// Legacy Microsoft Word binary format (OLE2 compound document).
    Doc,

    /// Legacy Microsoft Excel binary format — macro-capable.
    Xls,

    /// Legacy Microsoft PowerPoint binary format.
    Ppt,

    /// ZIP archive — may contain nested executables, symlink attacks.
    Zip,

    /// RAR archive — proprietary compression with potential for path traversal.
    Rar,

    /// 7-Zip archive — supports many compression algorithms.
    SevenZ,

    /// TAR archive — Unix tape archive, often used in software distribution.
    Tar,

    /// Scalable Vector Graphics — XML-based, may contain script elements or
    /// foreignObject with HTML/JavaScript.
    Svg,

    /// Portable Network Graphics — generally safe but may have malicious chunks.
    Png,

    /// Joint Photographic Experts Group — generally safe format.
    Jpeg,

    /// Bitmap Image — Windows native image format.
    Bmp,

    /// Graphics Interchange Format — may contain animated payloads.
    Gif,

    /// Unknown / unrecognized format — captured as string for diagnostics.
    Unknown(String),
}

impl DocumentFormat {
    /// Return the file extension commonly associated with this format.
    ///
    /// Used for logging and user-facing display. Does NOT drive format
    // detection — that is done via magic byte analysis.
    #[must_use]
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
            Self::Doc => "doc",
            Self::Xls => "xls",
            Self::Ppt => "ppt",
            Self::Zip => "zip",
            Self::Rar => "rar",
            Self::SevenZ => "7z",
            Self::Tar => "tar",
            Self::Svg => "svg",
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Bmp => "bmp",
            Self::Gif => "gif",
            Self::Unknown(_) => "bin",
        }
    }

    /// Check whether this format is an Office document (any variant).
    #[must_use]
    pub fn is_office_document(&self) -> bool {
        matches!(
            self,
            Self::Docx | Self::Xlsx | Self::Pptx | Self::Doc | Self::Xls | Self::Ppt
        )
    }

    /// Check whether this format is an archive (container of other files).
    #[must_use]
    pub fn is_archive(&self) -> bool {
        matches!(self, Self::Zip | Self::Rar | Self::SevenZ | Self::Tar)
    }

    /// Check whether this format is a raster image.
    #[must_use]
    pub fn is_raster_image(&self) -> bool {
        matches!(self, Self::Png | Self::Jpeg | Self::Bmp | Self::Gif)
    }
}

impl std::fmt::Display for DocumentFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(s) => write!(f, "unknown({s})"),
            other => write!(f, "{}", other.extension()),
        }
    }
}

/// Classification of active (potentially executable) content found within documents.
///
/// Each variant represents a distinct attack vector that CDR must neutralize.
/// The granularity here enables per-vector policy control (e.g., allow
/// hyperlinks but block JavaScript).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActiveContentType {
    /// Embedded JavaScript (PDF actions, SVG script tags, HTML in containers).
    JavaScript,

    /// Visual Basic for Applications macros (Office documents).
    VBMacro,

    /// OLE embedded object — arbitrary binary payload within OLE2 container.
    OLEEmbeddedObject,

    /// PDF AcroForm action or form field with attached script.
    ActionForm,

    /// Hyperlink pointing to an external (non-whitelisted) URL.
    HyperlinkExternal,

    /// Embedded font file — TrueType/OpenType fonts may contain bytecode.
    EmbeddedFont,

    /// Dynamic XFA form template (PDF 1.5+ XML Forms Architecture).
    DynamicXfaForm,

    /// Custom / vendor-specific active content type not in the standard set.
    Custom(String),
}

impl std::fmt::Display for ActiveContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JavaScript => write!(f, "javascript"),
            Self::VBMacro => write!(f, "vb_macro"),
            Self::OLEEmbeddedObject => write!(f, "ole_embedded_object"),
            Self::ActionForm => write!(f, "action_form"),
            Self::HyperlinkExternal => write!(f, "hyperlink_external"),
            Self::EmbeddedFont => write!(f, "embedded_font"),
            Self::DynamicXfaForm => write!(f, "dynamic_xfa_form"),
            Self::Custom(s) => write!(f, "custom({s})"),
        }
    }
}

/// Severity level assigned to detected active content.
///
/// Implements `Ord` and `PartialOrd` based on the numeric severity level
/// so that `max_severity()` can deterministically find the worst-case
/// threat across all findings in a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatSeverity {
    /// Immediate execution risk — code will run upon document open.
    Critical = 5,

    /// High-confidence attack vector — known exploit pattern detected.
    High = 4,

    /// Potentially dangerous content — requires user interaction to trigger.
    Medium = 3,

    /// Low-risk element — informational, unlikely to cause harm alone.
    Low = 2,

    /// Informational finding — no direct threat, logged for audit.
    Info = 1,
}

impl ThreatSeverity {
    /// Return the numeric severity level for ordering comparisons.
    #[must_use]
    pub const fn level(&self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }
}

impl Ord for ThreatSeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.level().cmp(&other.level())
    }
}

impl PartialOrd for ThreatSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

/// Action taken by the sanitization engine against a piece of active content.
///
/// Each action represents a different disarm strategy. The choice depends on
/// content type, policy configuration, and preservation requirements.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizeAction {
    /// The element was completely removed from the output document.
    Removed,

    /// The element's executable payload was zeroed out (NOP instructions).
    NopOut,

    /// The element was replaced with a safe placeholder or canonical equivalent.
    Replaced,

    /// Interactive elements were converted to static representation.
    Flattened,

    /// The content was extracted into a separate quarantined file.
    Extracted,

    /// The element was explicitly skipped (whitelisted or below threshold).
    Skipped,
}

impl std::fmt::Display for SanitizeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Removed => write!(f, "removed"),
            Self::NopOut => write!(f, "nopped_out"),
            Self::Replaced => write!(f, "replaced"),
            Self::Flattened => write!(f, "flattened"),
            Self::Extracted => write!(f, "extracted"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// XPath-like location identifier within a document's structural tree.
///
/// Encodes the precise position of an element using a path notation similar
/// to XPath, enabling operators to locate and verify sanitized elements.
/// Example: `/document/pages[0]/annotations[2]/action`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentLocation {
    /// XPath-like path string identifying the element position.
    pub path: String,
}

impl ContentLocation {
    /// Create a new content location from a path string.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    /// Return the path string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }
}

impl From<String> for ContentLocation {
    fn from(path: String) -> Self {
        Self::new(path)
    }
}

impl From<&str> for ContentLocation {
    fn from(path: &str) -> Self {
        Self::new(path)
    }
}

impl std::fmt::Display for ContentLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)
    }
}

/// Reference to a single piece of active content found during document analysis.
///
/// This structure is the atomic unit of CDR threat intelligence. Each instance
/// records what was found, where it lives, how dangerous it is, and what
/// (if anything) was done about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveContentRef {
    /// Type classification of the active content.
    pub content_type: ActiveContentType,

    /// Structural location within the document tree.
    pub location: ContentLocation,

    /// Assigned severity level based on content type and context.
    pub severity: ThreatSeverity,

    /// Sanitization action applied (None if not yet processed).
    pub action_taken: Option<SanitizeAction>,

    /// Cryptographic hash of the raw active content bytes (for audit chain).
    pub original_hash: Option<String>,
}

impl ActiveContentRef {
    /// Create a new active content reference.
    ///
    /// # Arguments
    /// * `content_type` - Classification of the active content.
    /// * `location` - Structural location within the document.
    /// * `severity` - Threat severity level.
    #[must_use]
    pub fn new(
        content_type: ActiveContentType,
        location: ContentLocation,
        severity: ThreatSeverity,
    ) -> Self {
        Self {
            content_type,
            location,
            severity,
            action_taken: None,
            original_hash: None,
        }
    }

    /// Set the sanitization action taken on this content.
    ///
    /// Returns `&mut self` for method chaining.
    pub fn with_action(mut self, action: SanitizeAction) -> Self {
        self.action_taken = Some(action);
        self
    }

    /// Set the original hash of the raw content bytes.
    ///
    /// Returns `&mut self` for method chaining.
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.original_hash = Some(hash.into());
        self
    }

    /// Check whether this content has been processed (action taken).
    #[must_use]
    pub fn is_processed(&self) -> bool {
        self.action_taken.is_some()
    }
}

/// Error type for CDR Engine v2 operations.
///
/// Uses thiserror for automatic Display/Source implementations and
/// structured error variants covering all failure modes in the pipeline.
#[derive(Debug, Error)]
pub enum CdrError {
    /// Document parsing failed — malformed input or unsupported structure.
    #[error("parse error: {0}")]
    ParseError(String),

    /// A specific pipeline stage failed with contextual information.
    #[error("stage '{stage}' failed: {detail}")]
    StageError {
        /// Name of the stage that produced the error.
        stage: String,

        /// Underlying error description.
        detail: String,
    },

    /// Policy violation — content blocked by security policy rules.
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// I/O error during file read/write operations.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // DocumentFormat Tests
    // -----------------------------------------------------------------

    #[test]
    fn document_format_extension_returns_correct_value() {
        assert_eq!(DocumentFormat::Pdf.extension(), "pdf");
        assert_eq!(DocumentFormat::Docx.extension(), "docx");
        assert_eq!(DocumentFormat::Unknown("xyz".into()).extension(), "bin");
    }

    #[test]
    fn document_format_is_office_document_detects_office_formats() {
        assert!(DocumentFormat::Docx.is_office_document());
        assert!(DocumentFormat::Xls.is_office_document());
        assert!(!DocumentFormat::Pdf.is_office_document());
        assert!(!DocumentFormat::Zip.is_office_document());
    }

    #[test]
    fn document_format_is_archive_detects_archives() {
        assert!(DocumentFormat::Zip.is_archive());
        assert!(DocumentFormat::SevenZ.is_archive());
        assert!(!DocumentFormat::Pdf.is_archive());
    }

    #[test]
    fn document_format_display_shows_extension() {
        assert_eq!(format!("{}", DocumentFormat::Pptx), "pptx");
        assert_eq!(
            format!("{}", DocumentFormat::Unknown("custom".into())),
            "unknown(custom)"
        );
    }

    // -----------------------------------------------------------------
    // ThreatSeverity Ordering Tests
    // -----------------------------------------------------------------

    #[test]
    fn threat_severity_ordering_is_correct() {
        assert!(ThreatSeverity::Critical > ThreatSeverity::High);
        assert!(ThreatSeverity::High > ThreatSeverity::Medium);
        assert!(ThreatSeverity::Medium > ThreatSeverity::Low);
        assert!(ThreatSeverity::Low > ThreatSeverity::Info);
    }

    #[test]
    fn threat_severity_level_matches_variant() {
        assert_eq!(ThreatSeverity::Critical.level(), 5);
        assert_eq!(ThreatSeverity::Info.level(), 1);
    }

    // -----------------------------------------------------------------
    // ActiveContentRef Builder Tests
    // -----------------------------------------------------------------

    #[test]
    fn active_content_ref_builder_creates_valid_instance() {
        let ref_item = ActiveContentRef::new(
            ActiveContentType::JavaScript,
            ContentLocation::new("/document/pages[0]/js[0]"),
            ThreatSeverity::Critical,
        )
        .with_action(SanitizeAction::Removed)
        .with_hash("abc123");

        assert_eq!(ref_item.content_type, ActiveContentType::JavaScript);
        assert!(ref_item.is_processed());
        assert_eq!(ref_item.action_taken, Some(SanitizeAction::Removed));
        assert_eq!(ref_item.original_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn active_content_ref_unprocessed_has_no_action() {
        let ref_item = ActiveContentRef::new(
            ActiveContentType::VBMacro,
            ContentLocation::new("/workbook/vba_project"),
            ThreatSeverity::High,
        );

        assert!(!ref_item.is_processed());
        assert!(ref_item.action_taken.is_none());
    }

    // -----------------------------------------------------------------
    // ContentLocation Tests
    // -----------------------------------------------------------------

    #[test]
    fn content_location_from_string() {
        let loc = ContentLocation::from("/root/child[0]");
        assert_eq!(loc.as_str(), "/root/child[0]");
    }

    #[test]
    fn content_location_display() {
        let loc = ContentLocation::new("/a/b/c");
        assert_eq!(format!("{loc}"), "/a/b/c");
    }

    // -----------------------------------------------------------------
    // CdrError Tests
    // -----------------------------------------------------------------

    #[test]
    fn cdr_error_parse_error_display() {
        let err = CdrError::ParseError("corrupt PDF header".into());
        assert_eq!(format!("{err}"), "parse error: corrupt PDF header");
    }

    #[test]
    fn cdr_error_stage_error_includes_context() {
        let err = CdrError::StageError {
            stage: "macro_stripper".into(),
            detail: "VBA decompression failed".into(),
        };
        assert!(format!("{err}").contains("macro_stripper"));
        assert!(format!("{err}").contains("VBA decompression failed"));
    }

    // -----------------------------------------------------------------
    // SanitizeAction Display Tests
    // -----------------------------------------------------------------

    #[test]
    fn sanitize_action_display_all_variants() {
        assert_eq!(format!("{}", SanitizeAction::Removed), "removed");
        assert_eq!(format!("{}", SanitizeAction::NopOut), "nopped_out");
        assert_eq!(format!("{}", SanitizeAction::Flattened), "flattened");
        assert_eq!(format!("{}", SanitizeAction::Extracted), "extracted");
        assert_eq!(format!("{}", SanitizeAction::Skipped), "skipped");
    }

    // -----------------------------------------------------------------
    // ActiveContentType Display Tests
    // -----------------------------------------------------------------

    #[test]
    fn active_content_type_display_custom() {
        let ct = ActiveContentType::Custom("vendor_specific".into());
        assert_eq!(format!("{ct}"), "custom(vendor_specific)");
    }
}
