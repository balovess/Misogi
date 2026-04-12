//! Base type definitions for OOXML True CDR.

use zip::ZipArchive;
use std::io::{Read, Seek};

use misogi_core::Result;

// =============================================================================
// Document Type Detection
// =============================================================================

/// Detected OOXML document type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OoxmlDocumentType {
    /// WordprocessingML document (.docx/.docm).
    Word,
    /// SpreadsheetML document (.xlsx/.xlsm).
    Excel,
    /// PresentationML document (.pptx/.pptm).
    PowerPoint,
    /// Unknown or generic OOXML package.
    Unknown,
}

impl OoxmlDocumentType {
    /// Detect document type from file extension or content analysis.
    pub fn from_filename(filename: &str) -> Self {
        let lower = filename.to_ascii_lowercase();
        if lower.ends_with(".docx") || lower.ends_with(".docm") {
            Self::Word
        } else if lower.ends_with(".xlsx") || lower.ends_with(".xlsm") {
            Self::Excel
        } else if lower.ends_with(".pptx") || lower.ends_with(".pptm") {
            Self::PowerPoint
        } else {
            Self::Unknown
        }
    }

    /// Detect document type from ZIP entry structure (content-based).
    pub fn from_zip_structure(archive: &mut ZipArchive<impl Read + Seek>) -> Result<Self> {
        // Check for characteristic root entries
        let has_word = (0..archive.len()).any(|i| {
            archive.by_index(i)
                .map(|e| e.name().starts_with("word/"))
                .unwrap_or(false)
        });
        let has_excel = (0..archive.len()).any(|i| {
            archive.by_index(i)
                .map(|e| e.name().starts_with("xl/"))
                .unwrap_or(false)
        });
        let has_ppt = (0..archive.len()).any(|i| {
            archive.by_index(i)
                .map(|e| e.name().starts_with("ppt/"))
                .unwrap_or(false)
        });

        match (has_word, has_excel, has_ppt) {
            (true, false, false) => Ok(Self::Word),
            (false, true, false) => Ok(Self::Excel),
            (false, false, true) => Ok(Self::PowerPoint),
            _ => Ok(Self::Unknown),
        }
    }
}

// =============================================================================
// Content Type Filter Mode
// =============================================================================

/// Strategy for handling unknown/custom content types in [Content_Types].xml.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentTypeFilterMode {
    /// Keep only well-known safe content types; remove unknown ones.
    Strict,
    /// Keep unknown content types but log warnings.
    Lenient,
    /// Keep everything except explicitly dangerous types (default).
    Permissive,
}

impl Default for ContentTypeFilterMode {
    fn default() -> Self {
        Self::Permissive
    }
}

// =============================================================================
// Filtered XML Result
// =============================================================================

/// Result of filtering an individual XML entry.
#[derive(Debug, Clone)]
pub struct FilteredXmlResult {
    /// Filtered XML bytes (may be empty if entire entry was dropped).
    pub filtered_bytes: Vec<u8>,
    /// Number of elements filtered out.
    pub elements_dropped: usize,
    /// IDs of referenced targets that were removed (for relationship cleanup).
    pub removed_target_ids: Vec<String>,
}

// =============================================================================
// CDR Processing Result
// =============================================================================

/// Result of OOXML True CDR processing.
#[derive(Debug, Clone)]
pub struct OoxmlTrueCdrResult {
    /// Sanitized output bytes (valid OOXML ZIP archive).
    pub output: Vec<u8>,
    /// Detailed processing report.
    pub report: super::report::OoxmlCdrReport,
    /// Whether validation passed (no critical errors).
    pub validation_passed: bool,
    /// Detected document type.
    pub document_type: OoxmlDocumentType,
}
