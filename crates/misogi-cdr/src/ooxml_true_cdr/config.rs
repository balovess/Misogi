//! Configuration structures for OOXML True CDR processing.

use std::collections::HashSet;

use super::constants::{
    DEFAULT_MAX_FILE_SIZE_BYTES,
    MAX_ZIP_EXPANSION_RATIO,
    DOCX_BODY_WHITELIST,
    XLSX_SHEET_WHITELIST,
    PPTX_SLIDE_WHITELIST,
};
use super::types::ContentTypeFilterMode;
use super::types::OoxmlDocumentType;

// =============================================================================
// Element Whitelist Configuration
// =============================================================================

/// XML element whitelist definitions per document type.
///
/// Each whitelist contains the set of element local names (with namespace prefix)
/// that are permitted in the sanitized output. Elements not in the whitelist
/// are silently dropped along with their children.
#[derive(Debug, Clone)]
pub struct ElementWhitelist {
    /// Whitelist for WordprocessingML body content.
    pub docx_body: HashSet<String>,
    /// Whitelist for SpreadsheetML worksheet content.
    pub xlsx_sheet: HashSet<String>,
    /// Whitelist for PresentationML slide content.
    pub pptx_slide: HashSet<String>,
}

impl Default for ElementWhitelist {
    fn default() -> Self {
        Self::jp_defaults()
    }
}

impl ElementWhitelist {
    /// Create whitelist with Japanese security defaults (paranoid mode).
    ///
    /// These defaults follow JIS X 3201 (Japanese Industrial Standard for
    /// electronic document security) guidelines for CDR processing.
    pub fn jp_defaults() -> Self {
        Self {
            docx_body: DOCX_BODY_WHITELIST.iter().map(|s| s.to_string()).collect(),
            xlsx_sheet: XLSX_SHEET_WHITELIST.iter().map(|s| s.to_string()).collect(),
            pptx_slide: PPTX_SLIDE_WHITELIST.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Get appropriate whitelist for a given document type.
    pub fn get_whitelist(&self, doc_type: OoxmlDocumentType) -> &HashSet<String> {
        match doc_type {
            OoxmlDocumentType::Word => &self.docx_body,
            OoxmlDocumentType::Excel => &self.xlsx_sheet,
            OoxmlDocumentType::PowerPoint => &self.pptx_slide,
            OoxmlDocumentType::Unknown => &self.docx_body, // fallback to Word as safest
        }
    }
}

// =============================================================================
// OOXML True CDR Configuration
// =============================================================================

/// Configuration for OOXML True CDR processing.
///
/// Controls which features are stripped and how aggressive the filtering is.
#[derive(Debug, Clone)]
pub struct OoxmlTrueCdrConfig {
    /// Strip VBA macro project entirely (default: true).
    pub strip_vba: bool,
    /// Strip ActiveX controls (default: true).
    pub strip_activex: bool,
    /// Strip OLE object embeddings (default: true).
    pub strip_ole_embeddings: bool,
    /// Strip external data connections (default: true).
    pub strip_data_connections: bool,
    /// Strip custom XML parts (potential script injection vector; default: true).
    pub strip_custom_xml: bool,
    /// Strip smart tags (potential data exfiltration; default: true).
    pub strip_smart_tags: bool,
    /// Content type filtering mode (default: Permissive).
    pub content_type_mode: ContentTypeFilterMode,
    /// XML element whitelist per document type.
    pub element_whitelist: ElementWhitelist,
    /// Maximum file size in bytes (default: 100 MB).
    pub max_file_size_bytes: u64,
    /// Maximum ZIP expansion ratio (default: 10x).
    pub max_expansion_ratio: u64,
}

impl Default for OoxmlTrueCdrConfig {
    fn default() -> Self {
        Self::jp_defaults()
    }
}

impl OoxmlTrueCdrConfig {
    /// Create configuration with Japanese security defaults.
    ///
    /// Enables all stripping options and uses paranoid whitelists.
    pub fn jp_defaults() -> Self {
        Self {
            strip_vba: true,
            strip_activex: true,
            strip_ole_embeddings: true,
            strip_data_connections: true,
            strip_custom_xml: true,
            strip_smart_tags: true,
            content_type_mode: ContentTypeFilterMode::Permissive,
            element_whitelist: ElementWhitelist::jp_defaults(),
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            max_expansion_ratio: MAX_ZIP_EXPANSION_RATIO,
        }
    }

    /// Create minimal configuration (only strip VBA, keep everything else).
    ///
    /// Useful for compatibility-focused scenarios where maximum fidelity is needed.
    pub fn minimal() -> Self {
        Self {
            strip_vba: true,
            strip_activex: false,
            strip_ole_embeddings: false,
            strip_data_connections: false,
            strip_custom_xml: false,
            strip_smart_tags: false,
            content_type_mode: ContentTypeFilterMode::Lenient,
            element_whitelist: ElementWhitelist::default(),
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            max_expansion_ratio: MAX_ZIP_EXPANSION_RATIO,
        }
    }
}
