use serde::{Deserialize, Serialize};
use super::policy::SanitizationPolicy;

/// Detailed record of every action taken during a single file's sanitization process.
/// This report serves as both an operational log and legal evidence chain for compliance audits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationReport {
    pub file_id: String,
    pub original_filename: String,
    pub original_hash: String,
    pub sanitized_hash: String,
    pub policy: SanitizationPolicy,
    pub actions_taken: Vec<SanitizationAction>,
    pub warnings: Vec<String>,
    pub processing_time_ms: u64,
    pub success: bool,
}

impl SanitizationReport {
    pub fn new(file_id: String, original_filename: String) -> Self {
        Self {
            file_id,
            original_filename,
            original_hash: String::new(),
            sanitized_hash: String::new(),
            policy: SanitizationPolicy::default(),
            actions_taken: Vec::new(),
            warnings: Vec::new(),
            processing_time_ms: 0,
            success: false,
        }
    }

    pub fn with_policy(mut self, policy: SanitizationPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Individual remediation action performed on a file during CDR processing.
/// Each variant captures enough context for audit trail reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail")]
pub enum SanitizationAction {
    /// JavaScript code removed from PDF object at specified byte offset
    PdfJsRemoved { offset: usize, length: usize },

    /// Additional Actions (AA) dictionary removed from page/object
    PdfAaRemoved { offset: usize },

    /// AcroForm flattened to static fields (values preserved, interactivity removed)
    PdfAcroFormFlattened,

    /// OpenAction dictionary removed from catalog
    PdfOpenActionRemoved,

    /// SubmitForm action URL removed
    PdfSubmitFormRemoved,

    /// URI action removed when pointing to external resource
    PdfUriRemoved { offset: usize },

    /// EmbeddedFile entry flagged (not removed in StripActiveContent mode)
    PdfEmbeddedFileFlagged { name: String },

    /// RichMedia annotation removed
    PdfRichMediaRemoved,

    /// VBA macro project removed from Office document
    VbaMacroRemoved { filename: String },

    /// ZIP inner entry sanitized recursively
    ZipEntrySanitized { entry_name: String },

    /// Document converted to flat format
    FileConvertedToFlat,
}
