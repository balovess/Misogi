//! Report structures for OOXML True CDR processing results.

/// Detailed report of OOXML True CDR processing actions.
#[derive(Debug, Clone)]
pub struct OoxmlCdrReport {
    /// Whether VBA macro project was found and removed.
    pub vba_removed: bool,
    /// Number of ActiveX controls removed.
    pub activex_removed: usize,
    /// Number of OLE object embeddings removed.
    pub ole_removed: usize,
    /// Number of external data connections removed.
    pub data_connections_removed: usize,
    /// Number of custom XML parts removed.
    pub custom_xml_removed: usize,
    /// Number of smart tags removed.
    pub smart_tags_removed: usize,
    /// Total number of XML elements filtered out (dropped).
    pub xml_elements_filtered: usize,
    /// Whether [Content_Types].xml was modified.
    pub content_types_modified: bool,
    /// Whether any relationships files were modified.
    pub relationships_modified: bool,
    /// Warnings encountered during processing (non-fatal issues).
    pub warnings: Vec<String>,
    /// Entries processed vs skipped counts.
    pub entries_processed: usize,
    pub entries_skipped: usize,
    // ---- Enhanced Threat Tracking ----
    /// Number of DDE attack payloads detected and neutralized.
    pub dde_attacks_detected: usize,
    /// Number of Excel-specific threats neutralized (sheetProtection, PivotCache, etc.).
    pub excel_threats_neutralized: usize,
    /// Number of Word-specific threats neutralized (instrText, altChunk, etc.).
    pub word_threats_neutralized: usize,
    /// Number of PowerPoint-specific threats neutralized (OLE, extLst, etc.).
    pub powerpoint_threats_neutralized: usize,
    /// Chronological list of all CDR actions taken during processing.
    ///
    /// Each entry provides an auditable record of what was detected and
    /// what remediation action was applied, suitable for compliance reporting.
    pub actions_taken: Vec<OoxmlCdrAction>,
}

impl Default for OoxmlCdrReport {
    fn default() -> Self {
        Self {
            vba_removed: false,
            activex_removed: 0,
            ole_removed: 0,
            data_connections_removed: 0,
            custom_xml_removed: 0,
            smart_tags_removed: 0,
            xml_elements_filtered: 0,
            content_types_modified: false,
            relationships_modified: false,
            warnings: Vec::new(),
            entries_processed: 0,
            entries_skipped: 0,
            dde_attacks_detected: 0,
            excel_threats_neutralized: 0,
            word_threats_neutralized: 0,
            powerpoint_threats_neutralized: 0,
            actions_taken: Vec::new(),
        }
    }
}

impl OoxmlCdrReport {
    /// Add a warning message to the report.
    pub fn add_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Check if any content was actually modified during processing.
    pub fn has_modifications(&self) -> bool {
        self.vba_removed
            || self.activex_removed > 0
            || self.ole_removed > 0
            || self.data_connections_removed > 0
            || self.custom_xml_removed > 0
            || self.smart_tags_removed > 0
            || self.xml_elements_filtered > 0
            || self.content_types_modified
            || self.relationships_modified
            || self.dde_attacks_detected > 0
            || self.excel_threats_neutralized > 0
            || self.word_threats_neutralized > 0
            || self.powerpoint_threats_neutralized > 0
            || !self.actions_taken.is_empty()
    }
}

/// Individual CDR action record for audit trail compliance.
///
/// Each variant captures sufficient context to reconstruct exactly what
/// threat was detected and what remediation was applied. These records
/// are serialized into the final sanitization report for legal/audit review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OoxmlCdrAction {
    /// VBA macro project removed from document.
    VbaMacroRemoved { filename: String },
    /// DDE attack payload detected and neutralized in cell/formula.
    DdeAttackDetected {
        location: String,
        pattern_matched: String,
    },
    /// External link with blocked protocol stripped.
    BlockedExternalLink {
        url: String,
        blocked_protocol: String,
    },
    /// Excel sheetProtection element stripped (password hash = brute-force vector).
    SheetProtectionStripped { location: String },
    /// Excel PivotCache with external data source reference stripped.
    PivotCacheExternalRefStripped { cache_id: String },
    /// Custom XML mapping element with script injection stripped.
    CustomXmlMappingStripped { map_id: String, reason: String },
    /// Data validation dropdown with malicious URL stripped.
    MaliciousDataValidationStripped { location: String, url: String },
    /// Word instrText field with script injection neutralized.
    InstrTextScriptNeutralized { field_content: String },
    /// Word altChunk (external content embedding) removed.
    AltChunkRemoved { chunk_id: String },
    /// Word hyperlink target blocked by protocol policy.
    HyperlinkBlocked { target: String, reason: String },
    /// Word IRM permission element (permStart/permEnd) stripped.
    IrmPermissionStripped { location: String },
    /// PowerPoint OLE object embedding disguised as picture detected.
    OleObjectDetected { object_id: String },
    /// PowerPoint transition sound with external reference stripped.
    ExternalSoundStripped { sound_ref: String },
    /// PowerPoint extension list (extLst) removed — zero-day vector.
    ExtLstRemoved { location: String },
    /// PowerPoint animation command with script injection stripped.
    AnimationCmdStripped { cmd_content: String },
}
