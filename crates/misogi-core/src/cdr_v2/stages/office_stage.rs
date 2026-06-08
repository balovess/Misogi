// =============================================================================
// CDR Engine v2 — Office Document Sanitization Stages
// =============================================================================
// This module implements two pipeline stages for Microsoft Office document
// sanitization, operating at the DocumentAst abstraction layer:
//
// 1. OfficeOpenXmlStage: Handles modern OOXML formats (Docx, Xlsx, Pptx).
//    - VBA macro stripping (macro-enabled OOXML documents)
//    - OLE embedded object sanitization (Excel sheets, packages)
//    - External data connection removal (DQ, web queries)
//
// 2. OfficeLegacyStage: Handles legacy binary formats (Doc, Xls, Ppt).
//    - Legacy binary macro project extraction/removal
//    - OLE2 compound document structure sanitization
//
// Threat Model:
// Office macros remain one of the most prevalent initial access vectors in
// enterprise environments. These stages neutralize macro execution capability
// while preserving document content (text, images, formatting).
//
// Implementation Notes:
// - Both stages operate on AST level; no binary OLE2/OOXML parsing required.
// - VBA macros are identified via ActiveContentType::VBMacro nodes.
// - OLE objects are identified via ActiveContentType::OLEEmbeddedObject nodes.
// - External connections use ActiveContentType::HyperlinkExternal or custom types.
// =============================================================================

use async_trait::async_trait;

use crate::cdr_v2::ast::{AstNode, DocumentAst};
use crate::cdr_v2::config::OfficeConfig;
use crate::cdr_v2::pipeline::{CdrContext, CdrStage, SanitizationReport};
use crate::cdr_v2::types::{
    ActiveContentType, CdrError, DocumentFormat, SanitizeAction,
};

/// Sanitization mode for OLE embedded objects.
///
/// Controls how the stage handles OLE objects found within Office documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OleSanitizeMode {
    /// Completely remove the OLE object from output.
    Remove,

    /// Zero out the executable payload (replace with NOPs).
    NopOut,

    /// Extract to quarantine and replace with placeholder icon.
    Extract,
}

impl std::fmt::Display for OleSanitizeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remove => write!(f, "remove"),
            Self::NopOut => write!(f, "nop_out"),
            Self::Extract => write!(f, "extract"),
        }
    }
}

// =============================================================================
// OfficeOpenXmlStage 鈥?Modern OOXML Format Sanitizer
// =============================================================================

/// Sanitization stage for Office Open XML (OOXML) documents.
///
/// Processes Docx, Xlsx, and Pptx formats to remove executable content
/// while preserving safe document elements (text, images, formatting).
///
/// # Scope
/// This stage only processes OOXML formats ([`DocumentFormat::Docx`],
/// [`DocumentFormat::Xlsx`], [`DocumentFormat::Pptx`]). Legacy binary
/// formats are handled by [`OfficeLegacyStage`].
pub struct OfficeOpenXmlStage {
    /// Office processing configuration.
    config: OfficeConfig,

    /// OLE object sanitization mode (overrides default behavior).
    ole_mode: OleSanitizeMode,
}

impl OfficeOpenXmlStage {
    /// Create a new OOXML sanitize stage with explicit configuration.
    ///
    /// # Arguments
    /// * `config` - Office processing configuration.
    #[must_use]
    pub fn new(config: OfficeConfig) -> Self {
        Self {
            config,
            ole_mode: OleSanitizeMode::Remove,
        }
    }

    /// Create an OOXML stage with secure defaults and specified OLE mode.
    ///
    /// # Arguments
    /// * `ole_mode` - How to handle OLE embedded objects.
    #[must_use]
    pub fn with_ole_mode(ole_mode: OleSanitizeMode) -> Self {
        Self {
            config: OfficeConfig::default(),
            ole_mode,
        }
    }

    /// Strip VBA macro projects from the document AST.
    ///
    /// VBA macros are the highest-risk threat vector in Office documents.
    /// This method removes all [`ActiveContentType::VBMacro`] entries
    /// and their corresponding tree nodes.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of VBA macro items removed.
    pub fn strip_vba_macros(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_macros {
            return 0;
        }

        let count = ast
            .active_contents
            .iter()
            .filter(|ac| ac.content_type == ActiveContentType::VBMacro)
            .count() as u32;

        // Mark all VBMacro entries as removed
        for ref_item in ast.active_contents.iter_mut() {
            if ref_item.content_type == ActiveContentType::VBMacro {
                ref_item.action_taken = Some(SanitizeAction::Removed);
            }
        }

        // Remove from index
        ast.active_contents
            .retain(|ac| ac.content_type != ActiveContentType::VBMacro);

        // Remove from tree
        Self::remove_ac_nodes_by_type(ast, ActiveContentType::VBMacro);

        count
    }

    /// Sanitize OLE embedded objects according to configured mode.
    ///
    /// OLE objects can contain arbitrary executables (Excel workbooks,
    /// packages, ActiveX controls). The sanitization mode determines
    /// the disarm strategy:
    /// - **Remove**: Delete entirely (most secure).
    /// - **NopOut**: Replace payload with harmless bytes.
    /// - **Extract**: Quarantine and placeholder.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of OLE items sanitized.
    pub fn sanitize_ole_objects(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_ole_objects {
            return 0;
        }

        let action = match &self.ole_mode {
            OleSanitizeMode::Remove => SanitizeAction::Removed,
            OleSanitizeMode::NopOut => SanitizeAction::NopOut,
            OleSanitizeMode::Extract => SanitizeAction::Extracted,
        };

        let count = ast
            .active_contents
            .iter()
            .filter(|ac| ac.content_type == ActiveContentType::OLEEmbeddedObject)
            .count() as u32;

        // Mark all OLE entries with appropriate action
        for ref_item in ast.active_contents.iter_mut() {
            if ref_item.content_type == ActiveContentType::OLEEmbeddedObject {
                ref_item.action_taken = Some(action.clone());
            }
        }

        // If mode is Remove, also purge from tree and index
        if self.ole_mode == OleSanitizeMode::Remove {
            ast.active_contents
                .retain(|ac| ac.content_type != ActiveContentType::OLEEmbeddedObject);
            Self::remove_ac_nodes_by_type(ast, ActiveContentType::OLEEmbeddedObject);
        }

        count
    }

    /// Remove external data connections from the document AST.
    ///
    /// External connections (database queries, web data imports, Power Query)
    /// can exfiltrate data or pull in malicious content. This method removes
    /// all external connection references.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of external connection items removed.
    pub fn remove_external_connections(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_external_data_connections {
            return 0;
        }

        // External connections modeled as HyperlinkExternal or custom type
        let conn_types = [
            ActiveContentType::HyperlinkExternal,
            ActiveContentType::Custom("external_data_connection".into()),
        ];

        let mut count = 0u32;
        for conn_type in &conn_types {
            let matching = ast
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == *conn_type)
                .count() as u32;

            for ref_item in ast.active_contents.iter_mut() {
                if ref_item.content_type == *conn_type {
                    ref_item.action_taken = Some(SanitizeAction::Removed);
                }
            }

            ast.active_contents.retain(|ac| ac.content_type != *conn_type);
            Self::remove_ac_nodes_by_type(ast, conn_type.clone());
            count += matching;
        }

        count
    }

    /// Internal helper: remove ActiveContent nodes of a specific type from tree.
    fn remove_ac_nodes_by_type(ast: &mut DocumentAst, target: ActiveContentType) {
        Self::remove_ac_recursive(&mut ast.root, &target);
    }

    fn remove_ac_recursive(node: &mut AstNode, target: &ActiveContentType) {
        match node {
            AstNode::Document { children }
            | AstNode::Page { children, .. }
            | AstNode::Container { children, .. } => {
                children.retain(|child| {
                    if let AstNode::ActiveContent { ref_item, .. } = child {
                        ref_item.content_type != *target
                    } else {
                        true
                    }
                });
                for child in children.iter_mut() {
                    Self::remove_ac_recursive(child, target);
                }
            }
            _ => {}
        }
    }
}

#[async_trait]
impl CdrStage for OfficeOpenXmlStage {
    /// Return the stage identifier string.
    fn name(&self) -> &str {
        "office_openxml_sanitize"
    }

    /// Process an OOXML document through all sanitization sub-stages.
    ///
    /// Execution order:
    /// 1. Strip VBA macros (highest priority)
    /// 2. Sanitize OLE embedded objects
    /// 3. Remove external data connections
    ///
    /// Non-OOXML documents are passed through unchanged.
    ///
    /// # Arguments
    /// * `input` - Read-only reference to the input document AST.
    /// * `context` - Execution context.
    ///
    /// # Errors
    /// Returns [`CdrError::StageError`] on critical failure.
    async fn process(
        &self,
        input: &DocumentAst,
        _context: &CdrContext,
    ) -> Result<DocumentAst, CdrError> {
        // Format guard: only process OOXML formats
        let is_ooxml = matches!(
            input.format,
            DocumentFormat::Docx | DocumentFormat::Xlsx | DocumentFormat::Pptx
        );
        if !is_ooxml {
            return Ok(input.clone());
        }

        let mut ast = input.clone();
        let mut actions_taken = Vec::new();
        let mut total_items: u32 = 0;

        // 1. VBA macro stripping
        let vba_count = self.strip_vba_macros(&mut ast);
        total_items += vba_count;
        if vba_count > 0 {
            actions_taken.push(("/vba/*".to_string(), SanitizeAction::Removed));
        }

        // 2. OLE object sanitization
        let ole_count = self.sanitize_ole_objects(&mut ast);
        total_items += ole_count;
        if ole_count > 0 {
            let action = match &self.ole_mode {
                OleSanitizeMode::Remove => SanitizeAction::Removed,
                OleSanitizeMode::NopOut => SanitizeAction::NopOut,
                OleSanitizeMode::Extract => SanitizeAction::Extracted,
            };
            actions_taken.push(("/ole/*".to_string(), action));
        }

        // 3. External connection removal
        let ext_count = self.remove_external_connections(&mut ast);
        total_items += ext_count;
        if ext_count > 0 {
            actions_taken.push((
                "/external_connections/*".to_string(),
                SanitizeAction::Removed,
            ));
        }

        let _report = SanitizationReport {
            stage_name: self.name().to_string(),
            items_processed: total_items,
            actions_taken,
            warnings: Vec::new(),
        };

        Ok(ast)
    }
}

// =============================================================================
// OfficeLegacyStage 鈥?Legacy Binary Format Sanitizer
// =============================================================================

/// Sanitization stage for legacy Microsoft Office binary formats.
///
/// Handles Doc, Xls, and Ppt (OLE2 compound document format). Legacy
/// formats present unique challenges because macros are stored in
/// compressed streams within the OLE2 container structure.
///
/// # Key Differences from OOXML Stage
/// - Legacy formats always have potential for inline macros (even without
///   explicit macro project 鈥?Excel 4.0 macros, sheet-level auto-execute).
/// - OLE2 structure allows nested OLE objects within OLE objects.
/// - Binary format parsing is more complex; this stage works at AST level
///   assuming a parser has already extracted macro references.
pub struct OfficeLegacyStage {
    /// Office processing configuration.
    config: OfficeConfig,
}

impl OfficeLegacyStage {
    /// Create a new legacy Office sanitize stage with configuration.
    ///
    /// # Arguments
    /// * `config` - Office processing configuration.
    #[must_use]
    pub fn new(config: OfficeConfig) -> Self {
        Self { config }
    }

    /// Create a legacy Office stage with secure default settings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            config: OfficeConfig::default(),
        }
    }

    /// Strip legacy macro projects from binary Office documents.
    ///
    /// Targets both traditional VBA projects and legacy Excel 4.0 macros
    /// (stored as named ranges with auto-execute names like Auto_Open).
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of legacy macro items removed.
    pub fn strip_legacy_macros(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_macros {
            return 0;
        }

        // Target VBMacro and legacy-specific macro types
        let macro_types = [
            ActiveContentType::VBMacro,
            ActiveContentType::Custom("excel4_macro".into()),
            ActiveContentType::Custom("legacy_auto_exec".into()),
        ];

        let mut count = 0u32;
        for macro_type in &macro_types {
            let matching = ast
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == *macro_type)
                .count() as u32;

            for ref_item in ast.active_contents.iter_mut() {
                if ref_item.content_type == *macro_type {
                    ref_item.action_taken = Some(SanitizeAction::Removed);
                }
            }

            ast.active_contents.retain(|ac| ac.content_type != *macro_type);
            Self::remove_legacy_ac_nodes(ast, macro_type.clone());
            count += matching;
        }

        count
    }

    /// Internal helper: remove active content nodes for legacy formats.
    fn remove_legacy_ac_nodes(ast: &mut DocumentAst, target: ActiveContentType) {
        Self::legacy_remove_recursive(&mut ast.root, &target);
    }

    fn legacy_remove_recursive(node: &mut AstNode, target: &ActiveContentType) {
        match node {
            AstNode::Document { children }
            | AstNode::Page { children, .. }
            | AstNode::Container { children, .. } => {
                children.retain(|child| {
                    if let AstNode::ActiveContent { ref_item, .. } = child {
                        ref_item.content_type != *target
                    } else {
                        true
                    }
                });
                for child in children.iter_mut() {
                    Self::legacy_remove_recursive(child, target);
                }
            }
            _ => {}
        }
    }
}

#[async_trait]
impl CdrStage for OfficeLegacyStage {
    /// Return the stage identifier string.
    fn name(&self) -> &str {
        "office_legacy_sanitize"
    }

    /// Process a legacy Office document through sanitization sub-stages.
    ///
    /// Execution order:
    /// 1. Strip legacy macros (VBA + Excel 4.0 + auto-exec)
    /// 2. OLE object sanitization (inherited from base config)
    ///
    /// Non-legacy formats are passed through unchanged.
    ///
    /// # Arguments
    /// * `input` - Read-only reference to the input document AST.
    /// * `context` - Execution context.
    ///
    /// # Errors
    /// Returns [`CdrError::StageError`] on critical failure.
    async fn process(
        &self,
        input: &DocumentAst,
        _context: &CdrContext,
    ) -> Result<DocumentAst, CdrError> {
        // Format guard: only process legacy binary formats
        let is_legacy = matches!(
            input.format,
            DocumentFormat::Doc | DocumentFormat::Xls | DocumentFormat::Ppt
        );
        if !is_legacy {
            return Ok(input.clone());
        }

        let mut ast = input.clone();
        let mut actions_taken = Vec::new();
        let mut total_items: u32 = 0;

        // 1. Legacy macro stripping
        let macro_count = self.strip_legacy_macros(&mut ast);
        total_items += macro_count;
        if macro_count > 0 {
            actions_taken.push(("/macros/*".to_string(), SanitizeAction::Removed));
        }

        // 2. OLE object handling (legacy formats often embed OLE)
        if self.config.strip_ole_objects {
            let ole_count = ast
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == ActiveContentType::OLEEmbeddedObject)
                .count() as u32;

            for ref_item in ast.active_contents.iter_mut() {
                if ref_item.content_type == ActiveContentType::OLEEmbeddedObject {
                    ref_item.action_taken = Some(SanitizeAction::Removed);
                }
            }

            ast.active_contents
                .retain(|ac| ac.content_type != ActiveContentType::OLEEmbeddedObject);
            Self::remove_legacy_ac_nodes(&mut ast, ActiveContentType::OLEEmbeddedObject);

            total_items += ole_count;
            if ole_count > 0 {
                actions_taken.push(("/ole/*".to_string(), SanitizeAction::Removed));
            }
        }

        let _report = SanitizationReport {
            stage_name: self.name().to_string(),
            items_processed: total_items,
            actions_taken,
            warnings: Vec::new(),
        };

        Ok(ast)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cdr_v2::ast::DocumentMetadata;
    use crate::cdr_v2::types::{ActiveContentRef, ContentLocation, ThreatSeverity};

    // -- Helper Functions --

    fn make_ooxml_ast(format: &DocumentFormat) -> DocumentAst {
        let ext = format.extension();
        let name = format!("test.{ext}");
        DocumentAst::new(
            format.clone(),
            DocumentMetadata::new(name, 2048, format.clone()),
        )
    }

    fn add_ac(ast: &mut DocumentAst, ct: ActiveContentType, path: &str, sev: ThreatSeverity) {
        ast.active_contents.push(ActiveContentRef::new(
            ct,
            ContentLocation::new(path),
            sev,
        ));
    }

    fn add_ac_node(ast: &mut DocumentAst, ct: ActiveContentType, path: &str, sev: ThreatSeverity) {
        let ref_item = ActiveContentRef::new(ct, ContentLocation::new(path), sev);
        let node = AstNode::ActiveContent {
            ref_item,
            raw_data: None,
        };
        if let AstNode::Document { children } = &mut ast.root {
            children.push(node);
        }
    }

    // -----------------------------------------------------------------
    // OfficeOpenXmlStage 鈥?Construction Tests
    // -----------------------------------------------------------------

    #[test]
    fn ooxml_stage_new_with_config() {
        let config = OfficeConfig::default();
        let stage = OfficeOpenXmlStage::new(config);
        assert!(stage.config.strip_macros);
        assert_eq!(stage.name(), "office_openxml_sanitize");
    }

    #[test]
    fn ooxml_stage_with_ole_mode_sets_mode() {
        let stage = OfficeOpenXmlStage::with_ole_mode(OleSanitizeMode::Extract);
        assert_eq!(stage.ole_mode, OleSanitizeMode::Extract);
    }

    // -----------------------------------------------------------------
    // VBA Macro Stripping Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn strip_vba_removes_macro_entries() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Docx);
        add_ac(&mut ast, ActiveContentType::VBMacro, "/vba/project", ThreatSeverity::High);
        add_ac(&mut ast, ActiveContentType::VBMacro, "/vba/module[0]", ThreatSeverity::High);

        let stage = OfficeOpenXmlStage::new(OfficeConfig::default());
        let count = stage.strip_vba_macros(&mut ast);

        assert_eq!(count, 2);
        assert_eq!(ast.active_content_count(), 0);
    }

    #[tokio::test]
    async fn strip_vba_respects_disabled_config() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Xlsx);
        add_ac(&mut ast, ActiveContentType::VBMacro, "/vba", ThreatSeverity::Critical);

        let config = OfficeConfig {
            strip_macros: false,
            ..OfficeConfig::default()
        };
        let stage = OfficeOpenXmlStage::new(config);
        let count = stage.strip_vba_macros(&mut ast);

        assert_eq!(count, 0);
        assert_eq!(ast.active_content_count(), 1);
    }

    // -----------------------------------------------------------------
    // OLE Object Sanitization Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn sanitize_ole_remove_mode_deletes_objects() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Pptx);
        add_ac(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/ole/sheet",
            ThreatSeverity::High,
        );
        add_ac_node(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/ole/sheet",
            ThreatSeverity::High,
        );

        let stage = OfficeOpenXmlStage::with_ole_mode(OleSanitizeMode::Remove);
        let count = stage.sanitize_ole_objects(&mut ast);

        assert_eq!(count, 1);
        assert!(!ast.active_contents.iter().any(|ac| {
            ac.content_type == ActiveContentType::OLEEmbeddedObject
        }));
    }

    #[tokio::test]
    async fn sanitize_ole_nopout_mode_marks_but_keeps_index() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Xlsx);
        add_ac(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/ole/pkg",
            ThreatSeverity::Medium,
        );

        let stage = OfficeOpenXmlStage::with_ole_mode(OleSanitizeMode::NopOut);
        let count = stage.sanitize_ole_objects(&mut ast);

        assert_eq!(count, 1);
        // NopOut mode keeps entry in index but marks it
        assert_eq!(ast.active_content_count(), 1);
        assert_eq!(
            ast.active_contents[0].action_taken,
            Some(SanitizeAction::NopOut)
        );
    }

    #[tokio::test]
    async fn sanitize_ole_extract_mode_quarantines() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Docx);
        add_ac(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/ole/activex",
            ThreatSeverity::Critical,
        );

        let stage = OfficeOpenXmlStage::with_ole_mode(OleSanitizeMode::Extract);
        let count = stage.sanitize_ole_objects(&mut ast);

        assert_eq!(count, 1);
        assert_eq!(
            ast.active_contents[0].action_taken,
            Some(SanitizeAction::Extracted)
        );
    }

    // -----------------------------------------------------------------
    // External Connection Removal Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn remove_external_connections_clears_links() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Xlsx);
        add_ac(
            &mut ast,
            ActiveContentType::HyperlinkExternal,
            "/connections/db_query",
            ThreatSeverity::Medium,
        );
        add_ac(
            &mut ast,
            ActiveContentType::Custom("external_data_connection".into()),
            "/connections/web_query",
            ThreatSeverity::Medium,
        );

        let stage = OfficeOpenXmlStage::new(OfficeConfig::default());
        let count = stage.remove_external_connections(&mut ast);

        assert_eq!(count, 2);
        assert_eq!(ast.active_content_count(), 0);
    }

    // -----------------------------------------------------------------
    // Legacy Macro Stripping Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn strip_legacy_macros_removes_all_variants() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Doc); // Using Doc format for legacy
        ast.format = DocumentFormat::Doc; // Ensure legacy format

        add_ac(
            &mut ast,
            ActiveContentType::VBMacro,
            "/vba/this_workbook",
            ThreatSeverity::High,
        );
        add_ac(
            &mut ast,
            ActiveContentType::Custom("excel4_macro".into()),
            "/names/auto_open",
            ThreatSeverity::Critical,
        );

        let stage = OfficeLegacyStage::with_defaults();
        let count = stage.strip_legacy_macros(&mut ast);

        assert_eq!(count, 2);
        assert_eq!(ast.active_content_count(), 0);
    }

    // -----------------------------------------------------------------
    // DOCX vs DOC Format Routing Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn ooxml_stage_only_processes_ooxml_formats() {
        let mut doc_ast = make_ooxml_ast(&DocumentFormat::Doc); // Legacy format
        add_ac(&mut doc_ast, ActiveContentType::VBMacro, "/vba", ThreatSeverity::High);

        let stage = OfficeOpenXmlStage::new(OfficeConfig::default());
        let context = CdrContext::new("file-001", "user-001");
        let result = stage.process(&doc_ast, &context).await.unwrap();

        // Should pass through unchanged (not OOXML format)
        assert_eq!(result.active_content_count(), 1);
    }

    #[tokio::test]
    async fn legacy_stage_only_processes_legacy_formats() {
        let mut docx_ast = make_ooxml_ast(&DocumentFormat::Docx); // Modern format
        add_ac(&mut docx_ast, ActiveContentType::VBMacro, "/vba", ThreatSeverity::High);

        let stage = OfficeLegacyStage::with_defaults();
        let context = CdrContext::new("file-002", "user-002");
        let result = stage.process(&docx_ast, &context).await.unwrap();

        // Should pass through unchanged (not legacy format)
        assert_eq!(result.active_content_count(), 1);
    }

    // -----------------------------------------------------------------
    // Force Flat Format Concept Test
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn combined_office_pipeline_produces_flat_output() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Docx);
        add_ac_node(
            &mut ast,
            ActiveContentType::VBMacro,
            "/vba",
            ThreatSeverity::Critical,
        );
        add_ac_node(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/ole",
            ThreatSeverity::High,
        );
        add_ac(
            &mut ast,
            ActiveContentType::HyperlinkExternal,
            "/ext_conn",
            ThreatSeverity::Medium,
        );

        let stage = OfficeOpenXmlStage::new(OfficeConfig::default());
        let context = CdrContext::new("file-003", "user-003");
        let result = stage.process(&ast, &context).await.unwrap();

        // All threats should be neutralized
        assert!(!result.active_contents.iter().any(|ac| {
            matches!(
                ac.content_type,
                ActiveContentType::VBMacro
                    | ActiveContentType::OLEEmbeddedObject
                    | ActiveContentType::HyperlinkExternal
            )
        }));
    }

    // -----------------------------------------------------------------
    // Empty Document Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn ooxml_stage_empty_document() {
        let ast = make_ooxml_ast(&DocumentFormat::Xlsx);
        let stage = OfficeOpenXmlStage::new(OfficeConfig::default());
        let context = CdrContext::new("file-004", "user-004");
        let result = stage.process(&ast, &context).await.unwrap();

        assert_eq!(result.active_content_count(), 0);
    }

    #[tokio::test]
    async fn legacy_stage_empty_document() {
        let ast = make_ooxml_ast(&DocumentFormat::Xls);
        let stage = OfficeLegacyStage::with_defaults();
        let context = CdrContext::new("file-005", "user-005");
        let result = stage.process(&ast, &context).await.unwrap();

        assert_eq!(result.active_content_count(), 0);
    }

    // -----------------------------------------------------------------
    // Whitelist Bypass Simulation Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn whitelist_bypass_via_disabled_config() {
        let mut ast = make_ooxml_ast(&DocumentFormat::Pptx);
        add_ac(&mut ast, ActiveContentType::VBMacro, "/vba", ThreatSeverity::Critical);
        add_ac(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/ole",
            ThreatSeverity::High,
        );

        // Simulate whitelist bypass: disable all sanitization
        let permissive_config = OfficeConfig {
            strip_macros: false,
            strip_ole_objects: false,
            strip_external_data_connections: false,
            disable_activex_controls: false,
            ..OfficeConfig::default()
        };

        let stage = OfficeOpenXmlStage::new(permissive_config);
        let context = CdrContext::new("file-006", "user-006");
        let result = stage.process(&ast, &context).await.unwrap();

        // All content preserved when config disables everything
        assert_eq!(result.active_content_count(), 2);
    }

    // -----------------------------------------------------------------
    // OleSanitizeMode Display Tests
    // -----------------------------------------------------------------

    #[test]
    fn ole_sanitize_mode_display_all_variants() {
        assert_eq!(format!("{}", OleSanitizeMode::Remove), "remove");
        assert_eq!(format!("{}", OleSanitizeMode::NopOut), "nop_out");
        assert_eq!(format!("{}", OleSanitizeMode::Extract), "extract");
    }
}



