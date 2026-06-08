// =============================================================================
// CDR Engine v2 — PDF Sanitization Stage
// =============================================================================
// This module implements [`PdfSanitizeStage`], a pipeline stage that neutralizes
// PDF-specific threat vectors by operating on the DocumentAst abstraction layer.
//
// Threat Vectors Addressed:
// 1. JavaScript execution (PDF actions, page-level scripts, form calculations)
// 2. OpenAction / OpenDestination auto-execution triggers
// 3. Embedded file attachments (potential malware containers)
// 4. Interactive AcroForm / XFA form fields (script-bearing UI elements)
// 5. Unknown/unrecognized PDF elements (defense-in-depth)
//
// Implementation Strategy:
// - Walks the AST tree to find ActiveContent nodes matching target types.
// - Marks each matched node with the appropriate SanitizeAction.
// - Removes the corresponding AstNode::ActiveContent from the tree structure.
// - Returns count of items sanitized for report generation.
//
// Safety Guarantee:
// This stage NEVER executes JavaScript or parses binary PDF structures.
// All operations are structural transformations on the AST representation.
// =============================================================================

use async_trait::async_trait;

use crate::cdr_v2::ast::{AstNode, DocumentAst};
use crate::cdr_v2::config::PdfConfig;
use crate::cdr_v2::pipeline::{CdrContext, CdrStage, SanitizationReport};
use crate::cdr_v2::types::{
    ActiveContentType, CdrError, DocumentFormat, SanitizeAction,
};

/// PDF document sanitization stage.
///
/// Neutralizes JavaScript, auto-run actions, embedded files, interactive forms,
/// and unknown elements within PDF documents represented as [`DocumentAst`].
///
/// # Configuration
/// Behavior is controlled via [`PdfConfig`] flags. Each sanitize method checks
/// its corresponding config flag before taking action, enabling fine-grained
/// policy control (e.g., preserve forms but strip JS).
///
/// # Format Scope
/// This stage only processes documents with [`DocumentFormat::Pdf`]. Non-PDF
/// documents are passed through unchanged with a zero-action report.
pub struct PdfSanitizeStage {
    /// PDF-specific configuration controlling which actions are applied.
    config: PdfConfig,
}

impl PdfSanitizeStage {
    /// Create a new PDF sanitize stage with explicit configuration.
    ///
    /// # Arguments
    /// * `config` - PDF processing configuration.
    #[must_use]
    pub fn new(config: PdfConfig) -> Self {
        Self { config }
    }

    /// Create a PDF sanitize stage with secure default settings.
    ///
    /// Defaults enable all sanitization: JavaScript stripping, OpenAction
    /// removal, embedded file extraction, XFA form flattening.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            config: PdfConfig::default(),
        }
    }

    /// Strip all JavaScript active content from the document AST.
    ///
    /// Walks the tree to find `ActiveContent` nodes where `content_type`
    /// equals [`ActiveContentType::JavaScript`], marks them with
    /// [`SanitizeAction::Removed`], and removes the nodes from the tree.
    ///
    /// Also updates the `active_contents` index to reflect removals.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of JavaScript items removed.
    fn strip_javascript(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_javascript {
            return 0;
        }

        let mut count = 0u32;
        let js_locations: Vec<String> = ast
            .active_contents
            .iter()
            .filter(|ac| ac.content_type == ActiveContentType::JavaScript)
            .map(|ac| ac.location.path.clone())
            .collect();

        for location in &js_locations {
            // Mark action in the active contents index
            if let Some(ref_item) = ast
                .active_contents
                .iter_mut()
                .find(|ac| ac.location.path == *location)
            {
                ref_item.action_taken = Some(SanitizeAction::Removed);
            }
            count += 1;
        }

        // Remove JavaScript nodes from tree
        Self::remove_active_content_nodes_by_type(ast, ActiveContentType::JavaScript);
        // Clean up active_contents index
        ast.active_contents
            .retain(|ac| ac.content_type != ActiveContentType::JavaScript);

        count
    }

    /// Strip OpenAction / auto-run active content from the document AST.
    ///
    /// Targets content classified as auto-execution triggers that run
    /// when the document is opened in a PDF reader.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of open action items removed.
    fn strip_open_actions(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_open_actions {
            return 0;
        }

        // OpenActions are modeled as ActionForm with Critical severity
        // or custom "open_action" type
        let mut count = 0u32;
        let open_action_types = [
            ActiveContentType::ActionForm,
            ActiveContentType::Custom("open_action".into()),
        ];

        let to_remove: Vec<ActiveContentType> = open_action_types.into_iter().collect();

        for content_type in &to_remove {
            let locations: Vec<String> = ast
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == *content_type)
                .map(|ac| ac.location.path.clone())
                .collect();

            for location in &locations {
                if let Some(ref_item) = ast
                    .active_contents
                    .iter_mut()
                    .find(|ac| ac.location.path == *location)
                {
                    ref_item.action_taken = Some(SanitizeAction::Removed);
                }
                count += 1;
            }

            Self::remove_active_content_nodes_by_type(ast, content_type.clone());
        }

        ast.active_contents
            .retain(|ac| !to_remove.contains(&ac.content_type));

        count
    }

    /// Strip embedded file references from the document AST.
    ///
    /// Embedded files in PDFs are a common malware distribution vector.
    /// This method removes all embedded file attachment nodes.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of embedded file items removed.
    fn strip_embedded_files(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.strip_embedded_files {
            return 0;
        }

        // Embedded files modeled as OLEEmbeddedObject or custom "embedded_file"
        let mut count = 0u32;
        let embed_types = [
            ActiveContentType::OLEEmbeddedObject,
            ActiveContentType::Custom("embedded_file".into()),
        ];

        let to_remove: Vec<ActiveContentType> = embed_types.into_iter().collect();

        for content_type in &to_remove {
            let locations: Vec<String> = ast
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == *content_type)
                .map(|ac| ac.location.path.clone())
                .collect();

            for location in &locations {
                if let Some(ref_item) = ast
                    .active_contents
                    .iter_mut()
                    .find(|ac| ac.location.path == *location)
                {
                    ref_item.action_taken = Some(SanitizeAction::Extracted);
                }
                count += 1;
            }

            Self::remove_active_content_nodes_by_type(ast, content_type.clone());
        }

        ast.active_contents
            .retain(|ac| !to_remove.contains(&ac.content_type));

        count
    }

    /// Flatten interactive form fields into static content.
    ///
    /// Converts ActionForm and DynamicXfaForm nodes from interactive
    /// (script-capable) to static text/metadata representations.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of form items flattened.
    fn flatten_form_fields(&self, ast: &mut DocumentAst) -> u32 {
        if !self.config.flatten_xfa_forms {
            return 0;
        }

        let mut count = 0u32;
        let form_types = [
            ActiveContentType::ActionForm,
            ActiveContentType::DynamicXfaForm,
        ];

        for form_type in &form_types {
            let locations: Vec<String> = ast
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == *form_type && ac.action_taken.is_none())
                .map(|ac| ac.location.path.clone())
                .collect();

            for location in &locations {
                if let Some(ref_item) = ast
                    .active_contents
                    .iter_mut()
                    .find(|ac| ac.location.path == *location)
                {
                    ref_item.action_taken = Some(SanitizeAction::Flattened);
                }
                count += 1;
            }
        }

        // Note: Form flattening marks as Flattened but keeps metadata nodes
        // The actual node replacement would happen in a reconstruction phase

        count
    }

    /// Remove unknown/unrecognized elements from the document AST.
    ///
    /// Defense-in-depth measure: any element not explicitly recognized
    /// as safe is removed to prevent zero-day exploitation of obscure
    /// PDF features.
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST.
    ///
    /// # Returns
    /// Count of unknown elements removed.
    fn remove_unknown_elements(&self, ast: &mut DocumentAst) -> u32 {
        // Recursively walk tree and remove Unknown nodes
        let original_count = ast.root.node_count();
        Self::remove_unknown_nodes_recursive(&mut ast.root);
        let new_count = ast.root.node_count();
        (original_count - new_count) as u32
    }

    /// Internal helper: remove ActiveContent nodes matching a specific type.
    ///
    /// Performs recursive tree mutation, replacing matched nodes with
    /// a safe placeholder or removing them entirely from child vectors.
    fn remove_active_content_nodes_by_type(ast: &mut DocumentAst, target_type: ActiveContentType) {
        Self::remove_ac_recursive(&mut ast.root, &target_type);
    }

    /// Recursive tree walker for ActiveContent removal.
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

    /// Recursive tree walker for Unknown node removal.
    fn remove_unknown_nodes_recursive(node: &mut AstNode) {
        match node {
            AstNode::Document { children }
            | AstNode::Page { children, .. }
            | AstNode::Container { children, .. } => {
                children.retain(|child| !matches!(child, AstNode::Unknown { .. }));
                for child in children.iter_mut() {
                    Self::remove_unknown_nodes_recursive(child);
                }
            }
            _ => {}
        }
    }
}

#[async_trait]
impl CdrStage for PdfSanitizeStage {
    /// Return the stage identifier string.
    fn name(&self) -> &str {
        "pdf_sanitize"
    }

    /// Process a PDF document through all sanitization sub-stages.
    ///
    /// Execution order:
    /// 1. Strip JavaScript (highest priority — immediate execution risk)
    /// 2. Strip OpenActions (auto-run prevention)
    /// 3. Strip embedded files (attachment removal)
    /// 4. Flatten form fields (interactive → static conversion)
    /// 5. Remove unknown elements (defense-in-depth)
    ///
    /// Non-PDF documents are passed through unchanged.
    ///
    /// # Arguments
    /// * `input` - Read-only reference to the input document AST.
    /// * `context` - Execution context (file identity, timing).
    ///
    /// # Errors
    /// Returns [`CdrError::StageError`] on critical processing failure.
    async fn process(
        &self,
        input: &DocumentAst,
        _context: &CdrContext,
    ) -> Result<DocumentAst, CdrError> {
        // Format guard: only process PDF documents
        if input.format != DocumentFormat::Pdf {
            return Ok(input.clone());
        }

        let mut ast = input.clone();
        let mut actions_taken = Vec::new();
        let mut total_items: u32 = 0;

        // Execute sanitization sub-stages in priority order
        let js_count = self.strip_javascript(&mut ast);
        total_items += js_count;
        if js_count > 0 {
            actions_taken.push((
                "/javascript/*".to_string(),
                SanitizeAction::Removed,
            ));
        }

        let oa_count = self.strip_open_actions(&mut ast);
        total_items += oa_count;
        if oa_count > 0 {
            actions_taken.push((
                "/open_actions/*".to_string(),
                SanitizeAction::Removed,
            ));
        }

        let ef_count = self.strip_embedded_files(&mut ast);
        total_items += ef_count;
        if ef_count > 0 {
            actions_taken.push((
                "/embedded_files/*".to_string(),
                SanitizeAction::Extracted,
            ));
        }

        let ff_count = self.flatten_form_fields(&mut ast);
        total_items += ff_count;
        if ff_count > 0 {
            actions_taken.push((
                "/form_fields/*".to_string(),
                SanitizeAction::Flattened,
            ));
        }

        let uk_count = self.remove_unknown_elements(&mut ast);
        total_items += uk_count;
        if uk_count > 0 {
            actions_taken.push((
                "/unknown/*".to_string(),
                SanitizeAction::Removed,
            ));
        }

        // Build sanitization report (stored implicitly via action_taken markers)
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

    /// Create a minimal PDF DocumentAst for testing.
    fn make_test_pdf_ast() -> DocumentAst {
        DocumentAst::new(
            DocumentFormat::Pdf,
            DocumentMetadata::new("test.pdf", 1024, DocumentFormat::Pdf),
        )
    }

    /// Add an ActiveContent entry to the AST's active_contents vector.
    fn add_active_content(
        ast: &mut DocumentAst,
        content_type: ActiveContentType,
        path: &str,
        severity: ThreatSeverity,
    ) {
        ast.active_contents.push(ActiveContentRef::new(
            content_type,
            ContentLocation::new(path),
            severity,
        ));
    }

    /// Add an AstNode::ActiveContent to the tree root.
    fn add_active_content_node(
        ast: &mut DocumentAst,
        content_type: ActiveContentType,
        path: &str,
        severity: ThreatSeverity,
    ) {
        let ref_item = ActiveContentRef::new(
            content_type,
            ContentLocation::new(path),
            severity,
        );
        let node = AstNode::ActiveContent {
            ref_item,
            raw_data: None,
        };
        if let AstNode::Document { children } = &mut ast.root {
            children.push(node);
        }
    }

    // -----------------------------------------------------------------
    // Construction Tests
    // -----------------------------------------------------------------

    #[test]
    fn pdf_stage_new_with_config() {
        let config = PdfConfig::default();
        let stage = PdfSanitizeStage::new(config);
        assert!(stage.config.strip_javascript);
        assert_eq!(stage.name(), "pdf_sanitize");
    }

    #[test]
    fn pdf_stage_with_defaults_enables_all_sanitization() {
        let stage = PdfSanitizeStage::with_defaults();
        assert!(stage.config.strip_javascript);
        assert!(stage.config.strip_open_actions);
        assert!(stage.config.flatten_xfa_forms);
        assert!(stage.config.strip_embedded_files);
    }

    // -----------------------------------------------------------------
    // JavaScript Stripping Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn strip_javascript_removes_js_entries() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::JavaScript,
            "/document/js[0]",
            ThreatSeverity::Critical,
        );
        add_active_content(
            &mut ast,
            ActiveContentType::JavaScript,
            "/document/js[1]",
            ThreatSeverity::High,
        );

        let stage = PdfSanitizeStage::with_defaults();
        let count = stage.strip_javascript(&mut ast);

        assert_eq!(count, 2);
        assert_eq!(ast.active_content_count(), 0);
    }

    #[tokio::test]
    async fn strip_javascript_respects_config_disabled() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::JavaScript,
            "/js",
            ThreatSeverity::Critical,
        );

        let config = PdfConfig {
            strip_javascript: false,
            ..PdfConfig::default()
        };
        let stage = PdfSanitizeStage::new(config);
        let count = stage.strip_javascript(&mut ast);

        assert_eq!(count, 0);
        assert_eq!(ast.active_content_count(), 1);
    }

    #[tokio::test]
    async fn strip_javascript_only_targets_js_type() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::JavaScript,
            "/js",
            ThreatSeverity::Critical,
        );
        add_active_content(
            &mut ast,
            ActiveContentType::VBMacro,
            "/vba",
            ThreatSeverity::High,
        );

        let stage = PdfSanitizeStage::with_defaults();
        stage.strip_javascript(&mut ast);

        assert_eq!(ast.active_content_count(), 1);
        assert_eq!(
            ast.active_contents[0].content_type,
            ActiveContentType::VBMacro
        );
    }

    // -----------------------------------------------------------------
    // OpenAction Stripping Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn strip_open_actions_removes_auto_run() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::ActionForm,
            "/document/open_action",
            ThreatSeverity::Critical,
        );

        let stage = PdfSanitizeStage::with_defaults();
        let count = stage.strip_open_actions(&mut ast);

        assert_eq!(count, 1);
        assert!(!ast.active_contents.iter().any(|ac| {
            ac.content_type == ActiveContentType::ActionForm
        }));
    }

    #[tokio::test]
    async fn strip_open_actions_handles_custom_open_action() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::Custom("open_action".into()),
            "/open_action",
            ThreatSeverity::Critical,
        );

        let stage = PdfSanitizeStage::with_defaults();
        let count = stage.strip_open_actions(&mut ast);

        assert_eq!(count, 1);
    }

    // -----------------------------------------------------------------
    // Embedded File Stripping Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn strip_embedded_files_removes_attachments() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/embedded/file[0]",
            ThreatSeverity::High,
        );
        add_active_content(
            &mut ast,
            ActiveContentType::Custom("embedded_file".into()),
            "/embedded/file[1]",
            ThreatSeverity::Medium,
        );

        let stage = PdfSanitizeStage::with_defaults();
        let count = stage.strip_embedded_files(&mut ast);

        assert_eq!(count, 2);
        assert_eq!(ast.active_content_count(), 0);
    }

    // -----------------------------------------------------------------
    // Form Field Flattening Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn flatten_form_fields_marks_as_flattened() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::DynamicXfaForm,
            "/forms/xfa",
            ThreatSeverity::Medium,
        );
        add_active_content(
            &mut ast,
            ActiveContentType::ActionForm,
            "/forms/acro",
            ThreatSeverity::Low,
        );

        let stage = PdfSanitizeStage::with_defaults();
        let count = stage.flatten_form_fields(&mut ast);

        assert_eq!(count, 2);
        // Forms should be marked but still present (flattened, not removed)
        assert_eq!(ast.active_content_count(), 2);
        for ac in &ast.active_contents {
            assert_eq!(ac.action_taken, Some(SanitizeAction::Flattened));
        }
    }

    // -----------------------------------------------------------------
    // Unknown Element Removal Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn remove_unknown_elements_clears_unknown_nodes() {
        let mut ast = make_test_pdf_ast();
        // Manually inject an Unknown node into the tree
        if let AstNode::Document { children } = &mut ast.root {
            children.push(AstNode::Unknown {
                tag: "SuspiciousElement".into(),
            });
            children.push(AstNode::Text {
                content: "safe text".into(),
            });
        }

        let stage = PdfSanitizeStage::with_defaults();
        let count = stage.remove_unknown_elements(&mut ast);

        assert_eq!(count, 1);
        // Safe text should remain
        if let AstNode::Document { children } = &ast.root {
            assert_eq!(children.len(), 1);
            assert!(matches!(&children[0], AstNode::Text { .. }));
        }
    }

    // -----------------------------------------------------------------
    // Combined Pipeline Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn process_combined_sanitizes_all_threats() {
        let mut ast = make_test_pdf_ast();
        add_active_content_node(
            &mut ast,
            ActiveContentType::JavaScript,
            "/js[0]",
            ThreatSeverity::Critical,
        );
        add_active_content_node(
            &mut ast,
            ActiveContentType::ActionForm,
            "/open_action",
            ThreatSeverity::Critical,
        );
        add_active_content_node(
            &mut ast,
            ActiveContentType::OLEEmbeddedObject,
            "/embed",
            ThreatSeverity::High,
        );
        add_active_content(
            &mut ast,
            ActiveContentType::DynamicXfaForm,
            "/xfa",
            ThreatSeverity::Medium,
        );

        let stage = PdfSanitizeStage::with_defaults();
        let context = CdrContext::new("file-001", "user-001");
        let result = stage.process(&ast, &context).await.unwrap();

        // JS, OpenAction, OLE should be removed; XFA should be flattened
        assert!(result.active_content_count() <= 1); // Only flattened forms may remain
    }

    // -----------------------------------------------------------------
    // Empty Document Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn process_empty_document_returns_unchanged() {
        let ast = make_test_pdf_ast();
        let stage = PdfSanitizeStage::with_defaults();
        let context = CdrContext::new("file-002", "user-001");
        let result = stage.process(&ast, &context).await.unwrap();

        assert_eq!(result.active_content_count(), 0);
        assert_eq!(ast.format, result.format);
    }

    // -----------------------------------------------------------------
    // No Active Content Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn process_document_with_no_active_content() {
        let mut ast = make_test_pdf_ast();
        // Add some safe nodes
        if let AstNode::Document { children } = &mut ast.root {
            children.push(AstNode::Text {
                content: "Hello World".into(),
            });
            children.push(AstNode::Image {
                width: 100,
                height: 200,
                format: "png".into(),
            });
        }

        let stage = PdfSanitizeStage::with_defaults();
        let context = CdrContext::new("file-003", "user-003");
        let result = stage.process(&ast, &context).await.unwrap();

        assert_eq!(result.active_content_count(), 0);
    }

    // -----------------------------------------------------------------
    // Severity Tracking Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn severity_tracking_after_sanitization() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::JavaScript,
            "/js",
            ThreatSeverity::Critical,
        );
        add_active_content(
            &mut ast,
            ActiveContentType::EmbeddedFont,
            "/font",
            ThreatSeverity::Low,
        );

        let stage = PdfSanitizeStage::with_defaults();
        stage.strip_javascript(&mut ast);

        // After JS removal, only font remains (Low severity)
        assert_eq!(ast.max_severity(), Some(ThreatSeverity::Low));
    }

    // -----------------------------------------------------------------
    // Policy Respect Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn policy_pass_mode_skips_sanitization() {
        let mut ast = make_test_pdf_ast();
        add_active_content(
            &mut ast,
            ActiveContentType::JavaScript,
            "/js",
            ThreatSeverity::Critical,
        );

        // Simulate pass policy: disable all stripping
        let config = PdfConfig {
            strip_javascript: false,
            strip_open_actions: false,
            flatten_xfa_forms: false,
            strip_embedded_files: false,
            ..PdfConfig::default()
        };
        let stage = PdfSanitizeStage::new(config);
        let context = CdrContext::new("file-004", "user-004");
        let result = stage.process(&ast, &context).await.unwrap();

        // Content should be preserved when policy says pass
        assert_eq!(result.active_content_count(), 1);
    }

    // -----------------------------------------------------------------
    // Format Check Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn process_only_handles_pdf_format() {
        let mut non_pdf_ast = DocumentAst::new(
            DocumentFormat::Docx,
            DocumentMetadata::new("test.docx", 2048, DocumentFormat::Docx),
        );
        non_pdf_ast.active_contents.push(ActiveContentRef::new(
            ActiveContentType::VBMacro,
            ContentLocation::new("/vba"),
            ThreatSeverity::High,
        ));

        let stage = PdfSanitizeStage::with_defaults();
        let context = CdrContext::new("file-005", "user-005");
        let result = stage.process(&non_pdf_ast, &context).await.unwrap();

        // Non-PDF should be passed through unchanged
        assert_eq!(result.active_content_count(), 1);
        assert_eq!(result.format, DocumentFormat::Docx);
    }

    #[tokio::test]
    async fn process_png_passthrough() {
        let png_ast = DocumentAst::new(
            DocumentFormat::Png,
            DocumentMetadata::new("image.png", 512, DocumentFormat::Png),
        );

        let stage = PdfSanitizeStage::with_defaults();
        let context = CdrContext::new("file-006", "user-006");
        let result = stage.process(&png_ast, &context).await.unwrap();

        assert_eq!(result.format, DocumentFormat::Png);
        assert_eq!(result.active_content_count(), 0);
    }
}
