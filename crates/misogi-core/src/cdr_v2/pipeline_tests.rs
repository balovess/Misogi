// =============================================================================
// CDR Engine v2 — Pipeline Unit Tests
// =============================================================================
// Tests for the pipeline architecture: CdrStage trait, CdrPolicy, CdrContext,
// CdrPipeline, SanitizationReport, CdrReport, and StrategyDecision.
// =============================================================================

use super::*;
use crate::cdr_v2::ast::{DocumentAst, DocumentMetadata};
use crate::cdr_v2::types::{
    ActiveContentRef, ActiveContentType, ContentLocation, DocumentFormat,
    ThreatSeverity,
};

// -----------------------------------------------------------------
// Dummy Stage Implementation for Testing
// -----------------------------------------------------------------

struct DummyStage {
    name_str: String,
    should_fail: bool,
}

impl DummyStage {
    fn new(name: &str, should_fail: bool) -> Self {
        Self {
            name_str: name.to_string(),
            should_fail,
        }
    }
}

#[async_trait]
impl CdrStage for DummyStage {
    fn name(&self) -> &str {
        &self.name_str
    }

    async fn process(
        &self,
        input: &DocumentAst,
        _context: &CdrContext,
    ) -> Result<DocumentAst, CdrError> {
        if self.should_fail {
            return Err(CdrError::ParseError("dummy failure".into()));
        }
        Ok(input.clone())
    }
}

// -----------------------------------------------------------------
// CdrPolicy Tests
// -----------------------------------------------------------------

#[test]
fn cdr_policy_default_values_are_secure() {
    let policy = CdrPolicy::default();
    assert_eq!(policy.default_action, "sanitize");
    assert_eq!(policy.fail_mode, "strict");
    assert!(policy.strip_javascript);
    assert!(policy.flatten_forms);
    assert!(!policy.remove_external_links);
    assert_eq!(policy.preserve_metadata_fields, vec!["title", "author"]);
}

#[test]
fn cdr_policy_validate_accepts_valid_config() {
    let policy = CdrPolicy::default();
    assert!(policy.validate().is_ok());
}

#[test]
fn cdr_policy_validate_rejects_invalid_action() {
    let mut policy = CdrPolicy::default();
    policy.default_action = "destroy".into();
    let result = policy.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid default_action"));
}

#[test]
fn cdr_policy_should_block_for_critical_in_block_mode() {
    let mut policy = CdrPolicy::default();
    policy.default_action = "block".into();
    assert!(policy.should_block_for_severity(ThreatSeverity::Critical));
    assert!(policy.should_block_for_severity(ThreatSeverity::High));
    assert!(!policy.should_block_for_severity(ThreatSeverity::Medium));
}

#[test]
fn cdr_policy_should_not_block_in_sanitize_mode() {
    let policy = CdrPolicy::default(); // default_action = "sanitize"
    assert!(!policy.should_block_for_severity(ThreatSeverity::Critical));
}

// -----------------------------------------------------------------
// CdrContext Tests
// -----------------------------------------------------------------

#[test]
fn cdr_context_new_creates_instance() {
    let ctx = CdrContext::new("file-123", "user-456");
    assert_eq!(ctx.file_id, "file-123");
    assert_eq!(ctx.user_id, "user-456");
    assert!(ctx.metadata.is_empty());
}

#[test]
fn cdr_context_with_metadata_chain() {
    let ctx = CdrContext::new("f1", "u1")
        .with_metadata("source_zone", "internet")
        .with_metadata("department", "engineering");

    assert_eq!(ctx.metadata.get("source_zone").unwrap(), "internet");
    assert_eq!(ctx.metadata.get("department").unwrap(), "engineering");
}

// -----------------------------------------------------------------
// CdrPipeline Tests
// -----------------------------------------------------------------

#[test]
fn cdr_pipeline_new_creates_empty_pipeline() {
    let pipeline = CdrPipeline::new(CdrPolicy::default());
    assert_eq!(pipeline.stage_count(), 0);
}

#[test]
fn cdr_pipeline_add_stage_increments_count() {
    let mut pipeline = CdrPipeline::new(CdrPolicy::default());
    pipeline.add_stage(Box::new(DummyStage::new("stage_a", false)));
    pipeline.add_stage(Box::new(DummyStage::new("stage_b", false)));
    assert_eq!(pipeline.stage_count(), 2);
}

#[tokio::test]
async fn cdr_pipeline_process_document_success() {
    let mut pipeline = CdrPipeline::new(CdrPolicy::default());
    pipeline.add_stage(Box::new(DummyStage::new("js_stripper", false)));

    let mut ast = DocumentAst::new(
        DocumentFormat::Pdf,
        DocumentMetadata::new("test.pdf", 1024, DocumentFormat::Pdf),
    );
    let ctx = CdrContext::new("fid", "uid");

    let report = pipeline.process_document(&mut ast, &ctx).await.unwrap();
    assert!(report.success);
    assert_eq!(report.stages_executed.len(), 1);
    assert_eq!(report.stages_executed[0].stage_name, "js_stripper");
}

#[tokio::test]
async fn cdr_pipeline_process_document_strict_failure() {
    let mut ast = DocumentAst::new(
        DocumentFormat::Pdf,
        DocumentMetadata::new("test.pdf", 1024, DocumentFormat::Pdf),
    );
    let ctx = CdrContext::new("fid", "uid");

    // Create a pipeline with a failing stage to test strict mode
    let mut strict_pipeline = CdrPipeline::new(CdrPolicy::default());
    strict_pipeline.add_stage(Box::new(DummyStage::new("failer", true)));

    let result = strict_pipeline.process_document(&mut ast, &ctx).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, CdrError::StageError { .. }));
}

// -----------------------------------------------------------------
// StrategyDecision Tests
// -----------------------------------------------------------------

#[test]
fn strategy_decision_display_all_variants() {
    assert_eq!(
        format!("{}", StrategyDecision::Sanitize(SanitizeAction::Removed)),
        "sanitize(removed)"
    );
    assert_eq!(
        format!("{}", StrategyDecision::Skip("clean".into())),
        "skip(clean)"
    );
    assert_eq!(
        format!("{}", StrategyDecision::Block("malicious".into())),
        "block(malicious)"
    );
    assert_eq!(
        format!("{}", StrategyDecision::Delegate("macro_handler".into())),
        "delegate(macro_handler)"
    );
}

// -----------------------------------------------------------------
// apply_policy_decision Tests
// -----------------------------------------------------------------

#[test]
fn apply_policy_skip_when_no_active_content() {
    let pipeline = CdrPipeline::new(CdrPolicy::default());
    let ast = DocumentAst::new(
        DocumentFormat::Png,
        DocumentMetadata::new("clean.png", 512, DocumentFormat::Png),
    );

    let decision = pipeline.apply_policy_decision(&ast);
    assert_eq!(decision, StrategyDecision::Skip("no active content found".into()));
}

#[test]
fn apply_policy_delegate_for_vba_macros() {
    let pipeline = CdrPipeline::new(CdrPolicy::default());

    let ast = DocumentAst {
        format: DocumentFormat::Docx,
        root: crate::cdr_v2::ast::AstNode::Document { children: vec![] },
        metadata: DocumentMetadata::new("macro.docx", 2048, DocumentFormat::Docx),
        active_contents: vec![ActiveContentRef::new(
            ActiveContentType::VBMacro,
            ContentLocation::new("/vba"),
            ThreatSeverity::High,
        )],
    };

    let decision = pipeline.apply_policy_decision(&ast);
    assert_eq!(decision, StrategyDecision::Delegate("macro_sanitizer".into()));
}

#[test]
fn apply_policy_block_critical_in_block_mode() {
    let mut policy = CdrPolicy::default();
    policy.default_action = "block".into();

    let pipeline = CdrPipeline::new(policy);

    let ast = DocumentAst {
        format: DocumentFormat::Pdf,
        root: crate::cdr_v2::ast::AstNode::Document { children: vec![] },
        metadata: DocumentMetadata::new("bad.pdf", 4096, DocumentFormat::Pdf),
        active_contents: vec![ActiveContentRef::new(
            ActiveContentType::JavaScript,
            ContentLocation::new("/js"),
            ThreatSeverity::Critical,
        )],
    };

    let decision = pipeline.apply_policy_decision(&ast);
    assert!(matches!(decision, StrategyDecision::Block(_)));
}
