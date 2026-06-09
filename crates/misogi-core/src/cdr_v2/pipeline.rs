// =============================================================================
// CDR Engine v2 — Pipeline Architecture
// =============================================================================
// This module defines the processing pipeline that drives document sanitization.
// The pipeline is a staged architecture where each stage implements [`CdrStage`]
// and processes the DocumentAST sequentially or in parallel depending on config.
//
// Pipeline Lifecycle:
// 1. Parse: Raw bytes -> DocumentAst (format-specific parser, not in this module)
// 2. Stage execution: Each CdrStage mutates/transforms the AST
// 3. Policy decision: Final allow/block decision based on accumulated findings
// 4. Report generation: CdrReport for audit trail persistence
//
// Thread Safety:
// - CdrPipeline itself is NOT Send+Sync (holds Vec<Box<dyn CdrStage>>).
// - Individual stages MUST be Send+Sync (enforced by trait bound).
// - Context is Clone + Send for sharing across async tasks.
// =============================================================================

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cdr_v2::ast::DocumentAst;
use crate::cdr_v2::types::{ActiveContentType, CdrError, SanitizeAction, ThreatSeverity};

/// Single processing stage within the CDR pipeline.
///
/// Each stage performs one well-defined transformation on the document AST.
/// Examples: macro stripping, JavaScript removal, form flattening, metadata
/// filtering, external link removal.
///
/// # Contract
/// Implementations MUST:
/// - Be idempotent: calling process() twice yields the same result.
/// - Never panic: return CdrError::StageError instead.
/// - Not modify input: return a new/modified DocumentAst (input is & reference).
#[async_trait]
pub trait CdrStage: Send + Sync {
    /// Return the human-readable name of this stage.
    ///
    /// Used for logging, stage ordering verification, and report attribution.
    /// Must be unique within a pipeline instance.
    fn name(&self) -> &str;

    /// Process the document through this stage and return the transformed AST.
    ///
    /// # Arguments
    /// * `input` - The current state of the document AST (read-only reference).
    /// * `context` - Execution context carrying file identity and metadata.
    ///
    /// # Errors
    /// Returns [`CdrError::StageError`] if processing fails for any reason.
    /// The stage name is automatically captured by the pipeline wrapper.
    async fn process(
        &self,
        input: &DocumentAst,
        context: &CdrContext,
    ) -> Result<DocumentAst, CdrError>;
}

/// Security policy governing CDR behavior for a single processing run.
///
/// This structure is instantiated per-file transfer request and controls
/// which sanitization actions are applied and how violations are handled.
/// All fields have sensible defaults suitable for government/enterprise use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrPolicy {
    /// Default action when active content is detected.
    /// - "sanitize": Disarm and reconstruct (default, recommended).
    /// - "block": Reject the entire file transfer.
    /// - "pass": Allow without modification (dangerous, audit-only mode).
    #[serde(default = "default_action")]
    pub default_action: String,

    /// Behavior when a stage encounters an unrecoverable error.
    /// - "strict": Abort the entire pipeline (default, secure).
    /// - "lenient": Skip the failing stage and continue.
    #[serde(default = "fail_mode")]
    pub fail_mode: String,

    /// Whether to strip JavaScript from documents (PDF actions, SVG scripts).
    #[serde(default = "default_true")]
    pub strip_javascript: bool,

    /// Whether to strip PDF Open Actions (auto-execute on open).
    #[serde(default = "default_true")]
    pub strip_open_actions: bool,

    /// Whether to extract and quarantine embedded files (attachments).
    #[serde(default = "default_true")]
    pub strip_embedded_files: bool,

    /// Whether to flatten interactive forms into static content.
    #[serde(default = "default_true")]
    pub flatten_forms: bool,

    /// Whether to remove hyperlinks pointing to external (non-whitelisted) URLs.
    #[serde(default = "default_false")]
    pub remove_external_links: bool,

    /// Metadata field names to preserve during sanitization.
    /// All other metadata fields are removed unless whitelisted here.
    #[serde(default = "default_preserve_metadata")]
    pub preserve_metadata_fields: Vec<String>,

    /// Action for unknown/unrecognized document elements.
    /// - "remove": Delete unknown elements (default, secure).
    /// - "keep": Preserve unknown elements unchanged.
    /// - "log": Preserve and log a warning.
    #[serde(default = "unknown_element_action")]
    pub unknown_element_action: String,
}

impl Default for CdrPolicy {
    fn default() -> Self {
        Self {
            default_action: default_action(),
            fail_mode: fail_mode(),
            strip_javascript: true,
            strip_open_actions: true,
            strip_embedded_files: true,
            flatten_forms: true,
            remove_external_links: false,
            preserve_metadata_fields: default_preserve_metadata(),
            unknown_element_action: unknown_element_action(),
        }
    }
}

// -- Serde defaults --

fn default_action() -> String {
    "sanitize".into()
}

fn fail_mode() -> String {
    "strict".into()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_preserve_metadata() -> Vec<String> {
    vec!["title".into(), "author".into()]
}

fn unknown_element_action() -> String {
    "remove".into()
}

impl CdrPolicy {
    /// Check whether the given action string is a valid default action.
    #[must_use]
    pub fn is_valid_default_action(action: &str) -> bool {
        matches!(action, "sanitize" | "block" | "pass")
    }

    /// Check whether the policy's default action is valid.
    pub fn validate(&self) -> Result<(), String> {
        if !Self::is_valid_default_action(&self.default_action) {
            return Err(format!(
                "invalid default_action '{}': must be sanitize|block|pass",
                self.default_action
            ));
        }
        if !matches!(self.fail_mode.as_str(), "strict" | "lenient") {
            return Err(format!(
                "invalid fail_mode '{}': must be strict|lenient",
                self.fail_mode
            ));
        }
        if !matches!(
            self.unknown_element_action.as_str(),
            "remove" | "keep" | "log"
        ) {
            return Err(format!(
                "invalid unknown_element_action '{}': must be remove|keep|log",
                self.unknown_element_action
            ));
        }
        Ok(())
    }

    /// Determine whether the policy requires blocking based on severity.
    ///
    /// In strict mode, Critical and High severities trigger block decisions.
    #[must_use]
    pub fn should_block_for_severity(&self, severity: ThreatSeverity) -> bool {
        matches!(severity, ThreatSeverity::Critical | ThreatSeverity::High)
            && self.default_action == "block"
    }
}

/// Execution context passed to every pipeline stage.
///
/// Carries identity, timing, and arbitrary key-value metadata enabling
/// stages to make context-aware decisions (e.g., stricter handling for
/// files from untrusted sources).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrContext {
    /// Unique identifier for this file processing session (UUID v4).
    pub file_id: String,

    /// ID of the user who initiated the transfer.
    pub user_id: String,

    /// Timestamp when processing began (UTC, ISO8601 via serde).
    pub timestamp: DateTime<Utc>,

    /// Arbitrary key-value metadata for stage-specific context.
    pub metadata: HashMap<String, String>,
}

impl CdrContext {
    /// Create a new execution context.
    ///
    /// # Arguments
    /// * `file_id` - Unique file identifier.
    /// * `user_id` - Initiating user identifier.
    #[must_use]
    pub fn new(file_id: impl Into<String>, user_id: impl Into<String>) -> Self {
        Self {
            file_id: file_id.into(),
            user_id: user_id.into(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Insert a key-value pair into the metadata map.
    ///
    /// Returns `&mut self` for method chaining.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Ordered processing pipeline for CDR document sanitization.
///
/// Stages are executed in insertion order. Each stage receives the output
/// of the previous stage. The pipeline accumulates reports from each stage
/// into a final [`CdrReport`].
pub struct CdrPipeline {
    /// Ordered list of processing stages.
    stages: Vec<Box<dyn CdrStage>>,

    /// Security policy controlling behavior.
    policy: CdrPolicy,
}

impl CdrPipeline {
    /// Create a new pipeline with the given security policy.
    ///
    /// The pipeline starts empty; stages must be added via [`add_stage()`](Self::add_stage).
    ///
    /// # Arguments
    /// * `policy` - Security policy configuration.
    #[must_use]
    pub fn new(policy: CdrPolicy) -> Self {
        Self {
            stages: Vec::new(),
            policy,
        }
    }

    /// Append a processing stage to the end of the pipeline.
    ///
    /// Stages execute in FIFO order. Duplicate stage names are allowed
    /// but discouraged (may confuse report attribution).
    ///
    /// # Arguments
    /// * `stage` - Boxed stage implementing [`CdrStage`].
    pub fn add_stage(&mut self, stage: Box<dyn CdrStage>) {
        self.stages.push(stage);
    }

    /// Return the number of registered stages.
    #[must_use]
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Process a document through all pipeline stages.
    ///
    /// Executes each stage sequentially, passing the output of stage N
    /// as input to stage N+1. Accumulates per-stage reports into the
    /// final [`CdrReport`].
    ///
    /// # Arguments
    /// * `ast` - Mutable reference to the document AST (will be updated in-place).
    /// * `context` - Execution context for this processing run.
    ///
    /// # Returns
    /// A complete [`CdrReport`] documenting all actions taken.
    ///
    /// # Errors
    /// Returns [`CdrError::StageError`] if any stage fails and the policy
    /// is in strict mode. In lenient mode, failed stages are skipped.
    pub async fn process_document(
        &self,
        ast: &mut DocumentAst,
        context: &CdrContext,
    ) -> Result<CdrReport, CdrError> {
        let mut current_ast = ast.clone();
        let mut stage_reports = Vec::new();
        let mut total_actions: u32 = 0;
        let success = true;

        for stage in &self.stages {
            match stage.process(&current_ast, context).await {
                Ok(processed_ast) => {
                    // Build a basic stage report from the processed AST diff
                    let items_processed = processed_ast.active_content_count() as u32;
                    let actions_taken: Vec<(String, SanitizeAction)> = processed_ast
                        .active_contents
                        .iter()
                        .filter_map(|ac| {
                            ac.action_taken
                                .as_ref()
                                .map(|a| (ac.location.path.clone(), a.clone()))
                        })
                        .collect();

                    total_actions += actions_taken.len() as u32;

                    stage_reports.push(SanitizationReport {
                        stage_name: stage.name().to_string(),
                        items_processed,
                        actions_taken,
                        warnings: Vec::new(),
                    });

                    current_ast = processed_ast;
                }
                Err(e) => {
                    if self.policy.fail_mode == "strict" {
                        return Err(CdrError::StageError {
                            stage: stage.name().to_string(),
                            detail: e.to_string(),
                        });
                    }
                    // Lenient mode: log warning and continue
                    stage_reports.push(SanitizationReport {
                        stage_name: stage.name().to_string(),
                        items_processed: 0,
                        actions_taken: Vec::new(),
                        warnings: vec![format!("stage skipped due to error: {e}")],
                    });
                }
            }
        }

        // Update the caller's AST with final result
        *ast = current_ast;

        Ok(CdrReport {
            success,
            stages_executed: stage_reports,
            total_active_contents_found: ast.active_content_count() as u32,
            total_actions_taken: total_actions,
            output_hash: None,
        })
    }

    /// Apply policy decision logic to determine the final disposition.
    ///
    /// Evaluates the post-processing AST against the security policy to
    /// produce a [`StrategyDecision`] indicating sanitize/skip/block/delegate.
    ///
    /// # Arguments
    /// * `ast` - The fully-processed document AST.
    ///
    /// # Returns
    /// A [`StrategyDecision`] guiding downstream behavior.
    #[must_use]
    pub fn apply_policy_decision(&self, ast: &DocumentAst) -> StrategyDecision {
        let max_sev = match ast.max_severity() {
            Some(s) => s,
            None => return StrategyDecision::Skip("no active content found".into()),
        };

        // Block decision for critical/high severity in strict policy mode
        if self.policy.should_block_for_severity(max_sev) {
            return StrategyDecision::Block(format!(
                "threat severity {} exceeds policy threshold",
                max_sev
            ));
        }

        // Delegate specific content types to specialist handlers
        if !ast
            .find_active_contents(Some(ActiveContentType::VBMacro))
            .is_empty()
        {
            return StrategyDecision::Delegate("macro_sanitizer".into());
        }

        // Default: sanitize with removal action
        StrategyDecision::Sanitize(SanitizeAction::Removed)
    }
}

/// Per-stage sanitization report documenting what the stage did.
///
/// One instance is produced per executed stage and aggregated into
/// the top-level [`CdrReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationReport {
    /// Name of the stage that produced this report.
    pub stage_name: String,

    /// Number of items (nodes, elements) examined by this stage.
    pub items_processed: u32,

    /// Pairs of (location_path, action) for each item modified.
    pub actions_taken: Vec<(String, SanitizeAction)>,

    /// Non-fatal warnings raised during stage execution.
    pub warnings: Vec<String>,
}

/// Complete CDR processing report for a single document.
///
/// This is the primary audit artifact produced by the pipeline. It is
/// serialized to JSON and appended to the immutable audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrReport {
    /// Whether the pipeline completed without fatal errors.
    pub success: bool,

    /// Per-stage reports in execution order.
    pub stages_executed: Vec<SanitizationReport>,

    /// Total number of active content entries found across all stages.
    pub total_active_contents_found: u32,

    /// Total number of sanitization actions performed.
    pub total_actions_taken: u32,

    /// SHA-256 hash of the sanitized output file (None if not computed).
    pub output_hash: Option<String>,
}

/// Final strategy decision emitted after policy evaluation.
///
/// This is the CDR v2 namespaced version, distinct from
/// `crate::traits::StrategyDecision`. Used internally by the v2 pipeline
/// to avoid coupling to V1 trait definitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StrategyDecision {
    /// Proceed with sanitization using the specified action.
    Sanitize(SanitizeAction),

    /// Skip sanitization — document is clean or below threshold.
    Skip(String),

    /// Block the document entirely — reason provided for audit log.
    Block(String),

    /// Delegate to a named specialist handler (e.g., macro sanitizer).
    Delegate(String),
}

impl std::fmt::Display for StrategyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sanitize(action) => write!(f, "sanitize({action})"),
            Self::Skip(reason) => write!(f, "skip({reason})"),
            Self::Block(reason) => write!(f, "block({reason})"),
            Self::Delegate(target) => write!(f, "delegate({target})"),
        }
    }
}

// Unit tests extracted to pipeline_tests.rs (line count limit)
#[cfg(test)]
mod pipeline_tests;
