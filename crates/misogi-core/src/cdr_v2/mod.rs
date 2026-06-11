// =============================================================================
// CDR Engine v2 — Module Root
// =============================================================================
// Content Disarm & Reconstruction Engine v2: signature-less proactive threat
// elimination system for document sanitization.
//
// This module provides a complete, self-contained CDR pipeline architecture:
//
// Sub-modules:
// - types:      Core type definitions (DocumentFormat, ThreatSeverity, CdrError, etc.)
// - ast:        Abstract Syntax Tree representation for parsed documents
// - pipeline:   Stage-based processing pipeline with policy-driven decisions
// - config:     Deserializable configuration structures (TOML/JSON/YAML)
//
// Architecture Overview:
// 1. Raw document bytes are parsed into a DocumentAst (format-specific parser,
//    not included in this module 鈥?parsers are format-dependent).
// 2. The DocumentAst is passed through a CdrPipeline of CdrStage implementations.
// 3. Each stage inspects, modifies, and/or annotates the AST.
// 4. After all stages execute, apply_policy_decision() produces a StrategyDecision.
// 5. A CdrReport is generated for the immutable audit trail.
//
// Design Principles:
// - Zero-copy where possible; owned strings for serializability.
// - Every active content finding is explicitly represented in the AST.
// - Policy decisions are deterministic and auditable.
// - All errors propagate via typed CdrError enum with thiserror.
//
// Relationship to V1:
// The existing crate::traits::CDRStrategy / StrategyDecision / SanitizationReport
// types define the V1 interface used by the broader Misogi runtime. CDR v2
// defines its own namespaced equivalents internally to avoid coupling between
// versions. A future adapter layer will bridge v2 -> v1 for backward compat.
// =============================================================================

// -- Public sub-module declarations --

pub mod ast;
pub mod config;
pub mod pipeline;
pub mod stages;
pub mod types;

// -- Re-exports at module root for ergonomic access --

pub use ast::{AstHandle, AstNode, DocumentAst, DocumentMetadata};
pub use config::{
    ArchiveConfig, CdrV2Config, OfficeConfig, PdfConfig, WhitelistConfig, WhitelistEntry,
};
pub use pipeline::{
    CdrContext, CdrPipeline, CdrPolicy, CdrReport, CdrStage, SanitizationReport, StrategyDecision,
};
pub use stages::{ArchiveStage, OfficeLegacyStage, OfficeOpenXmlStage, PdfSanitizeStage};
pub use types::{
    ActiveContentRef, ActiveContentType, CdrError, ContentLocation, DocumentFormat, ExecutionMode,
    SanitizeAction, ThreatSeverity,
};
