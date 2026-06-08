// =============================================================================
// CDR Engine v2 — Sanitization Stages Module Root
// =============================================================================
// This module aggregates all format-specific sanitization stage implementations
// for the CDR v2 pipeline. Each stage implements the [`CdrStage`] trait and
// operates on [`DocumentAst`] by mutating active content nodes.
//
// Stage Inventory:
// - pdf_stage:      PdfSanitizeStage — JavaScript, OpenAction, forms, embedded files
// - office_stage:   OfficeOpenXmlStage + OfficeLegacyStage — VBA, OLE, external connections
// - archive_stage:  ArchiveStage — Recursive archive unpacking and nested processing
//
// Design Contract:
// All stages MUST:
// 1. Implement Send + Sync for async pipeline compatibility.
// 2. Be idempotent (calling process() twice yields identical results).
// 3. Never panic — return CdrError::StageError on all failure paths.
// 4. Operate on AST abstraction level (no binary format parsing).
// =============================================================================

pub mod archive_stage;
pub mod office_stage;
pub mod pdf_stage;

// -- Public re-exports for ergonomic access --

pub use archive_stage::ArchiveStage;
pub use office_stage::{OfficeLegacyStage, OfficeOpenXmlStage};
pub use pdf_stage::PdfSanitizeStage;
