pub mod error;
pub mod types;

// Core modules (always available)
pub mod abac;
pub mod approval;
pub mod fec;
pub mod hash;
pub mod integrity;
pub mod pii;
pub mod presets;
pub mod relay;

// Protocol module: contains framing utilities, some async functions gated internally
pub mod protocol;

// Traits module: core trait definitions are WASM-compatible; sub-modules that
// depend on tokio (jtd_*) are conditionally compiled within those files.
// Note: LogFormatter trait uses AuditLogEntry which requires runtime feature.
pub mod traits;

// Modules that use tokio::fs for async file I/O (require runtime feature)
#[cfg(feature = "runtime")]
pub mod audit_log;

#[cfg(feature = "runtime")]
pub mod cdr_strategies;

/// CDR Engine v2 — signature-less proactive threat elimination system.
///
/// Provides AST-based document analysis, staged pipeline processing,
/// policy-driven sanitization decisions, and comprehensive audit reporting.
/// This is the next-generation CDR architecture, independent of V1 traits.
#[cfg(feature = "runtime")]
pub mod cdr_v2;

#[cfg(feature = "runtime")]
pub mod file_types;

// Async-dependent modules (require tokio runtime)
#[cfg(feature = "runtime")]
pub mod tunnel;

#[cfg(feature = "runtime")]
pub mod drivers;

#[cfg(feature = "runtime")]
pub mod engine;

#[cfg(feature = "runtime")]
pub mod log_engine;

#[cfg(feature = "runtime")]
pub mod blast;

#[cfg(feature = "runtime")]
pub mod plugin_registry;

#[cfg(feature = "runtime")]
pub mod versioning;

#[cfg(feature = "runtime")]
pub mod scanners;

#[cfg(feature = "runtime")]
pub mod storage;

// gRPC protobuf definitions (require tonic build-time codegen)
#[cfg(feature = "runtime")]
pub mod proto {
    tonic::include_proto!("misogi.file_transfer.v1");
}

// V1 type re-export at crate root — required by V2's generated gRPC code
// which references cross-version messages via super::super::v1::* paths.
#[cfg(feature = "runtime")]
pub mod v1 {
    pub use crate::proto::*;
}

/// V2 protocol definitions — future extension point for AI-enhanced features.
///
/// When V2 reaches production readiness, this module will expose the full
/// V2 gRPC service contracts defined in `proto/v2/misogi.proto`.
#[cfg(feature = "runtime")]
pub mod proto_v2 {
    tonic::include_proto!("misogi.file_transfer.v2");
}

#[cfg(any(feature = "jp_contrib", feature = "intl_contrib"))]
pub mod contrib;

// ===========================================================================
// Re-exports
// ===========================================================================

pub use abac::*;
pub use error::{MisogiError, Result};
pub use protocol::*;
pub use types::*;

#[cfg(feature = "runtime")]
pub use tunnel::*;

#[cfg(feature = "runtime")]
pub use approval::*;

#[cfg(feature = "runtime")]
pub use audit_log::*;

#[cfg(feature = "runtime")]
pub use presets::*;

// Core traits (WASM-compatible: PIIAction, PIIDetector, etc.)
// JTD traits and storage traits require runtime feature
#[cfg(feature = "runtime")]
pub use traits::{
    ApprovalTrigger, CDRStrategy, CalendarProvider, ChunkAck, DetectedEncoding, DriverHealthStatus,
    EncodingHandler, FileDetectionResult, FileTypeDetector, Holiday, HolidayCategory,
    JtdConversionError, JtdConversionResult, JtdConverter, LogFormatter, SanitizationReport,
    SanitizeContext, StateMachine, StrategyDecision, TransferDriver, TransferDriverConfig,
};

// PII types always available (used by wasm_compat layer)
pub use traits::{PIIAction, PIIDetector, PIIMatch, PIIScanResult};

// PII Enhancement module re-exports (feature-gated)
#[cfg(feature = "pii-context")]
pub use pii::context::{
    ContextAnalysisRequest, ContextAnalysisResponse, ContextAnalyzer, ContextAnalyzerConfig,
    ContextError, ContextMetadata, ContextProvider, FallbackStrategy, KeywordEngineConfig,
    KeywordPosition, KeywordRule, KeywordRuleEngine, KeywordRuleSet, KeywordRuleSource,
    MockContextProvider, PiiTypeRules, RuleEngineBuilder,
};

#[cfg(feature = "pii-structured")]
pub use pii::structured::{
    ArrayHandling, CsvPiiScanner, CsvScannerConfig, FieldAction, FieldClassification,
    FieldClassifier, FieldClassifierBuilder, FieldClassifierConfig, FieldMapping, FieldScanResult,
    JsonPiiScanner, JsonScannerConfig, StructuredFormat, StructuredScanResult,
    StructuredScannerConfig, XmlPiiScanner, XmlScannerConfig,
};

#[cfg(feature = "pii-ocr")]
pub use pii::ocr::{
    MockOcrProvider, OcrBoundingBox, OcrDetectorConfig, OcrError, OcrExtractionResult,
    OcrImageMetadata, OcrPiiDetector, OcrPiiMatch, OcrPiiScanResult, OcrProvider, OcrTextBlock,
};

#[cfg(feature = "pii-secrecy")]
pub use pii::secrecy::{
    ClassificationRule, Condition, ControlRequirement, FallbackPolicy, RuleResult,
    SecrecyClassificationResult, SecrecyClassifier, SecrecyLevelDef, SecrecySchemeBuilder,
    SecrecySchemeConfig,
};
#[cfg(feature = "runtime")]
pub use traits::jtd_dummy::DummyAction;
#[cfg(feature = "runtime")]
pub use traits::jtd_pipeline::{
    JtdConversionPipeline, JtdConverterType, JtdFailurePolicy, JtdPipelineConfig, PipelineOutput,
    should_convert_jtd,
};

#[cfg(feature = "runtime")]
pub use traits::storage::{StorageBackend, StorageError, StorageInfo};

#[cfg(feature = "runtime")]
pub use storage::{LocalConfig, LocalStorage};

#[cfg(feature = "runtime")]
pub use engine::*;

#[cfg(feature = "runtime")]
pub use scanners::*;

#[cfg(feature = "runtime")]
pub use storage::*;
