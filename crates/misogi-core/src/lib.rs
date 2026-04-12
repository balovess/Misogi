pub mod error;
pub mod protocol;
pub mod types;
pub mod hash;
pub mod tunnel;
pub mod approval;
pub mod audit_log;
pub mod presets;
pub mod traits;
pub mod drivers;
pub mod cdr_strategies;
pub mod file_types;
pub mod pii;
pub mod engine;
pub mod log_engine;
pub mod fec;
pub mod blast;
pub mod plugin_registry;
pub mod versioning;
pub mod scanners;
pub mod storage;

#[cfg(any(feature = "jp_contrib", feature = "intl_contrib"))]
pub mod contrib;
pub mod proto {
    tonic::include_proto!("misogi.file_transfer.v1");
}

// V1 type re-export at crate root — required by V2's generated gRPC code
// which references cross-version messages via super::super::v1::* paths.
pub mod v1 {
    pub use crate::proto::*;
}

/// V2 protocol definitions — future extension point for AI-enhanced features.
///
/// When V2 reaches production readiness, this module will expose the full
/// V2 gRPC service contracts defined in `proto/v2/misogi.proto`.
pub mod proto_v2 {
    tonic::include_proto!("misogi.file_transfer.v2");
}

pub use error::{MisogiError, Result};
pub use types::*;
pub use protocol::*;
pub use tunnel::*;
pub use approval::*;
pub use audit_log::*;
pub use presets::*;
pub use traits::{
    StateMachine, TransferDriverConfig, ChunkAck, DriverHealthStatus,
    TransferDriver, StrategyDecision, SanitizeContext, SanitizationReport,
    CDRStrategy, FileDetectionResult, FileTypeDetector,
    PIIAction, PIIMatch, PIIScanResult, PIIDetector,
    LogFormatter, ApprovalTrigger, Holiday, HolidayCategory, CalendarProvider,
    DetectedEncoding, EncodingHandler,
    JtdConverter, JtdConversionResult, JtdConversionError,
};
pub use traits::jtd_pipeline::{
    JtdConversionPipeline, JtdFailurePolicy, JtdPipelineConfig, PipelineOutput,
    JtdConverterType, should_convert_jtd,
};
pub use traits::jtd_dummy::DummyAction;
pub use traits::storage::{StorageBackend, StorageInfo, StorageError};
pub use storage::{LocalConfig, LocalStorage};
pub use engine::*;
pub use scanners::*;
pub use storage::*;
