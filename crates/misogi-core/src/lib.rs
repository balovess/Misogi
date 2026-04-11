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

#[cfg_attr(not(any(feature = "jp_contrib", feature = "intl_contrib")), allow(unexpected_cfgs))]
#[cfg(any(feature = "jp_contrib", feature = "intl_contrib"))]
pub mod contrib;
pub mod proto {
    tonic::include_proto!("misogi.file_transfer.v1");
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
};
pub use engine::*;
