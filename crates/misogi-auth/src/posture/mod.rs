//! Device Posture Assessment Module
//!
//! Evaluates client device security posture for conditional access decisions:
//!
//! - **OS version** compliance (Windows 10 22H2+, macOS 12+, etc.)
//! - **Patch level** verification (days since last security update)
//! - **Security software** status (antivirus, EDR, firewall)
//!
//! # Architecture
//!
//! ```text
//! Client Report          Misogi Posture Engine
//! ┌──────────────┐       ┌─────────────────────┐
//! │ OS/AV/Patch   │ ───▶ │ Parse & Validate     │
//! │ JSON payload  │ ◀─── │ Score vs Policy      │
//! └──────────────┘       │ Allow/Block/Warn     │
//!                        └─────────────────────┘
//! ```
//!
//! # Feature Flag
//!
//! Requires `posture` feature flag.

pub mod av_detector;
pub mod checker;
pub mod edr_bridge;
pub mod os_detector;
pub mod types;

pub use types::{
    CheckSeverity,
    DevicePosture,
    EncryptionStatus,
    FailureAction,
    OsPlatform,
    OsPosture,
    PatchStatus,
    PostureCheckResult,
    PosturePolicy,
    SecuritySoftwarePosture,
};
pub use checker::{PostureChecker, PostureEvaluationResult};
pub use edr_bridge::build_client_report_posture;
#[cfg(any(feature = "defender", feature = "falcon"))]
pub use edr_bridge::convert_edr_to_posture;
