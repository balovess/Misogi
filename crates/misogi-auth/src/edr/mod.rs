//! EDR (Endpoint Detection & Response) Integration Module
//!
//! Provides vendor-agnostic abstraction for querying device security posture
//! from enterprise EDR solutions:
//!
//! - **Microsoft Defender for Endpoint** via Graph Security API
//! - **CrowdStrike Falcon** via Falcon Zero Trust Assessment API
//!
//! # Architecture
//!
//! ```text
//! Misogi Auth Engine
//!       │
//!       ▼
//! ┌─────────────┐     ┌──────────────────────┐
//! │ EdrProvider  │◀────│ Defender ATP (Graph) │
//! │   (trait)    │◀────│ CrowdStrike Falcon   │
//! └──────────────┘     └──────────────────────┘
//! ```
//!
//! # Feature Flags
//!
//! - `defender` — Microsoft Defender for Endpoint integration
//! - `falcon` — CrowdStrike Falcon integration

pub mod defender;
pub mod falcon;
pub mod models;
pub mod traits;

pub use models::{
    EdrDevicePosture,
    EdrError,
    EdrRiskScore,
};
pub use traits::EdrProvider;
