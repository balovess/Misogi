//! TCG TCM / TPM Extension Interface Module
//!
//! Provides hardware-backed trusted computing abstraction:
//!
//! - **TCM Provider trait**: Pluggable interface for TPM 2.0 / Chinese TCM
//! - **Mock implementation**: For testing without hardware
//! - **Configuration**: Provider selection and attestation settings
//!
//! # Architecture
//!
//! ```text
//! Misogi Auth Engine
//!       │
//!       ▼
//! ┌─────────────┐     ┌──────────────────┐
//! │ TcmProvider  │◀───│ Windows TPM 2.0   │
//! │   (trait)    │◀───│ Chinese TCM       │
//! │              │◀───│ Mock (testing)    │
//! └──────────────┘     └──────────────────┘
//! ```
//!
//! # Feature Flag
//!
//! Requires `tcm` feature flag.

pub mod config;
pub mod mock;
pub mod traits;

pub use config::{TcmConfig, TcmProviderType};
pub use mock::MockTcmProvider;
pub use traits::{
    PcrValue,
    QuoteAlgorithm,
    TcmError,
    TcmProvider,
    TcmQuote,
    TcmSealedData,
};
