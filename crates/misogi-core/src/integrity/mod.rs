//! Self-healing transport integrity module.
//!
//! Provides per-chunk integrity verification, checkpoint-based resume,
//! automatic repair, and chain-linked tamper detection for the Misogi
//! transport layer. This module is the foundation of the self-healing
//! transport system that ensures data integrity across unreliable networks.
//!
//! # Architecture
//!
//! The integrity module is organized into seven sub-modules:
//!
//! - [`envelope`] — Integrity envelope types with hash computation,
//!   builder pattern, and verification logic.
//! - [`session`] — Transport session lifecycle management including
//!   state machine, chunk confirmation tracking, and verification reports.
//! - [`transport`] — `HealingTransport` trait defining the async interface
//!   for self-healing transport implementations.
//! - [`config`] — Configuration types for repair, resume, and verification
//!   behavior tuning.
//! - [`verifier`] — Per-chunk hash verification engine (Task 6.17).
//! - [`session_manager`] — Session lifecycle manager with persistence (Task 6.16).
//! - [`repair`] — Async chunk repair engine with retry/parallel support (Task 6.18).
//!
//! # Security Model
//!
//! Each data chunk is wrapped in an [`IntegrityEnvelope`](envelope::IntegrityEnvelope)        
//! that contains:
//!
//! 1. **Data hash** — Cryptographic digest of the payload (SHA-256/SHA-512/BLAKE3).
//! 2. **Envelope hash** — Digest of the entire serialized envelope (tamper-proof seal).       
//! 3. **Sequence nonce** — Monotonically increasing counter preventing replay attacks.       
//! 4. **Previous chunk hash** — Chain-linking enabling detection of insertion/deletion.       
//!
//! # Thread Safety
//!
//! All session state is protected by `Arc<RwLock<T>>` using `parking_lot` for
//! high-performance concurrent access. The [`SessionHandle`](session::SessionHandle)
//! type is `Clone + Send + Sync` and safe for use across async tasks.

pub mod config;
pub mod envelope;
pub mod session;
pub mod transport;

// New runtime engine modules (Tasks 6.16-6.18).
pub mod repair;
pub mod session_manager;
pub mod verifier;

// Test modules (compiled only under cfg(test)).
#[cfg(test)]
mod config_tests;

// Re-export primary types at module level for ergonomic imports.
pub use config::{
    IntegrityConfig, IntegrityConfigError, RepairConfig, ResumeConfig, VerificationConfig,
};
pub use envelope::{
    HashAlgorithm, IntegrityAck, IntegrityEnvelope, IntegrityEnvelopeBuilder, IntegrityError,
};
pub use session::{
    RepairProgress, SessionHandle, SessionMetadata, TransportCapabilities, TransportState,
    VerificationReport,
};
pub use transport::HealingTransport;

// Re-export new engine types.
pub use repair::RepairEngine;
pub use session_manager::SessionManager;
pub use verifier::IntegrityVerifier;
