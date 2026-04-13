//! Device Fingerprinting Module
//!
//! Provides lightweight device identification through browser/environment signals:
//!
//! - **User-Agent** parsing and hashing (stable signal)
//! - **Canvas hash** (browser-generated, privacy-safe)
//! - **Screen resolution** normalization
//!
//! # Architecture
//!
//! ```text
//! Client (Browser)                    Server (Misogi)
//! ┌──────────────┐                   ┌─────────────────┐
//! │ Collect FP   │ ──base64json──▶  │ Parse & Validate │
//! │ (UA+Canvas+  │ ◀──result──────  │ Compute Hash     │
//! │  Screen)     │                   │ Bind to JWT      │
//! └──────────────┘                   └─────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - All raw values are **HMAC-SHA256 hashed** before storage
//! - Fingerprint includes **entropy scoring** for reliability assessment
//! - Supports **fingerprint rotation** to prevent long-term tracking
//! - Compliant with GDPR Article 9 (special category data handling)
//!
//! # Feature Flag
//!
//! Requires `device` or `posture` feature flag in Cargo.toml.

pub mod collector;
pub mod fingerprint;
pub mod validator;

pub use fingerprint::{
    DeviceFingerprint,
    FingerprintSignal,
    ScreenResolution,
};
pub use validator::{
    FingerprintBindError,
    FingerprintValidator,
};
