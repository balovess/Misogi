//! RS256 JSON Web Token (JWT) Authentication Module — Modular Architecture
//!
//! Provides asymmetric (RSA) signed JWT issuance and validation for enterprise-grade
//! authentication. This module is split into three components:
//!
//! - **[`JwtIssuer`]**(issuer::JwtIssuer): Token issuance (signing) logic
//! - **[`JwtValidator`]**(validator::JwtValidator): Token validation (verification) logic
//! - **[`JwtAuthenticator`]**(authenticator::JwtAuthenticator): Backward-compatible wrapper
//!
//! Uses [`jsonwebtoken`] crate for encoding/decoding and [`rsa`]/[`ring`] for
//! RSA keypair generation and loading.
//!
//! # Feature Gate
//!
//! This module is only available when the `jwt` or `enterprise` feature is enabled.
//!
//! # Security Model
//!
//! - **Signing Algorithm**: RS256 (RSA Signature with SHA-256)
//! - **Key Material**: RSA-2048 minimum, loaded from PEM files on disk
//! - **Token Claims**: Uses [`MisogiClaims`](super::claims::MisogiClaims) as the canonical claims structure
//! - **Key Rotation**: Operator must rotate keys externally; this module loads from configured path
//!
//! # Architecture
//!
//! ```
//! ┌─────────────────────┐     issues      ┌──────────────────┐
//! │   JwtIssuer         │ ──────────────>  │  JWS Compact     │
//! │   (private key)     │                  │  Token String    │
//! └─────────────────────┘                  └────────┬─────────┘
//!                                                   │
//!                                                   │ validates
//!                                                   v
//! ┌─────────────────────┐     delegates to  ┌──────────────────┐
//! │  JwtAuthenticator   │ ──────────────>  │  JwtValidator    │
//! │  (backward-compat)  │                  │  (public key)    │
//! └─────────────────────┘                  └──────────────────┘
//! ```
//!
//! # Typical Usage (New API)
//!
//! ```ignore
//! use misogi_auth::jwt::{JwtIssuer, JwtValidator, JwtConfig};
//! use misogi_auth::claims::MisogiClaims;
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! let config = JwtConfig {
//!     issuer: "misogi-auth".to_string(),
//!     audience: "misogi-api".to_string(),
//!     rsa_pem_path: "/etc/misogi/jwt/private.pem".into(),
//!     rsa_pub_pem_path: "/etc/misogi/jwt/public.pem".into(),
//!     ttl_hours: 8,
//!     refresh_ttl_hours: 168,
//! };
//!
//! // Issuer: create tokens
//! let issuer = JwtIssuer::new(config.clone())?;
//! let claims = MisogiClaims::new("user-001".to_string(), now, now + 28800);
//! let token = issuer.issue(&claims)?;
//!
//! // Validator: verify tokens
//! let validator = JwtValidator::new(config)?;
//! let validated = validator.validate(&token)?;
//! ```
//!
//! # Typical Usage (Legacy API)
//!
//! ```ignore
//! use misogi_auth::jwt::{JwtAuthenticator, JwtConfig};
//! use misogi_auth::models::User;
//!
//! let auth = JwtAuthenticator::new(config)?;
//! let token = auth.issue_token(&user)?;
//! let claims = auth.validate_token(&token.jws)?;
//! ```

// --- Sub-modules ---
pub mod authenticator;
pub mod issuer;
pub mod validator;

// --- Re-exports for backward compatibility ---
pub use authenticator::JwtAuthenticator;
pub use issuer::JwtIssuer;
pub use validator::{JwtValidator, ValidatedToken};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

use std::path::PathBuf;

/// Configuration parameters for the JWT authentication subsystem.
///
/// All file paths are absolute paths to PEM-encoded RSA key material.
/// The private key is used for token issuance; the public key for validation.
///
/// # Example
///
/// ```ignore
/// JwtConfig {
///     issuer: "misogi-gov-jp".to_string(),
///     audience: "lgwan-file-transfer".to_string(),
///     rsa_pem_path: "./keys/private.pem".into(),
///     rsa_pub_pem_path: "./keys/public.pem".into(),
///     ttl_hours: 8,
///     refresh_ttl_hours: 168, // 7 days
/// }
/// ```
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Issuer (`iss`) claim value. Typically the service name or domain.
    pub issuer: String,

    /// Audience (`aud`) claim value. Typically the API identifier.
    pub audience: String,

    /// Filesystem path to the PEM-encoded RSA private key (PKCS#8 or PKCS#1).
    pub rsa_pem_path: PathBuf,

    /// Filesystem path to the PEM-encoded RSA public key.
    pub rsa_pub_pem_path: PathBuf,

    /// Access token time-to-live in hours.
    pub ttl_hours: i64,

    /// Refresh token time-to-live in hours (typically longer than `ttl_hours`).
    pub refresh_ttl_hours: i64,
}

// ---------------------------------------------------------------------------
// Public Output Types (Legacy Compatibility)
// ---------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An issued JWT token pair containing the access token and optional refresh token.
///
/// # Fields
///
/// - `jws`: The JWS Compact Serialization string (Bearer token value)
/// - `refresh_token`: Opaque refresh token string (if refresh tokens are enabled)
/// - `expires_at`: UTC datetime when the access token expires
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    /// JWS Compact Serialization — the actual bearer token string.
    pub jws: String,

    /// Refresh token for obtaining new access tokens without re-authentication.
    /// `None` if refresh tokens are disabled in configuration.
    pub refresh_token: Option<String>,

    /// UTC expiration timestamp of the access token.
    pub expires_at: DateTime<Utc>,
}

/// Validated claims extracted from a verified JWT (legacy format).
///
/// Produced by [`JwtAuthenticator::validate_token`](authenticator::JwtAuthenticator::validate_token)
/// after successful signature verification and claim validation.
///
/// # Migration Note
///
/// New code should prefer [`ValidatedToken`](validator::ValidatedToken) which includes
/// additional metadata and uses [`MisogiClaims`](super::claims::MisogiClaims) internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedClaims {
    /// Subject — user identifier (e.g., employee number)
    pub sub: String,

    /// Display name of the authenticated user
    pub name: String,

    /// Role strings extracted from the `roles` claim
    pub roles: Vec<String>,

    /// Bound device identifier (HMAC-SHA256 of fingerprint signals).
    ///
    /// Present when authentication includes device fingerprint verification
    /// (ZT-7 device proofing). Used to bind the session to a specific device.
    #[serde(default)]
    pub device_id: String,

    /// Issued-at timestamp (UNIX seconds since epoch)
    pub iat: u64,

    /// Expiration timestamp (UNIX seconds since epoch)
    pub exp: u64,
}

impl ValidatedClaims {
    /// Check whether these claims have expired relative to the current system time.
    pub fn is_expired(&self) -> bool {
        unix_timestamp() > self.exp
    }

    /// Parse the first role into a [`UserRole`](super::role::UserRole), returning `None` on failure.
    pub fn primary_role(&self) -> Option<super::role::UserRole> {
        self.roles
            .first()
            .and_then(|r| serde_json::from_str(r).ok())
    }
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Comprehensive error type for JWT operations.
///
/// All variants are non-recoverable without external intervention (e.g.,
/// fixing key files, regenerating tokens).
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Failed to load or parse RSA key material from PEM file.
    #[error("key load failed: {0}")]
    KeyLoadFailed(String),

    /// Failed to generate a new RSA keypair.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// JWT encoding (signing) operation failed.
    #[error("token encoding failed: {0}")]
    EncodingFailed(String),

    /// JWT signature verification failed — token may have been tampered with.
    #[error("invalid signature")]
    InvalidSignature,

    /// Token's `exp` claim has elapsed.
    #[error("token expired")]
    TokenExpired,

    /// One or more registered claims failed validation (iss, aud, nbf, etc.).
    #[error("claim validation failed: {0}")]
    ClaimValidationFailed(String),

    /// Token is not valid JWS compact serialization format.
    #[error("malformed token: {0}")]
    MalformedToken(String),

    /// I/O error during file operations (read/write keys).
    #[error("I/O error: {0}")]
    IoError(String),
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

use std::time::{SystemTime, UNIX_EPOCH};

/// Return current UNIX timestamp in seconds.
pub(crate) fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a cryptographically secure random hex string of the specified byte length.
pub(crate) fn generate_random_token(byte_length: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; byte_length];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

/// Encode raw DER bytes into PEM format with the given label.
pub(crate) fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    const LINE_WIDTH: usize = 64;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(LINE_WIDTH) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
