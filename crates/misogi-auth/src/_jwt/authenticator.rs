//! Backward-Compatible JWT Authenticator — Composition Wrapper
//!
//! Provides the legacy [`JwtAuthenticator`] API by composing [`JwtIssuer`](super::issuer::JwtIssuer)
//! and [`JwtValidator`](super::validator::JwtValidator) internally. This ensures all existing
//! code using `JwtAuthenticator` continues to work without modification.
//!
//! # Migration Path
//!
//! New code should prefer using `JwtIssuer` and `JwtValidator` directly for:
//! - **Clearer separation of concerns** (issuance vs. validation)
/// - **Reduced attack surface** (issuer holds only private key, validator only public key)
/// - **Flexible deployment** (can deploy issuer and validator on separate hosts)
//!
//! # Compatibility Guarantee
//!
//! This struct maintains 100% API compatibility with the original implementation:
//! - All public methods have identical signatures
/// - All error variants are preserved
/// - All return types are unchanged
/// - Behavior is byte-for-byte identical (same tokens, same validation results)
//!
//! # Usage Example (Legacy API)
//!
//! ```ignore
//! use misogi_auth::jwt::{JwtAuthenticator, JwtConfig};
//! use misogi_auth::models::User;
//!
//! let auth = JwtAuthenticator::new(config)?;
//! let token = auth.issue_token(&user)?;
//! let claims = auth.validate_token(&token.jws)?;
//! ```

use chrono::{DateTime, Utc};
use tracing::{info, instrument};

use super::{generate_random_token, JwtConfig, JwtError, JwtToken, ValidatedClaims};
use super::issuer::JwtIssuer;
use super::validator::JwtValidator;
use crate::claims::MisogiClaims;
use crate::models::User;

// ---------------------------------------------------------------------------
// Authenticator Structure
// ---------------------------------------------------------------------------

/// RS256 JWT Authenticator — backward-compatible wrapper combining issuance and validation.
///
/// Thread-safe: can be wrapped in `Arc<>` and shared across async tasks.
///
/// # Architecture
///
/// This is a **composition wrapper** that delegates to:
/// - [`JwtIssuer`] for token signing operations
/// - [`JwtValidator`] for token verification operations
///
/// Both sub-components are initialized from the same configuration at construction
/// time, maintaining the same behavior as the original monolithic implementation.
///
/// # When to Use
///
/// Use this struct when:
/// - Migrating existing code incrementally
/// - You need both issuance and validation in the same component
/// - You want to minimize code changes during migration
///
/// # When to Avoid
///
/// Prefer direct usage of `JwtIssuer`/`JwtValidator` when:
/// - Building microservices with separated concerns
/// - Deploying on hosts with different key access requirements
/// - Minimizing memory footprint (only load needed keys)
///
/// # Initialization
///
/// Load both RSA keys (private + public) from configured PEM paths at construction.
/// If either file is missing or malformed, returns an error.
pub struct JwtAuthenticator {
    /// Internal issuer component (holds private key).
    issuer: JwtIssuer,

    /// Internal validator component (holds public key).
    validator: JwtValidator,
}

impl JwtAuthenticator {
    /// Create a new JWT authenticator by loading RSA keys from configured PEM paths.
    ///
    /// Initializes both internal components (`JwtIssuer` and `JwtValidator`)
    /// from the same configuration. Requires both private and public key files
    /// to be present and valid.
    ///
    /// # Arguments
    ///
    /// * `config` - JWT configuration with paths to both PEM files
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::KeyLoadFailed`] if either PEM file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let auth = JwtAuthenticator::new(config)?;
    /// ```
    #[instrument(skip(config), fields(issuer = %config.issuer))]
    pub fn new(config: JwtConfig) -> Result<Self, JwtError> {
        // Initialize both components from the same config
        let issuer = JwtIssuer::new(config.clone())?;
        let validator = JwtValidator::new(config.clone())?;

        info!(
            issuer = %config.issuer,
            ttl_hours = config.ttl_hours,
            "JwtAuthenticator initialized successfully (backward-compatible mode)"
        );

        Ok(Self { issuer, validator })
    }

    /// Issue a new RS256-signed JWT for the given user (legacy API).
    ///
    /// Converts the [`User`] into [`MisogiClaims`], delegates to the internal
    /// [`JwtIssuer`], and wraps the result in the legacy [`JwtToken`] format.
    ///
    /// The token includes standard claims (sub, name, roles, iat, exp, iss, aud)
    /// and is signed with the private key loaded at construction time.
    ///
    /// # Arguments
    ///
    /// * `user` - The user to issue a token for
    ///
    /// # Returns
    ///
    /// A [`JwtToken`] containing:
    /// - `jws`: JWS Compact Serialization string (bearer token)
    /// - `refresh_token`: Cryptographically random refresh token string
    /// - `expires_at`: UTC datetime when the access token expires
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::EncodingFailed`] if token encoding fails.
    ///
    /// # Backward Compatibility
    ///
    /// This method maintains identical behavior to the original implementation:
    /// - Same claim structure (legacy Claims format converted to MisogiClaims)
    /// - Same refresh token generation
    /// - Same return type
    #[instrument(skip(self, user), fields(user_id = %user.user_id))]
    pub fn issue_token(&self, user: &User) -> Result<JwtToken, JwtError> {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(self.issuer.config().ttl_hours);

        // Convert User to MisogiClaims (preserving legacy field mapping)
        let claims = self.user_to_claims(user);

        // Delegate to issuer
        let jws = self.issuer.issue(&claims)?;

        // Generate refresh token (legacy behavior)
        let refresh_token = Some(generate_random_token(64));

        debug!(user_id = %user.user_id, "JWT issued successfully (legacy API)");

        Ok(JwtToken {
            jws,
            refresh_token,
            expires_at,
        })
    }

    /// Validate a JWT string: verify signature AND check all registered claims (legacy API).
    ///
    /// Delegates to internal [`JwtValidator::validate_and_extract`], then converts
    /// the result to the legacy [`ValidatedClaims`] format.
    ///
    /// Validates:
    /// - Cryptographic signature against the public key
    /// - `iss` claim matches configured issuer
    /// - `aud` claim matches configured audience
    /// - `exp` claim has not passed
    /// - `nbf` claim (if present) has passed
    ///
    /// # Arguments
    ///
    /// * `token` - JWS Compact Serialization string to validate
    ///
    /// # Returns
    ///
    /// Legacy [`ValidatedClaims`] on successful validation.
    ///
    /// # Errors
    ///
    /// - [`JwtError::InvalidSignature`] — signature verification failed
    /// - [`JwtError::TokenExpired`] — the `exp` claim is in the past
    /// - [`JwtError::ClaimValidationFailed`] — iss/aud/nbf mismatch
    /// - [`JwtError::MalformedToken`] — token is not valid JWS format
    #[instrument(skip(self, token))]
    pub fn validate_token(&self, token: &str) -> Result<ValidatedClaims, JwtError> {
        let validated = self.validator.validate_and_extract(token)?;

        // Convert MisogiClaims back to legacy ValidatedClaims format
        Ok(ValidatedClaims {
            sub: validated.claims.applicant_id.clone(),
            name: validated.claims.display_name.unwrap_or_default(),
            roles: validated.claims.roles.clone(),
            device_id: String::new(),
            iat: validated.claims.iat,
            exp: validated.claims.exp,
        })
    }

    /// Validate a JWT string WITHOUT checking expiration (legacy API).
    ///
    /// Delegates to [`JwtValidator::validate_without_expiry_check`] and converts
    /// result to legacy [`ValidatedClaims`] format.
    ///
    /// Identical to [`validate_token`](Self::validate_token) but skips the `exp`
    /// claim check. Intended for use with refresh tokens that may have a different
    /// validity window than access tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - JWS Compact Serialization string to validate
    ///
    /// # Returns
    ///
    /// Legacy [`ValidatedClaims`] on successful validation (even if expired).
    ///
    /// # Errors
    ///
    /// Same as [`validate_token`](Self::validate_token), except [`JwtError::TokenExpired`]
    /// will never be returned.
    #[instrument(skip(self, token))]
    pub fn validate_token_no_expire(
        &self,
        token: &str,
    ) -> Result<ValidatedClaims, JwtError> {
        let validated = self.validator.validate_without_expiry_check(token)?;

        Ok(ValidatedClaims {
            sub: validated.claims.applicant_id.clone(),
            name: validated.claims.display_name.unwrap_or_default(),
            roles: validated.claims.roles.clone(),
            device_id: String::new(),
            iat: validated.claims.iat,
            exp: validated.claims.exp,
        })
    }

    /// Generate a new RSA-2048 keypair and write PEM files to the specified directory.
    ///
    /// Static utility method (does not require an instance). Produces two files:
    /// - `<output_dir>/private.pem` — PKCS#1 RSA private key
    /// - `<output_dir>/public.pem` — PKCS#1 RSA public key
    ///
    /// This is a one-time setup operation. The generated keys should be secured
    /// with appropriate filesystem permissions (mode 0600 recommended).
    ///
    /// # Arguments
    ///
    /// * `output_dir` - Directory path where key files will be written
    ///
    /// # Errors
    ///
    /// - [`JwtError::KeyGenerationFailed`] if keypair generation fails
    /// - [`JwtError::IoError`] if writing the output files fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// JwtAuthenticator::generate_keypair("./keys")?;
    /// ```
    #[instrument(skip(output_dir))]
    pub fn generate_keypair(output_dir: &std::path::Path) -> Result<(), JwtError> {
        use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs1::EncodeRsaPublicKey};

        let rng = rand::thread_rng();
        let bits = 2048;

        // Generate RSA-2048 private key using rsa crate (ring 0.17 removed generate)
        let private_key = RsaPrivateKey::new(&mut rng.clone(), bits)
            .map_err(|e| {
                JwtError::KeyGenerationFailed(format!(
                    "RSA keypair generation failed: {e}"
                ))
            })?;

        // Export private key in PEM format (PKCS#1 DER)
        let private_der = private_key.to_pkcs1_der()
            .map_err(|e| {
                JwtError::KeyGenerationFailed(format!(
                    "Private key DER encoding failed: {e}"
                ))
            })?;
        let private_pem = super::pem_encode("RSA PRIVATE KEY", private_der.as_bytes());

        // Export public key in PEM format (PKCS#1 DER)
        let public_key = private_key.to_public_key();
        let public_der = public_key.to_pkcs1_der()
            .map_err(|e| {
                JwtError::KeyGenerationFailed(format!(
                    "Public key DER encoding failed: {e}"
                ))
            })?;
        let public_pem = super::pem_encode("RSA PUBLIC KEY", public_der.as_bytes());

        // Write both files
        let private_path = output_dir.join("private.pem");
        let public_path = output_dir.join("public.pem");

        std::fs::create_dir_all(output_dir).map_err(|e| {
            JwtError::IoError(format!(
                "Failed to create output directory {}: {}",
                output_dir.display(), e
            ))
        })?;

        std::fs::write(&private_path, &private_pem).map_err(|e| {
            JwtError::IoError(format!(
                "Failed to write private key to {}: {}",
                private_path.display(), e
            ))
        })?;

        std::fs::write(&public_path, &public_pem).map_err(|e| {
            JwtError::IoError(format!(
                "Failed to write public key to {}: {}",
                public_path.display(), e
            ))
        })?;

        info!(
            private_key = %private_path.display(),
            public_key = %public_path.display(),
            "RSA-2048 keypair generated successfully"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private Helpers
    // -----------------------------------------------------------------------

    /// Convert a [`User`] to [`MisogiClaims`] preserving legacy field mapping.
    ///
    /// Maps User fields to MisogiClaims fields:
    /// - `user.user_id` → `applicant_id`
    /// - `user.display_name` → `display_name`
    /// - `user.role` → `roles[0]` (serialized as JSON string)
    /// - Timestamps are set to 0 (will be overwritten by issuer)
    fn user_to_claims(&self, user: &User) -> MisogiClaims {
        MisogiClaims::new(user.user_id.clone(), 0, 0)
            .with_display_name(user.display_name.clone())
            .with_roles(vec![serde_json::to_string(&user.role).unwrap_or_default()])
            .with_idp_source("local".to_string())
    }

    /// Get reference to the internal issuer component (for advanced usage).
    ///
    /// Allows access to the underlying [`JwtIssuer`] for operations not exposed
    /// by the legacy API (e.g., custom TTL issuance).
    pub fn issuer(&self) -> &JwtIssuer {
        &self.issuer
    }

    /// Get reference to the internal validator component (for advanced usage).
    ///
    /// Allows access to the underlying [`JwtValidator`] for operations not exposed
    /// by the legacy API (e.g., metadata-rich validation).
    pub fn validator(&self) -> &JwtValidator {
        &self.validator
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
