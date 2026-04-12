//! JWT Token Issuer — RS256 Signing Component
//!
//! Provides token issuance (signing) functionality using RSA private keys.
//! This component is responsible for:
//! - Loading and holding the RSA private key (EncodingKey)
//! - Serializing [`MisogiClaims`](super::super::claims::MisogiClaims) into JWT payload
//! - Signing tokens with RS256 algorithm
//! - Supporting both default TTL and custom TTL issuance
//!
//! # Security Model
//!
//! - **Single Responsibility**: Only handles signing; never validates
//! - **Key Isolation**: Holds only private key material (no public key)
//! - **Thread-Safe**: Can be wrapped in `Arc<>` for concurrent use
//! - **Zero-Knowledge**: Does not store issued tokens; caller manages token lifecycle
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_auth::jwt::{JwtIssuer, JwtConfig};
//! use misogi_auth::claims::MisogiClaims;
//!
//! let config = JwtConfig { /* ... */ };
//! let issuer = JwtIssuer::new(config)?;
//!
//! let claims = MisogiClaims::new("user-001".to_string(), now, now + 28800);
//! let token = issuer.issue(&claims)?;  // Default TTL from config
//! let custom_token = issuer.issue_with_ttl(&claims, 3600)?;  // Custom 1-hour TTL
//! ```

use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use tracing::{debug, info, instrument};

use super::{JwtConfig, JwtError, unix_timestamp};
use crate::claims::MisogiClaims;

// ---------------------------------------------------------------------------
// Issuer Structure
// ---------------------------------------------------------------------------

/// RS256 JWT Token Issuer — signs and issues asymmetrically-signed tokens.
///
/// Thread-safe: can be wrapped in `Arc<>` and shared across async tasks.
///
/// # Initialization
///
/// Load RSA private key from PEM file at construction time. If the file is missing
/// or malformed, construction returns an error.
///
/// # Key Management
///
/// Private key is read once at construction and held in memory. For key rotation,
/// construct a new `JwtIssuer` instance with updated configuration and swap the
/// `Arc<>` reference atomically.
///
/// # Separation of Concerns
///
/// This struct ONLY handles token issuance (signing). For validation logic,
/// see [`JwtValidator`](super::validator::JwtValidator). For backward-compatible
/// combined interface, see [`JwtAuthenticator`](super::authenticator::JwtAuthenticator).
pub struct JwtIssuer {
    /// Configuration containing issuer/audience identifiers and key paths.
    config: JwtConfig,

    /// RSA private key used for signing tokens (RS256).
    encoding_key: EncodingKey,
}

impl JwtIssuer {
    /// Create a new JWT issuer by loading RSA private key from the configured PEM path.
    ///
    /// Only the private key is loaded; public key is NOT required for issuance.
    ///
    /// # Arguments
    ///
    /// * `config` - JWT configuration including `rsa_pem_path` pointing to private key PEM
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::KeyLoadFailed`] if the PEM file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let issuer = JwtIssuer::new(config)?;
    /// ```
    #[instrument(skip(config), fields(issuer = %config.issuer))]
    pub fn new(config: JwtConfig) -> Result<Self, JwtError> {
        let private_pem =
            std::fs::read_to_string(&config.rsa_pem_path).map_err(|e| {
                JwtError::KeyLoadFailed(format!(
                    "Failed to read private key from {}: {}",
                    config.rsa_pem_path.display(), e
                ))
            })?;

        let encoding_key =
            EncodingKey::from_rsa_pem(private_pem.as_bytes()).map_err(|e| {
                JwtError::KeyLoadFailed(format!(
                    "Invalid RSA private key: {e}"
                ))
            })?;

        info!(
            issuer = %config.issuer,
            ttl_hours = config.ttl_hours,
            "JwtIssuer initialized successfully"
        );

        Ok(Self {
            config,
            encoding_key,
        })
    }

    /// Create a [`JwtIssuer`] from a JSON configuration value.
    ///
    /// Factory method that constructs [`JwtConfig`] from a `serde_json::Value`
    /// (typically parsed from TOML or JSON config files) and initializes the issuer.
    ///
    /// This enables declarative configuration-driven initialization without
    /// manually constructing [`JwtConfig`] structs in application code.
    ///
    /// # Expected JSON Structure
    ///
    /// ```json
    /// {
    ///   "issuer": "misogi-auth",
    ///   "audience": "misogi-api",
    ///   "rsa_pem_path": "/etc/misogi/jwt/private.pem",
    ///   "rsa_pub_pem_path": "/etc/misogi/jwt/public.pem",
    ///   "ttl_hours": 8,
    ///   "refresh_ttl_hours": 168
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `value` — A `serde_json::Value` object containing JWT configuration fields.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::KeyLoadFailed`] if:
    /// - Required fields are missing from the config value
    /// - The RSA private key file cannot be read or parsed
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config_value = serde_json::json!({
    ///     "issuer": "misogi-auth",
    ///     "audience": "misogi-api",
    ///     "rsa_pem_path": "./keys/private.pem",
    ///     "rsa_pub_pem_path": "./keys/public.pem",
    ///     "ttl_hours": 8,
    ///     "refresh_ttl_hours": 168,
    /// });
    /// let issuer = JwtIssuer::from_config(&config_value)?;
    /// ```
    pub fn from_config(value: &serde_json::Value) -> Result<Self, JwtError> {
        let obj = value.as_object().ok_or_else(|| {
            JwtError::KeyLoadFailed("JWT config must be a JSON object".to_string())
        })?;

        // --- Required fields ---
        let issuer = obj
            .get("issuer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JwtError::KeyLoadFailed(
                    "Missing required field: 'issuer' in JWT config".to_string(),
                )
            })?
            .to_string();

        let audience = obj
            .get("audience")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JwtError::KeyLoadFailed(
                    "Missing required field: 'audience' in JWT config".to_string(),
                )
            })?
            .to_string();

        let rsa_pem_path = obj
            .get("rsa_pem_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JwtError::KeyLoadFailed(
                    "Missing required field: 'rsa_pem_path' in JWT config".to_string(),
                )
            })?;
        let rsa_pub_pem_path = obj
            .get("rsa_pub_pem_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JwtError::KeyLoadFailed(
                    "Missing required field: 'rsa_pub_pem_path' in JWT config".to_string(),
                )
            })?;

        // --- Optional fields with sensible defaults ---
        let ttl_hours = obj
            .get("ttl_hours")
            .and_then(|v| v.as_i64())
            .unwrap_or(8);

        let refresh_ttl_hours = obj
            .get("refresh_ttl_hours")
            .and_then(|v| v.as_i64())
            .unwrap_or(168);

        let config = super::JwtConfig {
            issuer,
            audience,
            rsa_pem_path: std::path::PathBuf::from(rsa_pem_path),
            rsa_pub_pem_path: std::path::PathBuf::from(rsa_pub_pem_path),
            ttl_hours,
            refresh_ttl_hours,
        };

        Self::new(config)
    }

    /// Issue a new RS256-signed JWT for the given claims using default TTL from config.
    ///
    /// The token is signed with RS256 algorithm using the private key loaded at
    /// construction time. The `exp` claim is automatically calculated based on
    /// current timestamp + `config.ttl_hours`.
    ///
    /// # Arguments
    ///
    /// * `claims` - The [`MisogiClaims`] to embed in the token. Note that `iat` and `exp`
    ///   fields will be overwritten by this method to ensure temporal consistency.
    ///
    /// # Returns
    ///
    /// A JWS Compact Serialization string (the actual bearer token value).
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::EncodingFailed`] if token encoding fails (should not occur
    /// with well-formed keys and valid claims).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let claims = MisogiClaims::new("user-001".to_string(), 0, 0); // iat/exp ignored
    /// let token = issuer.issue(&claims)?;
    /// ```
    #[instrument(skip(self, claims), fields(applicant_id = %claims.applicant_id))]
    pub fn issue(&self, claims: &MisogiClaims) -> Result<String, JwtError> {
        let ttl_secs = (self.config.ttl_hours as u64) * 3600;
        self.issue_with_ttl(claims, ttl_secs)
    }

    /// Issue a new RS256-signed JWT with a custom expiration TTL.
    ///
    /// Similar to [`issue`](Self::issue), but allows overriding the token lifetime.
    /// Useful for scenarios requiring different TTLs (e.g., service accounts vs. users).
    ///
    /// # Arguments
    ///
    /// * `claims` - The [`MisogiClaims`] to embed in the token (`iat`/`exp` are overwritten)
    /// * `ttl_secs` - Custom time-to-live in seconds (must be > 0)
    ///
    /// # Returns
    ///
    /// A JWS Compact Serialization string (the actual bearer token value).
    ///
    /// # Errors
    ///
    /// - [`JwtError::EncodingFailed`] if token encoding fails
    /// - [`JwtError::ClaimValidationFailed`] if `ttl_secs` is 0
    ///
    /// # Security Note
    ///
    /// Very long TTLs (e.g., > 24 hours for access tokens) may increase risk if
    /// the token is compromised. Use appropriate TTLs for your threat model.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Issue a 1-hour token regardless of config default
    /// let token = issuer.issue_with_ttl(&claims, 3600)?;
    /// ```
    #[instrument(skip(self, claims), fields(applicant_id = %claims.applicant_id, ttl_secs))]
    pub fn issue_with_ttl(
        &self,
        claims: &MisogiClaims,
        ttl_secs: u64,
    ) -> Result<String, JwtError> {
        if ttl_secs == 0 {
            return Err(JwtError::ClaimValidationFailed(
                "TTL must be greater than 0 seconds".to_string(),
            ));
        }

        let now = unix_timestamp();

        // Build claims with correct timestamps and issuer/audience
        let mut signed_claims = claims.clone();
        signed_claims.iat = now;
        signed_claims.exp = now + ttl_secs;

        // Inject standard registered claims into extra map for compatibility
        // This ensures iss/aud are present in the serialized JWT
        signed_claims
            .extra
            .insert("iss".to_string(), serde_json::json!(self.config.issuer));
        signed_claims
            .extra
            .insert("aud".to_string(), serde_json::json!(self.config.audience));

        let header = Header::new(Algorithm::RS256);

        let jws = encode(&header, &signed_claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodingFailed(e.to_string()))?;

        debug!(
            applicant_id = %claims.applicant_id,
            ttl_secs,
            "JWT issued successfully"
        );

        Ok(jws)
    }

    /// Issue a JWT token directly from an authenticated [`MisogiIdentity`].
    ///
    /// This is the **primary integration method** for the post-authentication
    /// token issuance flow. It performs the full conversion chain:
    ///
    /// ```text
    /// MisogiIdentity  ──(From trait)──>  MisogiClaims  ──(issue)──>  JWS String
    /// ```
    ///
    /// The conversion uses [`From<MisogiIdentity>`] for `MisogiClaims`, which
    /// sets sensible defaults for temporal fields (`iat`=now, `exp`=now+1h).
    /// These are then overwritten by [`issue_with_ttl`](Self::issue_with_ttl)
    /// to use the configured TTL.
    ///
    /// # Arguments
    ///
    /// * `identity` — The authenticated identity produced by any [`IdentityProvider`]
    ///
    /// # Returns
    ///
    /// A JWS Compact Serialization string (the actual bearer token value).
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying signing operation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // After successful authentication via IdentityRegistry:
    /// let identity = registry.authenticate("ldap-corp", &request).await?;
    /// let token = issuer.issue_identity(&identity)?;
    /// ```
    #[instrument(skip(self, identity), fields(applicant_id = %identity.applicant_id))]
    pub fn issue_identity(&self, identity: &crate::provider::MisogiIdentity) -> Result<String, JwtError> {
        let claims: MisogiClaims = identity.clone().into();
        self.issue(&claims)
    }

    /// Issue a JWT token from [`MisogiIdentity`] with a custom TTL.
    ///
    /// Same as [`issue_identity`](Self::issue_identity) but allows overriding
    /// the token lifetime. Useful for:
    /// - Service accounts with long-lived tokens
    /// - Short-lived tokens for high-security operations
    /// - Session-specific TTLs based on authentication context
    ///
    /// # Arguments
    ///
    /// * `identity` — The authenticated identity from any [`IdentityProvider`]
    /// * `ttl_secs` — Custom time-to-live in seconds (must be > 0)
    ///
    /// # Returns
    ///
    /// A JWS Compact Serialization string, or an error if TTL is invalid or
    /// signing fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Issue a 5-minute token for a sensitive operation
    /// let token = issuer.issue_with_ttl_identity(&identity, 300)?;
    /// ```
    #[instrument(skip(self, identity), fields(applicant_id = %identity.applicant_id, ttl_secs))]
    pub fn issue_with_ttl_identity(
        &self,
        identity: &crate::provider::MisogiIdentity,
        ttl_secs: u64,
    ) -> Result<String, JwtError> {
        let claims: MisogiClaims = identity.clone().into();
        self.issue_with_ttl(&claims, ttl_secs)
    }

    /// Get a reference to the configuration used by this issuer.
    pub fn config(&self) -> &JwtConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
