//! JWT Token Validator — RS256 Verification Component
//!
//! Provides token validation (verification) functionality using RSA public keys.
//! This component is responsible for:
//! - Loading and holding the RSA public key (DecodingKey)
//! - Verifying RS256 signatures on JWS compact tokens
//! - Extracting and validating [`MisogiClaims`](super::super::claims::MisogiClaims) from tokens
//! - Providing both simple validation and metadata-rich extraction
//!
//! # Security Model
//!
//! - **Single Responsibility**: Only handles validation; never signs
//! - **Key Isolation**: Holds only public key material (no private key)
//! - **Strict Validation**: Enforces algorithm (RS256), issuer, audience, and expiration
//! - **Defense in Depth**: Multiple layers of cryptographic and claim validation
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_auth::jwt::{JwtValidator, JwtConfig};
//!
//! let config = JwtConfig { /* ... */ };
//! let validator = JwtValidator::new(config)?;
//!
//! // Simple validation — returns MisogiClaims on success
//! let claims = validator.validate(&token_string)?;
//!
//! // Rich validation — returns ValidatedToken with metadata
//! let validated = validator.validate_and_extract(&token_string)?;
//! println!("Token issued at: {}", validated.issued_at);
//! ```

use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use tracing::{debug, instrument};

use super::{JwtConfig, JwtError, unix_timestamp};
use crate::claims::MisogiClaims;

// ---------------------------------------------------------------------------
// Validated Token Output Type
// ---------------------------------------------------------------------------

/// A validated JWT token with extracted claims and additional metadata.
///
/// Produced by [`JwtValidator::validate_and_extract`] after successful signature
/// verification, claim validation, and temporal checks.
///
/// # Fields
///
/// - `claims`: The extracted [`MisogiClaims`] payload from the token
/// - `issuer`: The `iss` claim value (should match configured issuer)
/// - `audience`: The `aud` claim value (should match configured audience)
/// - `issued_at`: The `iat` claim as a human-readable debug string
/// - `expires_at`: The `exp` claim as a human-readable debug string
/// - `is_expired`: Whether the token has expired (checked at validation time)
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    /// Extracted claims payload from the verified token.
    pub claims: MisogiClaims,

    /// Issuer identifier from the `iss` registered claim.
    pub issuer: String,

    /// Audience identifier from the `aud` registered claim.
    pub audience: String,

    /// Issued-at timestamp (UNIX seconds since epoch).
    pub issued_at: u64,

    /// Expiration timestamp (UNIX seconds since epoch).
    pub expires_at: u64,

    /// Whether the token was already expired at validation time.
    ///
    /// **Note**: This field is always `false` when returned from [`validate_and_extract`](JwtValidator::validate_and_extract)
    /// because expired tokens return an error instead. This field exists for
    /// post-validation inspection or when using [`validate_without_expiry_check`](JwtValidator::validate_without_expiry_check).
    pub is_expired: bool,
}

impl ValidatedToken {
    /// Calculate remaining lifetime in seconds (may be negative if expired).
    ///
    /// Returns `exp - now` in seconds. Positive value means token is still valid,
    /// zero or negative means it has expired or will expire immediately.
    pub fn remaining_seconds(&self) -> i64 {
        (self.expires_at as i64) - (unix_timestamp() as i64)
    }

    /// Check if this validated token contains a specific role (case-sensitive).
    ///
    /// Delegates to [`MisogiClaims::has_role`].
    pub fn has_role(&self, role: &str) -> bool {
        self.claims.has_role(role)
    }
}

// ---------------------------------------------------------------------------
// Validator Structure
// ---------------------------------------------------------------------------

/// RS256 JWT Token Validator — verifies asymmetrically-signed tokens.
///
/// Thread-safe: can be wrapped in `Arc<>` and shared across async tasks.
///
/// # Initialization
///
/// Load RSA public key from PEM file at construction time. If the file is missing
/// or malformed, construction returns an error.
///
/// # Key Management
///
/// Public key is read once at construction and held in memory. For key rotation,
/// construct a new `JwtValidator` instance with updated configuration and swap the
/// `Arc<>` reference atomically.
///
/// # Separation of Concerns
///
/// This struct ONLY handles token validation (verification). For issuance logic,
/// see [`JwtIssuer`](super::issuer::JwtIssuer). For backward-compatible combined
/// interface, see [`JwtAuthenticator`](super::authenticator::JwtAuthenticator).
pub struct JwtValidator {
    /// Configuration containing issuer/audience identifiers for claim validation.
    config: JwtConfig,

    /// RSA public key used for verifying token signatures (RS256).
    decoding_key: DecodingKey,
}

impl JwtValidator {
    /// Create a new JWT validator by loading RSA public key from the configured PEM path.
    ///
    /// Only the public key is loaded; private key is NOT required for validation.
    ///
    /// # Arguments
    ///
    /// * `config` - JWT configuration including `rsa_pub_pem_path` pointing to public key PEM
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::KeyLoadFailed`] if the PEM file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let validator = JwtValidator::new(config)?;
    /// ```
    #[instrument(skip(config), fields(issuer = %config.issuer))]
    pub fn new(config: JwtConfig) -> Result<Self, JwtError> {
        let public_pem =
            std::fs::read_to_string(&config.rsa_pub_pem_path).map_err(|e| {
                JwtError::KeyLoadFailed(format!(
                    "Failed to read public key from {}: {}",
                    config.rsa_pub_pem_path.display(), e
                ))
            })?;

        let decoding_key =
            DecodingKey::from_rsa_pem(public_pem.as_bytes()).map_err(|e| {
                JwtError::KeyLoadFailed(format!(
                    "Invalid RSA public key: {e}"
                ))
            })?;

        info!(
            issuer = %config.issuer,
            "JwtValidator initialized successfully"
        );

        Ok(Self {
            config,
            decoding_key,
        })
    }

    /// Validate a JWT string: verify RS256 signature AND check all registered claims.
    ///
    /// Performs comprehensive validation:
    /// - Cryptographic signature verification against the public key
    /// - Algorithm enforcement (RS256 only — prevents algorithm confusion attacks)
    /// - `iss` claim matches configured issuer
    /// - `aud` claim matches configured audience
    /// - `exp` claim has not passed (token not expired)
    /// - `nbf` claim (if present) has passed
    ///
    /// # Arguments
    ///
    /// * `token` - JWS Compact Serialization string to validate
    ///
    /// # Returns
    ///
    /// The extracted [`MisogiClaims`] on successful validation.
    ///
    /// # Errors
    ///
    /// - [`JwtError::InvalidSignature`] — signature verification failed (tampered token)
    /// - [`JwtError::TokenExpired`] — the `exp` claim is in the past
    /// - [`JwtError::ClaimValidationFailed`] — iss/aud/nbf mismatch or other claim errors
    /// - [`JwtError::MalformedToken`] — token is not valid JWS format
    ///
    /// # Security Note
    ///
    /// This method enforces strict algorithm checking (`RS256`). Tokens signed with
    /// other algorithms (e.g., HS256, none) will be rejected even if the signature
    /// is cryptographically valid for that algorithm. This prevents algorithm
    /// confusion attacks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// match validator.validate(&token_string) {
    ///     Ok(claims) => println!("Authenticated: {}", claims.applicant_id),
    ///     Err(JwtError::TokenExpired) => eprintln!("Token expired"),
    ///     Err(e) => eprintln!("Validation failed: {e}"),
    /// }
    /// ```
    #[instrument(skip(self, token))]
    pub fn validate(&self, token: &str) -> Result<MisogiClaims, JwtError> {
        let validated = self.validate_and_extract(token)?;
        Ok(validated.claims)
    }

    /// Validate a JWT string and return rich metadata alongside claims.
    ///
    /// Identical to [`validate`](Self::validate) but returns a [`ValidatedToken`]
    /// containing additional metadata useful for logging, auditing, and debugging:
    /// - Issuer and audience values actually present in the token
    /// - Issued-at and expiration timestamps
    /// - Expiration status flag
    ///
    /// Use this method when you need more than just the claims payload, such as
    /// for audit logging or token refresh decisions.
    ///
    /// # Arguments
    ///
    /// * `token` - JWS Compact Serialization string to validate
    ///
    /// # Returns
    ///
    /// A [`ValidatedToken`] with claims and metadata on successful validation.
    ///
    /// # Errors
    ///
    /// Same as [`validate`](Self::validate).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let validated = validator.validate_and_extract(&token)?;
    /// info!(
    ///     subject = %validated.claims.applicant_id,
    ///     issuer = %validated.issuer,
    ///     remaining_secs = validated.remaining_seconds(),
    ///     "Token validated successfully"
    /// );
    /// ```
    #[instrument(skip(self, token))]
    pub fn validate_and_extract(&self, token: &str) -> Result<ValidatedToken, JwtError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data = decode::<MisogiClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    JwtError::TokenExpired
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    JwtError::InvalidSignature
                }
                _ => JwtError::ClaimValidationFailed(e.to_string()),
            })?;

        let claims = token_data.claims;
        let now = unix_timestamp();

        // Extract standard claims from extra map (injected by issuer)
        let issuer = claims
            .extra
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.issuer)
            .to_string();

        let audience = claims
            .extra
            .get("aud")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.audience)
            .to_string();

        let is_expired = now > claims.exp;

        debug!(
            applicant_id = %claims.applicant_id,
            issuer = %issuer,
            is_expired,
            "JWT validated successfully"
        );

        Ok(ValidatedToken {
            claims,
            issuer,
            audience,
            issued_at: token_data.claims.iat,
            expires_at: token_data.claims.exp,
            is_expired,
        })
    }

    /// Validate a JWT string WITHOUT checking expiration.
    ///
    /// Identical to [`validate_and_extract`](Self::validate_and_extract) but skips
    /// the `exp` claim check. Intended for use cases where expiration should be
    /// handled externally (e.g., refresh token validation, audit log replay).
    ///
    /// # Warning
    ///
    /// **Security Implications**: Use this method ONLY when you have a specific
    /// reason to ignore expiration. In most cases, prefer [`validate`](Self::validate)
    /// or [`validate_and_extract`](Self::validate_and_extract) which enforce expiration.
    ///
    /// # Arguments
    ///
    /// * `token` - JWS Compact Serialization string to validate
    ///
    /// # Returns
    ///
    /// A [`ValidatedToken`] where `is_expired` reflects actual expiration state
    /// (but no error is returned for expired tokens).
    ///
    /// # Errors
    ///
    /// Same as [`validate_and_extract`](Self::validate_and_extract), except
    /// [`JwtError::TokenExpired`] will never be returned.
    #[instrument(skip(self, token))]
    pub fn validate_without_expiry_check(
        &self,
        token: &str,
    ) -> Result<ValidatedToken, JwtError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = false; // Skip expiration check
        validation.validate_nbf = true;

        let token_data = decode::<MisogiClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    JwtError::InvalidSignature
                }
                _ => JwtError::ClaimValidationFailed(e.to_string()),
            })?;

        let claims = token_data.claims;
        let now = unix_timestamp();

        let issuer = claims
            .extra
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.issuer)
            .to_string();

        let audience = claims
            .extra
            .get("aud")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.audience)
            .to_string();

        let is_expired = now > claims.exp;

        Ok(ValidatedToken {
            claims,
            issuer,
            audience,
            issued_at: token_data.claims.iat,
            expires_at: token_data.claims.exp,
            is_expired,
        })
    }

    /// Get a reference to the configuration used by this validator.
    pub fn config(&self) -> &JwtConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
