//! Identity Provider Trait — Unified Interface for All Authentication Plugins
//!
//! Defines the canonical [`IdentityProvider`] trait that every authentication backend
//! (LDAP, OIDC, SAML, local DB, API key) MUST implement. This trait serves as the
//! foundational abstraction layer for Misogi's Ultimate Pluggable Architecture
//! (終極可插拔架構).
//!
//! # Design Principles
//!
//! - **Trait Object Safety**: `IdentityProvider` is object-safe (`dyn IdentityProvider`)
//!   so that multiple providers can be stored in a `Vec<Box<dyn IdentityProvider>>`
//!   and dispatched at runtime.
//! - **Zero-Cost Abstraction**: Generic bounds allow monomorphization when the
//!   concrete type is known at compile time.
//! - **Error Transparency**: [`IdentityError`] carries structured context without
//!   leaking sensitive credential material.
//! - **Extensible Input**: [`AuthRequest`] enum covers all standard authentication
//!   flows; new variants can be added without breaking existing implementations.
//!
//! # Provider Lifecycle
//!
//! 1. **Construction**: Provider is created with its configuration (e.g., `LdapConfig`).
//! 2. **Health Check`: Caller invokes [`IdentityProvider::health_check`] to verify
//!    connectivity and configuration validity.
//! 3. **Authentication**: Caller dispatches an [`AuthRequest`] via
//!    [`IdentityProvider::authenticate`], receiving either a [`MisogiIdentity`] or
//!    an [`IdentityError`].
//! 4. **Token Issuance**: The caller converts `MisogiIdentity` → `MisogiClaims` → JWT.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::claims::MisogiClaims;

// ---------------------------------------------------------------------------
// Authentication Request Types
// ---------------------------------------------------------------------------

/// Unified authentication request covering all supported authentication flows.
///
/// Each variant corresponds to a distinct authentication protocol or mechanism.
/// The caller selects the appropriate variant based on the authentication context.
///
/// # Variants
///
/// | Variant | Protocol / Use Case |
/// |---------|-------------------|
/// | `Credentials` | Username + password (form-based login) |
/// | `AuthorizationCode` | OAuth 2.0 / OIDC Authorization Code flow |
/// | `SamlResponse` | SAML 2.0 POST binding response |
/// | `ApiKey` | API key / bearer token validation |
///
/// # Security
///
/// - Passwords in `Credentials` MUST be cleared from memory ASAP after use.
/// - `code_verifier` in `AuthorizationCode` is the PKCE secret; handle securely.
/// - `SamlResponse` contains XML that may carry signature material; validate strictly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthRequest {
    /// Username and password credentials for direct authentication.
    Credentials {
        /// User identifier (login name, UPN, email, etc.)
        username: String,

        /// Cleartext password. Implementations MUST hash/compare securely
        /// and MUST NOT log this value.
        #[serde(skip_serializing)]
        password: String,
    },

    /// OAuth 2.0 Authorization Code grant with optional PKCE verifier.
    AuthorizationCode {
        /// The authorization code received from the authorization server.
        code: String,

        /// Redirect URI used in the initial authorization request.
        redirect_uri: String,

        /// PKCE `code_verifier` (RFC 7636). `None` for plain code flow.
        #[serde(skip_serializing_if = "Option::is_none")]
        code_verifier: Option<String>,
    },

    /// Raw SAML 2.0 response from the IdP (POST binding).
    SamlResponse {
        /// Base64-encoded SAML Response XML from the HTTP POST body.
        response: String,
    },

    /// API key or bearer token for machine-to-machine authentication.
    ApiKey {
        /// The API key string to validate against the configured key store.
        key: String,
    },
}

// ---------------------------------------------------------------------------
// Identity Output Structure
// ---------------------------------------------------------------------------

/// Normalized identity output produced by any [`IdentityProvider`] implementation.
///
/// Protocol-agnostic result of authentication. Regardless of whether the user
/// authenticated via LDAP, OIDC, SAML, or API key, the result is always a
/// `MisogiIdentity` convertible into [`MisogiClaims`] for JWT issuance.
///
/// # Field Mapping to MisogiClaims
///
/// | MisogiIdentity Field | MisogiClaims Field |
/// |-----------------------|--------------------|
/// | `applicant_id` | Primary identifier |
/// | `display_name` | Human-readable name |
/// | `roles` | Authorization role list |
/// | `idp_source` | Originating provider ID |
/// | `original_subject` | Raw IdP subject (preserved) |
/// | `extra` | Forward-compatible extensions |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisogiIdentity {
    /// Unique identifier of the authenticated subject within the Misogi system.
    ///
    /// Primary lookup key for authorization decisions. May differ from
    /// `original_subject` if the IdP uses a different identifier format.
    pub applicant_id: String,

    /// Human-readable display name (UI only; NOT for auth decisions).
    pub display_name: Option<String>,

    /// Role strings granted to this subject. Empty = no roles (default/deny).
    pub roles: Vec<String>,

    /// Identifier of the identity provider that produced this identity.
    ///
    /// Examples: `"ldap"`, `"oidc-keycloak"`, `"saml-gcloud"`, `"api-key"`.
    pub idp_source: String,

    /// Original subject identifier from the upstream IdP (before mapping).
    ///
    /// Preserves raw subject for cross-referencing with IdP audit logs.
    pub original_subject: Option<String>,

    /// Arbitrary extension attributes from the IdP. Flattened into
    /// `MisogiClaims.extra` during conversion.
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl MisogiIdentity {
    /// Create a new `MisogiIdentity` with required fields only.
    ///
    /// Optional fields default to: `display_name` → None, `roles` → [],
    /// `original_subject` → None, `extra` → {}.
    pub fn new(applicant_id: impl Into<String>, idp_source: impl Into<String>) -> Self {
        Self {
            applicant_id: applicant_id.into(),
            display_name: None,
            roles: Vec::new(),
            idp_source: idp_source.into(),
            original_subject: None,
            extra: HashMap::new(),
        }
    }

    /// Builder-style method: set the display name.
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Builder-style method: set the roles list (replaces existing).
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Builder-style method: append a single role.
    pub fn add_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Builder-style method: set the original subject from upstream IdP.
    pub fn with_original_subject(mut self, sub: impl Into<String>) -> Self {
        self.original_subject = Some(sub.into());
        self
    }

    /// Builder-style method: insert an extra attribute.
    pub fn with_extra(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.extra.insert(key.into(), value);
        self
    }
}

// ---------------------------------------------------------------------------
// Conversion: MisogiIdentity → MisogiClaims
// ---------------------------------------------------------------------------

impl From<MisogiIdentity> for MisogiClaims {
    /// Convert `MisogiIdentity` into `MisogiClaims` for JWT token issuance.
    ///
    /// Temporal fields (`iat`, `exp`) are set to sensible defaults (now, now+1h).
    /// Callers SHOULD override these with policy-driven values after conversion.
    fn from(identity: MisogiIdentity) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            applicant_id: identity.applicant_id,
            iat: now,
            exp: now + 3600,
            display_name: identity.display_name,
            roles: identity.roles,
            idp_source: identity.idp_source,
            original_subject: identity.original_subject,
            issuer_dn: None,
            extra: identity.extra,
        }
    }
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Comprehensive error type for identity provider operations.
///
/// Each variant represents a distinct failure mode for retry/fallback logic.
/// Messages are safe for logging (no credential leakage).
///
/// # Error Classification
///
/// | Category | Variants | Recovery |
/// |----------|----------|----------|
/// | Client | `InvalidCredentials`, `UserNotFound` | Prompt user |
/// | Transient | `ProviderUnavailable` | Retry with backoff |
/// | Config | `ConfigurationError` | Fix config, restart |
/// | Protocol | `TokenExchangeFailed` | Re-initiate flow |
/// | Catch-all | `AuthenticationFailed`, `InternalError` | Escalate |
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Supplied credentials are invalid. Client-side error; retry WILL fail.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// User account not found in the identity provider.
    #[error("user not found")]
    UserNotFound,

    /// Provider unreachable or unhealthy (network failure, IdP downtime).
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),

    /// Configuration invalid or incomplete (missing settings, bad URLs).
    #[error("configuration error: {0}")]
    ConfigurationError(String),

    /// Token exchange failed at protocol level (OAuth2, SAML artifact, etc.).
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// General authentication failure with diagnostic description.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Internal error (bug, unexpected state). Do NOT retry without investigation.
    #[error("internal error: {0}")]
    InternalError(String),
}

// ---------------------------------------------------------------------------
// Identity Provider Trait
// ---------------------------------------------------------------------------

/// Unified interface for all authentication backend implementations.
///
/// Every identity provider (LDAP, OIDC, SAML, local DB, API key validator)
/// MUST implement this trait for Misogi's pluggable auth architecture.
///
/// This trait is **object-safe**: usable as `dyn IdentityProvider` for runtime
/// polymorphism via `Arc<dyn IdentityProvider>` in multi-provider routing.
///
/// # Implementation Requirements
///
/// 1. `provider_id()`: stable, unique, DNS-safe identifier (e.g., `"ldap-corporate"`).
/// 2. `provider_name()`: human-readable name for logs/UI.
/// 3. `authenticate()`: return `MisogiIdentity` on success, specific `IdentityError`
///    variant on failure.
/// 4. `health_check()`: verify backend connectivity; return `Err(ProviderUnavailable)`
///    if unreachable.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Unique identifier for this provider instance.
    ///
    /// Used as `idp_source` in [`MisogiIdentity`] and [`MisogiClaims`].
    /// Must be stable across restarts, unique deployment-wide, DNS-safe (`[a-zA-Z0-9_-]`).
    fn provider_id(&self) -> &str;

    /// Human-readable display name for this provider (logs, UI, errors).
    fn provider_name(&self) -> &str;

    /// Authenticate a request and return a normalized identity on success.
    ///
    /// Implementations must validate input, authenticate against the backend,
    /// resolve roles/groups, and return a fully-populated [`MisogiIdentity`].
    ///
    /// # Errors
    ///
    /// Returns specific [`IdentityError`] variants: `InvalidCredentials`,
    /// `UserNotFound`, `ProviderUnavailable`, `ConfigurationError`.
    ///
    /// # Security
    ///
    /// MUST NOT log passwords or sensitive tokens. Mitigate timing side-channels.
    async fn authenticate(
        &self,
        input: AuthRequest,
    ) -> Result<MisogiIdentity, IdentityError>;

    /// Health check against the backend identity provider.
    ///
    /// Verifies the provider is operational. Called by monitoring systems
    /// and during startup to detect issues before accepting auth requests.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — healthy
    /// - `Err(ProviderUnavailable)` — backend unreachable
    /// - `Err(ConfigurationError)` — config invalid
    async fn health_check(&self) -> Result<(), IdentityError>;
}

// ---------------------------------------------------------------------------
// Tests (separated to satisfy line-limit policy)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
