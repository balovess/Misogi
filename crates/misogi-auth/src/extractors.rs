//! Axum Extractors for Micro-Kernel Authentication Architecture
//!
//! Provides HTTP-layer extractors that integrate with the new micro-kernel
//! architecture where each authentication protocol has a dedicated plugin:
//!
//! - **[`JwtAuthExtractor`]**: Validates ONLY Misogi-issued JWTs via [`JwtValidator`](super::jwt::validator::JwtValidator)
//! - **[`IdentityAuthExtractor`]**: Extracts provider context for delegated auth flows
//!
//! # Architecture Migration (Phase 7)
//!
//! This module implements the refactored extractor design that separates concerns:
//! - **JWT extraction**: Only handles Misogi-signed tokens (RS256 with configured issuer/audience)
//! - **OIDC extraction**: Moved to [`OidcIdentityPlugin`](super::plugins::oidc) — not handled here
//! - **Provider delegation**: New pattern for multi-IdP routing via IdentityAuthExtractor
//!
//! # Error Response Format
//!
//! All extractors return backward-compatible JSON error responses:
//! ```json
//! { "error": "error_code", "message": "Human-readable message", "status_code": 401 }
//! ```
//!
//! # Usage Example
//!
//! ```ignore
//! use axum::{routing::get, Router};
//! use misogi_auth::extractors::JwtAuthExtractor;
//! use std::sync::Arc;
//!
//! async fn protected_handler(
//!     claims: JwtAuthExtractor,
//! ) -> impl IntoResponse {
//!     Json(serde_json::json!({
//!         "user": claims.claims.applicant_id,
//!         "roles": claims.claims.roles,
//!     }))
//! }
//!
//! let app = Router::new()
//!     .route("/api/protected", get(protected_handler))
//!     .layer(axum::Extension(validator_arc));
//! ```

#[cfg(feature = "axum")]
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "axum")]
use serde_json::json;
#[cfg(feature = "axum")]
use std::sync::Arc;
#[cfg(feature = "axum")]
use tracing::{debug, instrument, warn};

#[cfg(feature = "axum")]
use crate::claims::MisogiClaims;
#[cfg(all(feature = "axum", feature = "jwt"))]
use crate::jwt::validator::JwtValidator;

// ---------------------------------------------------------------------------
// Re-export for backward compatibility
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
pub use super::middleware::ApiKeyExtractor;
pub use super::middleware::ServiceAccount;

// ---------------------------------------------------------------------------
// Error Types (Axum-dependent)
// ---------------------------------------------------------------------------

/// Extraction error with machine-readable code and HTTP status.
///
/// Designed to produce consistent JSON error responses across all extractors.
/// Implements `IntoResponse` for direct use in Axum rejection handling.
#[cfg(feature = "axum")]
#[derive(Debug, thiserror::Error)]
pub enum ExtractionError {
    /// Authorization header is missing from the request.
    #[error("missing authorization header")]
    MissingAuthorization,

    /// Bearer token is empty or malformed.
    #[error("invalid or empty bearer token")]
    InvalidBearerToken,

    /// Token signature verification failed or token is malformed.
    #[error("token validation failed: {0}")]
    ValidationFailed(String),

    /// Token has expired.
    #[error("token has expired")]
    TokenExpired,

    /// Token is not a Misogi-issued JWT (wrong issuer/audience).
    ///
    /// This error indicates the token should be routed to an external
    /// identity provider plugin (OIDC, SAML) rather than rejected outright.
    #[error("external identity token detected — requires provider plugin")]
    ExternalIdentityToken {
        /// Detected issuer claim value (if present).
        issuer: Option<String>,
    },

    /// Identity provider header missing or invalid for delegated flows.
    #[error("identity provider context required")]
    MissingProviderContext,

    /// Internal error during extraction processing.
    #[error("internal extraction error: {0}")]
    InternalError(String),
}

#[cfg(feature = "axum")]
impl ExtractionError {
    /// Machine-readable error code for JSON responses.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::MissingAuthorization => "missing_authorization",
            Self::InvalidBearerToken => "invalid_bearer_token",
            Self::ValidationFailed(_) => "validation_failed",
            Self::TokenExpired => "token_expired",
            Self::ExternalIdentityToken { .. } => "external_identity_token",
            Self::MissingProviderContext => "missing_provider_context",
            Self::InternalError(_) => "internal_error",
        }
    }

    /// HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingAuthorization => StatusCode::UNAUTHORIZED,
            Self::InvalidBearerToken => StatusCode::UNAUTHORIZED,
            Self::ValidationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::TokenExpired => StatusCode::UNAUTHORIZED,
            // External tokens should be routed to plugins, not treated as errors
            // but we return 401 to trigger fallback middleware
            Self::ExternalIdentityToken { .. } => StatusCode::UNAUTHORIZED,
            Self::MissingProviderContext => StatusCode::BAD_REQUEST,
            Self::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Serialize as backward-compatible JSON error body.
    pub fn error_body(&self) -> serde_json::Value {
        json!({
            "error": self.error_code(),
            "message": self.to_string(),
            "status_code": self.status_code().as_u16(),
        })
    }
}

#[cfg(feature = "axum")]
impl IntoResponse for ExtractionError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        (
            status,
            Json(self.error_body()),
        ).into_response()
    }
}

// ===========================================================================
// JwtAuthExtractor — Misogi-Issued JWT Only
// ===========================================================================

/// Axum extractor that validates **only** Misogi-issued JWT tokens via [`JwtValidator`].
///
/// # Micro-Kernel Architecture (Phase 7)
///
/// This extractor is specifically designed for the new micro-kernel architecture where:
/// - **Misogi JWT validation**: Handled here using [`JwtValidator::validate`](JwtValidator::validate)
/// - **External IdP tokens (OIDC/SAML)**: Explicitly REJECTED with `ExternalIdentityToken` error
///   — these must be processed by the appropriate identity plugin (`OidcIdentityPlugin`, etc.)
///
/// # Extraction Flow
///
/// ```text
/// HTTP Request
///     |
///     v
/// +------------------+
/// | Extract Bearer    | ---> Missing: 401 missing_authorization
/// | token from Auth   |
/// | header            |
/// +------------------+
///     |
///     v
/// +------------------+
/// | Validate via      | ---> Invalid/expired: 401 validation_failed / token_expired
/// | JwtValidator      |
/// | (RS256 + iss/aud) |
/// +------------------+
///     |
///     v
/// +------------------+
/// | Check iss claim   | ---> Non-Misogi issuer: 401 external_identity_token
/// | matches config    |     (triggers plugin fallback)
/// +------------------+
///     |
///     v
/// Return MisogiClaims
/// ```
///
/// # State Requirements
///
/// This extractor requires `axum::Extension<Arc<JwtValidator>>` to be installed
/// as a layer on the router. The validator holds the RSA public key and
/// issuer/audience configuration for strict token validation.
///
/// # Error Responses
///
/// All errors return JSON format: `{ "error": "...", "message": "...", "status_code": 401 }`
///
/// # Example
///
/// ```ignore
/// use axum::{routing::get, Router, Extension};
/// use std::sync::Arc;
/// use misogi_auth::extractors::JwtAuthExtractor;
/// use misogi_auth::jwt::JwtValidator;
///
/// let validator = Arc::new(JwtValidator::new(jwt_config)?);
///
/// async fn handler(claims: JwtAuthExtractor) -> String {
///     format!("Hello, {}!", claims.claims.applicant_id)
/// }
///
/// let app = Router::new()
///     .route("/api/me", get(handler))
///     .layer(Extension(validator));
/// ```
#[cfg(all(feature = "jwt", feature = "axum"))]
pub struct JwtAuthExtractor {
    /// Validated Misogi claims extracted from the verified JWT token.
    pub claims: MisogiClaims,
}

#[cfg(all(feature = "jwt", feature = "axum"))]
impl JwtAuthExtractor {
    /// Create a new JwtAuthExtractor from validated claims.
    ///
    /// Used internally after successful token validation. External code should
    /// rely on the `FromRequestParts` implementation rather than calling this directly.
    pub fn new(claims: MisogiClaims) -> Self {
        Self { claims }
    }

    /// Get reference to the extracted claims.
    pub fn claims(&self) -> &MisogiClaims {
        &self.claims
    }
}

#[cfg(all(feature = "jwt", feature = "axum"))]
impl<S> axum::extract::FromRequestParts<S> for JwtAuthExtractor
where
    S: Send + Sync,
{
    type Rejection = ExtractionError;

    #[instrument(skip(parts, state), fields(extractor = "jwt_auth"))]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ExtractionError::MissingAuthorization)?;

        // Parse Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or(ExtractionError::InvalidBearerToken)?
            .trim();

        if token.is_empty() {
            return Err(ExtractionError::InvalidBearerToken);
        }

        // Extract JwtValidator from request extensions (installed via Layer)
        let validator = parts
            .extensions
            .get::<Arc<JwtValidator>>()
            .cloned()
            .ok_or_else(|| {
                ExtractionError::InternalError(
                    "JwtValidator not found in request extensions. \
                     Ensure axum::Extension(Arc<JwtValidator>) is installed as a layer."
                        .to_string(),
                )
            })?;

        // Validate token using JwtValidator (RS256 + claim checks)
        // This will reject non-Misogi tokens automatically due to issuer/audience mismatch
        match validator.validate(token) {
            Ok(claims) => {
                debug!(
                    applicant_id = %claims.applicant_id,
                    idp_source = %claims.idp_source,
                    "JWT validated successfully by JwtAuthExtractor"
                );
                Ok(Self { claims })
            }
            Err(crate::jwt::JwtError::TokenExpired) => {
                warn!("JwtAuthExtractor: token expired");
                Err(ExtractionError::TokenExpired)
            }
            Err(crate::jwt::JwtError::InvalidSignature) => {
                warn!("JwtAuthExtractor: invalid signature");
                Err(ExtractionError::ValidationFailed(
                    "Signature verification failed".to_string(),
                ))
            }
            Err(crate::jwt::JwtError::ClaimValidationFailed(msg)) => {
                // Check if this looks like an external IdP token (issuer mismatch)
                // These should be routed to OidcIdentityPlugin instead of being rejected
                if msg.contains("issuer") || msg.contains("audience") {
                    debug!(
                        error = %msg,
                        "External identity token detected (iss/aud mismatch)"
                    );
                    return Err(ExtractionError::ExternalIdentityToken {
                        issuer: None, // We don't have the actual issuer without decoding again
                    });
                }

                warn!(error = %msg, "JwtAuthExtractor: claim validation failed");
                Err(ExtractionError::ValidationFailed(msg))
            }
            Err(crate::jwt::JwtError::MalformedToken(msg)) => {
                warn!(error = %msg, "JwtAuthExtractor: malformed token");
                Err(ExtractionError::ValidationFailed(format!("Malformed token: {msg}")))
            }
            Err(e) => {
                warn!(error = %e, "JwtAuthExtractor: unexpected validation error");
                Err(ExtractionError::InternalError(e.to_string()))
            }
        }
    }
}

// ===========================================================================
// IdentityAuthExtractor — Provider Context for Delegated Auth
// ===========================================================================

/// Context extracted for delegated authentication flows.
///
/// Contains information about which external identity provider should handle
/// authentication for this request. Used in conjunction with identity plugins
/// that implement provider-specific authentication logic.
///
/// # Extraction Sources (in priority order)
///
/// 1. **`X-Identity-Provider` header**: Explicit provider specification
/// 2. **Path prefix `/auth/:provider_id/...`**: URL-based provider routing
///
/// # Fields
///
/// - `provider_id`: Identifier of the target identity provider (e.g., `"azure-ad"`, `"keycloak"`)
/// - `source`: Which extraction method was used (header vs path)
/// - `original_token`: Raw authentication token (if present) for forwarding to provider
#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct IdentityContext {
    /// Identity provider identifier (e.g., `"azure-ad"`, `"keycloak"`, `"ldap-corp"`).
    pub provider_id: String,

    /// How the provider context was determined.
    pub source: ProviderSource,

    /// Original bearer token (if present) for forwarding to the provider plugin.
    ///
    /// `None` if no authorization header was present; the handler may choose
    /// to initiate a fresh authentication flow (e.g., redirect to IdP login).
    pub original_token: Option<String>,
}

/// Source of the provider identity context.
#[cfg(feature = "axum")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderSource {
    /// Extracted from `X-Identity-Provider` request header.
    Header,

    /// Extracted from URL path prefix `/auth/:provider_id/...`.
    PathPrefix,
}

/// Axum extractor that extracts identity provider context for delegated authentication.
///
/// # Purpose
///
/// In the micro-kernel architecture, external identity providers (OIDC, SAML, LDAP)
/// are implemented as plugins. This extractor determines **which plugin** should
/// handle the current request based on:
///
/// 1. **Explicit header**: `X-Identity-Provider: azure-ad`
/// 2. **Path-based routing**: `/auth/azure-ad/callback?code=...`
///
/// # Usage Pattern
///
/// ```ignore
/// use axum::{routing::get, Router};
/// use misogi_auth::extractors::IdentityAuthExtractor;
///
/// async fn auth_callback(
///     ctx: IdentityAuthExtractor,
/// ) -> impl IntoResponse {
///     match ctx.provider_id.as_str() {
///         "azure-ad" => handle_azure_ad_callback(ctx).await,
///         "keycloak" => handle_keycloak_callback(ctx).await,
///         other => Err((StatusCode::BAD_REQUEST, "Unknown provider"))
///     }
/// }
///
/// let app = Router::new()
///     .route("/auth/{provider}/callback", get(auth_callback));
/// ```
///
/// # Error Handling
///
/// Returns 400 Bad Request if neither header nor path provides provider context.
/// Does NOT validate the authentication token — that's the responsibility of
/// the provider-specific plugin/handler.
#[cfg(feature = "axum")]
#[derive(Debug)]
pub struct IdentityAuthExtractor(pub IdentityContext);

#[cfg(feature = "axum")]
impl IdentityAuthExtractor {
    /// Get reference to the extracted identity context.
    pub fn context(&self) -> &IdentityContext {
        &self.0
    }

    /// Get the provider identifier.
    pub fn provider_id(&self) -> &str {
        &self.0.provider_id
    }

    /// Check if an original token is available for forwarding.
    pub fn has_token(&self) -> bool {
        self.0.original_token.is_some()
    }

    /// Get the original token (if present).
    pub fn original_token(&self) -> Option<&str> {
        self.0.original_token.as_deref()
    }
}

#[cfg(feature = "axum")]
impl<S> axum::extract::FromRequestParts<S> for IdentityAuthExtractor
where
    S: Send + Sync,
{
    type Rejection = ExtractionError;

    #[instrument(skip_all, fields(extractor = "identity_auth"))]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Priority 1: X-Identity-Provider header
        if let Some(provider_header) = parts
            .headers
            .get("X-Identity-Provider")
            .and_then(|v| v.to_str().ok())
        {
            let provider_id = provider_header.trim().to_string();

            if provider_id.is_empty() {
                return Err(ExtractionError::MissingProviderContext);
            }

            // Also extract the original token if present (for token-forwarding scenarios)
            let original_token = parts
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty());

            debug!(
                provider_id = %provider_id,
                source = "header",
                has_token = original_token.is_some(),
                "IdentityContext extracted from X-Identity-Provider header"
            );

            return Ok(Self(IdentityContext {
                provider_id,
                source: ProviderSource::Header,
                original_token,
            }));
        }

        // Priority 2: Path prefix extraction (/auth/:provider_id/...)
        // The path is available in parts.uri.path()
        let path = parts.uri.path();

        // Match pattern: /auth/<provider_id>/...
        if let Some(provider_id) = extract_provider_from_path(path) {
            // Also extract the original token if present
            let original_token = parts
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty());

            debug!(
                provider_id = %provider_id,
                source = "path",
                path = path,
                has_token = original_token.is_some(),
                "IdentityContext extracted from URL path prefix"
            );

            return Ok(Self(IdentityContext {
                provider_id,
                source: ProviderSource::PathPrefix,
                original_token,
            }));
        }

        // No provider context found
        warn!(
            path = path,
            has_auth_header = parts.headers.get(header::AUTHORIZATION).is_some(),
            "IdentityAuthExtractor: no provider context found in request"
        );

        Err(ExtractionError::MissingProviderContext)
    }
}

/// Extract provider ID from URL path matching pattern `/auth/<provider_id>/...`.
///
/// Supports patterns like:
/// - `/auth/azure-ad/callback` -> `Some("azure-ad")`
/// - `/auth/keycloak/login` -> `Some("keycloak")`
/// - `/api/users` -> `None`
/// - `/auth/` -> `None` (empty provider segment)
fn extract_provider_from_path(path: &str) -> Option<String> {
    // Split path into segments
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // Look for pattern: ["auth", "<provider_id>", ...]
    if segments.len() >= 2 && segments[0] == "auth" {
        let provider_id = segments[1].trim();

        // Reject empty provider IDs
        if !provider_id.is_empty() && !provider_id.contains('.') {
            // Basic sanitization: only allow alphanumeric, hyphens, underscores
            if provider_id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                return Some(provider_id.to_string());
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Posture-Aware Extractor (ZT-7 Device Proofing)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "axum", feature = "posture"))]
pub mod posture_extractor;

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests;
