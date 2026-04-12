//! Misogi Authentication Crate — Enterprise-Grade Auth for LGWAN File Transfer
//!
//! Provides a comprehensive authentication and authorization system supporting
//! multiple enterprise identity providers:
//!
//! - **JWT (RS256)**: Asymmetric signed tokens with configurable TTL and key management
//! - **LDAP / Active Directory**: Service-account-based authentication with group-to-role mapping
//! - **OIDC / OAuth 2.0**: Authorization Code flow with PKCE support (Keycloak, Okta, Azure AD)
//! - **SAML 2.0**: Structural stub for IdP integration (full implementation pending)
//! - **Fine-grained RBAC**: Role-based access control with 9 discrete permission actions
//! - **Middleware**: gRPC interceptors and Axum HTTP extractors
//!
//! # Feature Flags
//!
//! | Feature     | Description                              | Dependencies         |
//! |-------------|------------------------------------------|----------------------|
//! | `jwt`       | RS256 JWT issuance and validation         | jsonwebtoken, ring   |
//! | `ldap`      | LDAP/Active Directory integration         | ldap3                |
//! | `oidc`      | OIDC/OAuth2 Authorization Code flow       | reqwest              |
//! | `saml`      | SAML 2.0 SP structural stub               | (none)               |
//! | `enterprise`| Enable all auth backends (jwt+ldap+oidc)  | all of above         |
//!
//! # Quick Start (JWT-only)
//!
//! ```ignore
//! use misogi_auth::jwt::{JwtAuthenticator, JwtConfig};
//! use misogi_auth::models::User;
//!
//! // Generate RSA keypair (one-time setup)
//! misogi_auth::jwt::JwtAuthenticator::generate_keypair("./keys")?;
//!
//! // Create authenticator
//! let config = JwtConfig {
//!     issuer: "misogi-auth".to_string(),
//!     audience: "misogi-api".to_string(),
//!     rsa_pem_path: "./keys/private.pem".into(),
//!     rsa_pub_pem_path: "./keys/public.pem".into(),
//!     ttl_hours: 8,
//!     refresh_ttl_hours: 168,
//! };
//! let auth = JwtAuthenticator::new(config)?;
//!
//! // Issue token for user
//! let user = User::staff("001", "田中太郎");
//! let token = auth.issue_token(&user)?;
//! println!("Bearer: {}", token.jws);
//!
//! // Validate incoming request token
//! let claims = auth.validate_token(&token.jws)?;
//! assert_eq!(claims.sub, "001");
//! ```

// --- Core modules (always available) ---
pub mod claims;
pub mod models;
pub mod provider;
pub mod role;
pub mod store;

// --- Enterprise authentication modules (feature-gated) ---

/// RS256 JWT authentication module.
///
/// Provides asymmetric key management, token issuance, and signature verification.
/// Requires the `jwt` or `enterprise` feature flag.
#[cfg(feature = "jwt")]
pub mod jwt;

/// LDAP / Active Directory authentication provider.
///
/// Integrates with enterprise directory services for user authentication
/// and role resolution via group membership. Requires the `ldap` or `enterprise`
/// feature flag.
#[cfg(feature = "ldap")]
pub mod ldap_provider;

/// OpenID Connect / OAuth 2.0 authentication provider.
///
/// Implements Authorization Code flow with PKCE support for integration with
/// modern identity providers (Keycloak, Okta, Azure AD, etc.).
/// Requires the `oidc` or `enterprise` feature flag.
#[cfg(feature = "oidc")]
pub mod oidc_provider;

/// SAML 2.0 Service Provider — full protocol implementation with Japan IdP support.
///
/// Implements the complete SAML 2.0 Web Browser SSO Profile using pure Rust
/// (quick_xml + ring + flate2). Supports G-Cloud, Prefectural, and enterprise IdPs.
/// Requires the `saml` feature flag.
#[cfg(feature = "saml")]
pub mod saml_provider;

/// Authentication middleware for gRPC interceptors and Axum HTTP extractors.
///
/// Provides unified [`AuthEngine`](engine::AuthEngine) that combines JWT validation,
/// optional pluggable identity providers via [`IdentityRegistry`](registry::IdentityRegistry),
/// and API key management into a single authentication interface suitable for
/// both gRPC and REST APIs.
///
/// **Note**: Core types are now defined in [`engine`] module. This module
/// re-exports them for backward compatibility. New code should import from
/// `misogi_auth::engine::*` directly.
pub mod middleware;

/// Pluggable identity provider registry for runtime provider management.
///
/// Provides [`IdentityRegistry`](registry::IdentityRegistry) for dynamically
/// registering, looking up, and dispatching to [`IdentityProvider`](provider::IdentityProvider)
/// implementations (LDAP, OIDC, SAML, etc.).
pub mod registry;

/// Micro-kernel authentication engine — slim core with JWT + optional IdentityRegistry.
///
/// Contains the refactored [`AuthEngine`](engine::AuthEngine) that holds:
/// - [`JwtValidator`](jwt::JwtValidator) for RS256 token verification
/// - Optional [`IdentityRegistry`](registry::IdentityRegistry) for external IdPs
/// - API key store for service accounts
/// - Bounded audit log ring buffer
///
/// This is the **recommended** import path for new code.
///
/// # Example
///
/// ```ignore
/// use misogi_auth::engine::{AuthEngine, AuthError};
/// use misogi_auth::registry::IdentityRegistry;
/// ```
pub mod engine;

/// Axum HTTP Extractors — Micro-Kernel Architecture (Phase 7).
///
/// Provides extractor implementations that use the new micro-kernel architecture:
///
/// - **[`extractors::JwtAuthExtractor`]**: Validates ONLY Misogi-issued JWTs via `JwtValidator`
///   - Rejects external IdP tokens with clear error code (`external_identity_token`)
///   - Requires `axum::Extension<Arc<JwtValidator>>` as router layer
///   - Error format: `{ "error": "...", "message": "...", "status_code": 401 }`
///
/// - **[`extractors::IdentityAuthExtractor`]**: Extracts provider context for delegated auth
///   - Reads `X-Identity-Provider` header or path prefix `/auth/:provider_id/...`
///   - Passes context to handler for provider-specific processing
///
/// # Migration from Legacy Middleware
///
/// The legacy `middleware::JwtAuthExtractor` is still available for backward compatibility.
/// New code should use `extractors::JwtAuthExtractor` which uses `JwtValidator` directly
/// instead of going through `AuthEngine`.
#[cfg(feature = "axum")]
pub mod extractors;

/// gRPC Interceptors — Micro-Kernel Architecture (Phase 7).
///
/// Provides tonic-compatible interceptors for gRPC service authentication:
///
/// - **[`grpc_interceptors::JwtGrpcInterceptor`]**: Validates Misogi-issued JWTs via `JwtValidator`
///   - Returns `UNAUTHENTICATED` status on all authentication failures
///   - Inserts validated `MisogiClaims` into request extensions
///   - Rejects external IdP tokens with clear error message
///
/// # Usage Example
///
/// ```ignore
/// use tonic::transport::Server;
/// use misogi_auth::grpc_interceptors::create_jwt_grpc_interceptor;
/// use std::sync::Arc;
///
/// let validator = Arc::new(JwtValidator::new(config)?);
/// let interceptor = create_jwt_grpc_interceptor(validator);
///
/// Server::builder()
///     .interceptor(interceptor)
///     .add_service(my_service)
///     .serve(addr)
///     .await?;
/// ```
#[cfg(feature = "grpc")]
pub mod grpc_interceptors;

/// Identity Provider Plugins — pluggable [`IdentityProvider`] implementations.
///
/// Contains protocol-specific adapters for LDAP, OIDC, SAML, etc.
/// Each plugin implements the `IdentityProvider` trait and can be
/// registered with [`AuthEngine`](middleware::AuthEngine).
///
/// Part of Misogi's Ultimate Pluggable Architecture (終極可插拔架構).
#[cfg(any(feature = "ldap", feature = "oidc", feature = "saml"))]
pub mod plugins;

// --- Re-exports: Core types (always available) ---
pub use claims::MisogiClaims;
pub use models::{SessionToken, User};
pub use provider::{AuthRequest, IdentityError, IdentityProvider, MisogiIdentity};
pub use role::{PermissionAction, Permissions, UserRole};
pub use store::UserStore;

// --- Re-exports: JWT types ---
#[cfg(feature = "jwt")]
pub use jwt::{
    JwtAuthenticator, JwtConfig, JwtError, JwtToken, ValidatedClaims,
    JwtIssuer, JwtValidator, ValidatedToken,
};

// --- Re-exports: LDAP types ---
#[cfg(feature = "ldap")]
pub use ldap_provider::{LdapAuthProvider, LdapConfig, LdapError, LdapUser};

// --- Re-exports: OIDC types ---
#[cfg(feature = "oidc")]
pub use oidc_provider::{
    azure_ad_config, generate_code_verifier, generate_random_state,
    gcloud_japan_config, keycloak_config, okta_config,
    OidcAuthProvider, OidcConfig, OidcError, OidcMetadata, OidcTokens,
    OidcUserInfo, ValidatedIdToken,
};

// --- Re-exports: SAML types ---
#[cfg(feature = "saml")]
pub use saml_provider::{SamlAuthProvider, SamlAttributes, SamlConfig, SamlError, SamlIdpMetadata};

// --- Re-exports: Middleware types ---
pub use middleware::{AuthEngine, AuthError, ServiceAccount};
/// Re-export: Identity Registry types for provider management.
pub use registry::{IdentityRegistry, ProviderInfo};

// --- Re-exports: Plugin types ---
#[cfg(any(feature = "ldap", feature = "oidc"))]
pub use plugins::ldap::{LdapAttributeMappings, LdapIdentityProvider, LdapPluginConfig};

#[cfg(feature = "oidc")]
pub use plugins::oidc::{OidcIdentityProvider, OidcProviderConfig};

/// SAML 2.0 identity provider plugin types.
///
/// Re-exports from [`plugins::saml`] module for convenient access.
#[cfg(feature = "saml")]
pub use plugins::saml::{
    NameIdFormat, SamlAttributeMappings, SamlIdentityProvider, SamlPluginConfig,
};

/// API key extractor for Axum handlers (requires `axum` feature).
#[cfg(feature = "axum")]
pub use middleware::ApiKeyExtractor;

/// JWT extractor for Axum handlers (requires both `jwt` and `axum` features).
///
/// **Legacy**: This re-exports the old `middleware::JwtAuthExtractor`.
/// For new code using micro-kernel architecture, use `extractors::JwtAuthExtractor`
/// which uses [`JwtValidator`](jwt::JwtValidator) directly.
#[cfg(all(feature = "jwt", feature = "axum"))]
pub use middleware::JwtAuthExtractor;

// --- Re-exports: New Micro-Kernel Extractors (Phase 7) ---

/// Misogi-only JWT extractor for Axum handlers (micro-kernel architecture).
///
/// Uses [`JwtValidator`](jwt::JwtValidator) directly instead of [`AuthEngine`](middleware::AuthEngine).
/// Rejects external IdP tokens with `external_identity_token` error code.
///
/// Requires both `jwt` and `axum` feature flags.
#[cfg(all(feature = "jwt", feature = "axum"))]
pub use extractors::{ExtractionError, IdentityAuthExtractor, JwtAuthExtractor as MicroKernelJwtExtractor};

/// Provider context extractor for delegated authentication flows.
///
/// Extracts identity provider ID from `X-Identity-Provider` header or URL path prefix.
#[cfg(feature = "axum")]
pub use extractors::{IdentityContext, ProviderSource};

/// gRPC interceptor for Misogi-issued JWT validation (micro-kernel architecture).
///
/// Uses [`JwtValidator`](jwt::JwtValidator) directly. Returns `UNAUTHENTICATED` on failure.
#[cfg(all(feature = "grpc", feature = "jwt"))]
pub use grpc_interceptors::{
    create_jwt_grpc_interceptor, JwtGrpcInterceptor,
};

// ---------------------------------------------------------------------------
// Prelude — convenient re-export for common patterns
// ---------------------------------------------------------------------------

/// Prelude module with commonly used types.
///
/// Import with `use misogi_auth::prelude::*;` to get quick access to core types.
pub mod prelude {
    pub use super::models::{SessionToken, User};
    pub use super::role::{PermissionAction, Permissions, UserRole};

    #[cfg(feature = "jwt")]
    pub use super::jwt::{
        JwtAuthenticator, JwtConfig, JwtToken, ValidatedClaims,
        JwtIssuer, JwtValidator, ValidatedToken,
    };

    #[cfg(feature = "ldap")]
    pub use super::ldap_provider::{LdapAuthProvider, LdapConfig, LdapUser};

    #[cfg(feature = "oidc")]
    pub use super::oidc_provider::{
        OidcAuthProvider, OidcConfig, OidcTokens, OidcUserInfo,
    };

    #[cfg(feature = "saml")]
    pub use super::saml_provider::{SamlAuthProvider, SamlConfig};

    pub use super::middleware::{AuthEngine, ServiceAccount};

    #[cfg(feature = "ldap")]
    pub use super::plugins::ldap::{
        LdapAttributeMappings, LdapIdentityProvider, LdapPluginConfig,
    };

    #[cfg(feature = "oidc")]
    pub use super::plugins::oidc::{OidcIdentityProvider, OidcProviderConfig};

    #[cfg(feature = "saml")]
    pub use super::plugins::saml::{
        NameIdFormat, SamlAttributeMappings, SamlIdentityProvider, SamlPluginConfig,
    };

    // Micro-kernel architecture types (Phase 7)
    #[cfg(all(feature = "jwt", feature = "axum"))]
    pub use super::extractors::{
        ExtractionError, IdentityAuthExtractor, JwtAuthExtractor,
    };

    #[cfg(feature = "axum")]
    pub use super::extractors::{IdentityContext, ProviderSource};

    #[cfg(all(feature = "grpc", feature = "jwt"))]
    pub use super::grpc_interceptors::{create_jwt_grpc_interceptor, JwtGrpcInterceptor};
}
