//! Identity Provider Plugins — Pluggable Authentication Backends
//!
//! Contains concrete implementations of [`IdentityProvider`](super::provider::IdentityProvider)
//! trait for various authentication protocols. Each plugin is self-contained, feature-gated,
//! and conforms to Misogi''s Ultimate Pluggable Architecture (終極可插拔架構).
//!
//! # Available Plugins
//!
//! | Plugin       | Feature Flag | Protocol                  |
//! |--------------|-------------|---------------------------|
//! | `ldap`       | `ldap`      | LDAP v3 / Active Directory|
//! | `oidc`       | `oidc`      | OpenID Connect / OAuth 2.0|
//! | `saml`       | `saml`      | SAML 2.0 Web Browser SSO |
//!
//! # Plugin Contract
//!
//! Every plugin in this module MUST:
//! - Implement [`IdentityProvider`](super::provider::IdentityProvider) trait fully
//! - Return [`MisogiIdentity`](super::provider::MisogiIdentity) on successful auth
//! - Map protocol-specific errors to [`IdentityError`](super::provider::IdentityError) variants
//! - Set `idp_source` to a stable, unique identifier (e.g., `"ldap"`, `"oidc-keycloak"`)
//! - Be thread-safe (`Send + Sync`) for use in async multi-task contexts
//!
//! # Japanese Government Compatibility
//!
//! All plugins support Japan-specific requirements:
//! - Shift-JIS encoding for legacy directory attributes
//! - G-Cloud / Prefectural IdP integration patterns
//! - 総務省 (Ministry of Internal Affairs) security compliance

/// LDAP v3 / Active Directory identity provider plugin.
///
/// Implements [`IdentityProvider`] using ldap3 crate with connection pooling,
/// service-account bind pattern, and configurable attribute mappings.
/// Supports Japanese government LDAP quirks (Shift-JIS encoding, legacy schema).
#[cfg(feature = "ldap")]
pub mod ldap;

/// OIDC (OpenID Connect) identity provider plugin.
///
/// Implements [`IdentityProvider`] for OAuth 2.0 Authorization Code flow with PKCE support.
/// Compatible with Keycloak, Okta, Azure AD, Google, and G-Cloud Japan IdPs.
#[cfg(feature = "oidc")]
pub mod oidc;

/// SAML 2.0 identity provider plugin.
///
/// Implements [`IdentityProvider`] for SAML 2.0 Web Browser SSO (POST binding).
/// Supports XML signature verification, condition validation, and G-Cloud Japan
/// OID attribute name mappings (e.g., `urn:oid:2.5.4.42` for givenName).
#[cfg(feature = "saml")]
pub mod saml;
