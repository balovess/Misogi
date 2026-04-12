//! OIDC (OpenID Connect) Identity Provider Plugin.
//!
//! Provides [`OidcIdentityProvider`] implementing [`IdentityProvider`] trait
//! for OAuth 2.0 / OpenID Connect Authorization Code flow with PKCE support.

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::oidc_provider::{
    self, OidcAuthProvider, OidcConfig as CoreOidcConfig, OidcError, OidcUserInfo,
};
use crate::provider::{AuthRequest, IdentityError, IdentityProvider, MisogiIdentity};

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Encode bytes as base64url string without padding (RFC 4648 §5).
///
/// Uses URL-safe alphabet: `[A-Za-z0-9_-]` with no `=` padding.
fn base64_url_encode(data: &[u8]) -> String {
    let encoded = general_purpose::STANDARD.encode(data);
    // Convert to URL-safe: '+' → '-', '/' → '_', remove padding
    encoded
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`OidcIdentityProvider`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    /// Base URL of the OIDC issuer (used for OpenID Connect Discovery).
    pub issuer_url: String,
    /// OAuth2 client identifier registered with the OIDC provider.
    pub client_id: String,
    /// OAuth2 client secret (confidential client).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    /// Registered redirect URI (must match IdP registration exactly).
    pub redirect_uri: String,
    /// Requested OAuth2/OIDC scopes. Must include `"openid"`.
    pub scopes: Vec<String>,
    /// Override UserInfo endpoint URL.
    pub userinfo_endpoint: Option<String>,
    /// Override token endpoint URL.
    pub token_endpoint: Option<String>,
    /// Override authorization endpoint URL.
    pub authorization_endpoint: Option<String>,
    /// Enable PKCE (Proof Key for Code Exchange, RFC 7636).
    #[serde(default = "default_pkce")]
    pub pkce: bool,
}

fn default_pkce() -> bool {
    true
}

impl OidcProviderConfig {
    /// Create configuration for Okta Identity Cloud.
    pub fn okta_config(domain: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            issuer_url: format!("https://{domain}"),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_uri: String::new(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            userinfo_endpoint: None,
            token_endpoint: None,
            authorization_endpoint: None,
            pkce: true,
        }
    }

    /// Create configuration for Google Identity Platform.
    pub fn google_config(client_id: &str, client_secret: &str) -> Self {
        Self {
            issuer_url: "https://accounts.google.com".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: String::new(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            userinfo_endpoint: None,
            token_endpoint: None,
            authorization_endpoint: None,
            pkce: true,
        }
    }

    /// Create configuration for Microsoft Azure AD (Entra ID).
    pub fn azure_ad_config(tenant_id: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            issuer_url: format!("https://login.microsoftonline.com/{tenant_id}/v2.0"),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: String::new(),
            scopes: vec!["openid".into(), "profile".into(), "email".into(), "offline_access".into()],
            userinfo_endpoint: None,
            token_endpoint: None,
            authorization_endpoint: None,
            pkce: true,
        }
    }

    /// Create configuration for Keycloak Identity Provider.
    pub fn keycloak_config(server_url: &str, realm: &str, client_id: &str, client_secret: &str) -> Self {
        let base = server_url.trim_end_matches('/');
        Self {
            issuer_url: format!("{base}/realms/{realm}"),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: String::new(),
            scopes: vec!["openid".into(), "profile".into(), "email".into(), "roles".into()],
            userinfo_endpoint: None,
            token_endpoint: None,
            authorization_endpoint: None,
            pkce: true,
        }
    }

    /// Create configuration for Japan G-Cloud (Government Cloud) IdP.
    pub fn gcloud_japan_config(client_id: &str, client_secret: &str) -> Self {
        Self {
            issuer_url: "https://gcloud-japan.go.jp/idp".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: String::new(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            userinfo_endpoint: None,
            token_endpoint: None,
            authorization_endpoint: None,
            pkce: true,
        }
    }

    /// Convert to core [`CoreOidcConfig`] used by [`OidcAuthProvider`].
    fn to_core_config(&self) -> CoreOidcConfig {
        CoreOidcConfig {
            discovery_url: self.issuer_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scopes: self.scopes.clone(),
            pkce: self.pkce,
            jwks_ttl: Some(Duration::from_secs(3600)),
            nonce_validity_seconds: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// Provider Implementation
// ---------------------------------------------------------------------------

/// OIDC Identity Provider implementing [`IdentityProvider`] trait.
///
/// Wraps [`OidcAuthProvider`] and adapts it to the Misogi auth plugin interface.
/// Handles complete OAuth 2.0 Authorization Code flow with PKCE support.
pub struct OidcIdentityProvider {
    config: OidcProviderConfig,
    core: Arc<OidcAuthProvider>,
    provider_id: String,
    provider_name: String,
}

impl OidcIdentityProvider {
    /// Create a new OIDC identity provider instance.
    ///
    /// No network calls at construction. Call [`discover`](Self::discover) first.
    pub fn new(config: OidcProviderConfig) -> Result<Self, IdentityError> {
        if config.issuer_url.is_empty() {
            return Err(IdentityError::ConfigurationError("issuer_url is required".into()));
        }
        if config.client_id.is_empty() {
            return Err(IdentityError::ConfigurationError("client_id is required".into()));
        }
        if config.client_secret.is_empty() {
            return Err(IdentityError::ConfigurationError("client_secret is required".into()));
        }

        let provider_id = Self::build_provider_id(&config.issuer_url, &config.client_id);
        let provider_name = format!("OIDC ({})", config.issuer_url);
        let core = Arc::new(OidcAuthProvider::new(config.to_core_config()));

        info!(provider_id = %provider_id, issuer = %config.issuer_url, pkce = config.pkce, "OidcIdentityProvider created");

        Ok(Self { config, core, provider_id, provider_name })
    }

    /// Perform OpenID Connect Discovery against the configured issuer.
    ///
    /// **Must be called before** [`authenticate`](Self::authenticate).
    pub async fn discover(&self) -> Result<(), IdentityError> {
        debug!(issuer = %self.config.issuer_url, "Starting OIDC discovery");
        self.core.discover().await.map_err(|e: OidcError| match e {
            OidcError::DiscoveryFailed(m) => IdentityError::ProviderUnavailable(m),
            OidcError::InvalidMetadata(m) => IdentityError::ConfigurationError(m),
            OidcError::HttpError(m) => IdentityError::ProviderUnavailable(m),
            other => IdentityError::InternalError(other.to_string()),
        })?;
        info!(issuer = %self.config.issuer_url, "OIDC discovery completed");
        Ok(())
    }

    /// Generate a PKCE code_verifier and code_challenge pair.
    ///
    /// Returns `(code_verifier, code_challenge)` where verifier is 43-128 chars
    /// of `[A-Za-z0-9-.~]` and challenge is base64url-encoded SHA-256 hash.
    ///
    /// Implements RFC 7636 S256 (SHA-256) challenge method.
    pub fn generate_pkce_pair() -> (String, String) {
        let verifier = oidc_provider::generate_code_verifier();
        let challenge = Self::compute_code_challenge_s256(&verifier);
        (verifier, challenge)
    }

    /// Compute PKCE code_challenge using S256 method (RFC 7636 §4.2).
    ///
    /// Returns `BASE64URL(SHA256(code_verifier))` without padding.
    fn compute_code_challenge_s256(code_verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();
        // Base64url encode without padding
        base64_url_encode(&hash)
    }

    /// Build a stable, DNS-safe provider ID from issuer and client_id.
    fn build_provider_id(issuer_url: &str, client_id: &str) -> String {
        let host = issuer_url
            .strip_prefix("https://")
            .or_else(|| issuer_url.strip_prefix("http://"))
            .unwrap_or(issuer_url)
            .split('/')
            .next()
            .unwrap_or(issuer_url)
            .replace(['.', ':', '_'], "-");
        format!("oidc-{host}-{client_id}")
    }

    /// Map OIDC UserInfo claims to [`MisogiIdentity`].
    ///
    /// | Field | Source |
    /// |-------|--------|
    /// | `applicant_id` | `userinfo.sub` |
    /// | `display_name` | `name` → `preferred_username` → `email` |
    /// | `idp_source` | `"oidc"` |
    /// | `original_subject` | `userinfo.sub` |
    fn map_to_identity(userinfo: &OidcUserInfo) -> MisogiIdentity {
        let display_name = if !userinfo.name.is_empty() {
            Some(userinfo.name.clone())
        } else {
            userinfo.preferred_username.clone().or_else(|| userinfo.email.clone())
        };

        let mut extra: HashMap<String, serde_json::Value> = HashMap::new();
        extra.insert("sub".into(), serde_json::Value::String(userinfo.sub.clone()));
        if let Some(ref e) = userinfo.email {
            extra.insert("email".into(), serde_json::Value::String(e.clone()));
        }
        if let Some(ref u) = userinfo.preferred_username {
            extra.insert("preferred_username".into(), serde_json::Value::String(u.clone()));
        }
        if !userinfo.name.is_empty() {
            extra.insert("name".into(), serde_json::Value::String(userinfo.name.clone()));
        }

        MisogiIdentity {
            applicant_id: userinfo.sub.clone(),
            display_name,
            roles: Vec::new(),
            idp_source: "oidc".into(),
            original_subject: Some(userinfo.sub.clone()),
            extra,
        }
    }

    /// Convert internal [`OidcError`] to public [`IdentityError`].
    fn map_oidc_error(err: OidcError) -> IdentityError {
        match err {
            OidcError::TokenExchangeFailed(m) => IdentityError::TokenExchangeFailed(m),
            OidcError::DiscoveryFailed(_) | OidcError::NotDiscovered => {
                IdentityError::ProviderUnavailable(err.to_string())
            }
            OidcError::InvalidMetadata(_) | OidcError::UrlBuildFailed(_) => {
                IdentityError::ConfigurationError(err.to_string())
            }
            OidcError::HttpError(m) => IdentityError::ProviderUnavailable(m),
            OidcError::UserInfoFailed(m) => {
                IdentityError::AuthenticationFailed(format!("UserInfo failed: {m}"))
            }
            OidcError::IdTokenValidationFailed(m) => {
                warn!(error = %m, "ID token validation failed");
                IdentityError::AuthenticationFailed(format!("ID token invalid: {m}"))
            }
            other => IdentityError::InternalError(other.to_string()),
        }
    }
}

#[async_trait]
impl IdentityProvider for OidcIdentityProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn provider_name(&self) -> &str {
        &self.provider_name
    }

    async fn authenticate(&self, input: AuthRequest) -> Result<MisogiIdentity, IdentityError> {
        // Only AuthorizationCode flow is supported for OIDC
        let AuthRequest::AuthorizationCode { code, redirect_uri, code_verifier } = input else {
            return Err(IdentityError::AuthenticationFailed(
                "OIDC only supports AuthorizationCode flow".into(),
            ));
        };

        info!(provider_id = %self.provider_id, has_pkce = code_verifier.is_some(), "Processing OIDC auth");

        // Validate redirect URI matches configuration
        if !redirect_uri.is_empty() && redirect_uri != self.config.redirect_uri {
            return Err(IdentityError::AuthenticationFailed(
                "redirect_uri mismatch".into(),
            ));
        }

        // PKCE requirement check
        let verifier = if self.config.pkce {
            code_verifier.ok_or_else(|| {
                warn!("PKCE required but no verifier");
                IdentityError::AuthenticationFailed("PKCE code_verifier missing".into())
            })?
        } else {
            code_verifier.unwrap_or_default()
        };

        // Step 1: Exchange authorization code for tokens
        debug!("Exchanging authorization code for tokens");
        let tokens = self
            .core
            .exchange_code(&code, &verifier)
            .await
            .map_err(Self::map_oidc_error)?;

        info!(
            has_id_token = tokens.id_token.is_some(),
            has_refresh_token = tokens.refresh_token.is_some(),
            expires_in = tokens.expires_in,
            "Token exchange successful"
        );

        // Step 2: Validate ID token if present
        if let Some(ref idt) = tokens.id_token {
            debug!("Validating ID token");
            self.core.validate_id_token(idt).await.map_err(Self::map_oidc_error)?;
            debug!("ID token validated successfully");
        } else {
            warn!("No ID token in response — proceeding with access token only");
        }

        // Step 3: Fetch UserInfo using access token
        debug!("Fetching UserInfo from IdP");
        let ui = self.core.get_userinfo(&tokens.access_token).await.map_err(Self::map_oidc_error)?;
        info!(sub = %ui.sub, "UserInfo retrieved");

        // Step 4: Map to MisogiIdentity
        Ok(Self::map_to_identity(&ui))
    }

    async fn health_check(&self) -> Result<(), IdentityError> {
        debug!(provider_id = %self.provider_id, "Performing OIDC health check");

        // Verify provider configuration is valid
        if self.config.issuer_url.is_empty() {
            return Err(IdentityError::ConfigurationError("issuer_url is empty".into()));
        }
        if self.config.client_id.is_empty() {
            return Err(IdentityError::ConfigurationError("client_id is empty".into()));
        }

        // Attempt discovery to verify connectivity (idempotent if already discovered)
        match self.core.discover().await {
            Ok(_) => {
                debug!(issuer = %self.config.issuer_url, "OIDC health check passed");
                Ok(())
            }
            Err(e) => {
                // Map discovery errors to appropriate health check errors
                match e {
                    OidcError::DiscoveryFailed(m) => {
                        warn!(error = %m, "OIDC health check failed: discovery");
                        Err(IdentityError::ProviderUnavailable(m))
                    }
                    OidcError::HttpError(m) => {
                        warn!(error = %m, "OIDC health check failed: network");
                        Err(IdentityError::ProviderUnavailable(m))
                    }
                    other => {
                        warn!(error = %other, "OIDC health check failed: unexpected");
                        Err(IdentityError::InternalError(other.to_string()))
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (24 tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_rejects_missing_issuer() {
        let mut cfg = test_cfg();
        cfg.issuer_url.clear();
        assert!(matches!(
            OidcIdentityProvider::new(cfg),
            Err(IdentityError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_new_rejects_missing_client_id() {
        let mut cfg = test_cfg();
        cfg.client_id.clear();
        assert!(matches!(
            OidcIdentityProvider::new(cfg),
            Err(IdentityError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_new_rejects_missing_client_secret() {
        let mut cfg = test_cfg();
        cfg.client_secret.clear();
        assert!(matches!(
            OidcIdentityProvider::new(cfg),
            Err(IdentityError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_new_accepts_valid_config() {
        let p = OidcIdentityProvider::new(test_cfg()).unwrap();
        assert!(p.provider_id().starts_with("oidc-"));
        assert!(p.provider_name().contains("OIDC"));
    }

    // ===================================================================
    // Test: Built-in Provider Configurations
    // ===================================================================

    #[test]
    fn test_okta_config() {
        let c = OidcProviderConfig::okta_config("x.okta.com", "cid", "sec");
        assert_eq!(c.issuer_url, "https://x.okta.com");
        assert!(c.pkce);
        assert_eq!(c.scopes.len(), 3);
    }

    #[test]
    fn test_google_config() {
        let c = OidcProviderConfig::google_config("g", "s");
        assert_eq!(c.issuer_url, "https://accounts.google.com");
        assert!(c.pkce);
    }

    #[test]
    fn test_azure_ad_config() {
        let c = OidcProviderConfig::azure_ad_config("t", "c", "s");
        assert!(c.issuer_url.contains("microsoftonline"));
        assert!(c.scopes.contains(&"offline_access".into()));
    }

    #[test]
    fn test_keycloak_config() {
        let c = OidcProviderConfig::keycloak_config("http://k:8080", "r", "c", "s");
        assert_eq!(c.issuer_url, "http://k:8080/realms/r");
        assert!(c.scopes.contains(&"roles".into()));
    }

    #[test]
    fn test_gcloud_japan_config() {
        let c = OidcProviderConfig::gcloud_japan_config("c", "s");
        assert!(c.issuer_url.contains("gcloud-japan"));
        assert!(c.pkce);
    }

    // ===================================================================
    // Test: PKCE Support
    // ===================================================================

    #[test]
    fn test_pkce_lengths() {
        let (v, c) = OidcIdentityProvider::generate_pkce_pair();
        // RFC 7636: verifier MUST be 43-128 characters
        assert!(v.len() >= 43 && v.len() <= 128);
        // Challenge is base64url-encoded SHA-256 (43 chars, no padding)
        assert_eq!(c.len(), 43);
    }

    #[test]
    fn test_pkce_unique() {
        let (v1, c1) = OidcIdentityProvider::generate_pkce_pair();
        let (v2, c2) = OidcIdentityProvider::generate_pkce_pair();
        assert_ne!(v1, v2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pkce_safe_chars() {
        let (v, _) = OidcIdentityProvider::generate_pkce_pair();
        // Verifier uses base64url encoding: [A-Za-z0-9_-]
        // Per RFC 7636 §4.1, verifier MUST be URL-safe with no padding
        for ch in v.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "Invalid character '{ch}' in PKCE verifier"
            );
        }
    }

    // ===================================================================
    // Test: Identity Mapping
    // ===================================================================

    #[test]
    fn test_map_identity_full() {
        let ui = OidcUserInfo {
            sub: "s1".into(),
            name: "N".into(),
            email: Some("e@e".into()),
            preferred_username: Some("u".into()),
        };
        let id = OidcIdentityProvider::map_to_identity(&ui);
        assert_eq!(id.applicant_id, "s1");
        assert_eq!(id.display_name.as_deref(), Some("N"));
        assert_eq!(id.idp_source, "oidc");
    }

    #[test]
    fn test_map_identity_fallback_to_preferred() {
        let ui = OidcUserInfo {
            sub: "s2".into(),
            name: "".into(),
            email: Some("e".into()),
            preferred_username: Some("pu".into()),
        };
        assert_eq!(
            OidcIdentityProvider::map_to_identity(&ui).display_name.as_deref(),
            Some("pu")
        );
    }

    #[test]
    fn test_map_identity_fallback_to_email() {
        let ui = OidcUserInfo {
            sub: "s3".into(),
            name: "".into(),
            email: Some("em".into()),
            preferred_username: None,
        };
        assert_eq!(
            OidcIdentityProvider::map_to_identity(&ui).display_name.as_deref(),
            Some("em")
        );
    }

    #[test]
    fn test_map_identity_none_when_all_empty() {
        let ui = OidcUserInfo {
            sub: "s4".into(),
            name: "".into(),
            email: None,
            preferred_username: None,
        };
        assert!(OidcIdentityProvider::map_to_identity(&ui).display_name.is_none());
    }

    // ===================================================================
    // Test: Error Mapping
    // ===================================================================

    #[test]
    fn test_err_map_token_exchange() {
        assert!(matches!(
            OidcIdentityProvider::map_oidc_error(OidcError::TokenExchangeFailed("x".into())),
            IdentityError::TokenExchangeFailed(_)
        ));
    }

    #[test]
    fn test_err_map_discovery() {
        assert!(matches!(
            OidcIdentityProvider::map_oidc_error(OidcError::DiscoveryFailed("x".into())),
            IdentityError::ProviderUnavailable(_)
        ));
    }

    #[test]
    fn test_err_map_metadata() {
        assert!(matches!(
            OidcIdentityProvider::map_oidc_error(OidcError::InvalidMetadata("x".into())),
            IdentityError::ConfigurationError(_)
        ));
    }

    // ===================================================================
    // Test: Unsupported Auth Flow Rejection
    // ===================================================================

    #[tokio::test]
    async fn test_reject_credentials_flow() {
        let p = OidcIdentityProvider::new(test_cfg()).unwrap();
        assert!(p
            .authenticate(AuthRequest::Credentials {
                username: "u".into(),
                password: "p".into(),
            })
            .await
            .is_err());
    }

    // ===================================================================
    // Test: PKCE Verification Requirement
    // ===================================================================

    #[tokio::test]
    async fn test_reject_missing_pkce() {
        let mut c = test_cfg();
        c.pkce = true;
        let p = OidcIdentityProvider::new(c).unwrap();
        assert!(p
            .authenticate(AuthRequest::AuthorizationCode {
                code: "c".into(),
                redirect_uri: "r".into(),
                code_verifier: None,
            })
            .await
            .is_err());
    }

    // ===================================================================
    // Test: Provider ID Generation
    // ===================================================================

    #[test]
    fn test_provider_id_format() {
        let id = OidcIdentityProvider::build_provider_id("https://a.b.com", "cli");
        assert!(id.starts_with("oidc-") && id.ends_with("cli") && id.contains("a-b-com"));
    }

    #[test]
    fn test_provider_id_sanitizes_chars() {
        let id = OidcIdentityProvider::build_provider_id("https://x.y_z:8080/p", "c");
        assert!(!id.contains('.') && !id.contains(':') && !id.contains('_'));
    }

    // ===================================================================
    // Test: Redirect URI Mismatch Detection
    // ===================================================================

    #[tokio::test]
    async fn test_redirect_mismatch() {
        let mut c = test_cfg();
        c.redirect_uri = "https://good/cb".into();
        c.pkce = false;
        let p = OidcIdentityProvider::new(c).unwrap();
        assert!(p
            .authenticate(AuthRequest::AuthorizationCode {
                code: "c".into(),
                redirect_uri: "https://bad/cb".into(),
                code_verifier: Some("v".into()),
            })
            .await
            .is_err());
    }

    /// Helper: create a valid test config with minimal required fields.
    fn test_cfg() -> OidcProviderConfig {
        OidcProviderConfig {
            issuer_url: "https://example.com".into(),
            client_id: "t".into(),
            client_secret: "s".into(),
            redirect_uri: "https://r.com/cb".into(),
            scopes: vec!["openid".into()],
            userinfo_endpoint: None,
            token_endpoint: None,
            authorization_endpoint: None,
            pkce: false,
        }
    }
}
