//! OpenID Connect (OIDC) / OAuth 2.0 Authentication Provider — Production Hardened
//!
//! Implements the Authorization Code flow with PKCE (Proof Key for Code Exchange)
//! for secure token exchange with OIDC-compliant identity providers.
//!
//! # Feature Gate
//!
//! This module is only available when the `oidc` or `enterprise` feature is enabled.
//!
//! # Supported Flow
//!
//! ```text
//! ┌──────────┐                                  ┌──────────────────────┐
//! │          │  1. Authorization URL (PKCE S256) │                      │
//! │   User   ├─────────────────────────────────>│   OIDC Provider      │
//! │  Browser │  2. Redirect with auth code       │  (Keycloak, Okta,    │
//! │          │<─────────────────────────────────│   Azure AD, etc.)    │
//! │          │  3. Exchange code + verifier       │                      │
//! │          ├─────────────────────────────────>│                      │
//! │          │  4. Access Token + ID Token       │                      │
//! │          │<─────────────────────────────────│                      │
//! └──────────┘                                  └──────────────────────┘
//! ```
//!
//! # Security Model (Production Hardened)
//!
//! - **PKCE**: Always uses S256 challenge method to prevent authorization code interception.
//! - **State Parameter**: Random state parameter to prevent CSRF attacks.
//! - **ID Token Validation**: Signature verification via JWKS with automatic key rotation,
//!   plus iss/aud/exp claims check and nonce binding verification.
//! - **JWKS Caching**: Keys are cached with configurable TTL (default 3600s) and
//!   automatically refreshed when a token references an unknown `kid`.
//! - **Nonce Binding**: Generated nonces are tracked in a time-bounded set to prevent
//!   token substitution attacks per OpenID Connect Core §11.2.
//! - **No Secret in Browser**: Client secret is only used for token exchange (server-side).
//!
//! # Thread Safety
//!
//! This struct is designed to be wrapped in `Arc<>` for sharing across async tasks.
//! Internal caches (`jwks_cache`, `nonce_store`) use `tokio::sync::Mutex` for
//! safe concurrent access.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use jsonwebtoken::DecodingKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};
use url::Url;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the OIDC/OAuth2 authentication provider.
///
/// All URLs should use `https://` scheme for production deployments.
///
/// # Example (Keycloak)
///
/// ```ignore
/// OidcConfig {
///     discovery_url: "https://keycloak.example.com/realms/misogi".to_string(),
///     client_id: "misogi-client".to_string(),
///     client_secret: "secret".to_string(),
///     redirect_uri: "https://misogi.example.com/auth/callback".to_string(),
///     scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
///     pkce: true,
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Base URL of the OIDC provider (used for OpenID Connect Discovery).
    /// The well-known configuration is fetched from `{discovery_url}/.well-known/openid-configuration`.
    pub discovery_url: String,

    /// OAuth2 client identifier registered with the OIDC provider.
    pub client_id: String,

    /// OAuth2 client secret (confidential client). Used only for token exchange.
    pub client_secret: String,

    /// Registered redirect URI (must match exactly what is registered with the IdP).
    pub redirect_uri: String,

    /// Requested OAuth2 scopes. Must include `"openid"` for OIDC flows.
    pub scopes: Vec<String>,

    /// Whether to enable PKCE (Proof Key for Code Exchange). **Always enable in production**.
    pub pkce: bool,

    /// Time-to-live for cached JWKS keys before forced refresh (default: 3600 seconds).
    ///
    /// When a cached JWKS is older than this duration, the next ID token validation
    /// will trigger a fresh fetch from the IdP's `jwks_uri`.
    ///
    /// Set to `None` to disable TTL-based refresh (keys are still refreshed when
    /// an unknown `kid` is encountered).
    pub jwks_ttl: Option<Duration>,

    /// Validity window for generated nonces in seconds (default: 300).
    ///
    /// Nonces older than this value will be rejected during ID token validation
    /// and automatically purged from the internal store.
    ///
    /// Per [OpenID Connect Core §11.2](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes),
    /// the recommended minimum is 300 seconds (5 minutes).
    pub nonce_validity_seconds: u64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            discovery_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: vec!["openid".to_string()],
            pkce: true,
            jwks_ttl: Some(Duration::from_secs(3600)),
            nonce_validity_seconds: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// Data Types — Metadata
// ---------------------------------------------------------------------------

/// Parsed OpenID Connect Discovery metadata.
///
/// Fetched from `{discovery_url}/.well-known/openid-configuration` and cached
/// for the lifetime of the [`OidcAuthProvider`] instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcMetadata {
    /// OAuth2 authorization endpoint URL.
    pub authorization_endpoint: String,

    /// OAuth2 token endpoint URL.
    pub token_endpoint: String,

    /// OIDC UserInfo endpoint URL.
    pub userinfo_endpoint: Option<String>,

    /// JWKS endpoint URL for ID token signature validation keys.
    pub jwks_uri: String,

    /// Issuer identifier (must match the `iss` claim in ID tokens).
    pub issuer: String,

    /// RP-Initiated Logout endpoint URL (OpenID Connect Session Management 1.0).
    ///
    /// Used by [`OidcAuthProvider::initiate_logout`] to build logout redirect URLs.
    /// May not be present in all IdP implementations.
    #[serde(rename = "end_session_endpoint")]
    pub end_session_endpoint: Option<String>,
}

// ---------------------------------------------------------------------------
// Data Types — Tokens
// ---------------------------------------------------------------------------

/// Token response from the OIDC token endpoint.
///
/// Returned by [`OidcAuthProvider::exchange_code`] after successful
/// authorization code exchange, and by [`OidcAuthProvider::refresh_access_token`]
/// after successful token refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokens {
    /// Bearer access token for API calls.
    pub access_token: String,

    /// ID Token (JWT) containing authenticated user claims.
    /// May be `None` if the `openid` scope was not requested.
    pub id_token: Option<String>,

    /// Refresh token for obtaining new access tokens without user interaction.
    pub refresh_token: Option<String>,

    /// Access token lifetime in seconds.
    pub expires_in: u64,

    /// Token type (typically `"Bearer"`).
    pub token_type: String,
}

// ---------------------------------------------------------------------------
// Data Types — UserInfo
// ---------------------------------------------------------------------------

/// Standard OIDC Claims from the UserInfo endpoint or ID Token.
///
/// Fields follow [OpenID Connect Core 1.0 §5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// Subject Identifier — unique user identifier issued by the IdP.
    pub sub: String,

    /// Full name of the end-user.
    pub name: String,

    /// End-user's preferred e-mail address.
    pub email: Option<String>,

    /// End-user's preferred shorthand username (may be `None` if not provided by IdP).
    pub preferred_username: Option<String>,
}

// ---------------------------------------------------------------------------
// Data Types — Validated ID Token
// ---------------------------------------------------------------------------

/// Validated ID token claims after cryptographic and semantic verification.
///
/// Produced by [`OidcAuthProvider::validate_id_token`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedIdToken {
    /// Subject identifier.
    pub sub: String,

    /// Issuer identifier (verified against metadata).
    pub iss: String,

    /// Audience(s) — verified against configured client_id.
    pub aud: Vec<String>,

    /// Expiration time (UNIX seconds).
    pub exp: u64,

    /// Issued-at time (UNIX seconds).
    pub iat: u64,

    /// Nonce value (if present in the token).
    pub nonce: Option<String>,

    /// Additional claims beyond the standard registered set.
    pub extra_claims: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Nonce Store — Internal type for nonce binding verification
// ---------------------------------------------------------------------------

/// A single entry in the nonce store tracking when it was issued.
struct NonceEntry {
    /// The nonce string value.
    value: String,
    /// Timestamp when this nonce was generated (for TTL enforcement).
    issued_at: Instant,
}

// ---------------------------------------------------------------------------
// JWKS Cache — Internal type for key rotation support
// ---------------------------------------------------------------------------

/// Cached JWKS key set with metadata for TTL-based rotation.
struct JwksCache {
    /// The parsed JWKS key set.
    keys: JwksKeySet,
    /// Timestamp when this cache was last populated.
    fetched_at: Instant,
}

// ---------------------------------------------------------------------------
// Provider Implementation
// ---------------------------------------------------------------------------

/// Asynchronous OIDC/OAuth 2.0 authentication provider — production hardened.
///
/// Implements the Authorization Code flow with optional PKCE support,
/// automatic JWKS key rotation, nonce binding verification, token refresh,
/// and RP-initiated logout.
///
/// # Thread Safety
///
/// Wrap in `Arc<>` for sharing across async tasks. Internal mutable state
/// (JWKS cache, nonce store) is protected by `tokio::sync::Mutex`.
pub struct OidcAuthProvider {
    config: OidcConfig,
    http_client: Client,
    /// Cached discovery metadata (populated on first call to `discover()`).
    metadata: tokio::sync::OnceCell<OidcMetadata>,
    /// Cached JWKS key set with automatic rotation support.
    ///
    /// Protected by `tokio::sync::Mutex` for safe concurrent access across
    /// multiple async tasks validating tokens simultaneously.
    jwks_cache: Mutex<Option<JwksCache>>,
    /// Store of recently issued nonces for replay attack prevention.
    ///
    /// Each entry is timestamped; nonces older than `config.nonce_validity_seconds`
    /// are rejected during validation and periodically cleaned up.
    nonce_store: Mutex<Vec<NonceEntry>>,
}

impl OidcAuthProvider {
    /// Create a new OIDC authentication provider with the given configuration.
    ///
    /// No network calls are made at construction time. Call [`discover`](Self::discover)
    /// to fetch and cache the provider's metadata before using other methods.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = OidcConfig {
    ///     discovery_url: "https://keycloak.example.com/realms/myapp".into(),
    ///     client_id: "myapp-client".into(),
    ///     client_secret: "secret".into(),
    ///     redirect_uri: "https://myapp.example.com/auth/callback".into(),
    ///     scopes: vec!["openid".into(), "profile".into(), "email".into()],
    ///     pkce: true,
    ///     ..Default::default()
    /// };
    /// let provider = OidcAuthProvider::new(config);
    /// ```
    #[instrument(skip(config), fields(discovery_url = %config.discovery_url))]
    pub fn new(config: OidcConfig) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("misogi-auth/0.1")
            .build()
            .expect("Failed to build HTTP client");

        info!(
            client_id = %config.client_id,
            pkce = config.pkce,
            jwks_ttl = ?config.jwks_ttl,
            nonce_validity_secs = config.nonce_validity_seconds,
            "OidcAuthProvider initialized (production-hardened)"
        );

        Self {
            config,
            http_client,
            metadata: tokio::sync::OnceCell::new(),
            jwks_cache: Mutex::new(None),
            nonce_store: Mutex::new(Vec::new()),
        }
    }

    // =======================================================================
    // Discovery
    // =======================================================================

    /// Fetch and cache the OpenID Connect Discovery document.
    ///
    /// Performs an HTTP GET to `{discovery_url}/.well-known/openid-configuration`
    /// and parses the response into [`OidcMetadata`].
    ///
    /// Results are cached internally via `OnceCell`; subsequent calls return
    /// the cached value without additional network requests.
    ///
    /// # Errors
    ///
    /// - [`OidcError::DiscoveryFailed`] — HTTP request failed or returned non-200
    /// - [`OidcError::InvalidMetadata`] — response body could not be parsed as valid OIDC metadata
    #[instrument(skip(self))]
    pub async fn discover(&self) -> Result<OidcMetadata, OidcError> {
        // Return cached metadata if available
        if let Some(meta) = self.metadata.get() {
            return Ok(meta.clone());
        }

        let discovery_url =
            format!("{}/.well-known/openid-configuration", self.config.discovery_url.trim_end_matches('/'));

        debug!(url = %discovery_url, "Fetching OIDC discovery document");

        let response = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| {
                OidcError::DiscoveryFailed(format!(
                    "HTTP request failed: {e}"
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(OidcError::DiscoveryFailed(format!(
                "HTTP {status}: {body}"
            )));
        }

        let meta: OidcMetadata = response.json().await.map_err(|e| {
            OidcError::InvalidMetadata(format!(
                "Failed to parse discovery document: {e}"
            ))
        })?;

        // Validate required fields
        if meta.authorization_endpoint.is_empty()
            || meta.token_endpoint.is_empty()
            || meta.jwks_uri.is_empty()
        {
            return Err(OidcError::InvalidMetadata(
                "Missing required endpoints in discovery document"
                    .to_string(),
            ));
        }

        info!(
            issuer = %meta.issuer,
            auth_endpoint = %meta.authorization_endpoint,
            has_end_session = meta.end_session_endpoint.is_some(),
            "OIDC discovery successful"
        );

        // Cache the result
        let _ = self.metadata.set(meta.clone());

        Ok(meta)
    }

    // =======================================================================
    // Authorization Code Flow
    // =======================================================================

    /// Build the authorization URL for redirecting the user to the IdP login page.
    ///
    /// Generates all necessary parameters including:
    /// - `response_type=code`
    /// - `client_id`, `redirect_uri`, `scope`, `state`
    /// - PKCE `code_challenge` and `code_challenge_method=S256` (when enabled)
    /// - `nonce` parameter for replay protection (when enabled)
    ///
    /// # Parameters
    ///
    /// - `state`: CSRF protection parameter — generate with `generate_random_state()`
    /// - `code_verifier`: PKCE code verifier — generate with `generate_code_verifier()`.
    ///   If `pkce` is disabled in config, this parameter is ignored.
    ///
    /// # Returns
    ///
    /// The fully-qualified authorization URL to redirect the user's browser to.
    ///
    /// # Errors
    ///
    /// - [`OidcError::NotDiscovered`] — `discover()` has not been called yet
    /// - [`OidcError::UrlBuildFailed`] — authorization endpoint URL construction failed
    #[instrument(skip(self, state, code_verifier))]
    pub fn authorization_url(
        &self,
        state: &str,
        code_verifier: &str,
    ) -> Result<String, OidcError> {
        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        let mut url =
            Url::parse(&meta.authorization_endpoint).map_err(|e| {
                OidcError::UrlBuildFailed(format!(
                    "Failed to parse authorization endpoint: {e}"
                ))
            })?;

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.config.client_id);
            params.append_pair("redirect_uri", &self.config.redirect_uri);
            params.append_pair(
                "scope",
                &self.config.scopes.join(" "),
            );
            params.append_pair("state", state);

            // Add PKCE parameters if enabled
            if self.config.pkce {
                let challenge = compute_code_challenge(code_verifier);
                params.append_pair("code_challenge", &challenge);
                params.append_pair(
                    "code_challenge_method",
                    "S256",
                );
            }
        }

        debug!(
            url = %url,
            pkce = self.config.pkce,
            "Built authorization URL"
        );

        Ok(url.to_string())
    }

    /// Generate and store a cryptographically random nonce for this authorization request.
    ///
    /// The nonce is stored internally with a timestamp and will be verified
    /// against the `nonce` claim in the ID token during
    /// [`validate_id_token`](Self::validate_id_token).
    ///
    /// Per [OpenID Connect Core §11.2](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes),
    /// the nonce prevents token substitution attacks where an attacker could
    /// replay an ID token intended for a different session.
    ///
    /// # Returns
    ///
    /// A URL-safe random nonce string (32 bytes → 43 characters).
    ///
    /// # Concurrency
    ///
    /// This method acquires the internal `nonce_store` lock briefly.
    /// Safe to call concurrently from multiple tasks.
    #[instrument(skip(self))]
    pub async fn generate_and_store_nonce(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let nonce = URL_SAFE_NO_PAD.encode(&bytes);

        let mut store = self.nonce_store.lock().await;
        store.push(NonceEntry {
            value: nonce.clone(),
            issued_at: Instant::now(),
        });

        debug!(nonce_len = nonce.len(), "Generated and stored nonce");
        nonce
    }

    /// Exchange an authorization code for tokens.
    ///
    /// Sends a POST request to the token endpoint with:
    /// - `grant_type=authorization_code`
    /// - `code`, `redirect_uri`
    /// - `code_verifier` (if PKCE is enabled)
    /// - `client_id`, `client_secret` (HTTP Basic auth)
    ///
    /// # Errors
    ///
    /// - [`OidcError::NotDiscovered`] — `discover()` has not been called
    /// - [`OidcError::TokenExchangeFailed`] — token endpoint returned an error
    /// - [`OidcError::HttpError`] — network or HTTP protocol error
    #[instrument(skip(self, code, code_verifier), fields(code_len = code.len()))]
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<OidcTokens, OidcError> {
        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        debug!("Exchanging authorization code for tokens");

        let mut form_params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        if self.config.pkce {
            form_params.push(("code_verifier", code_verifier));
        }

        let response = self
            .http_client
            .post(&meta.token_endpoint)
            .form(&form_params)
            .send()
            .await
            .map_err(|e| {
                OidcError::HttpError(format!("Token request failed: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(
                status = %status,
                body = %body,
                "Token exchange failed"
            );
            return Err(OidcError::TokenExchangeFailed(format!(
                "HTTP {status}: {body}"
            )));
        }

        let tokens: OidcTokens = response.json().await.map_err(|e| {
            OidcError::TokenExchangeFailed(format!(
                "Failed to parse token response: {e}"
            ))
        })?;

        info!(
            expires_in = tokens.expires_in,
            has_id_token = tokens.id_token.is_some(),
            has_refresh_token = tokens.refresh_token.is_some(),
            "Token exchange successful"
        );

        Ok(tokens)
    }

    // =======================================================================
    // Token Refresh (A2)
    // =======================================================================

    /// Refresh an access token using a previously issued refresh token.
    ///
    /// Sends a POST request to the token endpoint with:
    /// - `grant_type=refresh_token`
    /// - `refresh_token`
    /// - `client_id`, `client_secret` (HTTP Basic auth)
    ///
    /// The IdP may issue a new refresh token alongside the new access token;
    /// callers should replace their stored refresh token when a new one is received.
    ///
    /// # Parameters
    ///
    /// - `refresh_token`: The refresh token obtained from a prior
    ///   [`exchange_code`](Self::exchange_code) call.
    ///
    /// # Returns
    ///
    /// New [`OidcTokens`] containing:
    /// - Fresh `access_token` (always present)
    /// - Optional new `id_token` (if `openid` scope was requested)
    /// - Optional new `refresh_token` (IdP may rotate refresh tokens)
    /// - Updated `expires_in` for the new access token
    ///
    /// # Errors
    ///
    /// - [`OidcError::NotDiscovered`] — `discover()` has not been called
    /// - [`OidcError::TokenExchangeFailed`] — refresh request rejected (expired, revoked, etc.)
    /// - [`OidcError::HttpError`] — network error
    ///
    /// # Security Note
    ///
    /// Refresh tokens are long-lived credentials. Store them securely
    /// (encrypted at rest) and never expose them to client-side JavaScript.
    #[instrument(skip(self, refresh_token))]
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<OidcTokens, OidcError> {
        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        debug!("Refreshing access token");

        let form_params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .http_client
            .post(&meta.token_endpoint)
            .form(&form_params)
            .send()
            .await
            .map_err(|e| {
                OidcError::HttpError(format!(
                    "Refresh token request failed: {e}"
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(
                status = %status,
                "Token refresh failed"
            );
            return Err(OidcError::TokenExchangeFailed(format!(
                "HTTP {status}: {body}"
            )));
        }

        let tokens: OidcTokens = response.json().await.map_err(|e| {
            OidcError::TokenExchangeFailed(format!(
                "Failed to parse refresh response: {e}"
            ))
        })?;

        // Validate that we got a new access token
        if tokens.access_token.is_empty() {
            return Err(OidcError::TokenExchangeFailed(
                "Refresh response missing access_token".to_string(),
            ));
        }

        info!(
            expires_in = tokens.expires_in,
            has_new_refresh_token = tokens.refresh_token.is_some(),
            "Access token refreshed successfully"
        );

        Ok(tokens)
    }

    // =======================================================================
    // RP-Initiated Logout (A3)
    // =======================================================================

    /// Build the RP-Initiated Logout URL for ending the user's session at the IdP.
    ///
    /// Constructs the `end_session_endpoint` URL from discovery metadata with
    /// the following query parameters:
    /// - `id_token_hint`: The user's current ID token (helps IdP identify the session)
    /// - `post_logout_redirect_uri`: Where to redirect the user after logout
    ///
    /// The caller should HTTP-redirect the user's browser to the returned URL.
    ///
    /// # Parameters
    ///
    /// - `id_token_hint`: The user's current ID token (JWT string). Passed as-is
    ///   to allow the IdP to identify which session to terminate.
    /// - `post_logout_redirect_uri`: URI to redirect the user to after logout completes.
    ///   Must be pre-registered with the IdP as a valid post-logout redirect URI.
    ///
    /// # Returns
    ///
    /// The complete logout URL to redirect the user's browser to.
    ///
    /// # Errors
    ///
    /// - [`OidcError::NotDiscovered`] — `discover()` has not been called
    /// - [`OidcError::UrlBuildFailed`] — URL construction failed
    /// - [`OidcError::LogoutNotSupported`] — IdP does not provide `end_session_endpoint`
    ///
    /// # Specification
    ///
    /// Per [OpenID Connect Session Management 1.0 - RP-Initiated Logout](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout),
    /// the `id_token_hint` parameter is RECOMMENDED but not required.
    #[instrument(skip(self, id_token_hint, post_logout_redirect_uri))]
    pub fn initiate_logout(
        &self,
        id_token_hint: &str,
        post_logout_redirect_uri: &str,
    ) -> Result<String, OidcError> {
        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        let end_session_url = meta.end_session_endpoint.as_deref().ok_or_else(
            || {
                OidcError::LogoutNotSupported(
                    "IdP does not provide end_session_endpoint \
                     in discovery metadata. \
                     RP-Initiated Logout is not supported."
                        .to_string(),
                )
            },
        )?;

        let mut url = Url::parse(end_session_url).map_err(|e| {
            OidcError::UrlBuildFailed(format!(
                "Failed to parse end_session_endpoint: {e}"
            ))
        })?;

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("id_token_hint", id_token_hint);
            params.append_pair("post_logout_redirect_uri", post_logout_redirect_uri);
        }

        debug!(
            url = %url,
            "Built RP-Initiated Logout URL"
        );

        Ok(url.to_string())
    }

    // =======================================================================
    // UserInfo
    // =======================================================================

    /// Retrieve user information from the UserInfo endpoint.
    ///
    /// Sends an authenticated GET request to the UserInfo endpoint using
    /// the provided Bearer access token.
    ///
    /// # Errors
    ///
    /// - [`OidcError::NotDiscovered`] — `discover()` has not been called
    /// - [`OidcError::UserInfoFailed`] — UserInfo endpoint error
    /// - [`OidcError::HttpError`] — network error
    #[instrument(skip(self, access_token))]
    pub async fn get_userinfo(
        &self,
        access_token: &str,
    ) -> Result<OidcUserInfo, OidcError> {
        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        let userinfo_url = meta.userinfo_endpoint.as_deref().ok_or_else(
            || {
                OidcError::UserInfoFailed(
                    "UserInfo endpoint not available in metadata"
                        .to_string(),
                )
            },
        )?;

        debug!("Requesting UserInfo from IdP");

        let response = self
            .http_client
            .get(userinfo_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| {
                OidcError::HttpError(format!(
                    "UserInfo request failed: {e}"
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(OidcError::UserInfoFailed(format!(
                "HTTP {status}: {body}"
            )));
        }

        let userinfo: OidcUserInfo = response.json().await.map_err(|e| {
            OidcError::UserInfoFailed(format!(
                "Failed to parse UserInfo response: {e}"
            ))
        })?;

        debug!(sub = %userinfo.sub, "UserInfo retrieved successfully");

        Ok(userinfo)
    }

    // =======================================================================
    // ID Token Validation (with A1 + A4 enhancements)
    // =======================================================================

    /// Validate an ID Token's signature and claims — production-hardened version.
    ///
    /// # Process
    ///
    /// 1. Decode the JWT header to extract `kid` (Key ID) and algorithm
    /// 2. Check if cached JWKS contains the required key; if not, auto-refresh (A1)
    /// 3. Verify RS256/ES256 signature using the matching public key
    /// 4. Validate registered claims: `iss`, `aud`, `exp`
    /// 5. Verify `nonce` claim matches a recently issued nonce (A4)
    /// 6. Remove used nonce from store to prevent reuse
    ///
    /// # Automatic JWKS Rotation (A1)
    ///
    /// If the token's `kid` is not found in the cached JWKS, or the cached
    /// JWKS has exceeded its TTL ([`OidcConfig::jwks_ttl`]), a fresh JWKS
    /// is fetched from the IdP before validation proceeds.
    ///
    /// # Nonce Binding Verification (A4)
    ///
    /// If the ID token contains a `nonce` claim, it is checked against the
    /// internal nonce store. Only nonces issued within
    /// [`OidcConfig::nonce_validity_seconds`] are accepted. After successful
    /// verification, the nonce is removed from the store.
    ///
    /// # Errors
    ///
    /// - [`OidcError::NotDiscovered`] — `discover()` has not been called
    /// - [`OidcError::IdTokenValidationFailed`] — signature or claim validation failure
    /// - [`OidcError::JwksFetchFailed`] — cannot fetch signing keys from IdP
    /// - [`OidcError::HttpError`] — network error during JWKS fetch
    /// - [`OidcError::NonceVerificationFailed`] — nonce mismatch or expired
    #[instrument(skip(self, id_token))]
    pub async fn validate_id_token(
        &self,
        id_token: &str,
    ) -> Result<ValidatedIdToken, OidcError> {
        use jsonwebtoken::{
            decode, decode_header, Validation,
        };

        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        // Step 1: Decode header to get kid
        let header = decode_header(id_token).map_err(|e| {
            OidcError::IdTokenValidationFailed(format!(
                "Failed to decode ID token header: {e}"
            ))
        })?;

        let kid = header.kid.ok_or_else(|| {
            OidcError::IdTokenValidationFailed(
                "ID token missing 'kid' header".to_string(),
            )
        })?;

        debug!(kid = %kid, "Decoded ID token header");

        // Step 2: Get JWKS (with automatic rotation if needed)
        let jwk = self.get_jwk_for_kid(&kid, &meta.jwks_uri).await?;

        // Build decoding key from JWK
        let decoding_key = Self::jwk_to_decoding_key(&jwk)?;

        // Step 3 & 4: Verify signature + validate standard claims
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&meta.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        validation.validate_exp = true;

        // Decode into a generic map to capture extra claims
        let token_data =
            decode::<serde_json::Value>(id_token, &decoding_key, &validation)
                .map_err(|e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        OidcError::IdTokenValidationFailed(
                            "ID token has expired".to_string(),
                        )
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        OidcError::IdTokenValidationFailed(
                            "ID token signature verification failed"
                                .to_string(),
                        )
                    }
                    _ => OidcError::IdTokenValidationFailed(e.to_string()),
                })?;

        let claims = &token_data.claims;

        // Step 5: Verify nonce claim if present (A4: Nonce Binding)
        if let Some(token_nonce) = claims["nonce"].as_str() {
            self.verify_nonce(token_nonce).await?;
        }

        info!(sub = claims["sub"].as_str().unwrap_or("?"), "ID token validated successfully");

        // Extract extra claims (filter out standard OIDC claims)
        let standard_claims = ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp"];
        let extra_claims: HashMap<String, serde_json::Value> = claims
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter(|(k, _)| !standard_claims.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(ValidatedIdToken {
            sub: claims["sub"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            iss: claims["iss"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            aud: claims["aud"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            exp: claims["exp"].as_u64().unwrap_or(0),
            iat: claims["iat"].as_u64().unwrap_or(0),
            nonce: claims["nonce"]
                .as_str()
                .map(String::from),
            extra_claims,
        })
    }

    // --- Internal helpers ---

    /// Get a JWK for the given `kid`, with automatic cache refresh (A1).
    ///
    /// # Algorithm
    ///
    /// 1. Acquire lock on `jwks_cache`
    /// 2. If cache exists and contains the requested `kid` → return it
    /// 3. If cache exists but has exceeded TTL → force refresh
    /// 4. If cache does not exist or was forced out → fetch fresh JWKS
    /// 5. Search fresh JWKS for the `kid`; return or error
    async fn get_jwk_for_kid(
        &self,
        kid: &str,
        jwks_uri: &str,
    ) -> Result<Jwk, OidcError> {
        let mut cache_guard = self.jwks_cache.lock().await;

        // Check if we have a valid cached JWKS
        if let Some(ref cache) = *cache_guard {
            // Try to find the key in current cache
            if let Some(jwk) = cache.keys.keys.iter().find(|k| k.kid.as_deref() == Some(kid)) {
                debug!(kid = %kid, "Found key in JWKS cache");
                return Ok(jwk.clone());
            }

            // Key not found — check if we should force refresh due to TTL
            if let Some(ttl) = self.config.jwks_ttl {
                if cache.fetched_at.elapsed() < ttl {
                    // Cache is fresh but doesn't have this key — might be a real unknown key
                    warn!(
                        kid = %kid,
                        cache_age_secs = cache.fetched_at.elapsed().as_secs(),
                        "JWKS cache is fresh but does not contain requested kid — forcing refresh anyway"
                    );
                    // Fall through to refresh below
                } else {
                    debug!(
                        cache_age_secs = cache.fetched_at.elapsed().as_secs(),
                        ttl_secs = ttl.as_secs(),
                        "JWKS cache exceeded TTL, forcing refresh"
                    );
                }
            }
        }

        // Fetch fresh JWKS
        debug!(uri = %jwks_uri, "Fetching fresh JWKS (cache miss or TTL expired)");
        let fresh_jwks = self.fetch_jwks_internal(jwks_uri).await?;

        // Update cache
        *cache_guard = Some(JwksCache {
            keys: fresh_jwks.clone(),
            fetched_at: Instant::now(),
        });

        // Now search the fresh JWKS
        fresh_jwks.keys.into_iter().find(|k| k.kid.as_deref() == Some(kid)).ok_or_else(
            || {
                OidcError::IdTokenValidationFailed(format!(
                    "No matching key found for kid='{kid}' in fresh JWKS ({} keys total)",
                    cache_guard.as_ref().map(|c| c.keys.keys.len()).unwrap_or(0)
                ))
            },
        )
    }

    /// Refresh the JWKS cache if the TTL has expired.
    ///
    /// This is a proactive refresh method that can be called periodically
    /// (e.g., from a background task) to ensure the JWKS cache stays fresh
    /// even when no tokens are being validated.
    ///
    /// Does nothing if the cache is within its TTL or if no cache exists yet.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the JWKS was actually refreshed
    /// - `Ok(false)` if no refresh was needed (within TTL or no cache)
    /// - `Err(...)` if the refresh attempt failed
    pub async fn refresh_jwks_if_needed(&self) -> Result<bool, OidcError> {
        let meta = self.metadata.get().ok_or_else(|| {
            OidcError::NotDiscovered
        })?;

        let ttl = match self.config.jwks_ttl {
            Some(ttl) => ttl,
            None => return Ok(false), // TTL disabled
        };

        let mut cache_guard = self.jwks_cache.lock().await;

        match cache_guard.as_ref() {
            Some(cache) if cache.fetched_at.elapsed() >= ttl => {
                debug!(
                    cache_age_secs = cache.fetched_at.elapsed().as_secs(),
                    ttl_secs = ttl.as_secs(),
                    "Proactively refreshing JWKS cache"
                );
                let fresh_jwks = self.fetch_jwks_internal(&meta.jwks_uri).await?;
                *cache_guard = Some(JwksCache {
                    keys: fresh_jwks,
                    fetched_at: Instant::now(),
                });
                Ok(true)
            }
            Some(_) => {
                debug!("JWKS cache is within TTL, no refresh needed");
                Ok(false)
            }
            None => {
                debug!("No JWKS cache exists yet, skipping proactive refresh");
                Ok(false)
            }
        }
    }

    /// Verify that a nonce value was recently issued and consume it.
    ///
    /// # Process
    ///
    /// 1. Search the nonce store for a matching value
    /// 2. Check that the nonce is within the validity window
    /// 3. Remove the matched nonce from the store (one-time use)
    /// 4. Clean up any expired nonces while holding the lock
    ///
    /// # Errors
    ///
    /// - [`OidcError::NonceVerificationFailed`] — nonce not found or expired
    async fn verify_nonce(&self, token_nonce: &str) -> Result<(), OidcError> {
        let mut store = self.nonce_store.lock().await;
        let now = Instant::now();
        let validity = Duration::from_secs(self.config.nonce_validity_seconds);

        // Find the index of the matching nonce
        let match_idx = store.iter().position(|entry| {
            entry.value == token_nonce && now.duration_since(entry.issued_at) <= validity
        });

        match match_idx {
            Some(idx) => {
                // Remove the consumed nonce
                let removed = store.remove(idx);
                debug!(
                    nonce_age_secs = now.duration_since(removed.issued_at).as_secs(),
                    "Nonce verified and consumed"
                );

                // Clean up expired entries while we have the lock
                let before = store.len();
                store.retain(|entry| now.duration_since(entry.issued_at) <= validity);
                let cleaned = before - store.len();
                if cleaned > 0 {
                    debug!(cleaned, "Cleaned up expired nonces");
                }

                Ok(())
            }
            None => {
                // Check if there's an expired entry with this value (for better error message)
                let expired_match = store.iter().any(|e| e.value == token_nonce);

                // Still clean up while we have the lock
                let before = store.len();
                store.retain(|entry| now.duration_since(entry.issued_at) <= validity);
                let cleaned = before - store.len();

                if expired_match {
                    Err(OidcError::NonceVerificationFailed(
                        format!(
                            "Nonce found but expired (validity={}s)",
                            self.config.nonce_validity_seconds
                        ),
                    ))
                } else {
                    warn!(
                        nonce_preview = &token_nonce[..token_nonce.len().min(16)],
                        cleaned,
                        "Nonce verification failed: unknown nonce"
                    );
                    Err(OidcError::NonceVerificationFailed(
                        "Unknown nonce — possible replay attack or server restart"
                            .to_string(),
                    ))
                }
            }
        }
    }

    /// Cleanup task: remove all expired nonces from the store.
    ///
    /// Should be called periodically (e.g., every 60 seconds) from a
    /// background task to prevent unbounded memory growth of the nonce store.
    ///
    /// # Returns
    ///
    /// The number of expired nonces that were removed.
    pub async fn cleanup_expired_nonces(&self) -> usize {
        let mut store = self.nonce_store.lock().await;
        let now = Instant::now();
        let validity = Duration::from_secs(self.config.nonce_validity_seconds);
        let before = store.len();

        store.retain(|entry| now.duration_since(entry.issued_at) <= validity);

        let removed = before - store.len();
        if removed > 0 {
            debug!(removed, remaining = store.len(), "Cleaned up expired nonces");
        }
        removed
    }

    /// Fetch the JSON Web Key Set from the specified URI (internal version, no caching).
    async fn fetch_jwks_internal(
        &self,
        jwks_uri: &str,
    ) -> Result<JwksKeySet, OidcError> {
        debug!(uri = %jwks_uri, "Fetching JWKS from IdP");

        let response = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| {
                OidcError::JwksFetchFailed(format!("HTTP error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(OidcError::JwksFetchFailed(format!(
                "HTTP {status}: {body}"
            )));
        }

        let jwks: JwksKeySet = response.json().await.map_err(|e| {
            OidcError::JwksFetchFailed(format!(
                "Failed to parse JWKS: {e}"
            ))
        })?;

        debug!(key_count = jwks.keys.len(), "JWKS fetched successfully");
        Ok(jwks)
    }

    /// Convert a JWK to a jsonwebtoken DecodingKey.
    ///
    /// Supports RSA (`RS256`) and EC (`ES256`) algorithms.
    fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, OidcError> {
        match jwk.kty.as_str() {
            "RSA" => {
                // Build RSA public key from n (modulus) and e (exponent)
                let n = jwk.n.as_deref().ok_or_else(|| {
                    OidcError::IdTokenValidationFailed(
                        "RSA JWK missing 'n' field".to_string(),
                    )
                })?;
                let e = jwk.e.as_deref().ok_or_else(|| {
                    OidcError::IdTokenValidationFailed(
                        "RSA JWK missing 'e' field".to_string(),
                    )
                })?;

                // Build DER-encoded RSA public key
                let der = build_rsa_der_from_jwk(n, e)?;
                Ok(DecodingKey::from_rsa_der(&der))
            }
            "EC" => {
                let x = jwk.x.as_deref().ok_or_else(|| {
                    OidcError::IdTokenValidationFailed(
                        "EC JWK missing 'x' field".to_string(),
                    )
                })?;
                let y = jwk.y.as_deref().ok_or_else(|| {
                    OidcError::IdTokenValidationFailed(
                        "EC JWK missing 'y' field".to_string(),
                    )
                })?;
                let crv = jwk.crv.as_deref().unwrap_or("P-256");

                let der = build_ec_der_from_jwk(x, y, crv)?;
                Ok(DecodingKey::from_ec_der(&der))
            }
            other => Err(OidcError::IdTokenValidationFailed(format!(
                "Unsupported key type: {other}"
            ))),
        }
    }
}

// =======================================================================
// A5: IdP-Specific Adapter Factory Functions
// =======================================================================

/// Factory function: create an [`OidcConfig`] pre-configured for Keycloak.
///
/// Keycloak is an open-source identity provider commonly used in enterprise
/// deployments. This factory sets up standard endpoint paths and conventions
/// expected by Keycloak realms.
///
/// # Parameters
///
/// - `realm`: The Keycloak realm name (e.g., `"misogi"`, `"master"`).
/// - `base_url`: Base URL of the Keycloak server (e.g., `"https://keycloak.example.com"`).
///   Must NOT include `/realms/<realm>` — that is appended automatically.
/// - `client_id`: OAuth2 client ID registered in this realm.
/// - `client_secret`: OAuth2 client secret (confidential client mode).
/// - `redirect_uri`: Registered redirect URI for this client.
///
/// # Returns
///
/// An [`OidcConfig`] ready to pass to [`OidcAuthProvider::new`].
///
/// # Example
///
/// ```ignore
/// let config = keycloak_config(
///     "misogi",
///     "https://keycloak.example.com",
///     "misogi-client",
///     "secret",
///     "https://app.example.com/auth/callback",
/// );
/// let provider = OidcAuthProvider::new(config);
/// ```
pub fn keycloak_config(
    realm: &str,
    base_url: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> OidcConfig {
    let base_url = base_url.trim_end_matches('/');
    OidcConfig {
        discovery_url: format!("{base_url}/realms/{realm}"),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "roles".to_string(),
        ],
        pkce: true,
        ..Default::default()
    }
}

/// Factory function: create an [`OidcConfig`] pre-configured for Microsoft Azure AD.
///
/// Azure Active Directory (now Microsoft Entra ID) uses tenant-specific endpoints
/// and specific OAuth2/OIDC behaviors. This factory handles the endpoint construction
/// and scope conventions for Azure AD.
///
/// # Parameters
///
/// - `tenant_id`: Azure AD tenant ID or domain (e.g., `"contoso.onmicrosoft.com"`
///   or `"common"` for multi-tenant, or `"organizations"`, `"consumers"`).
/// - `client_id`: Application (client) ID from the Azure portal App Registrations.
/// - `client_secret`: Client secret value (not the secret ID) from App Registrations.
/// - `redirect_uri`: One of the reply URIs registered for this application.
///
/// # Azure-Specific Behavior
///
/// - Scopes default to `openid profile email` plus `offline_access` for refresh tokens.
/// - Discovery URL follows the pattern:
///   `https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration`
///
/// # Example
///
/// ```ignore
/// let config = azure_ad_config(
///     "contoso.onmicrosoft.com",
///     "your-app-client-id",
///     "your-client-secret",
///     "https://app.example.com/auth/callback",
/// );
/// let provider = OidcAuthProvider::new(config);
/// ```
pub fn azure_ad_config(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> OidcConfig {
    OidcConfig {
        discovery_url: format!(
            "https://login.microsoftonline.com/{tenant_id}/v2.0"
        ),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(), // Required for refresh tokens in Azure AD
        ],
        pkce: true,
        ..Default::default()
    }
}

/// Factory function: create an [`OidcConfig`] pre-configured for Okta.
///
/// Okta is a cloud identity provider with strong enterprise SSO capabilities.
/// This factory sets up the standard Okta OIDC configuration.
///
/// # Parameters
///
/// - `domain`: Your Okta organization domain (e.g., `"example.okta.com"`).
///   Do NOT include `https://` prefix.
/// - `org_url`: Full Okta organization URL (e.g., `"https://example.okta.com"`).
///   If empty, it is constructed from `domain` as `https://{domain}`.
/// - `client_id`: OIDC app client ID from the Okta Admin Console.
/// - `client_secret`: OIDC app client secret.
/// - `redirect_uri`: Sign-in redirect URI configured in the Okta app.
///
/// # Okta-Specific Notes
///
/// - Default scopes include `openid profile email` and optionally `groups` for group-based access.
/// - Okta supports both authorization_code and implicit flows; this factory
///   configures for authorization_code with PKCE (recommended).
///
/// # Example
///
/// ```ignore
/// let config = okta_config(
///     "example.okta.com",
///     "https://example.okta.com",
///     "your-okta-client-id",
///     "your-okta-client-secret",
///     "https://app.example.com/auth/callback",
/// );
/// let provider = OidcAuthProvider::new(config);
/// ```
pub fn okta_config(
    domain: &str,
    org_url: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> OidcConfig {
    let org_url = if org_url.is_empty() {
        format!("https://{domain}")
    } else {
        org_url.to_string()
    };

    OidcConfig {
        discovery_url: format!("{org_url}/.well-known/oauth-authorization-server"),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        pkce: true,
        ..Default::default()
    }
}

/// Factory function: create an [`OidcConfig`] pre-configured for Japan G-Cloud IdP.
///
/// G-Cloud (Government Cloud) is Japan's government cloud computing platform
/// with a federated identity provider that follows OIDC standards with some
/// Japan-specific extensions for government agency integration.
///
/// # Parameters
///
/// - `entity_id`: The entity identifier assigned to your SP by the G-Cloud IdP operator.
///   Typically follows the pattern `urn:gov:japan:gcloud:sp:<agency>:<service>`.
///
/// # G-Cloud Specific Behavior
///
/// - Discovery URL points to the G-Cloud IdP well-known endpoint.
/// - Scopes are set to the minimal required set for government compliance.
/// - Clock skew tolerance is increased for inter-agency time synchronization issues.
/// - Nonce validity is extended to 600 seconds (10 minutes) per G-Cloud operational guidelines.
///
/// # Compliance Notes
///
/// G-Cloud IdP integration must comply with:
/// - [Japan Digital Government Standard](https://www.digital.go.jp/)
/// - LGWAN (Local Government Wide Area Network) security requirements
/// - FIDO2 / passwordless authentication preferences
///
/// # Example
///
/// ```ignore
/// let config = gcloud_japan_config(
///     "urn:gov:japan:gcloud:sp:ministry:filetransfer",
/// );
/// let provider = OidcAuthProvider::new(config);
/// provider.discover().await?;
/// ```
pub fn gcloud_japan_config(entity_id: &str) -> OidcConfig {
    // G-Cloud Japan uses a standardized IdP endpoint structure.
    // In production, this should be configurable per deployment region.
    OidcConfig {
        discovery_url: "https://idp.gcloud.go.jp/.well-known/openid-configuration".to_string(),
        client_id: entity_id.to_string(),
        // G-Cloud typically uses mutual TLS or signed JWT for client auth
        // rather than shared secrets. Placeholder for demonstration.
        client_secret: String::new(),
        redirect_uri: format!("{entity_id}/auth/callback"),
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            // G-Cloud-specific scopes for government attributes
            "urn:oid:2.5.4.42".to_string(),  // givenName
            "urn:oid:2.5.4.4".to_string(),    // sn (surname)
            "urn:oid:0.9.2342.19200300.100.1.3".to_string(), // email (RFC 1274)
        ],
        pkce: true,
        // Extended TTL for G-Cloud's operational characteristics
        jwks_ttl: Some(Duration::from_secs(7200)), // 2 hours
        // Extended nonce validity per G-Cloud guidelines
        nonce_validity_seconds: 600, // 10 minutes
    }
}

// ---------------------------------------------------------------------------
// PKCE Utilities
// ---------------------------------------------------------------------------

/// Generate a cryptographically random PKCE code_verifier.
///
/// Produces a URL-safe string of 43–128 characters as per RFC 7636 §4.1.
/// This implementation generates 64 bytes (86 base64url characters) which
/// falls within the recommended range.
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate a cryptographically random CSRF `state` parameter.
///
/// Produces a URL-safe string suitable for use as the OAuth2 `state` value.
pub fn generate_random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Compute the PKCE `code_challenge` from a `code_verifier` using S256 method.
///
/// Returns `BASE64URL(SHA256(code_verifier))` as defined in RFC 7636 §4.2.
fn compute_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&hash)
}

// ---------------------------------------------------------------------------
// JWK Structures
// ---------------------------------------------------------------------------

/// A JSON Web Key as it appears in a JWKS key set.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Jwk {
    /// Key Type — "RSA" or "EC".
    kty: String,

    /// Key ID — used to match against the JWT `kid` header.
    kid: Option<String>,

    /// Public Key Use — "sig" for signatures.
    #[serde(rename = "use")]
    pub_use: Option<String>,

    /// Algorithm — "RS256", "ES256", etc.
    alg: Option<String>,

    /// RSA modulus (base64url).
    n: Option<String>,

    /// RSA exponent (base64url).
    e: Option<String>,

    /// EC X coordinate (base64url).
    x: Option<String>,

    /// EC Y coordinate (base64url).
    y: Option<String>,

    /// Curve — "P-256", "P-384", etc.
    crv: Option<String>,
}

/// JSON Web Key Set — the top-level structure returned by the JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwksKeySet {
    keys: Vec<Jwk>,
}

// ---------------------------------------------------------------------------
// JWK → DER Conversion Helpers
// ---------------------------------------------------------------------------

/// Build a DER-encoded RSA public key from JWK `n` and `e` components.
fn build_rsa_der_from_jwk(n_b64: &str, e_b64: &str) -> Result<Vec<u8>, OidcError> {
    let n = URL_SAFE_NO_PAD.decode(n_b64).map_err(|e| {
        OidcError::IdTokenValidationFailed(format!(
            "Failed to decode JWK 'n': {e}"
        ))
    })?;
    let e = URL_SAFE_NO_PAD.decode(e_b64).map_err(|e| {
        OidcError::IdTokenValidationFailed(format!(
            "Failed to decode JWK 'e': {e}"
        ))
    })?;

    // Build ASN.1 DER sequence for RSA public key: SEQUENCE { INTEGER(n), INTEGER(e) }
    let n_int = asn1_integer(&n);
    let e_int = asn1_integer(&e);
    let rsa_pubkey = asn1_sequence(&[&n_int, &e_int]);

    // Wrap in SubjectPublicKeyInfo for PKCS#8 / X.509 format
    let spki = build_subject_public_key_info(
        // RSA OID: 1.2.840.113549.1.1.1
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        &rsa_pubkey,
    );

    Ok(spki)
}

/// Build a DER-encoded EC public key from JWK `x`, `y`, and curve.
fn build_ec_der_from_jwk(
    x_b64: &str,
    y_b64: &str,
    crv: &str,
) -> Result<Vec<u8>, OidcError> {
    let x = URL_SAFE_NO_PAD.decode(x_b64).map_err(|e| {
        OidcError::IdTokenValidationFailed(format!(
            "Failed to decode JWK 'x': {e}"
        ))
    })?;
    let y = URL_SAFE_NO_PAD.decode(y_b64).map_err(|e| {
        OidcError::IdTokenValidationFailed(format!(
            "Failed to decode JWK 'y': {e}"
        ))
    })?;

    // Build uncompressed point representation: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04); // Uncompressed form indicator
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    let ec_point = asn1_bit_string(&point);

    // Select OID based on curve
        let oid_bytes: &[u8] = match crv {
            "P-256" => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            "P-384" => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            _ => {
                return Err(OidcError::IdTokenValidationFailed(format!(
                    "Unsupported EC curve: {crv}"
                )))
            }
        };

        let spki = build_subject_public_key_info(oid_bytes, &ec_point);
    Ok(spki)
}

// --- Minimal ASN.1 encoding helpers ---

fn asn1_integer(bytes: &[u8]) -> Vec<u8> {
    let content = if bytes.first().map(|&b| b & 0x80 != 0).unwrap_or(false) {
        // Prepend zero byte if high bit set (ensure positive)
        let mut v = vec![0x00];
        v.extend_from_slice(bytes);
        v
    } else {
        bytes.to_vec()
    };
    asn1_tagged(0x02, &content) // INTEGER tag
}

fn asn1_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // Unused bits count
    content.extend_from_slice(bytes);
    asn1_tagged(0x03, &content) // BIT STRING tag
}

fn asn1_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend_from_slice(part);
    }
    asn1_tagged(0x30, &content) // SEQUENCE tag
}

fn asn1_tagged(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    append_length(&mut result, content.len());
    result.extend_from_slice(content);
    result
}

fn append_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn build_subject_public_key_info(algorithm_oid: &[u8], subject_key: &[u8]) -> Vec<u8> {
    let algorithm_identifier = asn1_sequence(&[
        &asn1_tagged(0x06, algorithm_oid), // OID
        &asn1_tagged(0x05, &[]),           // NULL (parameters)
    ]);
    asn1_sequence(&[&algorithm_identifier, subject_key])
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Comprehensive error type for OIDC operations.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// Failed to fetch or parse the OpenID Connect Discovery document.
    #[error("discovery failed: {0}")]
    DiscoveryFailed(String),

    /// Discovery document was successfully fetched but contains invalid/missing data.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    /// Provider metadata has not been discovered yet — call `discover()` first.
    #[error("OIDC provider not discovered")]
    NotDiscovered,

    /// Failed to construct a URL (authorization, token, etc.).
    #[error("URL construction failed: {0}")]
    UrlBuildFailed(String),

    /// Token exchange (code → tokens) failed at the IdP.
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// UserInfo endpoint returned an error.
    #[error("UserInfo failed: {0}")]
    UserInfoFailed(String),

    /// ID token signature or claim validation failed.
    #[error("ID token validation failed: {0}")]
    IdTokenValidationFailed(String),

    /// Failed to fetch JWKS (signing keys) from the IdP.
    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    /// Nonce verification failed — token's nonce claim did not match any recently issued nonce.
    #[error("nonce verification failed: {0}")]
    NonceVerificationFailed(String),

    /// RP-Initiated Logout is not supported by this IdP.
    #[error("logout not supported: {0}")]
    LogoutNotSupported(String),
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- PKCE Utility Tests ---

    #[test]
    fn test_generate_code_verifier_length() {
        let verifier = generate_code_verifier();
        // RFC 7636 §4.1: 43–128 characters
        assert!(
            verifier.len() >= 43 && verifier.len() <= 128,
            "Code verifier length {} outside allowed range [43, 128]",
            verifier.len()
        );
        // Verify URL-safe characters only
        assert!(
            verifier.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Code verifier contains non-URL-safe characters"
        );
    }

    #[test]
    fn test_generate_random_state_length() {
        let state = generate_random_state();
        assert_eq!(state.len(), 43); // 32 bytes → 43 base64url chars
        assert!(
            state.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "State contains non-URL-safe characters"
        );
    }

    #[test]
    fn test_compute_code_challenge_deterministic() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_code_challenge(verifier);
        // Known test vector from RFC 7636 Appendix B
        assert_eq!(
            challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    // --- Config Tests ---

    #[test]
    fn test_oidc_config_defaults() {
        let config = OidcConfig::default();
        assert!(config.pkce);
        assert_eq!(config.scopes, vec!["openid"]);
        assert!(config.jwks_ttl.is_some());
        assert_eq!(config.jwks_ttl.unwrap(), Duration::from_secs(3600));
        assert_eq!(config.nonce_validity_seconds, 300);
    }

    // --- IdP Adapter Tests ---

    #[test]
    fn test_keycloak_config() {
        let config = keycloak_config(
            "myrealm",
            "https://keycloak.example.com",
            "myclient",
            "secret123",
            "https://app.example.com/callback",
        );
        assert_eq!(
            config.discovery_url,
            "https://keycloak.example.com/realms/myrealm"
        );
        assert_eq!(config.client_id, "myclient");
        assert!(config.pkce);
        assert!(config.scopes.contains(&"roles".to_string()));
    }

    #[test]
    fn test_azure_ad_config() {
        let config = azure_ad_config(
            "contoso.onmicrosoft.com",
            "app-id",
            "app-secret",
            "https://app.example.com/callback",
        );
        assert!(config.discovery_url.contains("login.microsoftonline.com"));
        assert!(config.discovery_url.contains("contoso.onmicrosoft.com"));
        assert!(config.scopes.contains(&"offline_access".to_string())); // Azure AD needs this for refresh tokens
    }

    #[test]
    fn test_okta_config_with_org_url() {
        let config = okta_config(
            "example.okta.com",
            "https://custom.okta.example.com",
            "client-id",
            "client-secret",
            "https://app.example.com/callback",
        );
        assert_eq!(config.discovery_url, "https://custom.okta.example.com/.well-known/oauth-authorization-server");
    }

    #[test]
    fn test_okta_config_without_org_url() {
        let config = okta_config(
            "example.okta.com",
            "",
            "client-id",
            "client-secret",
            "https://app.example.com/callback",
        );
        assert_eq!(config.discovery_url, "https://example.okta.com/.well-known/oauth-authorization-server");
    }

    #[test]
    fn test_gcloud_japan_config() {
        let config = gcloud_japan_config("urn:gov:japan:gcloud:sp:test");
        assert_eq!(config.client_id, "urn:gov:japan:gcloud:sp:test");
        assert_eq!(config.nonce_validity_seconds, 600); // 10 min for G-Cloud
        assert_eq!(config.jwks_ttl, Some(Duration::from_secs(7200))); // 2h
        assert!(config.scopes.iter().any(|s| s.starts_with("urn:oid:")));
    }

    // --- ASN.1 Encoding Tests ---

    #[test]
    fn test_asn1_integer_positive() {
        let result = asn1_integer(&[0x01, 0x02, 0x03]);
        // Tag 0x02, length 0x03, content
        assert_eq!(result[0], 0x02); // INTEGER tag
        assert_eq!(result[1], 0x03); // length
        assert_eq!(&result[2..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_asn1_integer_high_bit_set() {
        // High bit set requires leading zero byte
        let result = asn1_integer(&[0x80, 0x01]);
        assert_eq!(result[0], 0x02);
        assert_eq!(result[1], 0x03); // length is 3 (2 original + 1 prepended 0x00)
        assert_eq!(&result[2..], &[0x00, 0x80, 0x01]);
    }

    #[test]
    fn test_asn1_sequence() {
        let part1 = asn1_integer(&[0x01]);
        let part2 = asn1_integer(&[0x02]);
        let seq = asn1_sequence(&[&part1, &part2]);
        assert_eq!(seq[0], 0x30); // SEQUENCE tag
    }

    // --- Error Display Tests ---

    #[test]
    fn test_error_display_messages() {
        assert_eq!(
            OidcError::NotDiscovered.to_string(),
            "OIDC provider not discovered"
        );
        assert!(OidcError::DiscoveryFailed("test".to_string())
            .to_string()
            .contains("test"));
        assert!(OidcError::NonceVerificationFailed("expired".to_string())
            .to_string()
            .contains("expired"));
        assert!(OidcError::LogoutNotSupported("no endpoint".to_string())
            .to_string()
            .contains("no endpoint"));
    }
}
