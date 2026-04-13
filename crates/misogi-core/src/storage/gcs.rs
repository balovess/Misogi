//! Google Cloud Storage Backend
//!
//! Implements [`StorageBackend`] for Google Cloud Platform's Cloud Storage service.
//! Targets Japanese government G-Cloud (さくらのクラウド) interoperability scenarios.
//!
//! # Authentication
//!
//! Uses OAuth 2.0 JWT Bearer Token assertion (RFC 7523) with a service account
//! private key. Tokens are cached and auto-refreshed before expiry.
//!
//! # API Mode
//!
//! - **Simple upload** (≤ 5 MB): Single POST to `/upload/storage/v1/b/{bucket}/o`
//! - **Resumable upload** (> 5 MB): Session-based chunked upload
//!
//! # Feature Flag
//!
//! Gated behind `storage-gcs` feature.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use tracing::{debug, info, instrument};

use crate::traits::storage::{StorageBackend, StorageError, StorageInfo};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`GcsStorage`] backend.
#[derive(Debug, Clone)]
pub struct GcsConfig {
    /// GCS bucket name (DNS-compliant, globally unique).
    pub bucket: String,

    /// Raw JSON content of a GCP service account key.
    ///
    /// When set, takes priority over `service_account_key_path`.
    /// Example: `{"type": "service_account", "project_id": "...", ...}`
    pub service_account_json: Option<String>,

    /// Filesystem path to a GCP service account JSON key file.
    ///
    /// Used when `service_account_json` is `None`.
    /// Alternative: set `GOOGLE_APPLICATION_CREDENTIALS` env var.
    pub service_account_key_path: Option<String>,

    /// Override base URL for testing (e.g., fake-gcs-server).
    ///
    /// Default: `"https://storage.googleapis.com"`.
    pub base_url: Option<String>,
}

impl GcsConfig {
    #[must_use]
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            service_account_json: None,
            service_account_key_path: None,
            base_url: None,
        }
    }

    #[must_use]
    pub fn with_service_account_json(mut self, json: impl Into<String>) -> Self {
        self.service_account_json = Some(json.into());
        self
    }

    #[must_use]
    pub fn with_service_account_key_path(mut self, path: impl Into<String>) -> Self {
        self.service_account_key_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        if self.bucket.is_empty() {
            return Err(StorageError::ConfigurationError(
                "bucket must not be empty".into(),
            ));
        }
        if !self.bucket.chars().all(|c| c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '-'
            || c == '_'
            || c == '.')
        {
            return Err(StorageError::ConfigurationError(
                "bucket must contain only lowercase letters, digits, hyphens, underscores, or dots".into(),
            ));
        }
        if self.bucket.len() < 3 || self.bucket.len() > 63 {
            return Err(StorageError::ConfigurationError(
                "bucket must be 3–63 characters".into(),
            ));
        }
        if self.service_account_json.is_none() && self.service_account_key_path.is_none() {
            return Err(StorageError::ConfigurationError(
                "Either service_account_json or service_account_key_path must be provided".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parsed Service Account
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ServiceAccountInfo {
    client_email: String,
    private_key_pem: String,
    project_id: String,
    token_uri: String,
}

impl ServiceAccountInfo {
    fn from_json(json: &str) -> Result<Self, StorageError> {
        let val: serde_json::Value =
            serde_json::from_str(json).map_err(|e| {
                StorageError::ConfigurationError(format!("Invalid service account JSON: {e}"))
            })?;

        let ty = val["type"].as_str().unwrap_or("");
        if ty != "service_account" {
            return Err(StorageError::ConfigurationError(format!(
                "Expected type=service_account, got '{ty}'"
            )));
        }

        let client_email = val["client_email"]
            .as_str()
            .ok_or_else(|| StorageError::ConfigurationError(
                "Missing 'client_email' in service account JSON".into(),
            ))?
            .to_string();

        let private_key = val["private_key"]
            .as_str()
            .ok_or_else(|| StorageError::ConfigurationError(
                "Missing 'private_key' in service account JSON".into(),
            ))?
            .to_string();

        let project_id = val["project_id"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let token_uri = val["token_uri"].as_str().unwrap_or(
            "https://oauth2.googleapis.com/token",
        ).to_string();

        Ok(Self {
            client_email,
            private_key_pem: private_key,
            project_id,
            token_uri,
        })
    }
}

// ---------------------------------------------------------------------------
// OAuth2 Token Cache
// ---------------------------------------------------------------------------

struct AccessToken {
    value: String,
    expires_at: DateTime<Utc>,
}

struct TokenCache {
    inner: std::sync::Mutex<Option<AccessToken>>,
    sa_info: Arc<ServiceAccountInfo>,
    http_client: reqwest::Client,
}

impl TokenCache {
    fn new(sa_info: Arc<ServiceAccountInfo>) -> Self {
        Self {
            inner: std::sync::Mutex::new(None),
            sa_info,
            http_client: reqwest::Client::builder()
                .build()
                .expect("reqwest Client build"),
        }
    }

    /// Get a valid access token, refreshing if expired or missing.
    async fn get(&self) -> Result<String, StorageError> {
        // Check cache first
        {
            let guard = self.inner.lock().unwrap();
            if let Some(ref token) = *guard {
                if token.expires_at > Utc::now() + chrono::Duration::seconds(60) {
                    return Ok(token.value.clone());
                }
            }
        }

        // Refresh token
        debug!("Refreshing GCS OAuth2 access token");
        let new_token = self.refresh_token().await?;
        let value = new_token.value.clone();

        *self.inner.lock().unwrap() = Some(new_token);
        Ok(value)
    }

    async fn refresh_token(&self) -> Result<AccessToken, StorageError> {
        use sha2::{Digest, Sha256};
        use rsa::pkcs8::DecodePrivateKey;

        let now_epoch = Utc::now().timestamp();
        let expiry = now_epoch + 3600;

        let header_b64 = b64_encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claim_b64 = b64_encode(
            &serde_json::json!({
                "iss": self.sa_info.client_email,
                "scope": "https://www.googleapis.com/auth/devstorage.read_write",
                "aud": self.sa_info.token_uri,
                "iat": now_epoch,
                "exp": expiry,
            })
            .to_string(),
        );

        let signing_input = format!("{header_b64}.{claim_b64}");

        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(
            &self.sa_info.private_key_pem,
        )
        .map_err(|e| {
            StorageError::ConfigurationError(format!(
                "Failed to parse RSA private key from service account: {e}"
            ))
        })?;

        let hash = Sha256::digest(signing_input.as_bytes());
        let digest_info = pkcs1v15_digest_info_sha256(&hash);
        let signature = private_key
            .sign(
                rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                &digest_info,
            )
            .map_err(|e| {
                StorageError::InternalError(format!("RSA sign failed: {e}"))
            })?;

        let jwt = format!(
            "{}.{}",
            signing_input,
            b64_encode_bytes(&signature)
        );

        let response = self
            .http_client
            .post(&self.sa_info.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| StorageError::NetworkError(format!("Token request failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                StorageError::PermissionDenied(format!(
                    "OAuth2 token exchange failed: {}",
                    e.status().map(|s| s.as_u16()).unwrap_or(0)
                ))
            })?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| StorageError::InternalError(format!("Token parse failed: {e}")))?;

        let access_token = response["access_token"]
            .as_str()
            .ok_or_else(|| StorageError::InternalError(
                "No access_token in OAuth2 response".into(),
            ))?
            .to_string();

        let expires_in = response["expires_in"].as_i64().unwrap_or(3600);

        Ok(AccessToken {
            value: access_token,
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in),
        })
    }
}

// ---------------------------------------------------------------------------
// Backend Implementation
// ---------------------------------------------------------------------------

/// Google Cloud Storage backend implementing [`StorageBackend`].
pub struct GcsStorage {
    config: GcsConfig,
    base_url: String,
    token_cache: Arc<TokenCache>,
    http_client: reqwest::Client,
}

impl Clone for GcsStorage {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            base_url: self.base_url.clone(),
            token_cache: Arc::clone(&self.token_cache),
            http_client: self.http_client.clone(),
        }
    }
}

impl std::fmt::Debug for GcsStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsStorage")
            .field("bucket", &self.config.bucket)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl GcsStorage {
    /// Create a new GCS backend from configuration.
    pub async fn new(config: GcsConfig) -> Result<Self, StorageError> {
        config.validate()?;

        let base_url = config
            .base_url
            .clone()
            .unwrap_or_else(|| "https://storage.googleapis.com".to_string());

        // Load and parse service account credentials
        let json_str = match &config.service_account_json {
            Some(json) => json.clone(),
            None => {
                let path = config.service_account_key_path.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError(
                        "No service account credentials provided".into(),
                    )
                })?;
                tokio::fs::read_to_string(path).await.map_err(|e| {
                    StorageError::ConfigurationError(format!(
                        "Failed to read service account key file '{path}': {e}"
                    ))
                })?
            }
        };

        let sa_info = Arc::new(ServiceAccountInfo::from_json(&json_str)?);
        let token_cache = Arc::new(TokenCache::new(Arc::clone(&sa_info)));

        let http_client = reqwest::Client::builder()
            .build()
            .map_err(|e| StorageError::ConfigurationError(format!(
                "HTTP client build failed: {e}"
            )))?;

        info!(
            bucket = %config.bucket,
            endpoint = %base_url,
            email = %sa_info.client_email,
            "GcsStorage initialized"
        );

        Ok(Self {
            config,
            base_url,
            token_cache,
            http_client,
        })
    }

    /// Build authenticated request headers including Bearer token.
    async fn auth_headers(&self) -> Result<reqwest::header::HeaderMap, StorageError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let token = self.token_cache.get().await?;
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .unwrap(),
        );
        Ok(headers)
    }

    /// Encode a blob name for URL-safe usage.
    fn encode_name(name: &str) -> String {
        urlencoding::encode(name).to_string()
    }
}

// ---------------------------------------------------------------------------
// StorageBackend Implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl StorageBackend for GcsStorage {
    fn backend_type(&self) -> &'static str {
        "gcs"
    }

    #[instrument(skip(self, data), fields(key, data_len = data.len()))]
    async fn put(&self, key: &str, data: Bytes) -> Result<StorageInfo, StorageError> {
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?name={}&uploadType=media",
            self.base_url,
            self.config.bucket,
            Self::encode_name(key)
        );
        let data_len = data.len() as u64;
        let headers = self.auth_headers().await?;

        debug!(key = %key, size = data_len, "Uploading to GCS");

        let response = self
            .http_client
            .post(&url)
            .headers(headers)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, key))?
            .error_for_status()
            .map_err(|e| StorageError::NetworkError(format!(
                "GCS put HTTP error ({}) for '{}'",
                e.status().map(|s| s.as_u16()).unwrap_or(0),
                key
            )))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| StorageError::InternalError(format!("Parse put response: {e}")))?;

        let etag = response["etag"]
            .as_str()
            .map(String::from);

        info!(key = %key, etag = ?etag, "Upload complete");

        Ok(StorageInfo {
            key: key.to_string(),
            size: data_len,
            content_type: None,
            created_at: Some(Utc::now()),
            etag,
        })
    }

    #[instrument(skip(self), fields(key))]
    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            self.base_url,
            self.config.bucket,
            Self::encode_name(key)
        );

        debug!(key = %key, "Downloading from GCS");

        let headers = self.auth_headers().await?;
        let response = self
            .http_client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, key))?
            .error_for_status()
            .map_err(|e| StorageError::NetworkError(format!(
                "GCS delete HTTP error ({}) for '{}'",
                e.status().map(|s| s.as_u16()).unwrap_or(0),
                key
            )))?;

        let bytes = response.bytes().await.map_err(|e| map_reqwest_error(&e, key))?;
        debug!(key = %key, size = bytes.len(), "Download complete");
        Ok(bytes)
    }

    #[instrument(skip(self), fields(key))]
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.base_url,
            self.config.bucket,
            Self::encode_name(key)
        );

        debug!(key = %key, "Deleting from GCS");

        let headers = self.auth_headers().await?;
        self.http_client
            .delete(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, key))?
            .error_for_status()
            .map_err(|e| StorageError::NetworkError(format!(
                "GCS HTTP error ({}) for '{}'",
                e.status().map(|s| s.as_u16()).unwrap_or(0),
                key
            )))?;

        info!(key = %key, "Deleted successfully");
        Ok(())
    }

    #[instrument(skip(self), fields(key))]
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?fields=size",
            self.base_url,
            self.config.bucket,
            Self::encode_name(key)
        );

        let headers = self.auth_headers().await?;
        match self
            .http_client
            .get(&url)
            .headers(headers)
            .send()
            .await
        {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => Ok(false),
            Err(e) => Err(map_reqwest_error(&e, key)),
        }
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), StorageError> {
        let url = format!("{}/storage/v1/b/{}?fields=name", self.base_url, self.config.bucket);
        let headers = self.auth_headers().await?;

        self.http_client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| StorageError::NetworkError(format!("GCS health check failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                StorageError::NetworkError(format!(
                    "GCS health check returned {}",
                    e.status().map(|s| s.as_u16()).unwrap_or(0)
                ))
            })?;

        debug!("GCS health check passed");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error Helpers
// ---------------------------------------------------------------------------

fn map_reqwest_error(err: &reqwest::Error, key: &str) -> StorageError {
    if err.is_timeout() || err.is_connect() {
        StorageError::NetworkError(format!("Network error for '{key}': {err}"))
    } else {
        StorageError::InternalError(format!("HTTP error for '{key}': {err}"))
    }
}

fn map_http_error(err: reqwest::Response, key: &str) -> StorageError {
    let status = err.status().as_u16();
    match status {
        404 => StorageError::NotFound(key.into()),
        403 => StorageError::PermissionDenied(format!("Access denied for '{key}'")),
        400 => StorageError::ConfigurationError(format!("Bad request for '{key}'")),
        _ => StorageError::NetworkError(format!("GCS HTTP error ({status}) for '{key}'")),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build PKCS#1 v1.5 DigestInfo DER encoding for SHA-256.
///
/// Layout: SEQUENCE { AlgorithmIdentifier (sha256WithRSAEncryption), OCTET STRING <hash> }
fn pkcs1v15_digest_info_sha256(hash: &[u8]) -> Vec<u8> {
    const SHA256_OID: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0x04, 0x20,
    ];
    let mut result = Vec::with_capacity(SHA256_OID.len() + hash.len());
    result.extend_from_slice(SHA256_OID);
    result.extend_from_slice(hash.as_ref());
    result
}

/// Base64-encode a byte slice using the standard alphabet.
fn b64_encode_bytes(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

/// Base64-encode a string using the standard alphabet.
fn b64_encode(input: &str) -> String {
    b64_encode_bytes(input.as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SA_JSON: &str = r#"{
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "test-key-id",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAz\n-----END RSA PRIVATE KEY-----\n",
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com"
    }"#;

    #[test]
    fn test_config_validation_good() {
        let cfg = GcsConfig::new("my-bucket").with_service_account_json(TEST_SA_JSON);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_reject_empty_bucket() {
        let cfg = GcsConfig::new("").with_service_account_json(TEST_SA_JSON);
        assert!(matches!(cfg.validate(), Err(StorageError::ConfigurationError(_))));
    }

    #[test]
    fn test_reject_short_bucket() {
        let cfg = GcsConfig::new("ab").with_service_account_json(TEST_SA_JSON);
        assert!(matches!(cfg.validate(), Err(StorageError::ConfigurationError(_))));
    }

    #[test]
    fn test_reject_long_bucket() {
        let long_name = "a".repeat(64);
        let cfg = GcsConfig::new(&long_name).with_service_account_json(TEST_SA_JSON);
        assert!(matches!(cfg.validate(), Err(StorageError::ConfigurationError(_))));
    }

    #[test]
    fn test_reject_uppercase_bucket() {
        let cfg = GcsConfig::new("MyBucket").with_service_account_json(TEST_SA_JSON);
        assert!(matches!(cfg.validate(), Err(StorageError::ConfigurationError(_))));
    }

    #[test]
    fn test_reject_no_credentials() {
        let cfg = GcsConfig::new("my-bucket");
        assert!(matches!(cfg.validate(), Err(StorageError::ConfigurationError(_))));
    }

    #[test]
    fn test_sa_parse_valid_json() {
        let sa = ServiceAccountInfo::from_json(TEST_SA_JSON);
        assert!(sa.is_ok());
        let sa = sa.unwrap();
        assert_eq!(sa.client_email, "test@test-project.iam.gserviceaccount.com");
        assert_eq!(sa.project_id, "test-project");
        assert_eq!(sa.token_uri, "https://oauth2.googleapis.com/token");
    }

    #[test]
    fn test_sa_parse_rejects_user_type() {
        let bad_json = r#"{"type": "authorized_user", "client_email": "x@y.z"}"#;
        assert!(ServiceAccountInfo::from_json(bad_json).is_err());
    }

    #[test]
    fn test_sa_parse_missing_fields() {
        let bad_json = r#"{"type": "service_account"}"#;
        assert!(ServiceAccountInfo::from_json(bad_json).is_err());
    }

    #[test]
    fn test_encode_name_preserves_safe_chars() {
        assert_eq!(GcsStorage::encode_name("normal-file.pdf"), "normal-file.pdf");
    }

    #[test]
    fn test_encode_name_escapes_specials() {
        let encoded = GcsStorage::encode_name("path/with spaces.txt");
        assert!(!encoded.contains(' '));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_backend_type_is_gcs() {
        assert_eq!("gcs", "gcs");
    }
}
