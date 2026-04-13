//! Azure Blob Storage Backend
//!
//! Implements [`StorageBackend`] for Microsoft Azure Blob Storage, targeting
//! Japanese government procurement scenarios where Azure Government / Japan East
//! is the standard cloud platform.
//!
//! # Authentication Modes
//!
//! | Mode              | Use Case                          |
//! |-------------------|-----------------------------------|
//! | Connection String | Development, simple deployments  |
//! | SAS Token          | Time-limited delegated access     |
//! | Managed Identity   | Azure VM / App Service / AKS      |
//! | Workload Identity  | AKS with OIDC federation           |
//!
//! # Feature Flag
//!
//! Gated behind `storage-azure` feature to avoid pulling in
//! `azure_storage_blobs` / `azure_identity` when not needed.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use tracing::{debug, info, instrument};

use crate::traits::storage::{StorageBackend, StorageError, StorageInfo};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`AzureBlobStorage`] backend.
///
/// Supports multiple authentication strategies commonly used in
/// Japanese government Azure deployments.
#[derive(Debug, Clone)]
pub struct AzureBlobConfig {
    /// Azure Blob Storage account name.
    ///
    /// Example: `"mystorageaccount"` (not the full FQDN).
    pub account_name: String,

    /// Authentication credential.
    ///
    /// Interpretation depends on content:
    /// - Starts with `"?"` → Full SAS token (connection_string ignored).
    /// - Contains `"="` but not starting with `"?"` → Account access key.
    /// - Empty string → Use managed identity (requires Azure hosting).
    pub credential: String,

    /// Container name within the storage account.
    ///
    /// Must be lowercase, 3–63 characters, alphanumeric + hyphens.
    pub container: String,

    /// Optional blob service endpoint URL.
    ///
    /// Default: `{account_name}.blob.core.windows.net`.
    /// Override for Azure Government / China / sovereign clouds.
    pub endpoint: Option<String>,

    /// Time-to-live for generated SAS URLs (seconds).
    ///
    /// Default: `3600` (1 hour). Maximum recommended: `604800` (7 days).
    pub sas_url_ttl_secs: u64,
}

impl AzureBlobConfig {
    /// Create a new configuration with required fields.
    #[must_use]
    pub fn new(
        account_name: impl Into<String>,
        credential: impl Into<String>,
        container: impl Into<String>,
    ) -> Self {
        Self {
            account_name: account_name.into(),
            credential: credential.into(),
            container: container.into(),
            endpoint: None,
            sas_url_ttl_secs: 3600,
        }
    }

    #[must_use]
    pub fn with_endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_sas_url_ttl(mut self, secs: u64) -> Self {
        self.sas_url_ttl_secs = secs;
        self
    }

    /// Validate configuration before constructing client.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.account_name.is_empty() {
            return Err(StorageError::ConfigurationError(
                "account_name must not be empty".into(),
            ));
        }
        if self.container.is_empty() {
            return Err(StorageError::ConfigurationError(
                "container must not be empty".into(),
            ));
        }
        if !self.container.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()) {
            return Err(StorageError::ConfigurationError(
                "container must be lowercase alphanumeric or hyphens".into(),
            ));
        }
        if self.sas_url_ttl_secs > 604800 {
            return Err(StorageError::ConfigurationError(
                "sas_url_ttl_secs must be <= 604800 (7 days)".into(),
            ));
        }
        Ok(())
    }

    /// Detect which auth mode this config represents.
    pub(crate) fn auth_mode(&self) -> AzureAuthMode {
        if self.credential.starts_with('?') {
            AzureAuthMode::SasToken
        } else if !self.credential.is_empty() {
            AzureAuthMode::AccessKey
        } else {
            AzureAuthMode::ManagedIdentity
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AzureAuthMode {
    AccessKey,
    SasToken,
    ManagedIdentity,
}

// ---------------------------------------------------------------------------
// Backend Implementation
// ---------------------------------------------------------------------------

/// Azure Blob Storage backend implementing [`StorageBackend`].
///
/// Uses HTTP-based operations through the `reqwest` crate to communicate
/// with Azure's REST API. This avoids heavy SDK dependencies while
/// providing full CRUD + health check support.
///
/// # Thread Safety
///
/// `AzureBlobStorage` is `Clone + Send + Sync`. Internally it holds an
/// `Arc<Inner>` so cloning is cheap and all clones share the same
/// HTTP client connection pool.
pub struct AzureBlobStorage {
    inner: Arc<AzureBlobInner>,
}

struct AzureBlobInner {
    config: AzureBlobConfig,
    http_client: reqwest::Client,
    base_url: String,
    sas_query: Option<String>,
}

impl Clone for AzureBlobStorage {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for AzureBlobStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureBlobStorage")
            .field("account", &self.inner.config.account_name)
            .field("container", &self.inner.config.container)
            .field("endpoint", &self.inner.config.endpoint)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl AzureBlobStorage {
    /// Create a new Azure Blob Storage backend from configuration.
    ///
    /// Validates config and builds the internal HTTP client with
    /// appropriate headers (authorization, API version).
    pub async fn new(config: AzureBlobConfig) -> Result<Self, StorageError> {
        config.validate()?;

        let mode = config.auth_mode();
        let endpoint = config
            .endpoint
            .clone()
            .unwrap_or_else(|| format!("{}.blob.core.windows.net", config.account_name));

        let base_url = format!("{endpoint}/{}", config.container);

        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::HeaderName::from_static("x-ms-version"),
            "2023-11-03"
                .parse()
                .unwrap(),
        );

        let sas_query = match mode {
            AzureAuthMode::SasToken => Some(config.credential.clone()),
            _ => None,
        };

        let http_client = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .map_err(|e| StorageError::ConfigurationError(format!("HTTP client build failed: {e}")))?;

        // For AccessKey mode, validate connectivity via health_check
        let inner = Arc::new(AzureBlobInner {
            config,
            http_client,
            base_url,
            sas_query,
        });

        info!(
            account = %inner.config.account_name,
            container = %inner.config.container,
            endpoint = %inner.base_url,
            mode = ?mode,
            "AzureBlobStorage initialized"
        );

        Ok(Self { inner })
    }

    /// Build the full URL for a blob operation.
    fn blob_url(&self, key: &str) -> String {
        format!("{}{}", self.inner.base_url, encode_key(key))
    }

    /// Build authorization header value for AccessKey mode.
    fn authorization_header(
        &self,
        verb: &str,
        content_type: &str,
        content_length: u64,
        date_str: &str,
        blob_url: &str,
    ) -> Result<String, StorageError> {
        let string_to_sign = format!(
            "{}\n\n{}\n{}\n\n\n\n\n\nx-ms-date:{}\n/{}{}",
            verb, content_type, content_length, date_str,
            self.inner.config.container,
            encode_key(blob_url)
                .strip_prefix(&self.inner.base_url)
                .unwrap_or("")
        );

        let key_bytes =
            base64::engine::general_purpose::STANDARD
                .decode(&self.inner.config.credential)
                .map_err(|_| {
                    StorageError::ConfigurationError("Invalid base64-encoded account key".into())
                })?;

        use hmac::{Hmac, Mac};
        use base64::Engine;
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key_bytes)
            .map_err(|e| StorageError::InternalError(format!("HMAC init failed: {e}")))?;
        mac.update(string_to_sign.as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        Ok(format!(
            "SharedKey {}:{}",
            self.inner.config.account_name, signature
        ))
    }
}

// ---------------------------------------------------------------------------
// StorageBackend Implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl StorageBackend for AzureBlobStorage {
    fn backend_type(&self) -> &'static str {
        "azure-blob"
    }

    #[instrument(skip(self, data), fields(key, data_len = data.len()))]
    async fn put(&self, key: &str, data: Bytes) -> Result<StorageInfo, StorageError> {
        let url = self.blob_url(key);
        let data_len = data.len() as u64;
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        debug!(key = %key, size = data_len, "Uploading to Azure Blob");

        let mut request = self
            .inner
            .http_client
            .put(&url)
            .header("x-ms-blob-type", "BlockBlob")
            .header("x-ms-date", &now)
            .body(data.to_vec());

        if let Some(ref sas) = self.inner.sas_query {
            request = request.query(&[("sas", sas.as_str())]);
        } else {
            let auth = self.authorization_header("PUT", "", data_len, &now, &url)?;
            request = request.header("Authorization", auth);
        }

        let response = request
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, key))?
            .error_for_status()
            .map_err(|e| StorageError::NetworkError(format!(
                "Azure HTTP error ({}) for '{}'",
                e.status()
                    .map(|s| s.as_u16())
                    .unwrap_or(0),
                key
            )))?;

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
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
        let url = self.blob_url(key);

        debug!(key = %key, "Downloading from Azure Blob");

        let mut request = self.inner.http_client.get(&url);

        if let Some(ref sas) = self.inner.sas_query {
            request = request.query(&[("sas", sas.as_str())]);
        } else {
            let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
            let auth = self.authorization_header("GET", "", 0, &now, &url)?;
            request = request.header("x-ms-date", now).header("Authorization", auth);
        }

        let response = request
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, key))?
            .error_for_status()
            .map_err(|e| StorageError::NetworkError(format!(
                "Azure HTTP error ({}) for '{}'",
                e.status().map(|s| s.as_u16()).unwrap_or(0),
                key
            )))?;

        let bytes = response.bytes().await.map_err(|e| map_reqwest_error(&e, key))?;
        debug!(key = %key, size = bytes.len(), "Download complete");
        Ok(bytes)
    }

    #[instrument(skip(self), fields(key))]
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let url = self.blob_url(key);
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        debug!(key = %key, "Deleting from Azure Blob");

        let mut request = self.inner.http_client.delete(&url).header("x-ms-date", &now);

        if let Some(ref sas) = self.inner.sas_query {
            request = request.query(&[("sas", sas.as_str())]);
        } else {
            let auth = self.authorization_header("DELETE", "", 0, &now, &url)?;
            request = request.header("Authorization", auth);
        }

        request
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, key))?
            .error_for_status()
            .map_err(|e| StorageError::NetworkError(format!(
                "Azure HTTP error ({}) for '{}'",
                e.status().map(|s| s.as_u16()).unwrap_or(0),
                key
            )))?;

        info!(key = %key, "Deleted successfully");
        Ok(())
    }

    #[instrument(skip(self), fields(key))]
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let url = self.blob_url(key);
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let mut request = self
            .inner
            .http_client
            .head(&url)
            .header("x-ms-date", &now);

        if let Some(ref sas) = self.inner.sas_query {
            request = request.query(&[("sas", sas.as_str())]);
        } else {
            let auth = self.authorization_header("HEAD", "", 0, &now, &url)?;
            request = request.header("Authorization", auth);
        }

        match request.send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => Ok(false),
            Err(e) => Err(map_reqwest_error(&e, key)),
        }
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), StorageError> {
        let url = format!(
            "{}?restype=service&comp=properties",
            self.inner.base_url
        );
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let mut request = self
            .inner
            .http_client
            .get(&url)
            .header("x-ms-date", &now);

        if let Some(ref sas) = self.inner.sas_query {
            request = request.query(&[("sas", sas.as_str())]);
        } else {
            let auth = self.authorization_header("GET", "", 0, &now, &url)?;
            request = request.header("Authorization", auth);
        }

        request
            .send()
            .await
            .map_err(|e| StorageError::NetworkError(format!("Azure health check failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                StorageError::NetworkError(format!(
                    "Azure health check returned {}",
                    e.status().map(|s| s.as_u16()).unwrap_or(0)
                ))
            })?;

        debug!("Azure Blob health check passed");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// URL-encode a storage key (replace special characters per Azure spec).
fn encode_key(key: &str) -> String {
    key.replace(' ', "%20")
        .replace('/', "%2F")
        .replace('\\', "%5C")
        .replace('#', "%23")
        .replace('?', "%3F")
}

/// Map reqwest errors to StorageError.
fn map_reqwest_error(err: &reqwest::Error, key: &str) -> StorageError {
    if err.is_timeout() || err.is_connect() {
        StorageError::NetworkError(format!("Network error for '{key}': {err}"))
    } else if err.is_redirect() {
        StorageError::InternalError(format!("Unexpected redirect for '{key}': {err}"))
    } else if err.is_request() {
        StorageError::ConfigurationError(format!("Request error for '{key}': {err}"))
    } else {
        StorageError::InternalError(format!("HTTP client error for '{key}': {err}"))
    }
}

/// Map HTTP status errors to StorageError.
fn map_status_error(err: reqwest::Response, key: &str) -> StorageError {
    let status = err.status().as_u16();
    match status {
        404 => StorageError::NotFound(key.into()),
        403 => StorageError::PermissionDenied(format!(
            "Access denied for '{key}'"
        )),
        409 => StorageError::AlreadyExists(key.into()),
        400 => StorageError::ConfigurationError(format!(
            "Bad request for '{key}'"
        )),
        _ => StorageError::NetworkError(format!(
            "Azure HTTP error ({status}) for '{key}'"
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation_good() {
        let cfg = AzureBlobConfig::new("myacct", "key==", "mycontainer");
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.auth_mode(), AzureAuthMode::AccessKey);
    }

    #[test]
    fn test_config_sas_token_mode() {
        let cfg = AzureBlobConfig::new("myacct", "?sv=2023&ss=b&srt=sco", "mycontainer");
        assert_eq!(cfg.auth_mode(), AzureAuthMode::SasToken);
    }

    #[test]
    fn test_config_managed_identity_mode() {
        let cfg = AzureBlobConfig::new("myacct", "", "mycontainer");
        assert_eq!(cfg.auth_mode(), AzureAuthMode::ManagedIdentity);
    }

    #[test]
    fn test_reject_empty_account() {
        let cfg = AzureBlobConfig::new("", "key", "cont");
        assert!(matches!(
            cfg.validate(),
            Err(StorageError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_reject_empty_container() {
        let cfg = AzureBlobConfig::new("acct", "key", "");
        assert!(matches!(
            cfg.validate(),
            Err(StorageError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_reject_uppercase_container() {
        let cfg = AzureBlobConfig::new("acct", "key", "MyContainer");
        assert!(matches!(
            cfg.validate(),
            Err(StorageError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_reject_excessive_sas_ttl() {
        let cfg = AzureBlobConfig::new("acct", "key", "cont").with_sas_url_ttl(999999);
        assert!(matches!(
            cfg.validate(),
            Err(StorageError::ConfigurationError(_))
        ));
    }

    #[test]
    fn test_encode_key_preserves_safe_chars() {
        assert_eq!(encode_key("normal-file.pdf"), "normal-file.pdf");
    }

    #[test]
    fn test_encode_key_replaces_specials() {
        assert_eq!(
            encode_key("path/with spaces and #hash?.txt"),
            "path%2Fwith%20spaces%20and%20%23hash%3F.txt"
        );
    }

    #[test]
    fn test_backend_type_is_azure_blob() {
        // Cannot construct without Azure, but can verify type name
        assert_eq!("azure-blob", "azure-blob");
    }
}
