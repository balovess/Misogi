// =============================================================================
// Misogi Core — ApiForwardStorage: Write-Only External API Forwarder
// =============================================================================
//! Implements a **write-only** storage backend that forwards data via HTTP
//! to a configured external API endpoint. This backend achieves **absolute
//! zero data retention** by design: it never stores data locally and does not
//! support retrieval, deletion, or existence-check operations.
//!
//! # Architecture Position
//!
//! This module implements [`StorageBackend`] trait (Pillar 2) as a **forward-only**
//! adapter suitable for:
//!
//! - **Event streaming pipelines**: Forward CDR results to SIEM / SOAR platforms.
//! - **Webhook delivery**: POST sanitized files to downstream processing services.
//! - **API gateway integration**: Bridge Misogi output to external REST endpoints.
//! - **Zero-retention compliance**: Satisfy regulatory requirements that forbid
//!   local persistence of processed data (e.g., GDPR Article 25, HIPAA minimum
//!   necessary rule).
//!
//! # Data Flow
//!
//! ```text
//! Misogi Engine → [ApiForwardStorage::put()] → HTTP POST → External Endpoint
//! ```
//!
//! No disk writes occur at any stage. Data flows from memory (`Bytes`) through
//! the HTTP request body directly to the network socket.
//!
//! # Write-Only Contract
//!
//! | Operation    | Behavior                                    |
//! |--------------|---------------------------------------------|
//! | `put()`      | HTTP POST/PUT to configured endpoint        |
//! | `get()`      | Returns `NotSupported` error                |
//! | `delete()`   | Returns `NotSupported` error                |
//! | `exists()`   | Returns `NotSupported` error                |
//! | `health_check()`| HTTP HEAD/GET to verify endpoint reachability|
//!
//! # Security Considerations
//!
//! - Authentication tokens support environment variable expansion
//!   (e.g., `${MISOGI_API_KEY}`) to avoid credential leakage in config files.
//! - All connections use TLS when the endpoint URL scheme is `https://`.
//! - Request timeouts prevent resource exhaustion from slow/hanging endpoints.
//!
//! # Example
//!
//! ```ignore
//! use misogi_core::storage::api_forward::{ApiForwardStorage, ApiForwardConfig};
//! use misogi_core::traits::storage::StorageBackend;
//! use bytes::Bytes;
//!
//! let config = ApiForwardConfig {
//!     endpoint: "https://logs.example.com/api/ingest".parse().unwrap(),
//!     headers: [("X-Tenant".to_string(), "acme-corp".to_string())]
//!         .into_iter().collect(),
//!     auth_token: Some("${MISOGI_API_TOKEN}".to_string()),
//!     auth_header: "Authorization".to_string(),
//!     timeout_secs: 30,
//!     method: HttpMethod::Post,
//! };
//!
//! let storage = ApiForwardStorage::new(config)?;
//! let info = storage.put("cdr/report.json", Bytes::from_static(b"{...}")).await?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, StatusCode, Url};

use crate::traits::storage::{StorageBackend, StorageError, StorageInfo};

// =============================================================================
// HttpMethod — Supported HTTP verbs for forwarding
// =============================================================================

/// HTTP method used when forwarding data to the external endpoint.
///
/// Most API-forwarding scenarios use `Post`, but some legacy or specialized
/// endpoints may require `Put`. The choice depends on the target API's
/// semantic contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMethod {
    /// HTTP POST — standard for creating resources or submitting data.
    #[default]
    Post,

    /// HTTP PUT — used for idempotent uploads where the key maps to a URI path.
    Put,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
        }
    }
}

impl HttpMethod {
    /// Convert to reqwest's [`Method`] enum for HTTP client construction.
    fn to_reqwest_method(&self) -> Method {
        match self {
            Self::Post => Method::POST,
            Self::Put => Method::PUT,
        }
    }
}

// =============================================================================
// ApiForwardStorage Configuration
// =============================================================================

/// Configuration for [`ApiForwardStorage`].
///
/// All fields are validated at construction time; invalid configurations
/// (empty endpoint, zero timeout) are rejected with [`StorageError::ConfigurationError`].
#[derive(Debug, Clone)]
pub struct ApiForwardConfig {
    /// Target URL for HTTP forwarding.
    ///
    /// MUST be a valid absolute URL with `http://` or `https://` scheme.
    /// The full URL is used as-is for each `put()` invocation; no path
    /// appending or key-based routing is performed by this backend.
    pub endpoint: Url,

    /// Additional HTTP headers included in every forwarded request.
    ///
    /// Common use cases: `X-Request-ID`, `X-Tenant`, custom correlation IDs.
    /// Authentication headers are handled separately via `auth_token` /
    /// `auth_header`.
    pub headers: HashMap<String, String>,

    /// Optional authentication token value.
    ///
    /// Supports environment variable expansion: if the value contains
    /// `${VAR_NAME}` pattern(s), each is replaced with the corresponding
    /// `std::env::var()` value at construction time. Missing environment
    /// variables cause a configuration error.
    ///
    /// When set, this value is sent as the header named by `auth_header`.
    pub auth_token: Option<String>,

    /// Header name for authentication token injection.
    ///
    /// Defaults to `"Authorization"` but can be overridden for APIs that
    /// use non-standard auth header names (e.g., `"X-API-Key"`).
    pub auth_header: String,

    /// Request timeout in seconds.
    ///
    /// Applies to the entire HTTP transaction: DNS resolution, TCP connect,
    /// TLS handshake, request transmission, and response receipt.
    /// Minimum allowed value: `1` second.
    pub timeout_secs: u64,

    /// HTTP verb for forwarding requests.
    ///
    /// See [`HttpMethod`] documentation for semantics.
    pub method: HttpMethod,
}

impl Default for ApiForwardConfig {
    fn default() -> Self {
        Self {
            // Intentionally invalid — caller MUST provide a valid endpoint.
            endpoint: Url::parse("http://invalid-placeholder.local").unwrap(),
            headers: HashMap::new(),
            auth_token: None,
            auth_header: "Authorization".to_string(),
            timeout_secs: 30,
            method: HttpMethod::default(),
        }
    }
}

// =============================================================================
// Environment Variable Expansion
// =============================================================================

/// Expand `${ENV_VAR}` patterns in a string using `std::env::var()`.
///
/// Each occurrence of `${NAME}` is replaced with the value of environment
/// variable `NAME`. Unset variables produce an error rather than silently
/// expanding to empty string — this prevents silent misconfiguration.
///
/// # Arguments
///
/// * `input` — String potentially containing `${...}` patterns.
///
/// # Returns
///
/// The expanded string on success, or an error message identifying the
/// unset variable name on failure.
pub(crate) fn expand_env_vars(input: &str) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            // Consume opening brace
            chars.next();

            // Extract variable name until closing brace
            let mut var_name = String::new();
            let mut found_close = false;

            while let Some(c) = chars.next() {
                if c == '}' {
                    found_close = true;
                    break;
                }
                var_name.push(c);
            }

            if !found_close {
                return Err(format!(
                    "Unterminated ${{}} expression in auth_token: '{}'",
                    input
                ));
            }

            // Look up environment variable
            match std::env::var(&var_name) {
                Ok(value) => result.push_str(&value),
                Err(std::env::VarError::NotPresent) => {
                    return Err(format!(
                        "Environment variable '{}' referenced in auth_token is not set",
                        var_name
                    ));
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(format!(
                        "Environment variable '{}' contains non-Unicode data",
                        var_name
                    ));
                }
            }
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

// =============================================================================
// ApiForwardStorage — Write-Only Storage Backend Implementation
// =============================================================================

/// Write-only storage backend that forwards data to an external HTTP API.
///
/// This implementation provides **zero local data retention**: every `put()`
/// call transmits data directly over HTTP without writing to any local
/// filesystem, database, or in-memory cache. Read operations are explicitly
/// unsupported to enforce the write-only contract at the type level.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` safe because it holds only immutable
/// configuration data and a thread-safe `reqwest::Client` (which manages
/// its own connection pool internally).
///
/// # Resource Management
///
/// The internal `reqwest::Client` is created once at construction time
/// and reused across all operations. Connection pooling is handled
/// automatically by reqwest's `ClientBuilder`.
///
/// # Error Classification
///
/// | Scenario                     | Error Variant                  |
/// |------------------------------|-------------------------------|
/// | Endpoint unreachable          | `NetworkError`                 |
/// | HTTP 4xx response             | `PermissionDenied` or appropriate|
/// | HTTP 5xx response             | `NetworkError` (retryable)     |
/// | Timeout                       | `NetworkError`                 |
/// | get/delete/exists called      | `NotSupported`                 |
/// | Invalid configuration         | `ConfigurationError`           |
pub struct ApiForwardStorage {
    /// Immutable configuration resolved at construction time.
    config: ApiForwardConfig,

    /// Shared HTTP client with connection pooling and configured timeout.
    http_client: Client,

    /// Resolved authentication header value (after env var expansion).
    /// `None` if no auth token was configured.
    resolved_auth: Option<String>,
}

impl ApiForwardStorage {
    /// Create a new `ApiForwardStorage` instance with the given configuration.
    ///
    /// Validates all configuration parameters, expands environment variables
    /// in `auth_token`, and initializes the internal HTTP client.
    ///
    /// # Arguments
    ///
    /// * `config` — Forwarding configuration including endpoint, credentials,
    ///   timeout, and HTTP method.
    ///
    /// # Returns
    ///
    /// Initialized `ApiForwardStorage` ready for `put()` operations.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ConfigurationError`] if:
    /// - Endpoint URL has empty host.
    /// - Timeout is less than 1 second.
    /// - Environment variable expansion fails (unset or non-Unicode variable).
    /// - HTTP client initialization fails.
    pub fn new(config: ApiForwardConfig) -> Result<Self, StorageError> {
        // Validate endpoint: reject empty or placeholder hosts
        let host = config
            .endpoint
            .host_str()
            .ok_or_else(|| {
                StorageError::ConfigurationError(
                    "Endpoint URL must have a valid host".to_string(),
                )
            })?;

        if host.is_empty() || host == "invalid-placeholder.local" {
            return Err(StorageError::ConfigurationError(
                "Endpoint URL must be a valid, non-empty host".to_string(),
            ));
        }

        // Validate timeout: enforce minimum of 1 second
        if config.timeout_secs < 1 {
            return Err(StorageError::ConfigurationError(format!(
                "Timeout must be >= 1 second, got {}",
                config.timeout_secs
            )));
        }

        // Expand environment variables in auth_token
        let resolved_auth = match &config.auth_token {
            Some(token) => {
                let expanded = expand_env_vars(token).map_err(|e| {
                    StorageError::ConfigurationError(format!(
                        "Failed to expand auth_token environment variables: {}",
                        e
                    ))
                })?;
                Some(expanded)
            }
            None => None,
        };

        // Build HTTP client with configured timeout
        let timeout = Duration::from_secs(config.timeout_secs);
        let http_client = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .build()
            .map_err(|e| {
                StorageError::InternalError(format!(
                    "Failed to initialize HTTP client: {}",
                    e
                ))
            })?;

        tracing::info!(
            endpoint = %config.endpoint,
            method = %config.method,
            timeout_secs = config.timeout_secs,
            has_auth = resolved_auth.is_some(),
            extra_headers_count = config.headers.len(),
            "ApiForwardStorage initialized"
        );

        Ok(Self {
            config,
            http_client,
            resolved_auth,
        })
    }

    /// Build an HTTP request with all configured headers and authentication.
    ///
    /// Constructs the base request object with:
    /// - Configured method (POST or PUT)
    /// - Target endpoint URL
    /// - Custom headers from configuration
    /// - Authentication header (if token was provided)
    ///
    /// # Arguments
    ///
    /// * `content_type` — MIME type for the Content-Type header.
    fn build_request(
        &self,
        content_type: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let method = self.config.method.to_reqwest_method();
        let mut request = self
            .http_client
            .request(method, self.config.endpoint.clone());

        // Set Content-Type from provided value or default
        let ct = content_type.unwrap_or("application/octet-stream");
        request = request.header("Content-Type", ct);

        // Apply custom headers from configuration
        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        // Apply authentication header if resolved
        if let Some(auth_value) = &self.resolved_auth {
            request = request.header(self.config.auth_header.as_str(), auth_value.as_str());
        }

        request
    }

    /// Extract metadata from HTTP response headers into [`StorageInfo`].
    ///
    /// Attempts to read common metadata headers from the upstream response:
    /// - `ETag` → `StorageInfo.etag`
    /// - `Last-Modified` → `StorageInfo.created_at`
    /// - `Content-Type` → `StorageInfo.content_type`
    ///
    /// Missing headers are gracefully treated as `None`.
    fn extract_response_metadata(
        &self,
        response: &reqwest::Response,
        key: &str,
        size: u64,
    ) -> StorageInfo {
        let headers = response.headers();

        // Extract ETag
        let etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Extract Last-Modified timestamp
        let created_at = headers
            .get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| DateTime::parse_from_rfc2822(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Extract Content-Type from response
        let content_type = headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());

        StorageInfo {
            key: key.to_string(),
            size,
            content_type,
            created_at,
            etag,
        }
    }
}

// =============================================================================
// StorageBackend Trait Implementation
// =============================================================================

#[async_trait]
impl StorageBackend for ApiForwardStorage {
    /// Forward data to the configured HTTP endpoint.
    ///
    /// Transmits the entire `data` payload as the HTTP request body without
    /// any intermediate disk writes. The body is streamed from the `Bytes`
    /// buffer directly to the network socket via reqwest's zero-copy path.
    ///
    /// # Arguments
    ///
    /// * `key` — Object identifier (included in returned `StorageInfo` but
    ///   NOT appended to the URL; the configured endpoint is used as-is).
    /// * `data` — Binary content to forward. Ownership is taken for efficient
    ///   zero-copy transmission.
    ///
    /// # Returns
    ///
    /// [`StorageInfo`] with metadata extracted from the HTTP response headers
    /// (ETag, Last-Modified, Content-Type) on success.
    ///
    /// # Errors
    ///
    /// - [`StorageError::NetworkError`] on connectivity failures, timeouts,
    ///   or server-side errors (HTTP 5xx).
    /// - [`StorageError::PermissionDenied`] on HTTP 401/403 responses.
    /// - [`StorageError::ConfigurationError`] should never occur (validated
    ///   at construction time).
    async fn put(&self, key: &str, data: Bytes) -> Result<StorageInfo, StorageError> {
        let size = data.len() as u64;

        tracing::debug!(
            key = key,
            size = size,
            endpoint = %self.config.endpoint,
            method = %self.config.method,
            "Forwarding data via HTTP"
        );

        // Build request with default content-type (caller cannot specify it via trait signature)
        let request = self.build_request(None);

        // Execute request with body
        match request.body(data).send().await {
            Ok(response) => {
                let status = response.status();

                tracing::debug!(
                    http_status = status.as_u16(),
                    key = key,
                    "Received HTTP response from forward endpoint"
                );

                if status.is_success() {
                    let info = self.extract_response_metadata(&response, key, size);
                    tracing::info!(
                        key = key,
                        size = info.size,
                        etag = ?info.etag,
                        "Data forwarded successfully"
                    );
                    Ok(info)
                } else if status == StatusCode::UNAUTHORIZED
                    || status == StatusCode::FORBIDDEN
                {
                    let body_text = response.text().await.unwrap_or_default();
                    Err(StorageError::PermissionDenied(format!(
                        "HTTP {} from {}: {}",
                        status, self.config.endpoint, body_text
                    )))
                } else if status.is_server_error() {
                    let body_text = response.text().await.unwrap_or_default();
                    Err(StorageError::NetworkError(format!(
                        "Server error HTTP {} from {}: {}",
                        status, self.config.endpoint, body_text
                    )))
                } else {
                    // Client errors other than 401/403
                    let body_text = response.text().await.unwrap_or_default();
                    Err(StorageError::NetworkError(format!(
                        "HTTP {} from {}: {}",
                        status, self.config.endpoint, body_text
                    )))
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    tracing::warn!(
                        error = %e,
                        timeout_secs = self.config.timeout_secs,
                        key = key,
                        "HTTP forward request timed out"
                    );
                    Err(StorageError::NetworkError(format!(
                        "Request timed out after {}s: {}",
                        self.config.timeout_secs, e
                    )))
                } else if e.is_connect() {
                    tracing::error!(error = %e, "Cannot connect to forward endpoint");
                    Err(StorageError::NetworkError(format!(
                        "Connection failed to {}: {}",
                        self.config.endpoint, e
                    )))
                } else {
                    tracing::error!(error = %e, "HTTP forward request failed");
                    Err(StorageError::NetworkError(format!(
                        "HTTP request failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Always returns [`StorageError::NotSupported`].
    ///
    /// `ApiForwardStorage` is write-only by design. Retrieving previously
    /// forwarded data would require the external endpoint to retain it,
    /// which contradicts the zero-data-retention guarantee.
    async fn get(&self, _key: &str) -> Result<Bytes, StorageError> {
        Err(StorageError::NotSupported(
            "ApiForwardStorage is write-only".to_string(),
        ))
    }

    /// Always returns [`StorageError::NotSupported`].
    ///
    /// Deletion is not meaningful for a forward-only backend: data is
    /// transmitted to the external endpoint and not retained locally.
    async fn delete(&self, _key: &str) -> Result<(), StorageError> {
        Err(StorageError::NotSupported(
            "ApiForwardStorage is write-only".to_string(),
        ))
    }

    /// Always returns [`StorageError::NotSupported`].
    ///
    /// Existence checking would imply the ability to query the remote
    /// endpoint about prior transmissions, which violates the fire-and-forget
    /// forwarding model.
    async fn exists(&self, _key: &str) -> Result<bool, StorageError> {
        Err(StorageError::NotSupported(
            "ApiForwardStorage is write-only".to_string(),
        ))
    }

    /// Verify reachability of the configured endpoint via HTTP HEAD request.
    ///
    /// Sends a lightweight HEAD request to the configured endpoint. Any
    /// successful HTTP response (including redirects) indicates health.
    /// If the server doesn't support HEAD, falls back to a GET request.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the endpoint responds to the probe.
    ///
    /// # Errors
    ///
    /// - [`StorageError::NetworkError`] if the endpoint is unreachable or
    ///   the probe times out.
    /// - [`StorageError::PermissionDenied`] on HTTP 401/403 responses.
    async fn health_check(&self) -> Result<(), StorageError> {
        tracing::debug!(
            endpoint = %self.config.endpoint,
            "Performing health check against forward endpoint"
        );

        // Try HEAD first (lighter), fall back to GET if needed
        let head_result = self.http_client.head(self.config.endpoint.clone()).send().await;

        match head_result {
            Ok(response) => {
                let status = response.status();

                if status.is_success()
                    || status == StatusCode::METHOD_NOT_ALLOWED
                    || status == StatusCode::NOT_FOUND
                {
                    // Accept success, or HEAD-not-supported (fall through treated as OK for
                    // basic connectivity check), or 404 (endpoint exists but path may differ)
                    tracing::info!(
                        http_status = status.as_u16(),
                        endpoint = %self.config.endpoint,
                        "Health check passed"
                    );
                    return Ok(());
                }

                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Err(StorageError::PermissionDenied(format!(
                        "Health check failed: HTTP {} from {}",
                        status, self.config.endpoint
                    )));
                }

                // For other statuses, still consider endpoint reachable
                tracing::warn!(
                    http_status = status.as_u16(),
                    "Health check returned non-success but endpoint is reachable"
                );
                Ok(())
            }
            Err(e) => {
                if e.is_timeout() {
                    Err(StorageError::NetworkError(format!(
                        "Health check timed out after {}s: {}",
                        self.config.timeout_secs, e
                    )))
                } else {
                    Err(StorageError::NetworkError(format!(
                        "Health check failed for {}: {}",
                        self.config.endpoint, e
                    )))
                }
            }
        }
    }

    /// Returns the static identifier `"api_forward"`.
    ///
    /// Used for logging, plugin registry identification, and runtime
    /// dispatch. This value is constant for all instances.
    fn backend_type(&self) -> &'static str {
        "api_forward"
    }
}

// =============================================================================
// Debug Implementation
// =============================================================================

impl fmt::Debug for ApiForwardStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiForwardStorage")
            .field("endpoint", &self.config.endpoint)
            .field("method", &self.config.method)
            .field("timeout_secs", &self.config.timeout_secs)
            .field("auth_header", &self.config.auth_header)
            .field("has_auth", &self.resolved_auth.is_some())
            .field("extra_headers_count", &self.config.headers.len())
            .finish()
    }
}

// Include unit tests from separate file to stay under 500-line limit.
#[cfg(test)]
include!("api_forward_tests.rs");
