// =============================================================================
// Misogi Core — Generic HTTP REST API Scanner Adapter
// =============================================================================
//! POSTs file content to a configurable HTTP endpoint and parses
//! the JSON response. Compatible with any cloud/on-premise scanning
//! API that accepts multipart/form-data or raw binary uploads.
//!
//! # Supported Use Cases
//!
//! - **Cloud APIs**: VirusTotal, Trend Micro Cloud, Google Safe Browsing
//! - **Enterprise Platforms**: Custom REST-based scanning microservices
//! - **SaaS Solutions**: Third-party malware analysis services
//! - **API Gateways**: Proxy to internal scanning infrastructure via HTTP
//!
//! # Configuration Flexibility
//!
//! The adapter supports:
//! - Custom authentication headers (Bearer tokens, API keys, etc.)
//! - Configurable request timeouts
//! - JSON path extraction for non-standard response formats
//! - Both multipart and raw binary upload modes
//!
//! # Example Usage
//!
//! ```ignore
//! use misogi_core::scanners::{HttpApiAdapter, HttpApiConfig};
//!
//! let config = HttpApiConfig {
//!     endpoint: "https://api.example.com/scan".to_string(),
//!     auth_header: Some("Bearer ${API_TOKEN}".to_string()),
//!     timeout_secs: 30,
//!     result_path: Some("result.status".to_string()),
//!     threat_name_path: Some("result.threat_name".to_string()),
//! };
//!
//! let scanner = HttpApiAdapter::new(config)?;
//! let result = scanner.scan_stream(&file_data).await?;
//! ```

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::{
    ExternalScanner, Result as ScannerResult, ScanResult, ScannerError,
    ScannerMetadata, ThreatSeverity,
};

// =============================================================================
// Configuration Types
// =============================================================================

/// Configuration for HTTP REST API scanner adapter.
///
/// Defines how to connect to an external HTTP-based scanning service,
/// including authentication, timeout settings, and response parsing rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpApiConfig {
    /// Base URL of the scanning API endpoint.
    ///
    /// Must include the full path (e.g., `"https://api.trendmicro.com/v1/scan"`).
    /// Will be called with POST method (configurable in future versions).
    pub endpoint: String,

    /// Authentication header value (optional).
    ///
    /// Common formats:
    /// - `"Bearer <token>"` — OAuth2/JWT token authentication
    /// - `"API-Key <key>"` — API key header authentication
    /// - `"Basic <base64>"` — HTTP Basic authentication
    ///
    /// If `None`, no authentication header is sent.
    pub auth_header: Option<String>,

    /// Request timeout in seconds.
    ///
    /// Maximum time to wait for the HTTP response (includes connection time,
    /// TLS handshake, upload time, and server processing).
    /// Default: `30` seconds.
    pub timeout_secs: u64,

    /// JSON path to extract scan result status from response body.
    ///
    /// Uses dot-notation for nested field access:
    /// - `"status"` → top-level `status` field
    /// - `"result.status"` → nested under `result` object
    /// - `"data.scan findings[0].verdict"` → array indexing (future enhancement)
    ///
    /// If `None`, expects standard format: `{ "status": "clean"|"infected"|... }`
    pub result_path: Option<String>,

    /// JSON path to extract threat name from response body.
    ///
    /// Used when status indicates infection to identify the specific threat.
    /// If `None`, generic "Unknown Threat" will be used for infected results.
    pub threat_name_path: Option<String>,

    /// JSON path to extract severity level from response body (optional).
    ///
    /// If provided, maps string values to [`ThreatSeverity`] enum.
    /// Expected values: `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`
    /// If not provided or unmapped, defaults to `ThreatSeverity::Medium`.
    pub severity_path: Option<String>,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            auth_header: None,
            timeout_secs: 30,
            result_path: None,
            threat_name_path: None,
            severity_path: None,
        }
    }
}

/// Standardized expected response structure (when paths not configured).
///
/// Many scanning APIs return responses in this common format.
/// When custom paths are configured via `result_path`, this structure
/// is not used — instead, fields are extracted dynamically.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct StandardScanResponse {
    /// Scan result status.
    #[serde(default)]
    status: Option<String>,

    /// Name of detected threat (if infected).
    #[serde(default)]
    threat_name: Option<String>,

    /// Severity level string (if provided by API).
    #[serde(default)]
    severity: Option<String>,

    /// Error message (if scan failed).
    #[serde(default)]
    error: Option<String>,

    /// Additional metadata (ignored but preserved).
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
}

// =============================================================================
// HTTP API Adapter Implementation
// =============================================================================

/// Adapter for HTTP REST API-based virus/malware scanners.
///
/// Sends file content to a configurable HTTP endpoint using POST requests
/// with multipart/form-data encoding. Parses JSON responses according to
/// configured extraction paths.
///
/// # Thread Safety
/// This struct is `Send + Sync` safe because it holds only configuration
/// data and a thread-safe `reqwest::Client` (which uses connection pooling
/// internally).
///
/// # Authentication
/// Supports flexible authentication via the `auth_header` configuration.
/// The header name is always `"Authorization"`; the value is configurable
/// to support Bearer tokens, API keys, Basic auth, etc.
///
/// # Response Parsing
///
/// Two parsing modes are supported:
///
/// 1. **Standard mode** (no paths configured): Expects `{ "status": "...", ... }`
/// 2. **Custom path mode**: Extracts values from arbitrary JSON locations
///
/// Status values are case-insensitive and mapped as follows:
/// - `"clean"`, `"ok"`, `"safe"`, `"pass"`, `"no_threat"` → `Clean`
/// - `"infected"`, `"malicious"`, `"threat"`, `"blocked"`, `"found"` → `Infected`
/// - Anything else → `Error`
pub struct HttpApiAdapter {
    /// Immutable configuration for this adapter instance.
    config: HttpApiConfig,

    /// Shared HTTP client with connection pooling.
    http_client: Client,

    /// Unique identifier for logging and chain identification.
    adapter_id: String,
}

impl HttpApiAdapter {
    /// Create a new HTTP API adapter with the specified configuration.
    ///
    /// Initializes the internal `reqwest::Client` with appropriate timeout
    /// settings derived from configuration.
    ///
    /// # Arguments
    /// * `config` — HTTP endpoint, authentication, and parsing configuration.
    ///
    /// # Returns
    /// Initialized `HttpApiAdapter` ready for scanning operations.
    ///
    /// # Errors
    /// Returns error if:
    /// - Endpoint URL is empty or invalid
    /// - HTTP client cannot be initialized
    pub fn new(config: HttpApiConfig) -> ScannerResult<Self> {
        if config.endpoint.is_empty() {
            return Err(ScannerError::Configuration(
                "Endpoint URL is required".to_string(),
            ));
        }

        // Validate URL format
        if let Err(e) = config.endpoint.parse::<reqwest::Url>() {
            return Err(ScannerError::Configuration(format!(
                "Invalid endpoint URL '{}': {}",
                config.endpoint, e
            )));
        }

        let adapter_id = format!("http-api-{}", &config.endpoint);

        tracing::info!(
            adapter_id = %adapter_id,
            endpoint = %config.endpoint,
            timeout = config.timeout_secs,
            "Creating HTTP API adapter"
        );

        // Build HTTP client with timeout
        let client_timeout = std::time::Duration::from_secs(config.timeout_secs);
        let http_client = Client::builder()
            .timeout(client_timeout)
            .build()
            .map_err(|e| {
                ScannerError::Internal(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config,
            http_client,
            adapter_id,
        })
    }

    /// Build and execute HTTP scan request.
    ///
    /// Constructs a multipart/form-data POST request containing the file
    /// content, sends it to the configured endpoint, and parses the response.
    ///
    /// # Arguments
    /// * `data` — File content bytes to send for scanning.
    /// * `filename` — Original filename to include in the multipart form.
    ///
    /// # Returns
    /// Parsed [`ScanResult`] or transport/protocol error.
    async fn call_scan_api(&self, data: &[u8], filename: &str) -> ScannerResult<ScanResult> {
        tracing::debug!(
            endpoint = %self.config.endpoint,
            filename = filename,
            data_size = data.len(),
            "Sending file to HTTP scan API"
        );

        // Build request with optional auth header
        let mut request = self
            .http_client
            .post(&self.config.endpoint)
            .header("Accept", "application/json");

        // Add authorization header if configured
        if let Some(auth) = &self.config.auth_header {
            request = request.header("Authorization", auth.as_str());
        }

        // Attach file as multipart form data
        let part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| {
                ScannerError::Internal(format!("Failed to create multipart part: {}", e))
            })?;

        let form = reqwest::multipart::Form::new().part("file", part);
        request = request.multipart(form);

        // Execute request
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                tracing::debug!(http_status = %status, "Received HTTP response");

                if !status.is_success() {
                    // Handle HTTP error statuses
                    let error_body = response.text().await.unwrap_or_default();
                    tracing::error!(
                        http_status = %status,
                        body = %error_body,
                        "HTTP scan API returned error status"
                    );
                    return Ok(ScanResult::Error {
                        message: format!(
                            "HTTP {}: {}",
                            status, error_body
                        ),
                        transient: status.is_server_error(), // 5xx might be retryable
                    });
                }

                // Parse JSON response
                let json_text = response.text().await.map_err(|e| {
                    ScannerError::Protocol(format!("Failed to read response body: {}", e))
                })?;

                self.parse_json_response(&json_text)
            }
            Err(e) => {
                if e.is_timeout() {
                    tracing::warn!(error = %e, "HTTP request timed out");
                    Ok(ScanResult::Timeout {
                        timeout_secs: self.config.timeout_secs,
                    })
                } else if e.is_connect() || e.is_request() {
                    tracing::error!(error = %e, "HTTP connection/request failed");
                    Err(ScannerError::Connection(format!(
                        "Failed to connect to {}: {}",
                        self.config.endpoint, e
                    )))
                } else {
                    tracing::error!(error = %e, "HTTP request failed");
                    Err(ScannerError::Internal(format!(
                        "HTTP request failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Parse JSON response body into ScanResult.
    ///
    /// Handles two modes:
    /// 1. **Standard mode** (no custom paths): Deserializes into known structure
    /// 2. **Custom path mode**: Extracts values using dot-notation paths
    fn parse_json_response(&self, json_text: &str) -> ScannerResult<ScanResult> {
        tracing::trace!(response = json_text, "Parsing JSON response");

        let json_value: serde_json::Value =
            serde_json::from_str(json_text).map_err(|e| {
                ScannerError::Protocol(format!("Invalid JSON response: {}", e))
            })?;

        // Determine which parsing mode to use
        if self.config.result_path.is_some()
            || self.config.threat_name_path.is_some()
            || self.config.severity_path.is_some()
        {
            // Custom path mode
            self.extract_by_paths(&json_value)
        } else {
            // Standard mode
            self.parse_standard_response(&json_value)
        }
    }

    /// Parse response using standard (non-path) format.
    fn parse_standard_response(&self, value: &serde_json::Value) -> ScannerResult<ScanResult> {
        // Try to deserialize as standard response
        let response: StandardScanResponse = serde_json::from_value(value.clone())
            .unwrap_or_else(|_| StandardScanResponse {
                status: None,
                threat_name: None,
                severity: None,
                error: None,
                extra: std::collections::BTreeMap::new(),
            });

        // Check for explicit error
        if let Some(error_msg) = response.error {
            tracing::error!(error = %error_msg, "API returned error");
            return Ok(ScanResult::Error {
                message: error_msg,
                transient: false,
            });
        }

        // Map status string to ScanResult
        match response.status.as_deref().map(|s| s.to_lowercase()).as_deref() {
            Some("clean") | Some("ok") | Some("safe") | Some("pass") | Some("no_threat") => {
                tracing::info!("HTTP API reports: CLEAN");
                Ok(ScanResult::Clean)
            }
            Some("infected") | Some("malicious") | Some("threat") | Some("blocked")
            | Some("found") => {
                let threat_name = response
                    .threat_name
                    .unwrap_or_else(|| "Unknown Threat".to_string());
                let severity = Self::map_severity_string(
                    response.severity.as_deref(),
                );

                tracing::warn!(
                    threat_name = %threat_name,
                    severity = %severity,
                    "HTTP API reports: INFECTED"
                );
                Ok(ScanResult::Infected {
                    threat_name,
                    severity,
                })
            }
            Some(other) => {
                tracing::warn!(status = other, "Unknown status from API");
                Ok(ScanResult::Error {
                    message: format!("Unknown status: {}", other),
                    transient: false,
                })
            }
            None => {
                tracing::warn!("No status field in response");
                Ok(ScanResult::Error {
                    message: "No status field in response".to_string(),
                    transient: false,
                })
            }
        }
    }

    /// Extract scan result using configured JSON paths.
    fn extract_by_paths(&self, value: &serde_json::Value) -> ScannerResult<ScanResult> {
        // Extract status
        let status_str = self
            .config
            .result_path
            .as_ref()
            .and_then(|path| Self::extract_json_path(value, path))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Extract threat name
        let threat_name = self
            .config
            .threat_name_path
            .as_ref()
            .and_then(|path| Self::extract_json_path(value, path))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Extract severity
        let severity_str = self
            .config
            .severity_path
            .as_ref()
            .and_then(|path| Self::extract_json_path(value, path))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Map status to ScanResult
        match status_str.as_deref().map(|s| s.to_lowercase()).as_deref() {
            Some("clean") | Some("ok") | Some("safe") | Some("pass") => {
                Ok(ScanResult::Clean)
            }
            Some("infected") | Some("malicious") | Some("threat") | Some("blocked") => {
                Ok(ScanResult::Infected {
                    threat_name: threat_name.unwrap_or_else(|| "Unknown Threat".to_string()),
                    severity: Self::map_severity_string(severity_str.as_deref()),
                })
            }
            _ => Ok(ScanResult::Error {
                message: format!(
                    "Unexpected or missing status: {:?}",
                    status_str
                ),
                transient: false,
            }),
        }
    }

    /// Extract value from JSON object using dot-notation path.
    ///
    /// Supports nested access like `"result.status"` or `"data.findings[0].name"`.
    /// Array index notation (`[0]`) is planned but not yet implemented.
    ///
    /// # Arguments
    /// * `value` — Root JSON value to search within.
    /// * `path` — Dot-separated path (e.g., `"result.status"`).
    ///
    /// # Returns
    /// Reference to found value, or `None` if path doesn't exist.
    fn extract_json_path<'a>(
        value: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let mut current = value;

        for key in path.split('.') {
            current = match current {
                serde_json::Value::Object(map) => map.get(key)?,
                _ => return None,
            };
        }

        Some(current)
    }

    /// Map severity string from API to ThreatSeverity enum.
    ///
    /// Normalizes various severity naming conventions to standard enum values.
    /// Case-insensitive matching.
    fn map_severity_string(severity: Option<&str>) -> ThreatSeverity {
        match severity.map(|s| s.to_lowercase()).as_deref() {
            Some("info") | Some("informational") => ThreatSeverity::Info,
            Some("low") | Some("minor") => ThreatSeverity::Low,
            Some("medium") | Some("moderate") | Some("warning") => ThreatSeverity::Medium,
            Some("high") | Some("major") | Some("severe") => ThreatSeverity::High,
            Some("critical") | Some("fatal") => ThreatSeverity::Critical,
            _ => ThreatSeverity::Medium, // Default when unknown/unspecified
        }
    }
}

#[async_trait]
impl ExternalScanner for HttpApiAdapter {
    /// Returns `"HttpApi"` as the display name.
    fn name(&self) -> &str {
        "HttpApi"
    }

    /// Returns unique identifier based on endpoint URL.
    fn id(&self) -> &str {
        &self.adapter_id
    }

    /// Scan file content via HTTP POST to configured endpoint.
    ///
    /// Sends file bytes as multipart/form-data to the scanning API endpoint.
    /// All I/O is bounded by configured timeout.
    ///
    /// # Arguments
    /// * `data` — Complete file bytes to scan.
    ///
    /// # Returns
    /// - `Ok(ScanResult::Clean)` — No threats detected
    /// - `Ok(ScanResult::Infected { ... })` — Threat found
    /// - `Ok(ScanResult::Error { ... })` — API-reported error
    /// - `Ok(ScanResult::Timeout { ... })` — Request timed out
    /// - `Err(ScannerError)` — Transport failure
    async fn scan_stream(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        // Generate a default filename if needed (use generic name)
        let filename = "scan_target.bin";
        self.call_scan_api(data, filename).await
    }

    /// Health check by sending lightweight GET request to endpoint.
    ///
    /// Attempts to reach the API base URL (or `/health` if available).
    /// A successful HTTP response (any 2xx/3xx) indicates health.
    ///
    /// # Returns
    /// - `true` — API endpoint is reachable and responding
    /// - `false` — Cannot connect or server error
    async fn health_check(&self) -> bool {
        tracing::debug!(adapter_id = %self.adapter_id, "Performing health check");

        // Try /health endpoint first, then fall back to base URL
        let health_urls = vec![
            format!("{}/health", self.config.endpoint.trim_end_matches('/')),
            self.config.endpoint.clone(),
        ];

        for url in health_urls {
            match self.http_client.head(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    tracing::info!(url = %url, "Health check passed");
                    return true;
                }
                Ok(response) => {
                    tracing::debug!(
                        url = %url,
                        status = %response.status(),
                        "Health check endpoint returned non-success"
                    );
                    // Continue trying next URL
                }
                Err(e) => {
                    tracing::debug!(url = %url, error = %e, "Health check failed for URL");
                    // Continue trying next URL
                }
            }
        }

        tracing::warn!("All health check attempts failed");
        false
    }

    /// Query API metadata (not typically available for HTTP APIs).
    ///
    /// Most HTTP scanning APIs don't expose version/metadata endpoints.
    /// This implementation returns `None` unless future enhancements add support.
    ///
    /// # Returns
    /// Always returns `None` for now.
    async fn metadata(&self) -> Option<ScannerMetadata> {
        tracing::debug!(adapter_id = %self.adapter_id, "Metadata query (not supported)");
        None
    }
}

impl std::fmt::Debug for HttpApiAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpApiAdapter")
            .field("adapter_id", &self.adapter_id)
            .field("endpoint", &self.config.endpoint)
            .field("timeout_secs", &self.config.timeout_secs)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // extract_json_path Tests
    // =========================================================================

    #[test]
    fn test_extract_simple_path() {
        let json: serde_json::Value = serde_json::json!({
            "status": "clean"
        });

        let value = HttpApiAdapter::extract_json_path(&json, "status");
        assert_eq!(value, Some(&serde_json::json!("clean")));
    }

    #[test]
    fn test_extract_nested_path() {
        let json: serde_json::Value = serde_json::json!({
            "result": {
                "status": "infected",
                "threat_name": "Malware.X"
            }
        });

        let status = HttpApiAdapter::extract_json_path(&json, "result.status");
        assert_eq!(status, Some(&serde_json::json!("infected")));

        let threat = HttpApiAdapter::extract_json_path(&json, "result.threat_name");
        assert_eq!(threat, Some(&serde_json::json!("Malware.X")));
    }

    #[test]
    fn test_extract_deeply_nested() {
        let json: serde_json::Value = serde_json::json!({
            "data": {
                "scan": {
                    "findings": {
                        "verdict": "threat"
                    }
                }
            }
        });

        let verdict = HttpApiAdapter::extract_json_path(&json, "data.scan.findings.verdict");
        assert_eq!(verdict, Some(&serde_json::json!("threat")));
    }

    #[test]
    fn test_extract_missing_path() {
        let json: serde_json::Value = serde_json::json!({
            "status": "clean"
        });

        let missing = HttpApiAdapter::extract_json_path(&json, "nonexistent.field");
        assert_eq!(missing, None);
    }

    #[test]
    fn test_extract_from_non_object() {
        let json: serde_json::Value = serde_json::json!("just a string");

        let result = HttpApiAdapter::extract_json_path(&json, "anything");
        assert_eq!(result, None);
    }

    // =========================================================================
    // Severity Mapping Tests
    // =========================================================================

    #[test]
    fn test_map_severity_all_levels() {
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("info")),
            ThreatSeverity::Info
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("low")),
            ThreatSeverity::Low
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("medium")),
            ThreatSeverity::Medium
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("high")),
            ThreatSeverity::High
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("critical")),
            ThreatSeverity::Critical
        );
    }

    #[test]
    fn test_map_severity_case_insensitive() {
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("HIGH")),
            ThreatSeverity::High
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("Critical")),
            ThreatSeverity::Critical
        );
    }

    #[test]
    fn test_map_severity_aliases() {
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("informational")),
            ThreatSeverity::Info
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("minor")),
            ThreatSeverity::Low
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("warning")),
            ThreatSeverity::Medium
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("severe")),
            ThreatSeverity::High
        );
    }

    #[test]
    fn test_map_severity_default() {
        assert_eq!(
            HttpApiAdapter::map_severity_string(None),
            ThreatSeverity::Medium
        );
        assert_eq!(
            HttpApiAdapter::map_severity_string(Some("unknown_level")),
            ThreatSeverity::Medium
        );
    }

    // =========================================================================
    // Response Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_standard_clean_response() {
        let adapter = create_test_adapter();

        let json = r#"{"status": "clean"}"#;
        let result = adapter.parse_json_response(json).unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[test]
    fn test_parse_standard_infected_response() {
        let adapter = create_test_adapter();

        let json = r#"{"status": "infected", "threat_name": "Trojan.Generic"}"#;
        let result = adapter.parse_json_response(json).unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threat_name(), Some("Trojan.Generic"));
    }

    #[test]
    fn test_parse_custom_path_response() {
        let adapter = HttpApiAdapter::new(HttpApiConfig {
            endpoint: "https://test.com/scan".to_string(),
            result_path: Some("result.status".to_string()),
            threat_name_path: Some("result.details.name".to_string()),
            ..Default::default()
        })
        .unwrap();

        let json = r#"{
            "result": {
                "status": "infected",
                "details": {
                    "name": "Ransomware.A"
                }
            }
        }"#;

        let result = adapter.parse_json_response(json).unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threat_name(), Some("Ransomware.A"));
    }

    #[test]
    fn test_parse_error_response() {
        let adapter = create_test_adapter();

        let json = r#"{"error": "Service temporarily unavailable"}"#;
        let result = adapter.parse_json_response(json).unwrap();
        assert!(result.is_error());
    }

    #[test]
    fn test_parse_invalid_json() {
        let adapter = create_test_adapter();

        let result = adapter.parse_json_response("not valid json");
        assert!(result.is_err());
    }

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_config_requires_endpoint() {
        let config = HttpApiConfig {
            endpoint: String::new(),
            ..Default::default()
        };
        let result = HttpApiAdapter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_rejects_invalid_url() {
        let config = HttpApiConfig {
            endpoint: "not-a-valid-url".to_string(),
            ..Default::default()
        };
        let result = HttpApiAdapter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = HttpApiConfig {
            endpoint: "https://api.example.com/v1/scan".to_string(),
            auth_header: Some("Bearer abc123".to_string()),
            timeout_secs: 60,
            result_path: Some("data.result".to_string()),
            threat_name_path: Some("data.threat".to_string()),
            severity_path: Some("data.severity".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HttpApiConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.endpoint, config.endpoint);
        assert_eq!(deserialized.auth_header, config.auth_header);
        assert_eq!(deserialized.timeout_secs, config.timeout_secs);
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    /// Create a test adapter with minimal valid configuration.
    fn create_test_adapter() -> HttpApiAdapter {
        HttpApiAdapter::new(HttpApiConfig {
            endpoint: "https://test.api/scan".to_string(),
            ..Default::default()
        })
        .expect("Test adapter creation should succeed")
    }
}
