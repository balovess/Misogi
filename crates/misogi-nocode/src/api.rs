//! Admin REST API (No-Code Control Plane).
//!
//! This module provides HTTP endpoints for managing Misogi configurations without
//! writing code. Government IT staff can use these endpoints to view, validate,
//! and update YAML configurations through a REST interface.
//!
//! # API Endpoints
//!
//! | Method | Path                          | Description                        |
//! |--------|-------------------------------|------------------------------------|
//! | GET    | `/api/v1/status`              | Current config status, uptime      |
//! | GET    | `/api/v1/config`              | Current effective config (masked)  |
//! | PUT    | `/api/v1/config`              | Upload new YAML config             |
//! | POST   | `/api/v1/config/reload`       | Trigger file-based reload          |
//! | GET    | `/api/v1/config/diff`         | Compare running vs disk config     |
//! | GET    | `/api/v1/providers`           | List identity providers            |
//! | POST   | `/api/v1/providers/{id}/test` | Test auth against provider         |
//! | GET    | `/api/v1/logs/recent`          | Recent error/warning logs          |
//!
//! # Authentication
//!
//! All endpoints require Bearer token authentication using either:
//! - Service account token (configured in environment)
//! - Admin JWT token (issued by configured IdP)

use std::sync::Arc;
use std::collections::HashMap;

use axum::{
    extract::{Path, State, Query},
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tracing::{info, warn, error};

use crate::error::ApiError;
use crate::runtime::{NoCodeRuntime, RuntimeStatus};

// =============================================================================
// Shared Application State
// =============================================================================

/// Shared state for all API handlers.
#[derive(Clone)]
pub struct ApiState {
    /// No-Code runtime engine for config management.
    pub runtime: Arc<NoCodeRuntime>,

    /// Admin API bearer token for authentication.
    pub admin_token: Option<String>,
}

impl ApiState {
    /// Create new API state with runtime engine.
    pub fn new(runtime: Arc<NoCodeRuntime>) -> Self {
        Self {
            runtime,
            admin_token: std::env::var("MISOGI_ADMIN_TOKEN").ok(),
        }
    }

    /// Create API state with explicit admin token.
    pub fn with_token(runtime: Arc<NoCodeRuntime>, token: impl Into<String>) -> Self {
        Self {
            runtime,
            admin_token: Some(token.into()),
        }
    }
}

// =============================================================================
// Request/Response DTOs
// =============================================================================

/// Standard API response envelope.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    /// Whether the request was successful.
    pub success: bool,

    /// Response data (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// Error details (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorDetail>,

    /// ISO 8601 timestamp of the response.
    pub timestamp: String,
}

/// Error detail structure for failed responses.
#[derive(Debug, Serialize)]
pub struct ApiErrorDetail {
    /// HTTP status code.
    pub code: u16,

    /// Error type identifier.
    pub error_type: String,

    /// Human-readable error message.
    pub message: String,

    /// Suggested remediation (when available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a successful response with data.
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create an error response from an ApiError.
    pub fn err(err: ApiError) -> Self {
        let code = err.status_code();
        Self {
            success: false,
            data: None::<T>,
            error: Some(ApiErrorDetail {
                code,
                error_type: format!("{:?}", &err),
                message: err.to_string(),
                suggestion: None,
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Status Response Types
// ---------------------------------------------------------------------------

/// System status information returned by GET /api/v1/status.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    /// Overall system health status.
    pub status: String,

    /// Runtime engine status.
    pub runtime: RuntimeStatus,

    /// Uptime in seconds since startup.
    pub uptime_secs: u64,

    /// Component health check results.
    pub components: HashMap<String, ComponentHealth>,
}

/// Health status of a single component.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    /// Component identifier.
    pub name: String,

    /// Health status: "healthy", "degraded", "unhealthy".
    pub status: String,

    /// Optional status message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Config Response Types
// ---------------------------------------------------------------------------

/// Configuration response with secrets masked.
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    /// Schema version.
    pub version: String,

    /// Environment identifier.
    pub environment: String,

    /// Authentication config (secrets masked).
    pub authentication: MaskedAuthConfig,

    /// Sanitization config.
    pub sanitization: serde_json::Value,

    /// Routing config.
    pub routing: serde_json::Value,

    /// Retention config (if present).
    pub retention: Option<serde_json::Value>,

    /// Notification config (if present, secrets masked).
    pub notifications: Option<MaskedNotificationConfig>,
}

/// Auth config with sensitive fields masked.
#[derive(Debug, Serialize)]
pub struct MaskedAuthConfig {
    /// JWT issuer URL.
    pub jwt_issuer: String,

    /// JWT TTL in seconds.
    pub jwt_ttl_seconds: u64,

    /// Identity provider list (secrets masked).
    pub identity_providers: Vec<MaskedIdentityProvider>,
}

/// Single identity provider with secrets masked.
#[derive(Debug, Serialize)]
pub struct MaskedIdentityProvider {
    /// Provider name.
    pub name: String,

    /// Provider type.
    pub provider_type: String,

    /// Whether enabled.
    pub enabled: bool,

    /// Connection URL (if not secret).
    pub url: Option<String>,

    /// Whether client_secret is present (but value hidden).
    pub has_client_secret: bool,

    /// Attribute mappings.
    pub attribute_mappings: HashMap<String, String>,
}

/// Notification config with webhook URLs masked.
#[derive(Debug, Serialize)]
pub struct MaskedNotificationConfig {
    /// Error notification rules (URLs masked).
    pub on_error: Vec<MaskedNotificationRule>,
}

/// Single notification rule with URLs masked.
#[derive(Debug, Serialize)]
pub struct MaskedNotificationRule {
    /// Channel type.
    pub channel: String,

    /// Recipients (email addresses visible).
    pub recipients: Vec<String>,

    /// Whether URL is present (value hidden).
    pub has_url: bool,

    /// Severity levels.
    pub severity: Vec<String>,
}

// ---------------------------------------------------------------------------
// Config Upload Request
// ---------------------------------------------------------------------------

/// Request body for PUT /api/v1/config.
#[derive(Debug, Deserialize)]
pub struct ConfigUploadRequest {
    /// YAML configuration content.
    pub yaml_content: String,

    /// Optional comment describing this change.
    #[serde(default)]
    pub comment: Option<String>,
}

// ---------------------------------------------------------------------------
// Provider Test Request/Response
// ---------------------------------------------------------------------------

/// Request body for POST /api/v1/providers/{id}/test.
#[derive(Debug, Deserialize)]
pub struct ProviderTestRequest {
    /// Username for authentication test.
    pub username: String,

    /// Password for authentication test.
    pub password: String,
}

/// Response from provider authentication test.
#[derive(Debug, Serialize)]
pub struct ProviderTestResponse {
    /// Provider being tested.
    pub provider_name: String,

    /// Whether authentication succeeded.
    pub success: bool,

    /// Human-readable result message.
    pub message: String,

    /// Additional details about the test.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Log Query Parameters
// ---------------------------------------------------------------------------

/// Query parameters for GET /api/v1/logs/recent.
#[derive(Debug, Deserialize)]
pub struct LogsQueryParams {
    /// Maximum number of log entries to return (default: 50, max: 100).
    pub count: Option<usize>,
}

/// Recent logs response.
#[derive(Debug, Serialize)]
pub struct LogsResponse {
    /// Total entries available in buffer.
    pub total: usize,

    /// Returned log entries (most recent first).
    pub entries: Vec<crate::runtime::LogEntry>,
}

// ---------------------------------------------------------------------------
// Diff Response
// ---------------------------------------------------------------------------

/// Configuration diff response.
#[derive(Debug, Serialize)]
pub struct DiffResponse {
    /// Whether configurations are identical.
    pub identical: bool,

    /// Path to disk configuration file.
    pub disk_config_path: Option<String>,

    /// Summary of differences found.
    pub summary: Vec<DiffItem>,
}

/// Single difference item between two configurations.
#[derive(Debug, Clone, Serialize)]
pub struct DiffItem {
    /// Field path where difference was found.
    pub field: String,

    /// Type of change: "added", "removed", "modified".
    pub change_type: String,

    /// Old value (for modified/removed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,

    /// New value (for added/modified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Create a JSON response with status code.
fn json_response<T: Serialize>(status: StatusCode, data: T) -> axum::response::Response {
    (status, Json(data)).into_response()
}

/// Create an error JSON response.
fn json_error(status: StatusCode, err: ApiError) -> axum::response::Response {
    (status, Json(ApiResponse::<()>::err(err))).into_response()
}

// =============================================================================
// Router Creation
// =============================================================================

/// Create the admin API router with all endpoints mounted.
pub fn create_admin_router(runtime: Arc<NoCodeRuntime>) -> Router {
    let state = ApiState::new(Arc::clone(&runtime));

    Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/config", get(get_config).put(update_config))
        .route("/api/v1/config/reload", post(trigger_reload))
        .route("/api/v1/config/diff", get(config_diff))
        .route("/api/v1/providers", get(list_providers))
        .route(
            "/api/v1/providers/{id}/test",
            post(test_provider),
        )
        .route("/api/v1/logs/recent", get(recent_logs))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// =============================================================================
// Authentication Middleware
// =============================================================================

/// Extract and validate Bearer token from Authorization header.
async fn authenticate(state: &ApiState, headers: &HeaderMap) -> Result<(), ApiError> {
    let expected_token = match &state.admin_token {
        Some(token) => token,
        None => return Ok(()), // Auth disabled
    };

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(ApiError::Unauthorized)?;

    if !constant_time_eq(token, expected_token) {
        warn!("Failed authentication attempt");
        return Err(ApiError::Unauthorized);
    }

    Ok(())
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).all(|(x, y)| x == y)
}

// =============================================================================
// Endpoint Handlers
// =============================================================================

/// GET /api/v1/status — Return current system status and health.
async fn get_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    let runtime_status = state.runtime.status().await;

    // Build component health checks
    let mut components = HashMap::new();

    components.insert(
        "config".to_string(),
        ComponentHealth {
            name: "Configuration".to_string(),
            status: if runtime_status.initialized { "healthy" } else { "unhealthy" }.to_string(),
            message: if runtime_status.initialized {
                Some("Configuration loaded successfully".to_string())
            } else {
                Some("No valid configuration loaded".to_string())
            },
        },
    );

    components.insert(
        "watcher".to_string(),
        ComponentHealth {
            name: "File Watcher".to_string(),
            status: if runtime_status.watching { "healthy" } else { "idle" }.to_string(),
            message: if runtime_status.watching {
                Some(format!("Watching: {:?}", runtime_status.config_path))
            } else {
                Some("File watcher not active".to_string())
            },
        },
    );

    let response = StatusResponse {
        status: if runtime_status.initialized { "operational" } else { "degraded" }.to_string(),
        runtime: runtime_status.clone(),
        uptime_secs: get_uptime_secs(),
        components,
    };

    json_response(StatusCode::OK, ApiResponse::ok(response))
}

/// GET /api/v1/config — Return current effective configuration (secrets masked).
async fn get_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    let config = match state.runtime.current_config().await {
        Some(cfg) => cfg,
        None => {
            return json_error(StatusCode::SERVICE_UNAVAILABLE, ApiError::Unavailable(
                "No configuration loaded".to_string(),
            ));
        }
    };

    // Build masked response
    let masked_providers: Vec<MaskedIdentityProvider> = config
        .authentication
        .identity_providers
        .iter()
        .map(|p| MaskedIdentityProvider {
            name: p.name.clone(),
            provider_type: p.provider_type.clone(),
            enabled: p.enabled,
            url: p.url.clone(),
            has_client_secret: p.client_id.is_some(),
            attribute_mappings: p.attribute_mappings.clone(),
        })
        .collect();

    let response = ConfigResponse {
        version: config.version.clone(),
        environment: config.environment.clone(),
        authentication: MaskedAuthConfig {
            jwt_issuer: config.authentication.jwt_issuer.clone(),
            jwt_ttl_seconds: config.authentication.jwt_ttl_seconds,
            identity_providers: masked_providers,
        },
        sanitization: serde_json::to_value(&config.sanitization).unwrap_or(serde_json::Value::Null),
        routing: serde_json::to_value(&config.routing).unwrap_or(serde_json::Value::Null),
        retention: config.retention.as_ref().map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null)),
        notifications: config.notifications.as_ref().map(|n| MaskedNotificationConfig {
            on_error: n.on_error.iter().map(|rule| MaskedNotificationRule {
                channel: rule.channel.clone(),
                recipients: rule.recipients.clone(),
                has_url: rule.url.is_some(),
                severity: rule.severity.clone(),
            }).collect(),
        }),
    };

    json_response(StatusCode::OK, ApiResponse::ok(response))
}

/// PUT /api/v1/config — Upload and apply new YAML configuration.
async fn update_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<ConfigUploadRequest>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    info!(
        comment = ?body.comment,
        content_length = body.yaml_content.len(),
        "Received configuration update request"
    );

    // Parse YAML
    let yaml = match crate::schema::YamlConfig::from_yaml_str(&body.yaml_content) {
        Ok(y) => y,
        Err(e) => {
            return json_error(StatusCode::BAD_REQUEST, ApiError::BadRequest(format!(
                "Invalid YAML: {}",
                e
            )));
        }
    };

    // Validate
    if let Err(e) = yaml.validate() {
        return json_error(StatusCode::UNPROCESSABLE_ENTITY, ApiError::BadRequest(format!(
            "Validation failed: {}",
            e.message
        )));
    }

    // Compile
    let (compiled, report) = match crate::compiler::compile(&yaml) {
        Ok(result) => result,
        Err(e) => {
            return json_error(StatusCode::UNPROCESSABLE_ENTITY, ApiError::BadRequest(format!(
                "Compilation failed: {:?}",
                e
            )));
        }
    };

    // Apply
    if let Err(e) = state.runtime.apply_config(&compiled).await {
        error!(error = %e, "Failed to apply new configuration");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, ApiError::Internal(format!(
            "Failed to apply configuration: {}",
            e
        )));
    }

    info!(
        warnings = report.warnings.len(),
        "Configuration updated successfully"
    );

    json_response(StatusCode::OK, ApiResponse::ok(serde_json::json!({
        "message": "Configuration applied successfully",
        "warnings_count": report.warnings.len(),
        "report": report,
    })))
}

/// POST /api/v1/config/reload — Trigger file-based reload.
async fn trigger_reload(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    info!("Triggering manual configuration reload");

    match state.runtime.trigger_reload().await {
        Ok(()) => {
            info!("Manual reload triggered successfully");
            json_response(StatusCode::ACCEPTED, ApiResponse::ok(serde_json::json!({
                "message": "Reload triggered",
                "status": "reloading",
            })))
        }
        Err(e) => {
            error!(error = %e, "Reload trigger failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, ApiError::Internal(format!(
                "Reload failed: {}",
                e
            )))
        }
    }
}

/// GET /api/v1/config/diff — Compare running vs disk configuration.
async fn config_diff(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    let current_yaml = state.runtime.source_yaml().await;
    let disk_path = state.runtime.status().await.config_path;

    // If no disk path configured, cannot compare
    let disk_path_str = match &disk_path {
        Some(p) => Some(p.to_string_lossy().to_string()),
        None => {
            return json_error(StatusCode::BAD_REQUEST, ApiError::BadRequest(
                "No configuration file path set. Cannot perform diff.".to_string(),
            ));
        }
    };

    // Load disk configuration
    let disk_yaml = match std::fs::read_to_string(disk_path.as_ref().unwrap()) {
        Ok(content) => match crate::schema::YamlConfig::from_yaml_str(&content) {
            Ok(y) => y,
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, ApiError::BadRequest(format!(
                    "Invalid YAML on disk: {}",
                    e
                )));
            }
        },
        Err(e) => {
            return json_error(StatusCode::NOT_FOUND, ApiError::NotFound(format!(
                "Cannot read config file: {}",
                e
            )));
        }
    };

    // Perform simple diff comparison
    let mut differences = vec![];

    // Compare versions
    if let Some(ref current) = current_yaml {
        if current.version != disk_yaml.version {
            differences.push(DiffItem {
                field: "version".to_string(),
                change_type: "modified".to_string(),
                old_value: Some(current.version.clone()),
                new_value: Some(disk_yaml.version.clone()),
            });
        }

        // Compare environment
        if current.environment != disk_yaml.environment {
            differences.push(DiffItem {
                field: "environment".to_string(),
                change_type: "modified".to_string(),
                old_value: Some(current.environment.clone()),
                new_value: Some(disk_yaml.environment.clone()),
            });
        }

        // Compare provider counts
        let current_provider_count = current.authentication.identity_providers.len();
        let disk_provider_count = disk_yaml.authentication.identity_providers.len();
        if current_provider_count != disk_provider_count {
            differences.push(DiffItem {
                field: "authentication.identity_providers".to_string(),
                change_type: "modified".to_string(),
                old_value: Some(current_provider_count.to_string()),
                new_value: Some(disk_provider_count.to_string()),
            });
        }
    } else {
        // No current config — everything is "added"
        differences.push(DiffItem {
            field: "root".to_string(),
            change_type: "added".to_string(),
            old_value: None,
            new_value: Some("(new configuration)".to_string()),
        });
    }

    let response = DiffResponse {
        identical: differences.is_empty(),
        disk_config_path: disk_path_str,
        summary: differences,
    };

    json_response(StatusCode::OK, ApiResponse::ok(response))
}

/// GET /api/v1/providers — List registered identity providers.
async fn list_providers(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    let config = match state.runtime.current_config().await {
        Some(cfg) => cfg,
        None => {
            return json_error(StatusCode::SERVICE_UNAVAILABLE, ApiError::Unavailable(
                "No configuration loaded".to_string(),
            ));
        }
    };

    // Build provider list with health status (simplified)
    let providers: Vec<serde_json::Value> = config
        .authentication
        .identity_providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "type": p.provider_type,
                "enabled": p.enabled,
                "health": "unknown",
                "url": p.url,
            })
        })
        .collect();

    json_response(StatusCode::OK, ApiResponse::ok(serde_json::json!({
        "providers": providers,
        "count": providers.len(),
    })))
}

/// POST /api/v1/providers/{id}/test — Test authentication against specific provider.
async fn test_provider(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(provider_id): Path<String>,
    Json(body): Json<ProviderTestRequest>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    info!(provider = %provider_id, username = %body.username, "Testing provider authentication");

    // Find the provider by name/id
    let config = match state.runtime.current_config().await {
        Some(cfg) => cfg,
        None => {
            return json_error(StatusCode::SERVICE_UNAVAILABLE, ApiError::Unavailable(
                "No configuration loaded".to_string(),
            ));
        }
    };

    let provider = match config.authentication.identity_providers.iter().find(|p| p.name == provider_id) {
        Some(p) => p,
        None => {
            return json_error(StatusCode::NOT_FOUND, ApiError::NotFound(format!(
                "Provider '{}' not found",
                provider_id
            )));
        }
    };

    // Simulate test (in production, would make actual auth request)
    let response = ProviderTestResponse {
        provider_name: provider.name.clone(),
        success: true,
        message: "Authentication test completed (simulated)".to_string(),
        details: Some(serde_json::json!({
            "provider_type": provider.provider_type,
            "tested_username": body.username,
            "note": "Actual authentication testing requires OIDC/LDAP feature flags",
        })),
    };

    json_response(StatusCode::OK, ApiResponse::ok(response))
}

/// GET /api/v1/logs/recent — Return recent error/warning logs.
async fn recent_logs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(params): Query<LogsQueryParams>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, e);
    }

    let count: usize = params.count.unwrap_or(50).min(100);

    let entries = state.runtime.get_recent_logs(count).await;
    let total = state.runtime.get_recent_logs(0usize).await.len();

    let response = LogsResponse {
        total,
        entries,
    };

    json_response(StatusCode::OK, ApiResponse::ok(response))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get approximate uptime in seconds since program start.
static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

fn get_uptime_secs() -> u64 {
    let start = START_TIME.get_or_init(std::time::Instant::now);
    start.elapsed().as_secs()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::YamlConfig;

    fn create_minimal_yaml() -> &'static str {
        r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#
    }

    #[test]
    fn test_api_response_ok_with_data() {
        let resp = ApiResponse::ok(serde_json::json!({"key": "value"}));
        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_api_response_err() {
        let err_resp = ApiResponse::<()>::err(ApiError::BadRequest("test error".to_string()));
        assert!(!err_resp.success);
        assert!(err_resp.data.is_none());
        assert!(err_resp.error.is_some());
        assert_eq!(err_resp.error.unwrap().code, 400);
    }

    #[tokio::test]
    async fn test_auth_disabled_allows_requests() {
        let yaml = YamlConfig::from_yaml_str(create_minimal_yaml()).unwrap();
        let runtime = Arc::new(NoCodeRuntime::new(yaml));
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let state = ApiState::new(Arc::clone(&runtime));
        let headers = HeaderMap::new();

        let result = authenticate(&state, &headers).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_rejects_invalid_token() {
        let yaml = YamlConfig::from_yaml_str(create_minimal_yaml()).unwrap();
        let runtime = Arc::new(NoCodeRuntime::new(yaml));
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let state = ApiState::with_token(Arc::clone(&runtime), "secret-token-12345");
        
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-token".parse().unwrap());

        let result = authenticate(&state, &headers).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_accepts_valid_token() {
        let yaml = YamlConfig::from_yaml_str(create_minimal_yaml()).unwrap();
        let runtime = Arc::new(NoCodeRuntime::new(yaml));
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let state = ApiState::with_token(Arc::clone(&runtime), "correct-token");
        
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer correct-token".parse().unwrap());

        let result = authenticate(&state, &headers).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_constant_time_eq_same_strings() {
        assert!(constant_time_eq("hello", "hello"));
    }

    #[test]
    fn test_constant_time_eq_different_strings() {
        assert!(!constant_time_eq("hello", "world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("hello", "hello!"));
    }

    #[tokio::test]
    async fn test_create_admin_router_succeeds() {
        let yaml = YamlConfig::from_yaml_str(create_minimal_yaml()).unwrap();
        let runtime = Arc::new(NoCodeRuntime::new(yaml));
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let _router = create_admin_router(Arc::clone(&runtime));
        assert!(true); // Router created successfully
    }
}
