//! No-Code Health Check Router for integration into misogi-rest-api.
//!
//! Provides lightweight health endpoints that inspect the [`NoCodeRuntime`] state
//! without exposing administrative operations. Designed to be merged into the
//! main REST API router at `/nocode/health/*`.
//!
//! # Endpoints
//!
//! | Method | Path                    | Description              |
//! |--------|-------------------------|--------------------------|
//! | GET    | `/nocode/health/status` | Runtime liveness status  |
//! | GET    | `/nocode/health/config` | Config loaded indicator  |

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    Json,
    routing::get,
    Router,
};
use serde_json::json;

use crate::runtime::NoCodeRuntime;

// =============================================================================
// Health State
// =============================================================================

/// Shared state for health check endpoints.
///
/// Holds a reference to the No-Code runtime for probing initialization state,
/// configuration validity, and reload statistics.
#[derive(Clone)]
pub struct HealthState {
    /// Reference to the No-Code runtime instance.
    pub runtime: Arc<NoCodeRuntime>,
}

// =============================================================================
// Router Builder
// =============================================================================

/// Build a health-check router that can be merged into the main REST API router.
///
/// Returns an Axum 0.8 `Router` with the following endpoints:
///
/// - `GET /nocode/health/status` — Runtime liveness and basic statistics
/// - `GET /nocode/health/config` — Configuration load status with details
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use misogi_nocode::{NoCodeRuntime, build_health_router};
///
/// let runtime = Arc::new(NoCodeRuntime::new());
/// let health_router = build_health_router(runtime);
///
/// // Merge into main app router:
/// // app.merge(health_router)
/// ```
#[must_use]
pub fn build_health_router(runtime: Arc<NoCodeRuntime>) -> Router {
    let state = HealthState { runtime };

    Router::new()
        .route("/nocode/health/status", get(nocode_status))
        .route("/nocode/health/config", get(nocode_config_check))
        .with_state(state)
}

// =============================================================================
// Handlers
// =============================================================================

/// Liveness probe: reports whether the No-Code runtime is operational.
///
/// Returns HTTP 200 when the runtime has been initialized (config loaded),
/// or HTTP 503 (Service Unavailable) when no valid configuration is active.
async fn nocode_status(
    State(state): State<HealthState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let status = state.runtime.status().await;
    let code = if status.initialized {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = json!({
        "service": "misogi-nocode",
        "status": if status.initialized { "ok" } else { "degraded" },
        "initialized": status.initialized,
        "version": status.version,
        "environment": status.environment,
        "watching": status.watching,
        "total_reloads": status.total_reloads,
        "total_failures": status.total_failures,
        "config_path": status.config_path.as_ref()
            .map(|p| p.display().to_string()),
        "last_reload_at": status.last_reload_at,
    });

    (code, Json(body))
}

/// Configuration readiness probe: reports whether a valid config is loaded.
///
/// Returns detailed configuration metadata on success, or HTTP 503 with
/// diagnostic information when no configuration is available.
async fn nocode_config_check(
    State(state): State<HealthState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let config = state.runtime.current_config().await;

    match config {
        Some(cfg) => (
            StatusCode::OK,
            Json(json!({
                "config_loaded": true,
                "version": cfg.version,
                "environment": cfg.environment,
                "provider_count": cfg.authentication.identity_providers.len(),
            })),
        ),
        None => {
            let status = state.runtime.status().await;
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "config_loaded": false,
                    "error": "No valid configuration loaded",
                    "initialized": status.initialized,
                    "total_failures": status.total_failures,
                })),
            )
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    use crate::schema::YamlConfig;

    fn make_test_runtime() -> NoCodeRuntime {
        let yaml = YamlConfig::from_yaml_str(
            r#"
version: "1.0"
environment: test
authentication:
  jwt:
    issuer: "https://test.misogi.local"
    secret: "test-secret-for-health-check-only"
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming: []
"#,
        ).expect("Valid test YAML");
        NoCodeRuntime::new(yaml)
    }

    #[tokio::test]
    async fn test_build_health_router() {
        let runtime = Arc::new(make_test_runtime());
        let _router = build_health_router(Arc::clone(&runtime));
    }

    #[tokio::test]
    async fn test_nocode_status_uninitialized() {
        let runtime = Arc::new(make_test_runtime());
        let state = HealthState { runtime };

        let (code, body) = nocode_status(State(state)).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.get("status").unwrap(), "degraded");
        assert_eq!(body.get("initialized").unwrap(), false);
    }

    #[tokio::test]
    async fn test_nocode_config_check_no_config() {
        let runtime = Arc::new(make_test_runtime());
        let state = HealthState { runtime };

        let (code, body) = nocode_config_check(State(state)).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.get("config_loaded").unwrap(), false);
    }
}
