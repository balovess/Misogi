//! HTTP Health Probe Handlers — Kubernetes-Compatible Endpoints
//!
//! Implements standard Kubernetes health probe endpoints with Axum integration.
//! This module is feature-gated behind the `http` feature flag.
//!
//! # Endpoints
//!
//! | Method | Path              | Handler             | Purpose                    |
//! |--------|-------------------|---------------------|----------------------------|
//! | GET    | `/healthz`        | [`liveness_probe`]  | Liveness (process alive)   |
//! | GET    | `/readyz`         | [`readiness_probe`] | Readiness (deps healthy)   |
//! | GET    | `/livez`          | [`liveness_probe`]  | Alias for /healthz         |
//! | GET    | `/healthz/deep`   | [`deep_health`]     | Full component status JSON |
//! | GET    | `/readyz/ready`   | [`readiness_probe`] | Explicit ready endpoint    |
//! | GET    | `/readyz/notready`| [`not_ready`]       | Force not-ready response   |
//!
//! # Kubernetes Configuration
//!
//! ```yaml
//! livenessProbe:
//!   httpGet:
//!     path: /healthz
//!     port: 8080
//!   initialDelaySeconds: 10
//!   periodSeconds: 15
//!
//! readinessProbe:
//!   httpGet:
//!     path: /readyz
//!     port: 8080
//!   initialDelaySeconds: 5
//!   periodSeconds: 10
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::Serialize;
use tracing::{debug, info, instrument, warn};

use crate::checker::HealthChecker;
use crate::types::{ComponentStatus, HealthStatus, OverallHealth};

// ===========================================================================
// Shared Application State
// ===========================================================================

/// Shared state for health probe handlers.
///
/// Contains the [`HealthChecker`] instance and optional configuration for
/// customizing probe behavior. Wrapped in `axum::State` for extraction.
#[derive(Clone)]
pub struct HealthState {
    /// Health checker engine with registered components.
    pub checker: std::sync::Arc<HealthChecker>,
}

impl HealthState {
    /// Create new health state from a checker instance.
    pub fn new(checker: std::sync::Arc<HealthChecker>) -> Self {
        Self { checker }
    }
}

// ===========================================================================
// Response Types
// ===========================================================================

/// Lightweight liveness probe response.
///
/// Minimal payload for frequent polling; omits component details to reduce
/// bandwidth. Always returns 200 OK if the handler executes successfully.
#[derive(Debug, Clone, Serialize)]
pub struct LivenessResponse {
    /// Always `"alive"` for successful liveness checks.
    pub status: String,

    /// ISO 8601 timestamp of the check.
    #[serde(rename = "timestamp")]
    pub checked_at: String,
}

/// Readiness probe response (abbreviated).
///
/// Includes overall status but not full component breakdown (use `/healthz/deep`
/// for detailed diagnostics).
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessResponse {
    /// Overall system readiness status.
    pub status: String,

    /// Human-readable summary message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// ISO 8601 timestamp of the check.
    #[serde(rename = "timestamp")]
    pub checked_at: String,
}

// ===========================================================================
// GET /healthz and /livez — Liveness Probe
// ===========================================================================

/// Kubernetes liveness probe endpoint.
///
/// Returns HTTP **200 OK** if the process is alive and the Axum runtime is
/// responsive. This endpoint performs **no** dependency checks — it merely
/// confirms the handler can execute. Use this for K8s `livenessProbe`.
///
/// # Behavior
///
/// - Always returns 200 OK (unless the handler panics or server is dead).
/// - Response body contains minimal metadata (status, timestamp).
/// - No dependency checks are performed.
///
/// # Kubernetes Example
///
/// ```yaml
/// livenessProbe:
///   httpGet:
///     path: /healthz
///     port: 8080
///   initialDelaySeconds: 15
///   periodSeconds: 20
///   failureThreshold: 3
/// ```
#[instrument]
pub async fn liveness_probe() -> Json<LivenessResponse> {
    debug!("Liveness probe received");

    Json(LivenessResponse {
        status: "alive".to_string(),
        checked_at: chrono::Utc::now().to_rfc3339(),
    })
}

// ===========================================================================
// GET /readyz — Readiness Probe
// ===========================================================================

/// Kubernetes readiness probe endpoint.
///
/// Checks all registered components via [`HealthChecker::check_all`] and
/// returns:
/// - **200 OK** if all components are healthy or not-configured.
/// - **503 Service Unavailable** if any component is unhealthy or unknown.
///
/// Unlike the liveness probe, this endpoint performs actual connectivity
/// and validation checks against dependencies.
///
/// # Behavior
///
/// 1. Executes all registered health checks concurrently.
/// 2. Aggregates results into overall status.
/// 3. Returns 503 if any component is `Unhealthy` or `Unknown`.
/// 4. Includes abbreviated status in response body regardless of code.
///
/// # Kubernetes Example
///
/// ```yaml
/// readinessProbe:
///   httpGet:
///     path: /readyz
///     port: 8080
///   initialDelaySeconds: 5
///   periodSeconds: 10
///   timeoutSeconds: 5
/// ```
#[instrument(skip(state))]
pub async fn readiness_probe(
    State(state): State<HealthState>,
) -> Result<Json<ReadinessResponse>, StatusCode> {
    debug!("Readiness probe: checking all components");

    let health_status = state.checker.check_all().await;

    match health_status.overall {
        OverallHealth::Healthy => {
            info!(
                status = %health_status.overall,
                checks = health_status.checks_run,
                "Readiness probe: system ready"
            );
            Ok(Json(ReadinessResponse {
                status: "ready".to_string(),
                message: None,
                checked_at: chrono::Utc::now().to_rfc3339(),
            }))
        }
        OverallHealth::Degraded => {
            warn!(
                status = %health_status.overall,
                checks = health_status.checks_run,
                "Readiness probe: system degraded but accepting traffic"
            );
            // Degraded still serves traffic; return 200 with warning
            Ok(Json(ReadinessResponse {
                status: "ready".to_string(),
                message: Some(format!(
                    "System degraded: {} component(s) not fully healthy",
                    health_status
                        .components
                        .values()
                        .filter(|c| !c.status.is_healthyish())
                        .count()
                )),
                checked_at: chrono::Utc::now().to_rfc3339(),
            }))
        }
        OverallHealth::Unhealthy => {
            warn!(
                status = %health_status.overall,
                checks = health_status.checks_run,
                "Readiness probe: system NOT ready"
            );
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

// ===========================================================================
// GET /healthz/deep — Deep Health Check
// ===========================================================================

/// Comprehensive health status endpoint with full component details.
///
/// Returns complete [`HealthStatus`] JSON including per-component status,
/// latency measurements, error messages, uptime, version, and timestamp.
///
/// Use this endpoint for:
/// - Operator dashboards and monitoring UIs.
/// - Debugging during incidents.
/// - Integration with observability platforms (Datadog, Prometheus, etc.)
///
/// # Response Example
///
/// ```json
/// {
///   "overall": "healthy",
///   "components": {
///     "jwt_validator": {
///       "status": "healthy",
///       "latency_ms": 2,
///       "last_checked": "2025-01-01T00:00:00Z"
///     },
///     "identity_registry": {
///       "status": "degraded",
///       "message": "LDAP timeout after 5000ms",
///       "latency_ms": 5001,
///       "last_checked": "2025-01-01T00:00:01Z"
///     }
///   },
///   "version": "0.1.0",
///   "uptime_secs": 86400,
///   "timestamp": "2025-01-01T00:00:02Z",
///   "checks_run": 2
/// }
/// ```
#[instrument(skip(state))]
pub async fn deep_health(
    State(state): State<HealthState>,
) -> Json<HealthStatus> {
    debug!("Deep health check requested");

    let status = state.checker.check_all().await;

    info!(
        overall = %status.overall,
        checks = status.checks_run,
        uptime_secs = status.uptime_secs,
        "Deep health check completed"
    );

    Json(status)
}

// ===========================================================================
// GET /readyz/notready — Forced Not-Ready (for maintenance)
// ===========================================================================

/// Force the service to report as not-ready.
///
/// Useful for graceful shutdown sequences where you want K8s to stop sending
/// traffic before the process actually exits. Call this before initiating
/// shutdown to allow in-flight requests to complete.
///
/// Always returns **503 Service Unavailable** with explanatory body.
#[instrument]
pub async fn not_ready() -> (StatusCode, Json<ReadinessResponse>) {
    warn!("Not-ready endpoint called; service draining");

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ReadinessResponse {
            status: "not_ready".to_string(),
            message: Some("Service is intentionally draining connections".to_string()),
            checked_at: chrono::Utc::now().to_rfc3339(),
        }),
    )
}

// ===========================================================================
// Route Builder Helper
// ===========================================================================

/// Build a standard Kubernetes health probe router.
///
/// Assembles all health endpoints under `/healthz`, `/readyz`, and `/livez`
/// paths. Callers should merge this router into their main application router.
///
/// # Arguments
///
/// * `state` — Shared [`HealthState`] containing the checker instance.
///
/// # Returns
///
/// An Axum [`Router`](axum::Router) with all health probe routes mounted.
///
/// # Example
///
/// ```ignore
/// use misogi_health::handlers::{HealthState, build_health_router};
/// use misogi_health::checker::HealthChecker;
/// use std::sync::Arc;
///
/// let checker = Arc::new(HealthChecker::new());
/// // ... register components ...
///
/// let state = HealthState::new(checker);
/// let health_routes = build_health_router(state);
///
/// // Merge into main app
/// let app = axum::Router::new().merge(health_routes);
/// ```
pub fn build_health_router(state: HealthState) -> axum::Router {
    axum::Router::new()
        // Liveness probes
        .route("/healthz", get(liveness_probe))
        .route("/livez", get(liveness_probe))
        // Readiness probes
        .route("/readyz", get(readiness_probe))
        .route("/readyz/ready", get(readiness_probe))
        .route("/readyz/notready", get(not_ready))
        // Deep health check
        .route("/healthz/deep", get(deep_health))
        .with_state(state)
}

// Tests are in separate module to satisfy 500-line-per-file policy
#[cfg(test)]
mod tests;
