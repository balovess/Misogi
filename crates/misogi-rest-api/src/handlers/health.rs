//! Health Probe Handlers
//!
//! Implements Kubernetes-compatible liveness and readiness probes plus
//! a dependency health aggregation endpoint.
//!
//! # Endpoints
//!
//! | Method   | Path                     | Handler              | Description              |
//! |----------|--------------------------|----------------------|--------------------------|
//! | GET      | `/api/v1/health/liveness` | [`liveness_probe`]   | Process alive check      |
//! | GET      | `/api/v1/health/readiness`| [`readiness_probe`]  | Dependency health check  |

#[allow(unused_imports)]
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use tracing::{debug, info, instrument, warn};
use std::path::PathBuf;
use std::time::Instant;

use crate::error::ApiError;
use crate::models::{ComponentHealth, HealthStatus};
use crate::router::AppState;

/// Build the base health status with version and uptime information.
fn build_health_base(components: Vec<ComponentHealth>) -> HealthStatus {
    // Calculate process uptime (simplified -- uses a static start time)
    // In production, record the startup Instant at application launch
    let uptime_secs = 0u64; // TODO: track actual startup time

    // Determine overall status based on components
    let overall_status = if components
        .iter()
        .all(|c| c.status == "healthy")
    {
        "ok".to_string()
    } else {
        "degraded".to_string()
    };

    HealthStatus {
        status: overall_status,
        // TODO: pull from env var or Cargo.toml package.version
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs,
        components,
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/health/liveness
// ---------------------------------------------------------------------------

/// Kubernetes liveness probe endpoint.
///
/// Returns HTTP 200 if the process is alive and capable of serving requests.
/// This probe should be lightweight -- it does **not** check external dependencies.
/// It merely confirms the Axum runtime is responsive.
///
/// Use this probe for Kubernetes `livenessProbe` configuration:
/// ```yaml
/// livenessProbe:
///   httpGet:
///     path: /api/v1/health/liveness
///     port: 8080
///   initialDelaySeconds: 10
///   periodSeconds: 15
/// ```
///
/// # Returns
///
/// - `200 OK` -- Process is alive (always, unless the handler panics)
#[instrument]
pub async fn liveness_probe() -> Json<HealthStatus> {
    debug!("Liveness probe checked");

    let components = vec![ComponentHealth {
        name: "runtime".to_string(),
        status: "healthy".to_string(),
        latency_ms: None,
    }];

    Json(build_health_base(components))
}

// ---------------------------------------------------------------------------
// GET /api/v1/health/readiness
// ---------------------------------------------------------------------------

/// Kubernetes readiness probe endpoint.
///
/// Checks all critical dependencies (auth engine, scanner connectivity)
/// before declaring the service ready to receive traffic. Unlike the liveness
/// probe, this endpoint performs actual connectivity/validation checks.
///
/// Use this probe for Kubernetes `readinessProbe` configuration:
/// ```yaml
/// readinessProbe:
///   httpGet:
///     path: /api/v1/health/readiness
///     port: 8080
///   initialDelaySeconds: 5
///   periodSeconds: 10
/// ```
///
/// # Returns
///
/// - `200 OK` -- All dependencies healthy; service is ready for traffic
/// - `503 Service Unavailable` -- One or more dependencies are unhealthy;
///   response body includes component-level details
#[instrument(skip(state))]
pub async fn readiness_probe(
    State(state): State<AppState>,
) -> Result<Json<HealthStatus>, ApiError> {
    debug!("Readiness probe: checking dependencies");
    let mut components = Vec::with_capacity(4);
    let mut all_healthy = true;

    // --- Check auth engine ---
    // The AuthEngine is stored as Arc<AuthEngine>; its mere presence indicates
    // successful initialization. A deeper check would validate JWT key loading.
    let auth_healthy = state.auth_engine.is_some();
    components.push(ComponentHealth {
        name: "auth_engine".to_string(),
        status: if auth_healthy {
            "healthy".to_string()
        } else {
            all_healthy = false;
            "unhealthy".to_string()
        },
        latency_ms: None,
    });

    // --- Check scanner (FileTypeDetector) ---
    match &state.detector {
        Some(det) => {
            let start = Instant::now();
            let result = det.detect(&PathBuf::from("readiness_probe.test"), "").await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            // Detection result is irrelevant for probe; we only care that
            // the detector responded without error.
            let scanner_healthy = result.is_ok();
            components.push(ComponentHealth {
                name: "scanner".to_string(),
                status: if scanner_healthy {
                    "healthy".to_string()
                } else {
                    all_healthy = false;
                    "unhealthy".to_string()
                },
                latency_ms: Some(elapsed),
            });
        }
        None => {
            components.push(ComponentHealth {
                name: "scanner".to_string(),
                status: "no_check".to_string(),
                latency_ms: None,
            });
        }
    }

    // --- Check storage backend ---
    match &state.storage {
        Some(store) => {
            let start = Instant::now();
            let result = store.health_check().await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            let storage_healthy = result.is_ok();
            components.push(ComponentHealth {
                name: "storage".to_string(),
                status: if storage_healthy {
                    "healthy".to_string()
                } else {
                    all_healthy = false;
                    "unhealthy".to_string()
                },
                latency_ms: Some(elapsed),
            });
        }
        None => {
            components.push(ComponentHealth {
                name: "storage".to_string(),
                status: "no_check".to_string(),
                latency_ms: None,
            });
        }
    }

    // --- Check No-Code runtime ---
    match &state.nocode_runtime {
        Some(runtime) => {
            let start = Instant::now();
            let status = runtime.status().await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            let ncode_healthy = status.initialized;
            components.push(ComponentHealth {
                name: "nocode_runtime".to_string(),
                status: if ncode_healthy {
                    "healthy".to_string()
                } else {
                    all_healthy = false;
                    "degraded".to_string()
                },
                latency_ms: Some(elapsed),
            });
        }
        None => {
            // No-Code runtime is optional; omit from component list or mark no_check
        }
    }

    let health = build_health_base(components);

    if all_healthy {
        info!("Readiness probe: all systems operational");
        Ok(Json(health))
    } else {
        warn!(
            status = %health.status,
            "Readiness probe: some dependencies unhealthy"
        );
        // Return 503 but still include the JSON body for debugging
        Err(ApiError::internal(
            ApiError::DEPENDENCY_UNAVAILABLE,
            "One or more dependencies are unhealthy",
            Some(serde_json::json!({ "components": &health.components })),
        ))
    }
}
