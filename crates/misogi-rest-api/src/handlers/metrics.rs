//! Prometheus Metrics Export Handler
//!
//! Exposes the `/metrics` endpoint in Prometheus text exposition format
//! for scraping by Prometheus, Grafana, or compatible monitoring systems.
//!
//! # Endpoint
//!
//! | Method   | Path          | Handler                 | Description              |
//! |----------|---------------|-------------------------|--------------------------|
//! | GET      | `/api/v1/metrics` | [`prometheus_metrics`] | Prometheus text format   |

#[allow(unused_imports)]
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
};
use tracing::debug;

#[allow(unused_imports)]
use crate::metrics_ext::MetricsCollector;
use crate::router::AppState;

// ---------------------------------------------------------------------------
// GET /api/v1/metrics
// ---------------------------------------------------------------------------

/// Export all collected metrics in Prometheus text exposition format.
///
/// Returns a `text/plain; version=0.0.4; charset=utf-8` response body
/// suitable for scraping by Prometheus or compatible monitoring systems.
///
/// # Metrics Exported
///
/// | Metric Type | Name                                    | Labels                       |
/// |-------------|-----------------------------------------|------------------------------|
/// | Counter     | `misogi_files_uploaded_total`           | `policy`                      |
/// | Histogram   | `misogi_scan_duration_seconds`          | (summary with quantiles)      |
/// | Counter     | `misogi_threats_found_total`            | `severity`                    |
/// | Counter     | `misogi_api_requests_total`            | `method`, `endpoint`, `status`|
/// | Gauge       | `misogi_active_jobs_current`            | (none)                        |
/// | Gauge       | `misogi_scanner_healthy`                | `scanner_name`                |
///
/// # Returns
///
/// - `200 OK` -- Plain-text metrics body
pub async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    debug!("Exporting Prometheus metrics");

    let body = state.metrics.export();

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
