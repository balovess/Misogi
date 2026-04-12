use axum::{Router, routing::{get, post}, middleware};
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use tracing::Instrument;
use crate::state::SharedState;
use crate::http_routes;

async fn request_id_middleware(
    mut req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let request_id = Uuid::new_v4().to_string();

    req.extensions_mut().insert(request_id.clone());

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %req.method(),
        path = %req.uri().path(),
    );

    let response = next.run(req).instrument(span).await;

    let mut response = response;
    if let Ok(header_value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", header_value);
    }

    response
}

/// Build the main Axum Router for the receiver node with version-scoped nesting.
///
/// # Architecture
///
/// ```text
/// Router (Receiver)
/// ├── /api/v1/*     → v1_routes()  (stable file reception)
/// ├── /api/v2/*     → v2_routes()  (future: enhanced streaming)
/// ├── /health        → health check
/// └── /version       → version info
/// ```
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        // === V1 Routes (stable, current production) ===
        .nest("/api/v1", v1_routes(state.clone()))
        // === V2 Routes (future extension point) ===
        .nest("/api/v2", v2_routes(state.clone()))
        // === Version-agnostic endpoints ===
        .route("/health", get(http_routes::health_check))
        .route("/version", get(version_info))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(CorsLayer::permissive())
}

/// All V1 receiver API endpoints — stable file reception interface.
fn v1_routes(state: SharedState) -> Router {
    Router::new()
        .route("/files", get(http_routes::list_files))
        .route("/download/{file_id}", get(http_routes::download_file))
        .route("/files/{file_id}/status", get(http_routes::get_file_status))
        .route("/files/{file_id}/reassemble", post(http_routes::reassemble))
        .route("/health", get(http_routes::health_check))
        .with_state(state)
}

/// V2 receiver API endpoints — future extension point.
///
/// Placeholder handlers that delegate to V1 logic. When V2 features are
/// implemented (e.g., Blast protocol integration, parallel reassembly),
/// replace these with real V2 implementations.
fn v2_routes(state: SharedState) -> Router {
    Router::new()
        // V2 file listing (delegates to V1)
        .route("/files", get(http_routes::list_files))
        // V2 download (enhanced with integrity metadata)
        .route("/download/{file_id}", get(http_routes::download_file))
        // V2 status check (delegates to V1)
        .route("/files/{file_id}/status", get(http_routes::get_file_status))
        // V2 reassemble (may use FEC in future)
        .route("/files/{file_id}/reassemble", post(http_routes::reassemble))
        // V2-specific: Blast transfer status (placeholder)
        .route("/blast/status", get(v2_blast_status_placeholder))
        .with_state(state)
}

async fn v2_blast_status_placeholder() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "not_implemented",
        "message": "V2 Blast transfer status endpoint is not yet available",
        "documentation": "https://docs.misogi.dev/api/v2/blast",
        "api_version": "v2"
    }))
}

/// Version information endpoint returning supported API versions.
async fn version_info() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "name": "Misogi CDR Platform — Receiver Node",
        "versions": ["v1", "v2"],
        "default_version": "v1",
        "latest_stable": "v1",
        "deprecated_versions": [],
        "proto_packages": [
            "misogi.file_transfer.v1",
            "misogi.file_transfer.v2"
        ],
        "documentation": "https://docs.misogi.dev/api/versioning"
    }))
}
