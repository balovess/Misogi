use axum::{Router, routing::{get, post}, middleware};
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use tracing::Instrument;
use crate::state::SharedState;

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

/// Build the main Axum Router with version-scoped route nesting.
///
/// # Architecture
///
/// ```text
/// Router
/// ├── /api/v1/*     → v1_routes()  (stable, current production)
/// ├── /api/v2/*     → v2_routes()  (future: AI semantic sanitization)
/// ├── /health        → health check (version-agnostic)
/// └── /version       → version info endpoint (version-agnostic)
/// ```
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        // === V1 Routes (stable, current production) ===
        .nest("/api/v1", v1_routes(state.clone()))
        // === V2 Routes (future extension point) ===
        .nest("/api/v2", v2_routes(state.clone()))
        // === Version-agnostic endpoints ===
        .route("/health", get(crate::http_routes::health))
        .route("/version", get(version_info))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(CorsLayer::permissive())
}

/// All V1 API endpoints — the stable, production-ready interface.
///
/// These routes are frozen in their shape. New features go into V2.
fn v1_routes(state: SharedState) -> Router {
    Router::new()
        .route("/upload", post(crate::http_routes::upload))
        .route("/files/:file_id", get(crate::http_routes::get_file)
            .post(crate::http_routes::trigger_transfer))
        .route("/files", get(crate::http_routes::list_files))
        .route("/sanitize/:file_id", post(crate::http_routes::sanitize_file))
        .route("/sanitize/policies", get(crate::http_routes::list_policies))
        .route("/health", get(crate::http_routes::health))
        .route("/transfers", post(crate::approval_routes::create_transfer_request)
            .get(crate::approval_routes::list_transfers))
        .route("/transfers/pending", get(crate::approval_routes::list_pending_requests))
        .route("/transfers/:request_id", get(crate::approval_routes::get_transfer))
        .route("/transfers/:request_id/approve", post(crate::approval_routes::approve_request))
        .route("/transfers/:request_id/reject", post(crate::approval_routes::reject_request))
        .route("/ppap/detect", post(crate::http_routes::ppap_detect))
        .route("/ppap/statistics", get(crate::http_routes::ppap_statistics))
        .with_state(state)
}

/// V2 API endpoints — future extension point for AI-enhanced features.
///
/// Currently delegates to V1 handlers as placeholders. When V2 logic is
// implemented, replace these with real V2 handler functions.
//
/// A deprecation shim middleware can be applied here to warn legacy clients
/// that they should migrate to V3 when it exists.
fn v2_routes(state: SharedState) -> Router {
    Router::new()
        // V2 upload (enhanced with metadata support — delegates to V1 for now)
        .route("/upload", post(crate::http_routes::upload))
        // V2 sanitize (AI-enhanced path — delegates to V1 for now)
        .route("/sanitize/:file_id", post(crate::http_routes::sanitize_file))
        // V2-specific: Pre-scan with ML analysis (placeholder)
        .route("/pre-scan", post(v2_pre_scan_placeholder))
        // V2 file listing (delegates to V1)
        .route("/files", get(crate::http_routes::list_files))
        .route("/files/:file_id", get(crate::http_routes::get_file))
        // V2 transfers (delegates to V1)
        .route("/transfers", post(crate::approval_routes::create_transfer_request)
            .get(crate::approval_routes::list_transfers))
        // V2 PPAP detection (delegates to V1)
        .route("/ppap/detect", post(crate::http_routes::ppap_detect))
        .route("/ppap/statistics", get(crate::http_routes::ppap_statistics))
        .with_state(state)
}

async fn v2_pre_scan_placeholder(
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "not_implemented",
        "message": "V2 AI pre-scan endpoint is not yet available",
        "documentation": "https://docs.misogi.dev/api/v2/pre-scan",
        "api_version": "v2"
    }))
}

/// Version information endpoint returning supported API versions.
async fn version_info() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "name": "Misogi CDR Platform",
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
