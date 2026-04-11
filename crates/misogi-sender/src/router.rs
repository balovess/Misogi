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

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/upload", post(crate::http_routes::upload))
        .route("/api/v1/files/:file_id", get(crate::http_routes::get_file).post(crate::http_routes::trigger_transfer))
        .route("/api/v1/files", get(crate::http_routes::list_files))
        .route("/api/v1/sanitize/:file_id", post(crate::http_routes::sanitize_file))
        .route("/api/v1/sanitize/policies", get(crate::http_routes::list_policies))
        .route("/api/v1/health", get(crate::http_routes::health))
        .route("/api/v1/transfers", post(crate::approval_routes::create_transfer_request).get(crate::approval_routes::list_transfers))
        .route("/api/v1/transfers/pending", get(crate::approval_routes::list_pending_requests))
        .route("/api/v1/transfers/:request_id", get(crate::approval_routes::get_transfer))
        .route("/api/v1/transfers/:request_id/approve", post(crate::approval_routes::approve_request))
        .route("/api/v1/transfers/:request_id/reject", post(crate::approval_routes::reject_request))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
