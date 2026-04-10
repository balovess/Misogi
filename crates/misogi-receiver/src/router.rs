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

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/files", get(http_routes::list_files))
        .route("/api/v1/download/{file_id}", get(http_routes::download_file))
        .route("/api/v1/files/{file_id}/status", get(http_routes::get_file_status))
        .route("/api/v1/files/{file_id}/reassemble", post(http_routes::reassemble))
        .route("/api/v1/health", get(http_routes::health_check))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
