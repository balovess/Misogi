//! E2E: NoCode Health Router Integration
//!
//! Verifies that [`build_health_router()`](misogi_nocode::build_health_router)
//! produces a working Axum router responding to HTTP requests.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;
use misogi_nocode::{build_health_router, NoCodeRuntime};

fn make_test_runtime() -> Arc<NoCodeRuntime> {
    let yaml_config = r#"
nocode:
  enabled: true
  checkers:
    - name: "disk_space"
      type: "builtin"
      config: {}
    - name: "memory_usage"
      type: "builtin"
      config: {}
"#;
    Arc::new(NoCodeRuntime::new(yaml_config.to_string()))
}

#[tokio::test]
async fn e2e_health_status_uninitialized_returns_503() {
    let runtime = make_test_runtime();
    let app = build_health_router(runtime);

    let req = Request::builder()
        .uri("/nocode/health/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "uninitialized runtime must return 503"
    );

    let body = http_body_util::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "degraded");
    assert_eq!(json["initialized"], false);
}

#[tokio::test]
async fn e2e_health_status_initialized_returns_200() {
    let mut runtime = make_test_runtime();
    runtime.initialize().await.expect("initialization must succeed");
    let runtime = Arc::new(runtime);

    let app = build_health_router(runtime);

    let req = Request::builder()
        .uri("/nocode/health/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "initialized runtime must return 200"
    );

    let body = http_body_util::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "healthy");
    assert_eq!(json["initialized"], true);
}

#[tokio::test]
async fn e2e_health_config_check_returns_content() {
    let runtime = make_test_runtime();
    let app = build_health_router(runtime);

    let req = Request::builder()
        .uri("/nocode/health/config")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = http_body_util::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("checkers").is_some(), "response must contain checkers");
    assert!(
        json["checkers"].as_array().map_or(false, |a| !a.is_empty()),
        "must have at least one checker configured"
    );
}

#[tokio::test]
async fn e2e_health_unknown_route_returns_404() {
    let runtime = make_test_runtime();
    let app = build_health_router(runtime);

    let req = Request::builder()
        .uri("/nocode/health/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "unknown route must return 404"
    );
}
