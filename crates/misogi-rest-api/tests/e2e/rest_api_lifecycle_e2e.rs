//! E2E: REST API Lifecycle
//!
//! Verifies that [`create_app()`](misogi_rest_api::router::create_app)
//! accepts new optional parameters without panicking.

use misogi_rest_api::{
    models::RestApiConfig,
    router::create_app,
};

#[tokio::test]
async fn e2e_create_app_without_nocode_succeeds() {
    let config = RestApiConfig::default();

    let app = create_app(config, None, None, None, None);

    assert!(
        !format!("{:?}", app).is_empty(),
        "create_app without nocode must produce a valid Router"
    );
}

#[tokio::test]
async fn e2e_create_app_with_nocode_runtime_succeeds() {
    let config = RestApiConfig::default();
    let yaml = r#"
nocode:
  enabled: true
  checkers:
    - name: "health_check"
      type: "builtin"
      config: {}
"#;

    let runtime = {
        use misogi_nocode::NoCodeRuntime;
        let mut rt = NoCodeRuntime::new(yaml.to_string());
        let _ = rt.initialize().await;
        std::sync::Arc::new(rt)
    };

    let result = std::panic::catch_unwind(|| {
        let _app = create_app(config, None, None, None, Some(runtime));
    });

    assert!(
        result.is_ok(),
        "create_app with nocode runtime must not panic, got: {:?}",
        result.err()
    );
}
