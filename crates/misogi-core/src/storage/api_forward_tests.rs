// =============================================================================
// ApiForwardStorage — Unit Tests
// =============================================================================
//
// Test strategy: Lightweight mock HTTP server using raw tokio TCP listener.
// Each test spawns a dedicated server on an ephemeral port, ensuring full
// isolation between test cases without depending on axum's Handler trait.
//
// NOTE: This file is included via `include!()` from api_forward.rs, so it
// shares the parent's scope. Do NOT re-import types already present there.
//
// Coverage matrix (15 tests):
//
// | # | Test Name                              | Target Behavior               |
// |---|----------------------------------------|-------------------------------|
// | 1 | test_put_success_with_content_verification | POST forwards correct bytes |
// | 2 | test_auth_header_forwarded_correctly   | Auth header injection works   |
// | 3 | test_custom_headers_included           | Custom headers propagated     |
// | 4 | test_get_returns_not_supported         | get() -> NotSupported         |
// | 5 | test_delete_returns_not_supported      | delete() -> NotSupported      |
// | 6 | test_exists_returns_not_supported      | exists() -> NotSupported      |
// | 7 | test_env_var_expansion                 | ${VAR} expansion in auth_token|
// | 8 | test_env_var_expansion_unset_error     | Missing env var -> error       |
// | 9 | test_env_var_expansion_multiple        | Multiple ${VAR} in one string |
// |10 | test_health_check_success              | HEAD probe succeeds           |
// |11 | test_health_check_unreachable          | Unreachable -> NetworkError    |
// |12 | test_backend_type_identifier           | Returns "api_forward"         |
// |13 | test_rejects_empty_endpoint_host       | Config validation: bad host   |
// |14 | test_rejects_zero_timeout              | Config validation: timeout < 1|
// |15 | test_http_method_enum                  | HttpMethod Display/to_reqwest |

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// =========================================================================
// Test Infrastructure: Raw TCP Mock Server
// =========================================================================

/// Handle for a running mock HTTP server task.
struct MockServer {
    url: String,
    _handle: JoinHandle<()>,
}

impl MockServer {
    fn url(&self) -> &str { &self.url }
}

/// Start a raw TCP mock HTTP server on an ephemeral port.
///
/// Reads one HTTP request, runs optional validator, sends configured response.
async fn start_raw_mock_server<F>(
    response_status: &str,
    response_headers: &[(&str, &str)],
    response_body: &str,
    request_validator: Option<F>,
) -> MockServer
where
    F: FnOnce(Vec<u8>) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let status = response_status.to_string();
    let headers: Vec<(String, String)> = response_headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let body = response_body.to_string();

    let handle = tokio::spawn(async move {
        if let Ok((mut stream, _addr)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request_data = buf[..n].to_vec();

            if let Some(v) = request_validator {
                v(request_data);
            }

            let mut resp = format!(
                "HTTP/1.1 {}\r\nContent-Length: {}\r\n",
                status, body.len()
            );
            for (key, val) in &headers {
                resp.push_str(&format!("{}: {}\r\n", key, val));
            }
            resp.push_str("\r\n");
            resp.push_str(&body);
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    MockServer { url, _handle: handle }
}

/// Build a minimal valid [`ApiForwardConfig`] pointing at the given URL.
fn make_test_config(endpoint: &str) -> ApiForwardConfig {
    ApiForwardConfig {
        endpoint: endpoint.parse().expect("Test URL must be valid"),
        headers: HashMap::new(),
        auth_token: None,
        auth_header: "Authorization".to_string(),
        timeout_secs: 5,
        method: HttpMethod::Post,
    }
}

/// Extract body portion from raw HTTP request bytes (after \r\n\r\n).
fn extract_request_body(request_bytes: &[u8]) -> Vec<u8> {
    if let Some(pos) = request_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        request_bytes[pos + 4..].to_vec()
    } else {
        Vec::new()
    }
}

/// Extract a specific header value from raw HTTP request bytes.
fn extract_header_value(request_bytes: &[u8], header_name: &str) -> Option<String> {
    let request_str = String::from_utf8_lossy(request_bytes);
    let target = format!("{}:", header_name).to_lowercase();
    for line in request_str.lines() {
        if line.to_lowercase().starts_with(&target) {
            return Some(line[target.len()..].trim().to_string());
        }
    }
    None
}

// =========================================================================
// Group 1: PUT Operation — Core Forwarding Functionality
// =========================================================================

#[tokio::test]
async fn test_put_success_with_content_verification() {
    let mock = start_raw_mock_server(
        "200 OK",
        &[("ETag", "\"abc123\""), ("Content-Type", "application/json")],
        "",
        Some(|req_bytes: Vec<u8>| {
            let body = extract_request_body(&req_bytes);
            assert_eq!(body, b"hello-api-forward");
        }),
    )
    .await;

    let storage =
        ApiForwardStorage::new(make_test_config(mock.url())).expect("Config should be valid");
    let result = storage.put("test-key", Bytes::from_static(b"hello-api-forward")).await;
    assert!(result.is_ok(), "put() should succeed: {:?}", result.err());

    let info = result.unwrap();
    assert_eq!(info.key, "test-key");
    assert_eq!(info.size, 17);
    assert_eq!(info.etag, Some("\"abc123\"".to_string()));
}

#[tokio::test]
async fn test_auth_header_forwarded_correctly() {
    let mock = start_raw_mock_server(
        "200 OK", &[], "",
        Some(|req_bytes: Vec<u8>| {
            let auth = extract_header_value(&req_bytes, "X-Custom-Auth");
            assert!(auth.is_some(), "Expected X-Custom-Auth header");
            assert_eq!(auth.unwrap(), "Bearer secret-token-xyz");
        }),
    )
    .await;

    let mut config = make_test_config(mock.url());
    config.auth_token = Some("Bearer secret-token-xyz".to_string());
    config.auth_header = "X-Custom-Auth".to_string();

    let storage = ApiForwardStorage::new(config).expect("Config valid");
    assert!(storage.put("auth-test", Bytes::from_static(b"data")).await.is_ok());
}

#[tokio::test]
async fn test_custom_headers_included() {
    let mock = start_raw_mock_server(
        "201 Created", &[], "",
        Some(|req_bytes: Vec<u8>| {
            let tenant = extract_header_value(&req_bytes, "X-Tenant");
            let trace_id = extract_header_value(&req_bytes, "X-Trace-Id");
            assert_eq!(tenant.as_deref(), Some("acme-corp"));
            assert_eq!(trace_id.as_deref(), Some("trace-001"));
        }),
    )
    .await;

    let mut config = make_test_config(mock.url());
    config.headers = [
        ("X-Tenant".to_string(), "acme-corp".to_string()),
        ("X-Trace-Id".to_string(), "trace-001".to_string()),
    ]
    .into_iter()
    .collect();

    let storage = ApiForwardStorage::new(config).expect("Config valid");
    assert!(storage.put("header-test", Bytes::from_static(b"{}")).await.is_ok());
}

// =========================================================================
// Group 2: Write-Only Contract Enforcement
// =========================================================================

#[tokio::test]
async fn test_get_returns_not_supported() {
    let mock = start_raw_mock_server("200 OK", &[], "", None::<fn(Vec<u8>)>).await;
    let storage = ApiForwardStorage::new(make_test_config(mock.url())).expect("Config valid");

    match storage.get("any-key").await.unwrap_err() {
        StorageError::NotSupported(msg) => assert!(msg.contains("write-only")),
        other => panic!("Expected NotSupported, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_delete_returns_not_supported() {
    let mock = start_raw_mock_server("200 OK", &[], "", None::<fn(Vec<u8>)>).await;
    let storage = ApiForwardStorage::new(make_test_config(mock.url())).expect("Config valid");

    match storage.delete("any-key").await.unwrap_err() {
        StorageError::NotSupported(msg) => assert!(msg.contains("write-only")),
        other => panic!("Expected NotSupported, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_exists_returns_not_supported() {
    let mock = start_raw_mock_server("200 OK", &[], "", None::<fn(Vec<u8>)>).await;
    let storage = ApiForwardStorage::new(make_test_config(mock.url())).expect("Config valid");

    match storage.exists("any-key").await.unwrap_err() {
        StorageError::NotSupported(msg) => assert!(msg.contains("write-only")),
        other => panic!("Expected NotSupported, got: {:?}", other),
    }
}

// =========================================================================
// Group 3: Environment Variable Expansion
// =========================================================================

#[tokio::test]
async fn test_env_var_expansion() {
    unsafe { std::env::set_var("MISOGI_TEST_API_KEY", "expanded-secret-value-42") };

    let mock = start_raw_mock_server(
        "200 OK", &[], "",
        Some(|req_bytes: Vec<u8>| {
            let auth = extract_header_value(&req_bytes, "Authorization");
            assert_eq!(auth.as_deref(), Some("Bearer expanded-secret-value-42"));
        }),
    )
    .await;

    let mut config = make_test_config(mock.url());
    config.auth_token = Some("Bearer ${MISOGI_TEST_API_KEY}".to_string());

    let storage = ApiForwardStorage::new(config).expect("Env expansion ok");
    assert!(storage.put("env-test", Bytes::from_static(b"test")).await.is_ok());

    unsafe { std::env::remove_var("MISOGI_TEST_API_KEY") };
}

#[test]
fn test_env_var_expansion_unset_variable_error() {
    unsafe { std::env::remove_var("MISOGI_NONEXISTENT_VAR_XYZ") };
    let result = expand_env_vars("${MISOGI_NONEXISTENT_VAR_XYZ}");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not set"));
    unsafe { std::env::remove_var("MISOGI_NONEXISTENT_VAR_XYZ") };
}

#[test]
fn test_env_var_expansion_multiple_variables() {
    unsafe { std::env::set_var("MISOGI_TEST_PART_A", "hello") };
    unsafe { std::env::set_var("MISOGI_TEST_PART_B", "world") };
    let result = expand_env_vars("prefix-${MISOGI_TEST_PART_A}-${MISOGI_TEST_PART_B}-suffix");
    assert_eq!(result.unwrap(), "prefix-hello-world-suffix");
    unsafe { std::env::remove_var("MISOGI_TEST_PART_A") };
    unsafe { std::env::remove_var("MISOGI_TEST_PART_B") };
}

// =========================================================================
// Group 4: Health Check
// =========================================================================

#[tokio::test]
async fn test_health_check_success() {
    let mock = start_raw_mock_server("200 OK", &[], "", None::<fn(Vec<u8>)>).await;
    let storage = ApiForwardStorage::new(make_test_config(mock.url())).expect("Config valid");
    assert!(storage.health_check().await.is_ok());
}

#[tokio::test]
async fn test_health_check_unreachable() {
    let config = ApiForwardConfig {
        endpoint: "http://127.0.0.1:59999".parse().unwrap(),
        timeout_secs: 1,
        ..Default::default()
    };
    let storage = ApiForwardStorage::new(config).expect("Config valid");
    match storage.health_check().await.unwrap_err() {
        StorageError::NetworkError(_) => {}
        other => panic!("Expected NetworkError, got: {:?}", other),
    }
}

// =========================================================================
// Group 5: Backend Identity and Configuration Validation
// =========================================================================

#[tokio::test]
async fn test_backend_type_identifier() {
    let mock = start_raw_mock_server("200 OK", &[], "", None::<fn(Vec<u8>)>).await;
    let storage = ApiForwardStorage::new(make_test_config(mock.url())).expect("Config valid");
    assert_eq!(storage.backend_type(), "api_forward");
}

#[test]
fn test_rejects_empty_endpoint_host() {
    let config = ApiForwardConfig {
        endpoint: "http://invalid-placeholder.local".parse().unwrap(),
        ..Default::default()
    };
    match ApiForwardStorage::new(config).unwrap_err() {
        StorageError::ConfigurationError(msg) => assert!(msg.contains("valid")),
        other => panic!("Expected ConfigurationError, got: {:?}", other),
    }
}

#[test]
fn test_rejects_zero_timeout() {
    let config = ApiForwardConfig {
        endpoint: "http://example.com/api".parse().unwrap(),
        timeout_secs: 0,
        ..Default::default()
    };
    match ApiForwardStorage::new(config).unwrap_err() {
        StorageError::ConfigurationError(msg) => {
            assert!(msg.to_lowercase().contains("timeout"), "Should reject zero: {}", msg);
        }
        other => panic!("Expected ConfigurationError, got: {:?}", other),
    }
}

// =========================================================================
// Group 6: HttpMethod Enum
// =========================================================================

#[test]
fn test_http_method_display() {
    assert_eq!(HttpMethod::Post.to_string(), "POST");
    assert_eq!(HttpMethod::Put.to_string(), "PUT");
}

#[test]
fn test_http_method_to_reqwest() {
    assert_eq!(HttpMethod::Post.to_reqwest_method(), Method::POST);
    assert_eq!(HttpMethod::Put.to_reqwest_method(), Method::PUT);
}
