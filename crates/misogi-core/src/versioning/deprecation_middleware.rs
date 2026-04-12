//! Axum middleware that emits deprecation warnings for legacy API versions.
//!
//! Japanese government SIers need concrete log evidence to justify
//! budget requests for system upgrades. This middleware provides exactly that:
//!
//! ```text
//! [WARN] [DEPRECATION] Client accessed deprecated API v1 endpoint: /api/v1/upload
//! [WARN] [DEPRECATION]   ├─ Client IP: 192.168.1.100
//! [WARN] [DEPRECATION]   ├─ Request ID: a1b2c3d4-e5f6-7890
//! [WARN] [DEPRECATION]   ├─ User-Agent: LegacySystem/1.0
//! [WARN] [DEPRECATION]   └─ Sunset date: 2027-03-31
//! [WARN] [DEPRECATION] → Please migrate to /api/v2/upload
//! ```
//!
//! The request STILL completes successfully — this is purely informational
//! logging for compliance auditing per RFC 8594 (Link: rel="successor-version").

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue},
    response::Response,
};
use serde::{Deserialize, Serialize};

use super::api_version::ApiVersion;
use super::sunset_policy::VersionSunsetPolicy;

/// Configuration controlling deprecation warning behavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeprecationConfig {
    /// Map of version string → optional sunset date (ISO 8601).
    ///
    /// If the value is `Some(date)`, requests to that version emit warnings.
    /// If `None` or missing, the version is considered active (no warning).
    pub sunset_dates: std::collections::HashMap<String, Option<String>>,

    /// Whether to include detailed caller info in warning logs.
    #[serde(default = "default_true")]
    pub include_caller_info: bool,

    /// Whether to add RFC 8594 `Deprecated` and `Link` HTTP headers
    /// to responses from deprecated endpoints.
    #[serde(default = "default_true")]
    pub deprecation_headers: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DeprecationConfig {
    fn default() -> Self {
        Self {
            sunset_dates: std::collections::HashMap::new(),
            include_caller_info: true,
            deprecation_headers: true,
        }
    }
}

/// Shared state passed through Axum's State extractor to the middleware.
#[derive(Clone)]
pub struct DeprecationMiddlewareState {
    pub config: Arc<DeprecationConfig>,
    pub policies: Arc<std::collections::HashMap<String, VersionSunsetPolicy>>,
}

/// Extract the API version from a URI path string.
///
/// Returns `"v1"`, `"v2"`, etc., or an empty string if no version detected.
fn extract_version_from_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        if (*seg == "api" || *seg == "grpc") && i + 1 < segments.len() {
            let candidate = segments[i + 1];
            if ApiVersion::from_path_segment(candidate).is_some() {
                return candidate.to_string();
            }
        }
    }
    String::new()
}

/// Strip the version prefix from a path to get the resource-relative path.
///
/// Example: `/api/v1/upload` → `upload`
fn strip_version_prefix(path: &str) -> &str {
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() >= 4 && (segments[1] == "api" || segments[1] == "grpc") {
        // Skip "", "api"/"grpc", and version segment (e.g. "v1") to reach resource
        let offset = segments[0].len() + 1 + segments[1].len() + 1 + segments[2].len() + 1;
        return &path[offset..];
    }
    path
}

/// Build the successor-version URL for a given deprecated path.
///
/// Example: `/api/v1/upload` → `/api/v2/upload`
#[allow(dead_code)]
fn versioned_link(original_path: &str, next_ver: &ApiVersion) -> String {
    let resource = strip_version_prefix(original_path);
    format!("{}/{}", next_ver.url_prefix(), resource)
}

/// Axum middleware function that logs deprecation warnings for legacy API calls.
///
/// Does NOT block or modify request processing — only adds diagnostic logging
/// and optionally injects HTTP headers per RFC 8594.
///
/// # Usage with Axum Router
///
/// ```rust,ignore
/// use axum::middleware;
///
/// let v2_routes = Router::new()
///     .route("/upload", post(handler))
///     .layer(middleware::from_fn_with_state(
///         dep_state,
///         deprecation_warning_middleware,
///     ));
/// ```
pub async fn deprecation_warning_middleware(
    state: State<DeprecationMiddlewareState>,
    req: axum::extract::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let version_str = extract_version_from_path(&path);

    if version_str.is_empty() {
        return next.run(req).await;
    }

    let policy_match = state.policies.get(&version_str);
    let sunset_date = state
        .config
        .sunset_dates
        .get(&version_str)
        .and_then(|d| d.as_deref());

    let is_deprecated = policy_match
        .map(|p| p.is_deprecated())
        .unwrap_or(sunset_date.is_some());

    if !is_deprecated {
        return next.run(req).await;
    }

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .map(|v| v.to_str().unwrap_or("?"))
        .unwrap_or("unknown");
    let user_agent = req
        .headers()
        .get("user-agent")
        .map(|v| v.to_str().unwrap_or("?"))
        .unwrap_or("?");

    tracing::warn!(
        "[DEPRECATION] Client accessed deprecated API {} endpoint: {} {}",
        version_str, method, path
    );
    if state.config.include_caller_info {
        tracing::warn!("[DEPRECATION]   ├─ Client IP: {}", client_ip);
        tracing::warn!(
            "[DEPRECATION]   ├─ User-Agent: {}",
            truncate_user_agent(user_agent, 80)
        );
    }
    if let Some(date) = sunset_date {
        tracing::warn!("[DEPRECATION]   ├─ Sunset date: {}", date);
    }
    tracing::warn!("[DEPRECATION]   └─ Current date: {}", now);

    if let Some(next_ver) = ApiVersion::from_path_segment(&version_str)
        .and_then(|v| v.successor())
    {
        tracing::warn!(
            "[DEPRECATION] → Please migrate to {}{}",
            next_ver.url_prefix(),
            strip_version_prefix(&path)
        );
    }

    let mut response = next.run(req).await;

    if state.config.deprecation_headers {
        let headers = response.headers_mut();

        if let Some(policy) = policy_match {
            if let Some(sunset_val) = policy.sunset_header_value() {
                if let Ok(val) = sunset_val.parse::<HeaderValue>() {
                    headers.insert(HeaderName::from_static("sunset"), val);
                }
            }
            if let Some(link_val) = policy.successor_link_header(&path) {
                if let Ok(val) = link_val.parse::<HeaderValue>() {
                    headers.insert(
                        HeaderName::from_static("link"),
                        val,
                    );
                }
            }
            if let Ok(val) = "true".parse::<HeaderValue>() {
                headers.insert(HeaderName::from_static("deprecated"), val);
            }
        } else if let Some(date) = sunset_date {
            if let Ok(val) =
                format!(r#"true, Sunset="{}""#, date).parse::<HeaderValue>()
            {
                headers.insert(HeaderName::from_static("deprecated"), val);
            }
        }
    }

    response
}

/// Truncate User-Agent string to max_len characters for log readability.
fn truncate_user_agent(ua: &str, max_len: usize) -> &str {
    if ua.len() > max_len {
        &ua[..max_len]
    } else {
        ua
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version_v1() {
        assert_eq!(extract_version_from_path("/api/v1/upload"), "v1");
    }

    #[test]
    fn test_extract_version_v2() {
        assert_eq!(extract_version_from_path("/api/v2/sanitize/abc"), "v2");
    }

    #[test]
    fn test_extract_version_no_version() {
        assert_eq!(extract_version_from_path("/health"), "");
        assert_eq!(extract_version_from_path("/version"), "");
    }

    #[test]
    fn test_strip_version_prefix() {
        assert_eq!(strip_version_prefix("/api/v1/upload"), "upload");
        assert_eq!(strip_version_prefix("/api/v2/files/123"), "files/123");
    }

    #[test]
    fn test_versioned_link() {
        assert_eq!(
            versioned_link("/api/v1/upload", &ApiVersion::V2),
            "/api/v2/upload"
        );
        assert_eq!(
            versioned_link("/api/v2/pre-scan", &ApiVersion::V1),
            "/api/v1/pre-scan"
        );
    }

    #[test]
    fn test_default_config() {
        let cfg = DeprecationConfig::default();
        assert!(cfg.include_caller_info);
        assert!(cfg.deprecation_headers);
        assert!(cfg.sunset_dates.is_empty());
    }

    #[test]
    fn test_truncate_user_agent_short() {
        assert_eq!(truncate_user_agent("short", 100), "short");
    }

    #[test]
    fn test_truncate_user_agent_long() {
        let long = "a".repeat(200);
        let result = truncate_user_agent(&long, 50);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn test_config_serialization() {
        let cfg = DeprecationConfig {
            sunset_dates: [("v1".to_string(), Some("2027-03-31".to_string()))]
                .into_iter()
                .collect(),
            include_caller_info: false,
            deprecation_headers: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: DeprecationConfig = serde_json::from_str(&json).unwrap();
        assert!(!decoded.include_caller_info);
    }
}
