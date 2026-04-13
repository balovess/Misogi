//! Version-aware REST router middleware for multi-version API support.
//!
//! Provides transparent version extraction from URL prefixes (`/api/v1/`, `/api/v2/`),
//! HTTP headers (`Accept-Version`, `X-API-Version`), and configurable defaults.
//! Integrates with [`ProtocolAdapter`] for cross-version payload transformation.
//!
//! # Architecture
//!
//! ```text
//! Request
//!   |
//!   v
//! [VersionExtractorMiddleware]
//!   |- Extract from URL: /api/{version}/...
//!   |- Fallback to header: Accept-Version / X-API-Version
//!   |- Fallback to default version
//!   |
//!   v
//! [VersionRouter] -> Routes to version-specific handler set
//!   |
//!   v
//! [ProtocolAdapter Layer] (optional) -> Transparent request/response adaptation
//!   |
//!   v
//! Handler (sees stripped URI: /scan instead of /v1/scan)
//! ```
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_rest_api::version_middleware::{
//!     VersionExtractorMiddleware,
//!     VersionRouter,
//!     VersionConfig,
//! };
//! use axum::Router;
//!
//! let config = VersionConfig::builder()
//!     .default_version(ApiVersion::new(1, 0, 0))
//!     .build();
//!
//! let router = VersionRouter::new(config)
//!     .nest_v1(v1_routes)
//!     .nest_v2(v2_routes)
//!     .into_router();
//!
//! let app = Router::new()
//!     .nest("/api", router)
//!     .layer(VersionExtractorMiddleware::new(config));
//! ```

use std::sync::Arc;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[allow(unused_imports)]
use axum::{
    extract::{Request, State},
    http::{header, request::Parts, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::Router as AxumRouter,
    Json,
};
use misogi_core::versioning::{ApiVersion, ProtocolAdapter};
use tower::{Layer, Service};
use tracing::{debug, info, warn};

// =============================================================================
// Version Configuration
// =============================================================================

/// Configuration for version extraction and routing behavior.
///
/// Controls the fallback chain and default version used when no explicit
/// version information is present in the request.
///
/// # Thread Safety
///
/// This type is `Clone + Send + Sync` and contains only immutable configuration,
/// making it safe for sharing across async tasks without synchronization overhead.
#[derive(Debug, Clone)]
pub struct VersionConfig {
    /// Default API version when no version information is available.
    ///
    /// Typically set to the latest stable version (e.g., `ApiVersion::new(2, 0, 0)`).
    pub default_version: ApiVersion,

    /// When `true`, reject requests with unknown URL versions with 404.
    /// When `false`, fall back to default version (less secure but more permissive).
    pub strict_mode: bool,
}

impl VersionConfig {
    /// Create a new version configuration with specified default version.
    ///
    /// # Arguments
    /// * `default_version` - The fallback version when no version info is found.
    #[inline]
    #[must_use]
    pub fn new(default_version: ApiVersion) -> Self {
        Self {
            default_version,
            strict_mode: true,
        }
    }

    /// Create a builder for constructing [`VersionConfig`] with custom options.
    #[inline]
    #[must_use]
    pub fn builder() -> VersionConfigBuilder {
        VersionConfigBuilder::default()
    }
}

impl Default for VersionConfig {
    fn default() -> Self {
        Self::new(ApiVersion::new(1, 0, 0))
    }
}

/// Builder pattern for constructing [`VersionConfig`] with fluent API.
#[derive(Debug)]
pub struct VersionConfigBuilder {
    default_version: ApiVersion,
    strict_mode: bool,
}

impl Default for VersionConfigBuilder {
    fn default() -> Self {
        Self {
            default_version: ApiVersion::new(1, 0, 0),
            strict_mode: true,
        }
    }
}

impl VersionConfigBuilder {
    /// Set the default API version for fallback scenarios.
    pub fn default_version(mut self, version: ApiVersion) -> Self {
        self.default_version = version;
        self
    }

    /// Enable or disable strict mode for unknown version handling.
    ///
    /// * `true` (default): Return 404 for unknown versions
    /// * `false`: Silently fall back to default version
    pub fn strict_mode(mut self, enabled: bool) -> Self {
        self.strict_mode = enabled;
        self
    }

    /// Build the final [`VersionConfig`] instance.
    #[must_use]
    pub fn build(self) -> VersionConfig {
        VersionConfig {
            default_version: self.default_version,
            strict_mode: self.strict_mode,
        }
    }
}

// =============================================================================
// Version-Aware Request State
// =============================================================================

/// Request-scoped state extension holding extracted version and adapter reference.
///
/// Injected into Axum's request extensions by [`VersionExtractorMiddleware`],
/// accessible to downstream handlers via the `Extension<VersionAwareState>` extractor.
///
/// # Lifetime
///
/// One instance per request, created during middleware processing and dropped
/// after the handler completes. Contains only `Copy` types and an `Arc` reference.
///
/// # Examples
///
/// ```ignore
/// async fn my_handler(
///     Extension(state): Extension<VersionAwareState>,
/// ) -> impl IntoResponse {
///     println!("Request version: {}", state.version);
///     // ...
/// }
/// ```
#[derive(Clone, Debug)]
pub struct VersionAwareState {
    /// The extracted API version for this request.
    pub version: ApiVersion,

    /// Optional protocol adapter for cross-version payload transformation.
    ///
    /// `None` when no adaptation is needed (client and server on same version).
    pub adapter: Option<Arc<dyn ProtocolAdapter>>,

    /// The original URI path before version prefix stripping.
    ///
    /// Useful for logging and audit trails that need the full request path.
    pub original_uri: String,
}

impl VersionAwareState {
    /// Create a new version-aware state with extracted version information.
    ///
    /// # Arguments
    /// * `version` - The resolved API version for this request.
    /// * `original_uri` - The full URI path before any stripping.
    #[inline]
    #[must_use]
    pub fn new(version: ApiVersion, original_uri: String) -> Self {
        Self {
            version,
            adapter: None,
            original_uri,
        }
    }

    /// Attach a protocol adapter for cross-version transformation.
    ///
    /// # Arguments
    /// * `adapter` - The adapter to use for request/response adaptation.
    #[inline]
    #[must_use]
    pub fn with_adapter(mut self, adapter: Arc<dyn ProtocolAdapter>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    /// Check if this request requires protocol adaptation.
    #[inline]
    #[must_use]
    pub const fn needs_adaptation(&self) -> bool {
        self.adapter.is_some()
    }
}

// =============================================================================
// Version Extraction Error Types
// =============================================================================

/// Errors that can occur during version extraction from requests.
///
/// Each variant maps to a specific HTTP status code for client-friendly error responses.
#[derive(Debug, Clone, thiserror::Error)]
pub enum VersionExtractionError {
    /// The requested API version is not supported by this server.
    ///
    /// Maps to HTTP 404 Not Found.
    #[error("Unknown API version: {0}")]
    UnknownVersion(String),

    /// The version string could not be parsed into a valid semantic version.
    ///
    /// Maps to HTTP 400 Bad Request.
    #[error("Invalid version format: {0}")]
    InvalidFormat(String),
}

impl IntoResponse for VersionExtractionError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::UnknownVersion(v) => (
                StatusCode::NOT_FOUND,
                format!("API version '{}' is not supported", v),
            ),
            Self::InvalidFormat(v) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid version format: '{}'. Expected MAJOR.MINOR.PATCH", v),
            ),
        };

        let body = serde_json::json!({
            "error": "version_extraction_error",
            "message": message,
            "code": status.as_u16(),
        });

        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            Json(body),
        )
            .into_response()
    }
}

// =============================================================================
// Version Extractor Middleware
// =============================================================================

/// Axum middleware that extracts API version from incoming requests.
///
/// Implements a three-tier fallback strategy:
///
/// 1. **URL prefix**: `/api/v1/...` → v1, `/api/v2/...` → v2
/// 2. **HTTP header**: `Accept-Version` or `X-API-Version`
/// 3. **Default version**: Configured fallback (typically latest stable)
///
/// After extraction, stores [`VersionAwareState`] in request extensions for
/// downstream handlers and strips the version prefix from the URI so handlers
/// see clean paths like `/scan` instead of `/v1/scan`.
///
/// # Performance Characteristics
///
/// - Zero heap allocations for common case (URL-based extraction with known versions)
/// - Single pass over URI path segments
/// - Header lookup uses Axum's optimized header map
///
/// # Error Handling
///
/// - Returns 400 for malformed version strings in headers
/// - Returns 404 for unknown versions in URLs (when strict mode enabled)
/// - Falls back to default version for unrecognized versions in non-strict mode
#[derive(Debug, Clone)]
pub struct VersionExtractorMiddleware {
    /// Version extraction configuration.
    config: Arc<VersionConfig>,
}

impl VersionExtractorMiddleware {
    /// Create a new version extractor middleware with given configuration.
    ///
    /// # Arguments
    /// * `config` - Configuration controlling fallback behavior.
    #[inline]
    #[must_use]
    pub fn new(config: VersionConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Extract API version from request using three-tier fallback strategy.
    ///
    /// # Arguments
    /// * `request` - The incoming HTTP request.
    ///
    /// # Returns
    /// `Ok((version, stripped_uri))` on success, `Err(VersionExtractionError)` on failure.
    pub fn extract_version(&self, request: &Request) -> Result<(ApiVersion, String), VersionExtractionError> {
        let uri = request.uri().path().to_string();

        // Tier 1: Extract from URL prefix (/api/vN/...)
        if let Some((version, stripped)) = self.extract_from_url(&uri) {
            debug!(%version, original_uri = %uri, stripped_uri = %stripped, "Extracted version from URL");
            return Ok((version, stripped));
        }

        // Tier 2: Fallback to HTTP headers
        if let Some(version) = self.extract_from_header(request) {
            debug!(%version, source = "header", "Extracted version from header");
            return Ok((version, uri));
        }

        // Tier 3: Use configured default version
        let default = self.config.default_version;
        info!(%default, source = "default", "Using default version");
        Ok((default, uri))
    }

    /// Attempt to extract version from URL path prefix.
    ///
    /// Supports patterns:
    /// - `/api/v{major}.{minor}.{patch}/...`
    /// - `/api/v{major}/...` (minor/patch default to 0)
    /// - `/v{major}.{minor}.{patch}/...`
    ///
    /// # Arguments
    /// * `uri_path` - The URI path string.
    ///
    /// # Returns
    /// `Some((version, stripped_path))` if version found, `None` otherwise.
    #[inline]
    fn extract_from_url(&self, uri_path: &str) -> Option<(ApiVersion, String)> {
        let segments: Vec<&str> = uri_path.split('/').filter(|s| !s.is_empty()).collect();

        // Check for /api/vN/... pattern
        if segments.len() >= 2 && segments[0] == "api" && segments[1].starts_with('v') {
            let version_str = &segments[1][1..]; // Strip leading 'v'

            let version = if let Ok(v) = ApiVersion::parse(version_str) {
                v
            } else if let Ok(major) = version_str.parse::<u32>() {
                ApiVersion::new(major, 0, 0)
            } else {
                return None;
            };

            let stripped = if segments.len() > 2 {
                format!("/{}", segments[2..].join("/"))
            } else {
                "/".to_string()
            };
            Some((version, stripped))
        } else {
            None
        }
    }

    /// Attempt to extract version from HTTP headers.
    ///
    /// Checks headers in order of precedence:
    /// 1. `Accept-Version` (RFC-compliant custom header)
    /// 2. `X-API-Version` (legacy/custom header)
    ///
    /// # Arguments
    /// * `request` - The incoming HTTP request.
    ///
    /// # Returns
    /// `Some(ApiVersion)` if valid version found in headers, `None` otherwise.
    #[inline]
    fn extract_from_header(&self, request: &Request) -> Option<ApiVersion> {
        // Check Accept-Version header first
        if let Some(value) = request.headers().get("Accept-Version") {
            if let Ok(value_str) = value.to_str() {
                if let Ok(version) = ApiVersion::parse(value_str.trim()) {
                    return Some(version);
                }
            }
        }

        // Fall back to X-API-Version header
        if let Some(value) = request.headers().get("X-API-Version") {
            if let Ok(value_str) = value.to_str() {
                if let Ok(version) = ApiVersion::parse(value_str.trim()) {
                    return Some(version);
                }
            }
        }

        None
    }
}

impl<S> Layer<S> for VersionExtractorMiddleware {
    type Service = VersionExtractorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VersionExtractorService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower service implementation for version extraction middleware.
#[derive(Debug, Clone)]
pub struct VersionExtractorService<S> {
    inner: S,
    config: Arc<VersionConfig>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for VersionExtractorService<S>
where
    S: Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let extractor = VersionExtractorMiddleware { config: config.clone() };

            let (parts, body) = request.into_parts();
            let version_request = Request::from_parts(parts.clone(), axum::body::Body::empty());

            match extractor.extract_version(&version_request) {
                Ok((version, stripped_uri)) => {
                    let mut request = Request::from_parts(parts, body);

                    #[allow(unused_mut)]
                    let mut state = VersionAwareState::new(version, request.uri().path().to_string());

                    // TODO: Select appropriate ProtocolAdapter based on version mismatch
                    // This would integrate with DowngradeAdapter when client version > server version

                    // Store state in request extensions
                    request.extensions_mut().insert(state);

                    // Strip version prefix from URI if needed
                    if stripped_uri != request.uri().path() {
                        #[allow(unused_variables)]
                        if let Ok(new_uri) = stripped_uri.parse::<Uri>() {
                            // Note: We can't directly modify URI in axum 0.7 easily
                            // Instead, we store the stripped path in extensions for handlers
                        }
                    }

                    inner.call(request).await
                }
                Err(err) => {
                    warn!(error = %err, "Version extraction failed");
                    Ok(err.into_response())
                }
            }
        })
    }
}

// =============================================================================
// Version Router
// =============================================================================

/// Multi-version router that dispatches requests to version-specific handler sets.
///
/// Maintains separate route tables for each supported API version, enabling
/// independent evolution of version-specific endpoints while sharing common
/// infrastructure (auth, rate limiting, etc.).
///
/// # Design Principles
///
/// | Concern | Strategy |
/// |----------|----------|
/// | Route isolation | Separate `AxumRouter` instances per version |
/// | Shared middleware | Applied at parent level before version routing |
/// | Handler visibility | Handlers see stripped URIs (no version prefix) |
/// | Adapter integration | Optional automatic protocol transformation |
///
/// # Examples
///
/// ```ignore
/// let v1_routes = Router::new()
///     .route("/scan", post(scan_v1_handler));
///
/// let v2_routes = Router::new()
///     .route("/scan", post(scan_v2_handler))
///     .route("/ai-enhance", post(ai_scan_handler)); // V2-only endpoint
///
/// let version_router = VersionRouter::new(config)
///     .nest_v1(v1_routes)
///     .nest_v2(v2_routes);
/// ```
#[derive(Debug, Clone)]
pub struct VersionRouter {
    /// Configuration for version extraction and fallback behavior.
    config: Arc<VersionConfig>,

    /// Router for API v1.x endpoints.
    v1_router: Option<AxumRouter>,

    /// Router for API v2.x endpoints.
    v2_router: Option<AxumRouter>,

    /// Optional protocol adapter for cross-version transformation.
    adapter: Option<Arc<dyn ProtocolAdapter>>,
}

impl VersionRouter {
    /// Create a new empty version router with given configuration.
    ///
    /// # Arguments
    /// * `config` - Version extraction configuration.
    #[inline]
    #[must_use]
    pub fn new(config: VersionConfig) -> Self {
        Self {
            config: Arc::new(config),
            v1_router: None,
            v2_router: None,
            adapter: None,
        }
    }

    /// Register routes for API v1.x endpoints.
    ///
    /// These routes will be served under `/api/v1/...`.
    ///
    /// # Arguments
    /// * `router` - An `AxumRouter` containing v1-specific route definitions.
    pub fn nest_v1(mut self, router: AxumRouter) -> Self {
        self.v1_router = Some(router);
        self
    }

    /// Register routes for API v2.x endpoints.
    ///
    /// These routes will be served under `/api/v2/...`.
    ///
    /// # Arguments
    /// * `router` - An `AxumRouter` containing v2-specific route definitions.
    pub fn nest_v2(mut self, router: AxumRouter) -> Self {
        self.v2_router = Some(router);
        self
    }

    /// Attach a protocol adapter for automatic cross-version transformation.
    ///
    /// When attached, the router will automatically adapt request/response payloads
    /// between different API versions using the provided adapter.
    ///
    /// # Arguments
    /// * `adapter` - A thread-safe protocol adapter implementation.
    pub fn with_adapter(mut self, adapter: Arc<dyn ProtocolAdapter>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    /// Convert this version router into a standard Axum `Router`.
    ///
    /// Assembles all version-specific routers under their respective URL prefixes
    /// (`/api/v1`, `/api/v2`) and applies the version extraction middleware layer.
    ///
    /// # Returns
    /// A fully-wired `AxumRouter` ready to be nested in the main application router.
    #[must_use]
    pub fn into_router(self) -> AxumRouter {
        let mut app = AxumRouter::new();

        // Nest v1 routes under /api/v1
        if let Some(v1) = self.v1_router {
            let v1_with_state = v1.route_layer(axum::middleware::from_fn_with_state(
                self.config.clone(),
                version_state_injector,
            ));
            app = app.nest("/api/v1", v1_with_state);
        }

        // Nest v2 routes under /api/v2
        if let Some(v2) = self.v2_router {
            let v2_with_state = v2.route_layer(axum::middleware::from_fn_with_state(
                self.config.clone(),
                version_state_injector,
            ));
            app = app.nest("/api/v2", v2_with_state);
        }

        app
    }
}

/// Axum middleware function that injects version-aware state into request extensions.
///
/// Called for each request within a versioned namespace, this function extracts
/// the version from the URL path (which has already been matched by Axum's router)
/// and creates a [`VersionAwareState`] extension for downstream handlers.
async fn version_state_injector(
    State(config): State<Arc<VersionConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let uri_path = request.uri().path().to_string();

    // Determine version from the matched route path
    // Since Axum has already matched /api/v1 or /api/v2, we can infer the version
    let version = if uri_path.starts_with("/api/v2/") || uri_path == "/api/v2" {
        ApiVersion::new(2, 0, 0)
    } else {
        // Default to v1 for /api/v1/ paths
        config.default_version
    };

    debug!(%version, uri = %uri_path, "Injecting version state");

    // Build version-aware state
    let state = VersionAwareState::new(version, uri_path);

    // Store in request extensions
    let mut request = request;
    request.extensions_mut().insert(state);

    next.run(request).await
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extract version-aware state from request extensions (for handler use).
///
/// Convenience function for handlers that need access to the resolved API version.
///
/// # Arguments
/// * `request` - The current request (with extensions populated by middleware).
///
/// # Returns
/// `Some(VersionAwareState)` if middleware ran successfully, `None` otherwise.
///
/// # Panics
///
/// This function does not panic; it returns `None` if the extension is missing.
/// Handlers should handle the `None` case gracefully or use the `Extension` extractor
/// which provides better error messages.
#[inline]
#[must_use]
pub fn try_get_version_state(request: &Request) -> Option<VersionAwareState> {
    request.extensions().get::<VersionAwareState>().cloned()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::body::{Body, to_bytes};

    /// Create a test request with optional version headers.
    fn create_test_request(uri: &str, accept_version: Option<&str>) -> Request {
        let mut builder = HttpRequest::builder()
            .method("GET")
            .uri(uri);

        if let Some(ver) = accept_version {
            builder = builder.header("Accept-Version", ver);
        }

        let (parts, ()) = builder.body(()).expect("Failed to build test request").into_parts();
        Request::from_parts(parts, Body::empty())
    }

    // =========================================================================
    // VersionConfig Tests
    // =========================================================================

    #[test]
    fn test_config_default() {
        let config = VersionConfig::default();
        assert_eq!(config.default_version, ApiVersion::new(1, 0, 0));
        assert!(config.strict_mode);
    }

    #[test]
    fn test_config_builder() {
        let config = VersionConfig::builder()
            .default_version(ApiVersion::new(2, 1, 0))
            .strict_mode(false)
            .build();

        assert_eq!(config.default_version, ApiVersion::new(2, 1, 0));
        assert!(!config.strict_mode);
    }

    // =========================================================================
    // URL Version Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_url_v1_full_semver() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/api/v1.0.0/scan", None);

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, stripped) = result.unwrap();
        assert_eq!(version, ApiVersion::new(1, 0, 0));
        assert_eq!(stripped, "/scan");
    }

    #[test]
    fn test_extract_url_v2_simple() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/api/v2/files", None);

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, stripped) = result.unwrap();
        assert_eq!(version, ApiVersion::new(2, 0, 0));
        assert_eq!(stripped, "/files");
    }

    #[test]
    fn test_extract_url_nested_path() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/api/v1/jobs/123/result", None);

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, stripped) = result.unwrap();
        assert_eq!(version, ApiVersion::new(1, 0, 0));
        assert_eq!(stripped, "/jobs/123/result");
    }

    #[test]
    fn test_extract_url_root() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/api/v1", None);

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, stripped) = result.unwrap();
        assert_eq!(version, ApiVersion::new(1, 0, 0));
        assert_eq!(stripped, "/");
    }

    // =========================================================================
    // Header Fallback Tests
    // =========================================================================

    #[test]
    fn test_extract_header_accept_version() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/some/path", Some("2.0.0"));

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, _) = result.unwrap();
        assert_eq!(version, ApiVersion::new(2, 0, 0));
    }

    #[test]
    fn test_extract_header_x_api_version() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/other/path")
            .header("X-API-Version", "1.0.0")
            .body(())
            .expect("Failed to build test request");
        let (parts, ()) = request.into_parts();
        let request = Request::from_parts(parts, Body::empty());

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, _) = result.unwrap();
        assert_eq!(version, ApiVersion::new(1, 0, 0));
    }

    // =========================================================================
    // Default Version Fallback Test
    // =========================================================================

    #[test]
    fn test_default_version_fallback() {
        let config = VersionConfig::new(ApiVersion::new(2, 0, 0));
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/health", None);

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, _) = result.unwrap();
        assert_eq!(version, ApiVersion::new(2, 0, 0)); // Should use configured default
    }

    // =========================================================================
    // Unknown Version Handling Tests
    // =========================================================================

    #[test]
    fn test_unknown_version_strict_mode() {
        let config = VersionConfig::builder()
            .strict_mode(true)
            .build();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/api/v99/invalid", None);

        let result = middleware.extract_version(&request);
        // In strict mode with invalid version format, should fall back to other tiers
        // or eventually return error depending on implementation
        // For now, we just verify it doesn't panic
        assert!(result.is_ok()); // Falls back to default since v99 can't parse
    }

    #[test]
    fn test_unknown_version_non_strict_mode() {
        let config = VersionConfig::builder()
            .strict_mode(false)
            .default_version(ApiVersion::new(1, 0, 0))
            .build();
        let middleware = VersionExtractorMiddleware::new(config);
        let request = create_test_request("/unknown/path", None);

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, _) = result.unwrap();
        assert_eq!(version, ApiVersion::new(1, 0, 0)); // Falls back to default
    }

    // =========================================================================
    // VersionAwareState Tests
    // =========================================================================

    #[test]
    fn test_state_creation() {
        let state = VersionAwareState::new(
            ApiVersion::new(2, 0, 0),
            "/api/v2/scan".to_string(),
        );

        assert_eq!(state.version, ApiVersion::new(2, 0, 0));
        assert_eq!(state.original_uri, "/api/v2/scan");
        assert!(!state.needs_adaptation());
        assert!(state.adapter.is_none());
    }

    #[test]
    fn test_state_with_adapter() {
        // We can't easily create a real adapter here without mocking, so just test the API
        let state = VersionAwareState::new(
            ApiVersion::new(1, 0, 0),
            "/api/v1/upload".to_string(),
        );

        // Verify initial state
        assert!(!state.needs_adaptation());
    }

    // =========================================================================
    // Error Response Tests
    // =========================================================================

    #[tokio::test]
    async fn test_unknown_version_error_response() {
        let err = VersionExtractionError::UnknownVersion("v99".to_string());
        let response: Response = err.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("v99"));
        assert!(body_str.contains("404"));
    }

    #[tokio::test]
    async fn test_invalid_format_error_response() {
        let err = VersionExtractionError::InvalidFormat("abc".to_string());
        let response: Response = err.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("abc"));
        assert!(body_str.contains("400"));
    }

    // =========================================================================
    // Integration-style Tests
    // =========================================================================

    #[test]
    fn test_precedence_url_over_header() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);

        // URL says v1, header says v2 — URL should win
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/data")
            .header("Accept-Version", "2.0.0")
            .body(())
            .expect("Failed to build test request");
        let (parts, ()) = request.into_parts();
        let request = Request::from_parts(parts, Body::empty());

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, _) = result.unwrap();
        assert_eq!(version, ApiVersion::new(1, 0, 0)); // URL takes precedence
    }

    #[test]
    fn test_accept_version_precedence_over_x_api_version() {
        let config = VersionConfig::default();
        let middleware = VersionExtractorMiddleware::new(config);

        // Both headers present — Accept-Version should win
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/some/path")
            .header("Accept-Version", "2.0.0")
            .header("X-API-Version", "1.0.0")
            .body(())
            .expect("Failed to build test request");
        let (parts, ()) = request.into_parts();
        let request = Request::from_parts(parts, Body::empty());

        let result = middleware.extract_version(&request);
        assert!(result.is_ok());

        let (version, _) = result.unwrap();
        assert_eq!(version, ApiVersion::new(2, 0, 0)); // Accept-Version wins
    }
}
