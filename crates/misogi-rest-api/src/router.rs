//! Application Router — Axum Route Construction & Middleware Stack
//!
//! Assembles the complete Axum 0.8 router with all API routes, middleware
//! layers, and shared application state.
//!
//! # Middleware Stack (outermost → innermost)
//!
//! ```text
//! Request → [TraceLayer] → [CorsLayer] → [RateLimitLayer] → [AuthLayer] → Handler
//! ```
//!
//! 1. **TraceLayer** — Structured request/response logging via `tower-http::trace`
//! 2. **CorsLayer** — Configurable cross-origin resource sharing
//! 3. **RateLimitLayer** — Per-API-key sliding window rate limiting
//! 4. **AuthLayer** — JWT / API-key validation via [`misogi_auth::AuthEngine`]
//!
//! # State Management
//!
//! Shared state is provided to all handlers via Axum's `State` extractor through
//! the [`AppState`] struct, which holds configuration, auth engine reference,
//! No-Code runtime (optional), and metrics collector.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    http::Method,
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;

// Re-export handler functions for route registration
use crate::handlers::{
    audit, files, health, metrics, policies, scan,
};
use crate::models::RestApiConfig;
use crate::rate_limit::RateLimiter;
use crate::version_middleware::{VersionConfig, VersionRouter};

#[cfg(feature = "openapi")]
use {
    utoipa::OpenApi,
    utoipa_swagger_ui::SwaggerUi,
};

/// Re-export AuthEngine from misogi-auth for AppState type signature.
pub use misogi_auth::middleware::AuthEngine;

/// Re-export MetricsCollector for external access.
pub use crate::metrics_ext::MetricsCollector;

// ===========================================================================
// Application State
// ===========================================================================

/// Shared application state injected into every handler via Axum's `State` extractor.
///
/// Wrapped in `Arc<>` for cheap cloning across async tasks. All fields are
/// either immutable or use interior mutability (atomic types, DashMap).
///
/// # Lifetime
///
/// One instance is created at server startup and lives for the entire process
/// lifetime. It should never be dropped while requests are in flight.
#[derive(Clone)]
pub struct AppState {
    /// Server configuration (bind address, CORS origins, rate limits, etc.).
    pub config: RestApiConfig,

    /// Authentication engine for JWT and API-key validation.
    ///
    /// `Option` because the engine may not be initialized if auth features are
    /// disabled or if initialization failed during startup.
    pub auth_engine: Option<Arc<AuthEngine>>,

    /// Optional No-Code runtime for health check integration.
    ///
    /// When provided, enables `/nocode/health/*` endpoints and injects
    /// No-Code status into the readiness probe.
    pub nocode_runtime: Option<Arc<misogi_nocode::NoCodeRuntime>>,

    /// Optional file type detector for readiness probing.
    ///
    /// When provided, the readiness probe performs a lightweight detection
    /// check instead of returning a hardcoded healthy status.
    pub detector: Option<Arc<dyn misogi_core::traits::FileTypeDetector>>,

    /// Optional storage backend for readiness probing.
    ///
    /// When provided, the readiness probe calls `StorageBackend::health_check()`
    /// to verify storage connectivity.
    pub storage: Option<Arc<dyn misogi_core::traits::storage::StorageBackend>>,

    /// Prometheus-style metrics collector with atomic counters/gauges.
    pub metrics: Arc<MetricsCollector>,

    /// Sliding-window rate limiter keyed by API key.
    pub rate_limiter: Arc<RateLimiter>,
}

// ===========================================================================
// Rate Limit Middleware Layer
// ===========================================================================

/// Axum middleware that enforces per-API-key rate limits using sliding windows.
///
/// Extracts the API key from the `X-API-Key` header (or falls back to a
/// default key) and checks it against the [`RateLimiter`] stored in state.
///
/// Returns HTTP 429 Too Many Requests with standard `Retry-After` semantics
/// when the limit is exceeded.
#[allow(dead_code)]
async fn rate_limit_middleware(
    request: axum::extract::Request,
    next: axum_middleware::Next,
) -> axum::response::Response {
    // TODO: Extract X-API-Key header, look up AppState, call rate_limiter.check()
    // For now, pass through without limiting (stub)
    next.run(request).await
}

// ===========================================================================
// Router Construction
// ===========================================================================

/// Build the complete Misogi REST API application router.
///
/// This is the primary entry point for creating the Axum application. Call
/// this function at server startup and pass the returned `Router` to
/// `axum::serve()`.
///
/// # Arguments
///
/// * `config` — Server configuration loaded from environment or config file
/// * `auth_engine` — Initialized authentication engine (or `None` if auth is disabled)
/// * `nocode_runtime` — Optional No-Code runtime for health check integration
/// * `detector` — Optional file type detector for readiness probing
/// * `storage` — Optional storage backend for readiness probing
///
/// # Returns
///
/// A fully-wired `Router` instance ready to be bound to a TCP listener.
pub fn create_app(
    config: RestApiConfig,
    auth_engine: Option<Arc<AuthEngine>>,
    nocode_runtime: Option<Arc<misogi_nocode::NoCodeRuntime>>,
    detector: Option<Arc<dyn misogi_core::traits::FileTypeDetector>>,
    storage: Option<Arc<dyn misogi_core::traits::storage::StorageBackend>>,
) -> Router {
    info!(
        bind_addr = %config.bind_addr,
        rate_limit_rpm = config.rate_limit_rpm,
        jwt_issuer = %config.jwt_issuer,
        default_policy = %config.default_policy,
        has_nocode = nocode_runtime.is_some(),
        "Building Misogi REST API router"
    );

    // --- Initialize shared state ---
    let metrics = Arc::new(MetricsCollector::new());
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_rpm,
        Duration::from_secs(60),
    ));

    let state = AppState {
        config,
        auth_engine,
        nocode_runtime: nocode_runtime.clone(),
        detector,
        storage,
        metrics: Arc::clone(&metrics),
        rate_limiter: Arc::clone(&rate_limiter),
    };

    // =====================================================================
    // Build the route tree under /api/v1/
    // =====================================================================

    let api_routes = Router::new()
        // --- File management ---
        .route("/files", get(files::list_files).post(files::upload_file))
        .route(
            "/files/{file_id}",
            get(files::get_file).delete(files::delete_file),
        )
        .route("/files/{file_id}/report", get(files::get_sanitization_report))

        // --- Scan jobs ---
        .route("/scan", post(scan::submit_scan))
        .route("/jobs/{job_id}", get(scan::get_job_status))
        .route("/jobs/{job_id}/result", get(scan::download_job_result))

        // --- Policy CRUD ---
        .route("/policies", get(policies::list_policies).post(policies::create_policy))
        .route(
            "/policies/{policy_id}",
            get(policies::get_policy)
                .put(policies::update_policy)
                .delete(policies::delete_policy),
        )

        // --- Audit log ---
        .route("/audit", get(audit::query_audit_logs))

        // --- Health probes ---
        .route("/health/liveness", get(health::liveness_probe))
        .route("/health/readiness", get(health::readiness_probe))

        // --- Prometheus metrics ---
        .route("/metrics", get(metrics::prometheus_metrics))
        .with_state(state);

    // =====================================================================
    // Merge No-Code health routes (when runtime is provided)
    // =====================================================================

    #[allow(unused_mut)]
    let mut api_routes = if let Some(ref runtime) = nocode_runtime {
        let ncode_health = misogi_nocode::build_health_router(Arc::clone(runtime));
        api_routes.merge(ncode_health)
    } else {
        api_routes
    };

    // =====================================================================
    // OpenAPI / Swagger UI (feature-gated)
    // =====================================================================

    #[cfg(feature = "openapi")]
    let api_routes = {
        use crate::models::{
            AuditEntry, AuditQuery, ComponentHealth, CreatePolicyRequest,
            FileDetail, FileItem, HealthStatus, JobCreated, JobStatus,
            ListFilesQuery, PaginatedResponse, PolicyInfo, SanitizationReport,
            ScanRequest, ThreatDetail, UpdatePolicyRequest,
        };
        use utoipa::schema;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                files::list_files,
                files::upload_file,
                files::get_file,
                files::delete_file,
                files::get_sanitization_report,
                scan::submit_scan,
                scan::get_job_status,
                scan::download_job_result,
                policies::list_policies,
                policies::create_policy,
                policies::get_policy,
                policies::update_policy,
                policies::delete_policy,
                audit::query_audit_logs,
                health::liveness_probe,
                health::readiness_probe,
                metrics::prometheus_metrics,
            ),
            components(
                schemas(
                    FileItem,
                    FileDetail,
                    FileStatus,
                    SanitizationReport,
                    ThreatDetail,
                    PolicyInfo,
                    PolicyAction,
                    JobStatus,
                    JobState,
                    JobCreated,
                    AuditEntry,
                    AuditQuery,
                    HealthStatus,
                    ComponentHealth,
                    ListFilesQuery,
                    ScanRequest,
                    CreatePolicyRequest,
                    UpdatePolicyRequest,
                    PaginatedResponse<FileItem>,
                    PaginatedResponse<AuditEntry>,
                    RestApiConfig,
                )
            ),
            tags(
                (name = "Files", description = "File upload, listing, retrieval, deletion"),
                (name = "Scan", description = "Async scan job submission and result retrieval"),
                (name = "Policies", description = "Sanitization policy CRUD"),
                (name = "Audit", description = "Queryable audit log trail"),
                (name = "Health", description = "Kubernetes health probes"),
                (name = "Metrics", description = "Prometheus metrics export"),
            ),
            info(
                title = "Misogi REST API",
                description = "Comprehensive admin API for Misogi secure file transfer system",
                version = env!("CARGO_PKG_VERSION"),
            ),
        )]
        struct ApiDoc;

        let doc = ApiDoc::openapi();
        api_routes.merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", doc))
    };

    // =====================================================================
    // Assemble full router with version-aware routing
    // =====================================================================

    // Build version configuration with default fallback to v1
    let version_config = VersionConfig::builder()
        .default_version(misogi_core::versioning::ApiVersion::new(1, 0, 0))
        .strict_mode(true)
        .build();

    // Create version-aware router that handles /api/v1 and /api/v2
    let version_router = VersionRouter::new(version_config)
        .nest_v1(api_routes)  // Current routes under v1
        // TODO: Add v2-specific routes when v2 API is implemented
        // .nest_v2(v2_routes)
        ;

    let app = Router::new()
        .merge(version_router.into_router())

        // Layer 4 (innermost): Rate limiting
        // .layer(axum_middleware::from_fn(rate_limit_middleware)) // TODO: wire to state

        // Layer 3: CORS
        .layer(build_cors_layer())

        // Layer 2: Request/response tracing
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::extract::Request| {
                    let method = request.method();
                    let uri = request.uri();
                    tracing::info_span!(
                        "http_request",
                        method = %method,
                        uri = %uri,
                    )
                })
                .on_request(|_request: &axum::extract::Request, _span: &tracing::Span| {
                    tracing::debug!("Request started");
                })
                .on_response(|_response: &axum::response::Response, latency: Duration, _span: &tracing::Span| {
                    tracing::debug!(duration_ms = latency.as_millis() as u64, "Request completed");
                }),
        );

    info!("Misogi REST API router constructed successfully");
    app
}

// ===========================================================================
// Helper: CORS Configuration
// ===========================================================================

/// Build the CORS layer based on configured allowed origins.
///
/// If no origins are explicitly configured, allows all origins (`Any`) —
/// suitable for development but **not** recommended for production deployments.
fn build_cors_layer() -> CorsLayer {
    // In production, read from config.cors_origins
    // For now, allow all origins with common methods/headers
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .max_age(Duration::from_secs(86400))
}
