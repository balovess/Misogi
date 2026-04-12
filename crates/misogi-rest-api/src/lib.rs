//! # Misogi REST API -- Comprehensive Admin RESTful Interface
//!
//! This crate provides a production-grade HTTP REST API for the Misogi secure file
//! transfer system, built on [Axum 0.7](https://docs.rs/axum/0.7/axum/index.html)
//! with full OpenAPI 3.0 specification support.
//!
//! ## Architecture Overview
//!
//! ```text
//!   HTTP Client (Browser / CLI)
//!            |
//!           HTTPS
//!            |
//!   +--------v---------+
//!   |  Middleware Stack  |  (outermost -> innermost)
//!   |  [TraceLayer]     |
//!   |  -> [CorsLayer]   |
//!   |  -> [RateLimit]   |
//!   |  -> [AuthLayer]   |
//!   |                   |
//!   |  Router (/api/v1) |
//!   |  /files /scan     |
//!   |  /policies /audit |
//!   |  /health /metrics|
//!   +-------------------+
//! ```
//!
//! ## Feature Flags
//!
//! | Flag       | Description                                      | Default |
//! |------------|--------------------------------------------------|---------|
//! | `full`     | Enable all standard features                     | yes     |
//! | `openapi`  | Enable OpenAPI 3.0 spec generation + Swagger UI  | no      |
//!
//! ## Key Capabilities
//!
//! - **File Management**: Upload, list, retrieve, delete files with sanitization reports
//! - **Scan Orchestration**: Submit async scan jobs, poll status, download sanitized results
//! - **Policy CRUD**: Full lifecycle management for sanitization policies
//! - **Audit Logging**: Queryable audit trail with time-range and action-type filtering
//! - **Health Probes**: Kubernetes liveness (`/health/liveness`) and readiness (`/health/readiness`)
//! - **Prometheus Metrics**: Export `/metrics` endpoint in Prometheus text exposition format
//! - **Rate Limiting**: Per-API-key sliding-window rate limiter using [`DashMap`](dashmap::DashMap)
//! - **JWT Authentication**: Integration with [`misogi_auth::AuthEngine`](misogi_auth::middleware::AuthEngine)
//!
//! ## Quick Start
//!
//! ```ignore
//! use misogi_rest_api::{router::create_app, models::RestApiConfig};
//! use misogi_auth::middleware::AuthEngine;
//! use std::sync::Arc;
//!
//! let config = RestApiConfig::default();
//! let auth_engine = Arc::new(AuthEngine::new(jwt_config)?);
//! let app = create_app(config, auth_engine).await?;
//!
//! // Bind and serve
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//! axum::serve(listener, app).await?;
//! ```

// ---------------------------------------------------------------------------
// Public module declarations
// ---------------------------------------------------------------------------

/// Application router construction and Axum state management.
pub mod router;

/// Request handler implementations for each API resource group.
pub mod handlers;

/// Domain models, request/response types, and configuration structures.
///
/// All public types in this module derive `Serialize`, `Deserialize`,
/// and (when `openapi` feature is enabled) `ToSchema`.
pub mod models;

/// Centralized error type mapping to HTTP status codes with JSON error bodies.
pub mod error;

/// Sliding-window rate limiter backed by concurrent hash map.
pub mod rate_limit;

/// Prometheus-style metrics collector with atomic counters/gauges/histograms.   
pub mod metrics_ext;

/// Version-aware REST router middleware for multi-version API support.
///
/// Provides transparent version extraction from URL prefixes, HTTP headers,
/// and configurable defaults with [`ProtocolAdapter`] integration.
pub mod version_middleware;

// ---------------------------------------------------------------------------
// Re-exports: convenience access to core types
// ---------------------------------------------------------------------------

pub use error::ApiError;
pub use models::{
    AuditEntry, AuditQuery, ComponentHealth, CreatePolicyRequest,
    FileDetail, FileItem, HealthStatus, JobCreated, JobStatus,
    ListFilesQuery, PaginatedResponse, PolicyInfo, RestApiConfig,
    SanitizationReport, ScanRequest, ThreatDetail, UpdatePolicyRequest,
};
pub use version_middleware::{
    VersionConfig, VersionConfigBuilder, VersionExtractorMiddleware,
    VersionRouter, VersionAwareState, VersionExtractionError,
};
