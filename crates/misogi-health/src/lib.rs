//! Misogi Health Monitoring — Kubernetes-Compatible System Health Probes
//!
//! Provides a comprehensive, production-ready health monitoring system for the
//! Misogi secure file transfer platform. Implements standard Kubernetes probe
//! endpoints with deep component-level status reporting.
//!
//! # Architecture
//!
//! ```text
//! misogi-health
//! ├── types.rs           — Health status data models (serde-compatible)
//! ├── checker.rs         — Health check engine with component registry
//! ├── built_in_checks.rs — Built-in implementations (feature-gated)
//! ├── handlers.rs        — HTTP endpoint handlers (feature-gated: `http`)
//! └── *_tests.rs        — Comprehensive test suites (separated for line limits)
//! ```
//!
//! # Features
//!
//! | Feature     | Description                              | Default |
//! |-------------|------------------------------------------|---------|
//! | (none)      | Core types + checker engine only         | Yes     |
//! | `http`      | Axum HTTP handlers for K8s probes        | No      |
//! | `full`      | All features including HTTP              | No      |
//!
//! # Quick Start (Library Usage)
//!
//! ```ignore
//! use misogi_health::checker::{HealthChecker, HealthCheckable};
//! use misogi_health::types::{ComponentHealth, ComponentStatus};
//!
//! // Create checker and register components
//! let checker = HealthChecker::new();
//! checker.register(Box::new(MyDatabaseCheck::new(pool)));
//!
//! // Execute health checks
//! let status = checker.check_all().await;
//! assert_eq!(status.overall, OverallHealth::Healthy);
//! ```
//!
//! # Quick Start (HTTP Integration)
//!
//! ```ignore
//! use misogi_health::handlers::{HealthState, build_health_router};
//! use std::sync::Arc;
//!
//! let state = HealthState::new(Arc::new(checker));
//! let health_routes = build_health_router(state);
//!
//! // Merge into main Axum app
//! let app = axum::Router::new().merge(health_routes);
//!
//! // Endpoints available:
//! // GET /healthz       — Liveness probe (always 200)
//! // GET /readyz        — Readiness probe (checks components)
//! // GET /healthz/deep  — Full JSON with all details
//! ```
//!
//! # Kubernetes Integration
//!
//! Configure your deployment with standard probes:
//!
//! ```yaml
//! livenessProbe:
//!   httpGet:
//!     path: /healthz
//!     port: 8080
//!   initialDelaySeconds: 15
//!   periodSeconds: 20
//!
//! readinessProbe:
//!   httpGet:
//!     path: /readyz
//!     port: 8080
//!   initialDelaySeconds: 5
//!   periodSeconds: 10
//! ```

// ===========================================================================
// Public Module Exports
// ===========================================================================

/// Core type definitions for health status representation.
///
/// Includes [`OverallHealth`](types::OverallHealth), [`ComponentStatus`](types::ComponentStatus),
/// [`ComponentHealth`](types::ComponentHealth), and [`HealthStatus`](types::HealthStatus).
pub mod types;

/// Health checking engine with pluggable component registry.
///
/// Includes [`HealthChecker`](checker::HealthChecker), [`HealthCheckable`](checker::HealthCheckable) trait,
/// and built-in check implementations (when features are enabled).
pub mod checker;

/// Built-in health check implementations for core Misogi subsystems.
///
/// Feature-gated concrete implementations of [`HealthCheckable`] targeting:
/// - JWT validator (`misogi-auth` feature)
/// - Identity provider registry (`misogi-auth` feature)
/// - Storage backend (`misogi-core` feature)
/// - CDR parser registry (`misogi-cdr` feature)
pub mod built_in_checks;

/// HTTP endpoint handlers for Kubernetes-style probes.
///
/// Only available when the `http` feature is enabled. Provides:
/// - [`liveness_probe`](handlers::liveness_probe) — `/healthz`, `/livez`
/// - [`readiness_probe`](handlers::readiness_probe) — `/readyz`
/// - [`deep_health`](handlers::deep_health) — `/healthz/deep`
/// - [`build_health_router`](handlers::build_health_router) — Route assembly helper
#[cfg(feature = "http")]
pub mod handlers;

// ===========================================================================
// Re-exports for Convenience
// ===========================================================================

// Re-export core types at crate root for ergonomic imports
pub use types::{
    ComponentHealth, ComponentStatus, HealthStatus, OverallHealth,
};

// Re-export checker components
pub use checker::{
    HealthChecker, HealthCheckable, DEFAULT_CHECK_TIMEOUT_MS, MAX_REGISTERED_COMPONENTS,
};

// Re-export built-in checks when available
#[cfg(feature = "misogi-auth")]
pub use built_in_checks::{
    IdentityRegistryHealthCheck, JwtValidatorHealthCheck,
};

#[cfg(feature = "misogi-core")]
pub use built_in_checks::StorageBackendHealthCheck;

#[cfg(feature = "misogi-cdr")]
pub use built_in_checks::ParserRegistryHealthCheck;

// Re-export HTTP handlers when http feature is enabled
#[cfg(feature = "http")]
pub use handlers::{
    build_health_router, deep_health, liveness_probe, not_ready,
    readiness_probe, HealthState, LivenessResponse, ReadinessResponse,
};
