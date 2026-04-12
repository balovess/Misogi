//! Health Checker Engine — Component Registration and Concurrent Probing
//!
//! Implements the core health checking logic that:
//! 1. Maintains a registry of pluggable [`HealthCheckable`] components.
//! 2. Executes checks concurrently with timeout protection.
//! 3. Aggregates results into a unified [`crate::types::HealthStatus`].
//!
//! # Architecture
//!
//! ```text
//! HealthChecker
//! ├── registry: Arc<RwLock<Vec<Box<dyn HealthCheckable>>>>
//! └── start_time: Instant
//! ```
//!
//! # Thread Safety
//!
//! The checker uses `Arc<RwLock<>>` for the component registry, allowing
//! concurrent reads (during check execution) and exclusive writes (during
//! registration). Individual checks run via `tokio::spawn` with timeouts.
//!
//! # Built-in Checks
//!
//! See [`crate::built_in_checks`] module for feature-gated implementations
//! targeting auth, storage, and CDR subsystems.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use chrono::Utc;
use tokio::time::timeout;
use tracing::{debug, error, instrument, warn};

use crate::types::{ComponentHealth, ComponentStatus, HealthStatus, OverallHealth};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timeout per individual component health check (milliseconds).
pub const DEFAULT_CHECK_TIMEOUT_MS: u64 = 5000;

/// Maximum number of components that can be registered.
///
/// Prevents unbounded memory growth from misconfiguration or registration bugs.
/// Kubernetes deployments rarely exceed 20-30 components; 256 provides ample headroom.
pub const MAX_REGISTERED_COMPONENTS: usize = 256;

// ===========================================================================
// Health Checkable Trait
// ===========================================================================

/// Trait for components that can report their own health status.
///
/// Implementations perform an actual probe (e.g., database ping, HTTP request,
/// JWT validation) and return structured results. Each implementation MUST:
///
/// - Be `Send + Sync` for concurrent execution across async tasks.
/// - Complete within a reasonable time (ideally < 1 second).
/// - Return meaningful messages on failure for operator diagnostics.
///
/// # Example
///
/// ```ignore
/// struct DatabaseHealth {
///     pool: sqlx::PgPool,
/// }
///
/// impl HealthCheckable for DatabaseHealth {
///     fn component_name(&self) -> &str { "database" }
///
///     async fn check_health(&self) -> ComponentHealth {
///         let start = Instant::now();
///         match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
///             Ok(_) => ComponentHealth::healthy(Some(start.elapsed().as_millis() as u64)),
///             Err(e) => ComponentHealth::unhealthy(e.to_string(), None),
///         }
///     }
/// } ```
pub trait HealthCheckable: Send + Sync {
    /// Return the unique identifier for this component.
    ///
    /// Used as the key in [`HealthStatus::components`] map. Must be stable
    /// across restarts and DNS-safe (`[a-zA-Z0-9_-]`).
    fn component_name(&self) -> &str;

    /// Perform an actual health check against this component.
    ///
    /// Implementations should measure latency, catch errors gracefully,
    /// and return structured status. This method is called concurrently
    /// with other components' checks.
    ///
    /// # Returns
    ///
    /// A [`ComponentHealth`] containing status, optional message, latency,
    /// and timestamp.
    async fn check_health(&self) -> ComponentHealth;
}

// ===========================================================================
// Health Checker
// ===========================================================================

/// Central health monitoring engine for the Misogi system.
///
/// Manages a registry of [`HealthCheckable`] components, executes periodic
/// or on-demand checks, and produces aggregated [`HealthStatus`] reports.
///
/// # Lifecycle
///
/// 1. Create via [`HealthChecker::new()`] at application startup.
/// 2. Register components via [`HealthChecker::register()`] during init.
/// 3. Call [`HealthChecker::check_all()`] on demand (HTTP probes) or timer.
/// 4. Optionally query individual components via [`HealthChecker::check_component()`].
///
/// # Example
///
/// ```ignore
/// let checker = HealthChecker::new();
/// checker.register(Box::new(JwtValidatorHealthCheck::new(validator)));
/// checker.register(Box::new(DatabaseHealth { pool }));
///
/// // In HTTP handler:
/// let status = checker.check_all().await;
/// Json(status)
/// ```
pub struct HealthChecker {
    /// Registry of health-checkable components.
    ///
    /// Wrapped in `Arc<>` for cheap cloning; wrapped in `RwLock<>` for
    /// safe concurrent access during registration and checking.
    registry: Arc<RwLock<Vec<Box<dyn HealthCheckable>>>>,

    /// Monotonic instant when this checker was created (for uptime calc).
    start_time: Instant,

    /// Per-check timeout in milliseconds.
    check_timeout_ms: u64,
}

impl HealthChecker {
    /// Create a new empty health checker with default timeout (5s).
    ///
    /// Records the current instant as the startup time for uptime tracking.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
            check_timeout_ms: DEFAULT_CHECK_TIMEOUT_MS,
        }
    }

    /// Create a health checker with custom check timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout_ms` — Maximum milliseconds to wait for each component check.
    ///   Checks exceeding this duration are marked as `Unknown` (timeout).
    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            registry: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
            check_timeout_ms: timeout_ms,
        }
    }

    /// Register a health-checkable component into the checker.
    ///
    /// Components are checked in registration order. Duplicate names are
    /// allowed but will overwrite previous entries in the output map
    /// (last-write-wins semantics).
    ///
    /// # Panics
    ///
    /// Panics if more than [`MAX_REGISTERED_COMPONENTS`] are registered
    /// (prevents unbounded memory growth from misconfiguration).
    #[instrument(skip(self, component), fields(name = %component.component_name()))]
    pub fn register(&self, component: Box<dyn HealthCheckable>) {
        match self.registry.write() {
            Ok(mut guard) => {
                if guard.len() >= MAX_REGISTERED_COMPONENTS {
                    error!(
                        count = guard.len(),
                        max = MAX_REGISTERED_COMPONENTS,
                        "Component registration limit reached"
                    );
                    panic!("HealthChecker: exceeded maximum registered components ({MAX_REGISTERED_COMPONENTS})");
                }

                debug!(name = %component.component_name(), "Component registered");
                guard.push(component);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if guard.len() >= MAX_REGISTERED_COMPONENTS {
                    panic!("HealthChecker: exceeded maximum registered components ({MAX_REGISTERED_COMPONENTS})");
                }
                warn!("Registry lock poisoned during register, recovered");
                guard.push(component);
            }
        }
    }

    /// Execute health checks against all registered components concurrently.
    ///
    /// Snapshots the component list under a brief read lock, releases it,
    /// then spawns all checks as concurrent tasks with timeout protection.
    ///
    /// One failing component does NOT abort others; all results are collected
    /// and aggregated into the final [`HealthStatus`].
    ///
    /// # Returns
    ///
    /// Complete [`HealthStatus`] with overall status, per-component details,
    /// version info, uptime, and check count.
    #[instrument(skip(self))]
    pub async fn check_all(&self) -> HealthStatus {
        // Acquire read lock to snapshot component references
        let check_futures: Vec<_> = {
            match self.registry.read() {
                Ok(guard) => guard
                    .iter()
                    .map(|component| {
                        let name = component.component_name().to_string();
                        let timeout_dur = std::time::Duration::from_millis(self.check_timeout_ms);

                        async move {
                            let result = timeout(timeout_dur, component.check_health()).await;

                            match result {
                                Ok(health) => (name, health),
                                Err(_) => (
                                    name,
                                    ComponentHealth::unknown(format!(
                                        "check timed out after {}ms",
                                        self.check_timeout_ms
                                    )),
                                ),
                            }
                        }
                    })
                    .collect(),
                Err(poisoned) => {
                    let guard = poisoned.into_inner();
                    guard
                        .iter()
                        .map(|component| {
                            let name = component.component_name().to_string();
                            async move {
                                (
                                    name,
                                    ComponentHealth::unknown("registry lock poisoned"),
                                )
                            }
                        })
                        .collect()
                }
            }
        };

        // Execute all checks concurrently via join_all
        let results = futures::future::join_all(check_futures).await;

        // Build component map from results
        let mut components_map = HashMap::with_capacity(results.len());
        for (name, health) in results {
            components_map.insert(name, health);
        }

        // Compute overall health from component statuses
        let overall = OverallHealth::aggregate(&components_map);

        HealthStatus {
            overall,
            components: components_map,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            timestamp: Utc::now(),
            checks_run: components_map.len(),
        }
    }

    /// Execute health check for a single named component.
    ///
    /// Useful for targeted debugging or when only specific component
    /// status is needed (reduces overhead vs. full `check_all`).
    ///
    /// # Arguments
    ///
    /// * `name` — Component identifier matching [`HealthCheckable::component_name`]
    ///
    /// # Returns
    ///
    /// - `Some(ComponentHealth)` — Found and checked successfully.
    /// - `None` — No component with that name is registered.
    #[instrument(skip(self), fields(component_name = %name))]
    pub async fn check_component(&self, name: &str) -> Option<ComponentHealth> {
        let timeout_dur = std::time::Duration::from_millis(self.check_timeout_ms);

        // Brief read lock to find component; execute check under lock
        // (acceptable because check itself should be fast or we release after timeout)
        match self.registry.read() {
            Ok(guard) => {
                let found = guard.iter().find(|c| c.component_name() == name);

                if let Some(comp) = found {
                    let result = timeout(timeout_dur, comp.check_health()).await;

                    Some(match result {
                        Ok(health) => health,
                        Err(_) => ComponentHealth::unknown(format!(
                            "check timed out after {}ms",
                            self.check_timeout_ms
                        )),
                    })
                } else {
                    None
                }
            }
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                let found = guard.iter().find(|c| c.component_name() == name);

                found.map(|comp| comp.check_health().await.unwrap_or_else(|| {
                    ComponentHealth::unknown("lock poisoned during check")
                }))
            }
        }
    }

    /// Return the number of currently registered components.
    pub fn len(&self) -> usize {
        match self.registry.read() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Check whether any components are registered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

// Tests are in separate module to satisfy 500-line-per-file policy
#[cfg(test)]
mod tests;
