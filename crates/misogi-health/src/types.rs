//! Health Status Types — Kubernetes-Compatible Component Health Model
//!
//! Defines the core data structures for representing system health in a
//! Kubernetes-compatible format. These types are used by both the health
//! checker engine and HTTP probe handlers.
//!
//! # Design Principles
//!
//! - **Kubernetes Compatibility**: Follows K8s probe conventions (liveness,
//!   readiness, startup) with structured JSON responses.
//! - **Component Granularity**: Each subsystem reports independent health,
//!   enabling degraded-but-operational states.
//! - **Serialization Safety**: All types derive `serde::Serialize` for JSON
//!   output; sensitive details are omitted from wire format.
//!
//! # Hierarchy
//!
//! ```text
//! HealthStatus (top-level)
//! ├── overall: OverallHealth
//! ├── components: HashMap<String, ComponentHealth>
//! ├── version: String
//! ├── uptime_secs: u64
//! ├── timestamp: DateTime<Utc>
//! └── checks_run: usize
//!
//! ComponentHealth (per-component)
//! ├── status: ComponentStatus
//! ├── message: Option<String>
//! ├── latency_ms: Option<u64>
//! └── last_checked: DateTime<Utc>
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// Overall Health Status
// ===========================================================================

/// Aggregate health status for the entire Misogi system.
///
/// Computed from individual component statuses using deterministic rules:
/// - `Healthy` — All critical components healthy, zero unhealthy components.
/// - `Degraded` — No unhealthy components, but at least one degraded/unknown.
/// - `Unhealthy` — One or more components in `Unhealthy` state.
///
/// # Serialization
///
/// Serializes to lowercase string (`"healthy"`, `"degraded"`, `"unhealthy"`)
/// for Kubernetes probe compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverallHealth {
    /// System fully operational; all components healthy.
    Healthy,

    /// System partially operational; some components degraded but functional.
    ///
    /// Service may continue serving requests with reduced capability.
    Degraded,

    /// System non-operational; one or more critical components failed.
    ///
    /// Kubernetes should restart the pod or remove from service pool.
    Unhealthy,
}

impl OverallHealth {
    /// Convert to string representation for logging and serialization.
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// Parse from string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "healthy" => Some(Self::Healthy),
            "degraded" => Some(Self::Degraded),
            "unhealthy" => Some(Self::Unhealthy),
            _ => None,
        }
    }

    /// Compute overall health from a collection of component statuses.
    ///
    /// # Rules
    ///
    /// 1. Any `Unhealthy` component → `Unhealthy` overall.
    /// 2. No `Unhealthy`, but any `Degraded` or `Unknown` → `Degraded`.
    /// 3. All `Healthy` or `NotConfigured` → `Healthy`.
    pub fn aggregate(components: &HashMap<String, ComponentHealth>) -> Self {
        let has_unhealthy = components.values().any(|c| {
            matches!(
                c.status,
                ComponentStatus::Unhealthy
            )
        });

        if has_unhealthy {
            return Self::Unhealthy;
        }

        let has_degraded = components.values().any(|c| {
            matches!(
                c.status,
                ComponentStatus::Degraded | ComponentStatus::Unknown
            )
        });

        if has_degraded {
            return Self::Degraded;
        }

        Self::Healthy
    }
}

impl std::fmt::Display for OverallHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ===========================================================================
// Component Status
// ===========================================================================

/// Health status of an individual component or dependency.
///
/// More granular than [`OverallHealth`] to support partial failure scenarios.
/// A component in `Degraded` state may still provide limited functionality
/// (e.g., LDAP working but slow, storage on reduced redundancy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    /// Component fully operational within normal parameters.
    Healthy,

    /// Component operational but exhibiting issues (high latency, warnings).
    ///
    /// Does NOT block traffic but should trigger operator alerting.
    Degraded,

    /// Component failed or unreachable; requests will fail.
    Unhealthy,

    /// Component status could not be determined (timeout, error during check).
    Unknown,

    /// Component not configured/disabled for this deployment.
    NotConfigured,
}

impl ComponentStatus {
    /// Convert to string representation.
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
            Self::NotConfigured => "not_configured",
        }
    }

    /// Check whether this status represents a healthy-ish state.
    ///
    /// Returns `true` for `Healthy` and `NotConfigured` (absence is not failure).
    #[inline]
    pub fn is_healthyish(&self) -> bool {
        matches!(self, Self::Healthy | Self::NotConfigured)
    }
}

impl std::fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ===========================================================================
// Component Health Detail
// ===========================================================================

/// Detailed health information for a single monitored component.
///
/// Produced by [`crate::checker::HealthCheckable`] implementations during each
/// check cycle. Contains timing data for SLO monitoring and human-readable
/// messages for debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Current status of this component.
    pub status: ComponentStatus,

    /// Human-readable description of current state (or error message).
    ///
    /// Present when status is not `Healthy`; omitted when healthy to reduce
    /// response size for frequent polling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Round-trip latency of the health check in milliseconds.
    ///
    /// `None` if latency was not measurable (e.g., in-process check).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,

    /// Timestamp when this component was last checked.
    pub last_checked: DateTime<Utc>,
}

impl ComponentHealth {
    /// Create a new healthy component status.
    pub fn healthy(latency_ms: Option<u64>) -> Self {
        Self {
            status: ComponentStatus::Healthy,
            message: None,
            latency_ms,
            last_checked: Utc::now(),
        }
    }

    /// Create a degraded component status with explanatory message.
    pub fn degraded(message: impl Into<String>, latency_ms: Option<u64>) -> Self {
        Self {
            status: ComponentStatus::Degraded,
            message: Some(message.into()),
            latency_ms,
            last_checked: Utc::now(),
        }
    }

    /// Create an unhealthy component status with error message.
    pub fn unhealthy(message: impl Into<String>, latency_ms: Option<u64>) -> Self {
        Self {
            status: ComponentStatus::Unhealthy,
            message: Some(message.into()),
            latency_ms,
            last_checked: Utc::now(),
        }
    }

    /// Create an unknown status (check timed out or errored).
    pub fn unknown(message: impl Into<String>) -> Self {
        Self {
            status: ComponentStatus::Unknown,
            message: Some(message.into()),
            latency_ms: None,
            last_checked: Utc::now(),
        }
    }

    /// Create a not-configured status (component disabled).
    pub fn not_configured() -> Self {
        Self {
            status: ComponentStatus::NotConfigured,
            message: None,
            latency_ms: None,
            last_checked: Utc::now(),
        }
    }
}

// ===========================================================================
// Top-Level Health Status
// ===========================================================================

/// Comprehensive health status report for the entire Misogi system.
///
/// Returned by [`crate::checker::HealthChecker::check_all`] and serialized as
/// JSON by the `/healthz/deep` endpoint. Contains enough detail for operators
/// to diagnose issues without accessing internal metrics.
///
/// # Example JSON Output
///
/// ```json
/// {
///   "overall": "healthy",
///   "components": {
///     "jwt_validator": { "status": "healthy", "latency_ms": 2 },
///     "identity_registry": { "status": "degraded", "message": "LDAP timeout" }
///   },
///   "version": "0.1.0",
///   "uptime_secs": 86400,
///   "timestamp": "2025-01-01T00:00:00Z",
///   "checks_run": 5
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Aggregate system health computed from all component statuses.
    pub overall: OverallHealth,

    /// Per-component health breakdown keyed by component name.
    pub components: HashMap<String, ComponentHealth>,

    /// Semantic version string from `CARGO_PKG_VERSION` at build time.
    pub version: String,

    /// Number of seconds since process start (monotonic clock).
    pub uptime_secs: u64,

    /// UTC timestamp when this health report was generated.
    pub timestamp: DateTime<Utc>,

    /// Number of component checks executed to produce this report.
    pub checks_run: usize,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_overall_health_serialization() {
        assert_eq!(serde_json::to_string(&OverallHealth::Healthy).unwrap(), "\"healthy\"");
        assert_eq!(serde_json::to_string(&OverallHealth::Degraded).unwrap(), "\"degraded\"");
        assert_eq!(serde_json::to_string(&OverallHealth::Unhealthy).unwrap(), "\"unhealthy\"");
    }

    #[test]
    fn test_component_status_serialization() {
        assert_eq!(
            serde_json::to_string(&ComponentStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&ComponentStatus::NotConfigured).unwrap(),
            "\"not_configured\""
        );
    }

    #[test]
    fn test_overall_health_aggregate_all_healthy() {
        let mut components = HashMap::new();
        components.insert("a".to_string(), ComponentHealth::healthy(Some(1)));
        components.insert("b".to_string(), ComponentHealth::healthy(Some(2)));

        assert_eq!(OverallHealth::aggregate(&components), OverallHealth::Healthy);
    }

    #[test]
    fn test_overall_health_aggregate_with_degraded() {
        let mut components = HashMap::new();
        components.insert("a".to_string(), ComponentHealth::healthy(Some(1)));
        components.insert(
            "b".to_string(),
            ComponentHealth::degraded("slow response", Some(500)),
        );

        assert_eq!(OverallHealth::aggregate(&components), OverallHealth::Degraded);
    }

    #[test]
    fn test_overall_health_aggregate_with_unhealthy() {
        let mut components = HashMap::new();
        components.insert("a".to_string(), ComponentHealth::healthy(Some(1)));
        components.insert(
            "b".to_string(),
            ComponentHealth::unhealthy("connection refused", None),
        );

        assert_eq!(
            OverallHealth::aggregate(&components),
            OverallHealth::Unhealthy
        );
    }

    #[test]
    fn test_component_health_constructors() {
        let healthy = ComponentHealth::healthy(Some(10));
        assert_eq!(healthy.status, ComponentStatus::Healthy);
        assert_eq!(healthy.latency_ms, Some(10));
        assert!(healthy.message.is_none());

        let degraded = ComponentHealth::degraded("high latency", Some(200));
        assert_eq!(degraded.status, ComponentStatus::Degraded);
        assert_eq!(degraded.message, Some("high latency".to_string()));

        let unhealthy = ComponentHealth::unhealthy("error", None);
        assert_eq!(unhealthy.status, ComponentStatus::Unhealthy);

        let unknown = ComponentHealth::unknown("timeout");
        assert_eq!(unknown.status, ComponentStatus::Unknown);

        let not_configured = ComponentHealth::not_configured();
        assert_eq!(not_configured.status, ComponentStatus::NotConfigured);
    }

    #[test]
    fn test_component_status_is_healthyish() {
        assert!(ComponentStatus::Healthy.is_healthyish());
        assert!(ComponentStatus::NotConfigured.is_healthyish());
        assert!(!ComponentStatus::Degraded.is_healthyish());
        assert!(!ComponentStatus::Unhealthy.is_healthyish());
        assert!(!ComponentStatus::Unknown.is_healthyish());
    }

    #[test]
    fn test_health_status_serialization_roundtrip() {
        let mut components = HashMap::new();
        components.insert("test".to_string(), ComponentHealth::healthy(Some(5)));

        let status = HealthStatus {
            overall: OverallHealth::Healthy,
            components,
            version: "0.1.0".to_string(),
            uptime_secs: 3600,
            timestamp: Utc::now(),
            checks_run: 1,
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: HealthStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.overall, OverallHealth::Healthy);
        assert_eq!(deserialized.version, "0.1.0");
        assert_eq!(deserialized.checks_run, 1);
    }

    #[test]
    fn test_overall_health_from_str() {
        assert_eq!(OverallHealth::from_str("healthy"), Some(OverallHealth::Healthy));
        assert_eq!(OverallHealth::from_str("DEGRADED"), Some(OverallHealth::Degraded));
        assert_eq!(OverallHealth::from_str("UnHealthy"), Some(OverallHealth::Unhealthy));
        assert_eq!(OverallHealth::from_str("invalid"), None);
    }

    #[test]
    fn test_display_traits() {
        assert_eq!(format!("{}", OverallHealth::Healthy), "healthy");
        assert_eq!(format!("{}", ComponentStatus::Degraded), "degraded");
    }
}
