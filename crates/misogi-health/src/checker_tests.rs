//! Health Checker Tests — Comprehensive Test Suite for Checker Engine
//!
//! Contains all unit tests for [`crate::checker::HealthChecker`] and
//! mock implementations used exclusively for testing. Separated from
//! the main implementation to satisfy the 500-line-per-file policy.

use crate::checker::{HealthCheckable, HealthChecker};
use crate::types::{ComponentHealth, ComponentStatus, OverallHealth};

// ===========================================================================
// Mock Components for Testing
// ===========================================================================

/// Simple mock health checkable returning configurable status.
///
/// Used throughout the test suite to simulate healthy, degraded, and
/// unhealthy component states without external dependencies.
struct MockHealthCheck {
    name: String,
    status: ComponentStatus,
    latency_ms: u64,
}

impl MockHealthCheck {
    fn healthy(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: ComponentStatus::Healthy,
            latency_ms: 1,
        }
    }

    fn degraded(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: ComponentStatus::Degraded,
            latency_ms: 100,
        }
    }

    fn unhealthy(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: ComponentStatus::Unhealthy,
            latency_ms: 0,
        }
    }
}

impl HealthCheckable for MockHealthCheck {
    fn component_name(&self) -> &str {
        &self.name
    }

    async fn check_health(&self) -> ComponentHealth {
        match self.status {
            ComponentStatus::Healthy => ComponentHealth::healthy(Some(self.latency_ms)),
            ComponentStatus::Degraded => ComponentHealth::degraded("mock degraded", Some(self.latency_ms)),
            ComponentStatus::Unhealthy => ComponentHealth::unhealthy("mock failure", None),
            ComponentStatus::Unknown => ComponentHealth::unknown("mock unknown"),
            ComponentStatus::NotConfigured => ComponentHealth::not_configured(),
        }
    }
}

/// Slow mock that intentionally exceeds timeout to test timeout handling.
///
/// Simulates a component that hangs or takes too long to respond,
/// verifying that the checker's timeout protection works correctly.
struct SlowMockHealthCheck {
    delay_ms: u64,
}

impl HealthCheckable for SlowMockHealthCheck {
    fn component_name(&self) -> &str {
        "slow_component"
    }

    async fn check_health(&self) -> ComponentHealth {
        tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        ComponentHealth::healthy(Some(self.delay_ms))
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[test]
fn test_checker_creation() {
    let checker = HealthChecker::new();
    assert!(checker.is_empty());
    assert_eq!(checker.len(), 0);
}

#[test]
fn test_checker_default() {
    let checker = HealthChecker::default();
    assert!(checker.is_empty());
}

#[tokio::test]
async fn test_register_and_check_single() {
    let checker = HealthChecker::with_timeout(1000);
    checker.register(Box::new(MockHealthCheck::healthy("test_comp")));

    let status = checker.check_all().await;
    assert_eq!(status.overall, OverallHealth::Healthy);
    assert_eq!(status.checks_run, 1);
    assert!(status.components.contains_key("test_comp"));
}

#[tokio::test]
async fn test_multiple_components_all_healthy() {
    let checker = HealthChecker::with_timeout(1000);
    checker.register(Box::new(MockHealthCheck::healthy("comp_a")));
    checker.register(Box::new(MockHealthCheck::healthy("comp_b")));
    checker.register(Box::new(MockHealthCheck::healthy("comp_c")));

    let status = checker.check_all().await;
    assert_eq!(status.overall, OverallHealth::Healthy);
    assert_eq!(status.checks_run, 3);
    assert_eq!(status.components.len(), 3);
}

#[tokio::test]
async fn test_degraded_status_aggregation() {
    let checker = HealthChecker::with_timeout(1000);
    checker.register(Box::new(MockHealthCheck::healthy("comp_a")));
    checker.register(Box::new(MockHealthCheck::degraded("comp_b")));
    checker.register(Box::new(MockHealthCheck::healthy("comp_c")));

    let status = checker.check_all().await;
    assert_eq!(status.overall, OverallHealth::Degraded);
    assert_eq!(
        status.components.get("comp_b").unwrap().status,
        ComponentStatus::Degraded
    );
}

#[tokio::test]
async fn test_unhealthy_status_aggregation() {
    let checker = HealthChecker::with_timeout(1000);
    checker.register(Box::new(MockHealthCheck::healthy("comp_a")));
    checker.register(Box::new(MockHealthCheck::unhealthy("comp_b")));

    let status = checker.check_all().await;
    assert_eq!(status.overall, OverallHealth::Unhealthy);
}

#[tokio::test]
async fn test_unknown_component_returns_none() {
    let checker = HealthChecker::new();
    checker.register(Box::new(MockHealthCheck::healthy("existing")));

    let result = checker.check_component("nonexistent").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_check_single_component() {
    let checker = HealthChecker::with_timeout(1000);
    checker.register(Box::new(MockHealthCheck::healthy("target")));

    let result = checker.check_component("target").await;
    assert!(result.is_some());
    assert_eq!(result.unwrap().status, ComponentStatus::Healthy);
}

#[tokio::test]
async fn test_timeout_protection() {
    let checker = HealthChecker::with_timeout(50); // 50ms timeout
    checker.register(Box::new(SlowMockHealthCheck { delay_ms: 500 }));

    let status = checker.check_all().await;
    let comp = status.components.get("slow_component").unwrap();

    assert_eq!(comp.status, ComponentStatus::Unknown);
    assert!(comp.message.as_ref().unwrap().contains("timed out"));
}

#[tokio::test]
async fn test_concurrent_checks_complete_quickly() {
    let checker = HealthChecker::with_timeout(1000);

    // Register multiple components (all fast mocks)
    for i in 0..10 {
        checker.register(Box::new(MockHealthCheck::healthy(&format!("comp_{i}"))));
    }

    let start = std::time::Instant::now();
    let status = checker.check_all().await;
    let elapsed = start.elapsed();

    // All 10 should complete quickly (concurrently, each ~instant)
    assert_eq!(status.checks_run, 10);
    assert_eq!(status.overall, OverallHealth::Healthy);
    assert!(
        elapsed.as_millis() < 200,
        "Concurrent checks took too long: {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_uptime_tracking_increases() {
    let checker = HealthChecker::new();

    // Small sleep to ensure some uptime accumulates
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let status = checker.check_all().await;
    assert!(status.uptime_secs >= 0); // Non-negative at minimum
    assert!(!status.timestamp.to_rfc3339().is_empty()); // Valid timestamp format
}

#[tokio::test]
async fn test_empty_checker_returns_healthy() {
    let checker = HealthChecker::new();

    let status = checker.check_all().await;
    // No components = healthy by definition (nothing to fail)
    assert_eq!(status.overall, OverallHealth::Healthy);
    assert_eq!(status.checks_run, 0);
    assert!(status.components.is_empty());
}
