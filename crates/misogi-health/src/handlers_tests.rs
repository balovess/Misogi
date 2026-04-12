//! HTTP Handlers Tests — Test Suite for Kubernetes Probe Endpoints
//!
//! Contains all unit tests for [`crate::handlers`] HTTP endpoint implementations.
//! Separated from the main implementation to satisfy the 500-line-per-file policy.

use axum::extract::State;
use crate::checker::{HealthChecker, HealthCheckable};
use crate::handlers::{
    build_health_router, deep_health, liveness_probe, not_ready,
    readiness_probe, HealthState, LivenessResponse, ReadinessResponse,
};
use crate::types::{ComponentHealth, ComponentStatus, OverallHealth};
use std::sync::Arc;

// ===========================================================================
// Mock Components for Handler Testing
// ===========================================================================

/// Simple healthy mock for readiness probe testing.
struct HealthyMock;

impl HealthCheckable for HealthyMock {
    fn component_name(&self) -> &str {
        "healthy_component"
    }

    async fn check_health(&self) -> ComponentHealth {
        ComponentHealth::healthy(Some(1))
    }
}

/// Unhealthy mock to trigger 503 responses.
struct UnhealthyMock;

impl HealthCheckable for UnhealthyMock {
    fn component_name(&self) -> &str {
        "unhealthy_component"
    }

    async fn check_health(&self) -> ComponentHealth {
        ComponentHealth::unhealthy("simulated failure", None)
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[tokio::test]
async fn test_liveness_always_returns_200() {
    let response = liveness_probe().await;
    assert_eq!(response.status, "alive");
    assert!(!response.checked_at.is_empty());
}

#[tokio::test]
async fn test_readiness_healthy_returns_ok() {
    let checker = Arc::new(HealthChecker::with_timeout(1000));
    checker.register(Box::new(HealthyMock));

    let state = HealthState::new(checker);
    let result = readiness_probe(State(state)).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status, "ready");
    assert!(response.message.is_none());
}

#[tokio::test]
async fn test_readiness_unhealthy_returns_503() {
    let checker = Arc::new(HealthChecker::with_timeout(1000));
    checker.register(Box::new(UnhealthyMock));

    let state = HealthState::new(checker);
    let result = readiness_probe(State(state)).await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_deep_health_returns_full_status() {
    let checker = Arc::new(HealthChecker::with_timeout(1000));
    checker.register(Box::new(HealthyMock));
    checker.register(Box::new(UnhealthyMock));

    let state = HealthState::new(checker);
    let response = deep_health(State(state)).await;

    assert_eq!(response.overall, OverallHealth::Unhealthy);
    assert_eq!(response.checks_run, 2);
    assert!(response.components.contains_key("healthy_component"));
    assert!(response.components.contains_key("unhealthy_component"));
    assert_eq!(
        response.components.get("unhealthy_component").unwrap().status,
        ComponentStatus::Unhealthy
    );
}

#[tokio::test]
async fn test_not_ready_always_returns_503() {
    let (status, response) = not_ready().await;

    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.status, "not_ready");
    assert!(response.message.unwrap().contains("draining"));
}

#[test]
fn test_build_health_router_succeeds() {
    let checker = Arc::new(HealthChecker::new());
    let state = HealthState::new(checker);

    // Should not panic; returns valid Router
    let _router = build_health_router(state);
}

#[tokio::test]
async fn test_liveness_response_serialization_valid() {
    let response = liveness_probe().await;
    let json = serde_json::to_string(&response).unwrap();

    assert!(json.contains("\"status\":\"alive\""));
    assert!(json.contains("\"checked_at\""));
}

#[tokio::test]
async fn test_readiness_response_serialization_valid() {
    let checker = Arc::new(HealthChecker::with_timeout(1000));
    checker.register(Box::new(HealthyMock));

    let state = HealthState::new(checker);
    let result = readiness_probe(State(state)).await;

    if let Ok(response) = result {
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ready\""));
    }
}

#[tokio::test]
async fn test_deep_response_json_structure_complete() {
    let checker = Arc::new(HealthChecker::with_timeout(1000));
    checker.register(Box::new(HealthyMock));

    let state = HealthState::new(checker);
    let response = deep_health(State(state)).await;

    let json = serde_json::to_value(&response).unwrap();

    // Verify top-level fields exist
    assert!(json.get("overall").is_some());
    assert!(json.get("components").is_some());
    assert!(json.get("version").is_some());
    assert!(json.get("uptime_secs").is_some());
    assert!(json.get("timestamp").is_some());
    assert!(json.get("checks_run").is_some());

    // Verify nested component structure
    let components = json.get("components").unwrap().as_object().unwrap();
    assert!(components.contains_key("healthy_component"));

    let comp = components.get("healthy_component").unwrap();
    assert!(comp.get("status").is_some());
    assert!(comp.get("last_checked").is_some());
}

#[tokio::test]
async fn test_empty_checker_readiness_is_ready() {
    let checker = Arc::new(HealthChecker::new());
    let state = HealthState::new(checker);

    let result = readiness_probe(State(state)).await;
    // No components registered = ready by default (nothing to fail)
    assert!(result.is_ok());
}
