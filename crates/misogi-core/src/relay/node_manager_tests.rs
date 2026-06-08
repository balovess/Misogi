// ===========================================================================
// Unit Tests — RelayNodeManager
// ===========================================================================
//
// Comprehensive test suite covering node lifecycle, health propagation,
// circuit breaker state machine transitions, and availability queries.

use super::super::{config::*, node::*, topology::*};
use super::*;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn make_edge_node(id: &str) -> RelayNode {
    RelayNode::new(id, NodeRole::Edge,
        EndpointConfig::new("tls", "10.0.0.1", 8443), 1,
        CapacityLimits::new(500, 10_000))
}

fn make_hub_node(id: &str) -> RelayNode {
    RelayNode::new(id, NodeRole::Hub,
        EndpointConfig::new("tls", "10.0.0.100", 9443), 3,
        CapacityLimits::new(5000, 100_000))
}

// ===========================================================================
// 1. Registration / Deregistration
// ===========================================================================

#[test]
fn test_register_node_successfully() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    assert!(mgr.register_node(make_edge_node("edge-tokyo-01")).is_ok());
    assert_eq!(mgr.node_count(), 1);
    assert!(mgr.is_available("edge-tokyo-01"));
    assert_eq!(mgr.failure_count("edge-tokyo-01"), Some(0));
}

#[test]
fn test_register_duplicate_node_id_fails() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    assert!(mgr.register_node(make_edge_node("dup-id")).is_ok());

    let result = mgr.register_node(make_edge_node("dup-id"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("duplicate"));
    assert_eq!(mgr.node_count(), 1); // Original still present.
}

#[test]
fn test_unregister_existing_node_returns_it() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("to-remove")).unwrap();

    let removed = mgr.unregister_node("to-remove");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().node_id, "to-remove");
    assert_eq!(mgr.node_count(), 0);
    assert_eq!(mgr.failure_count("to-remove"), None);
}

#[test]
fn test_unregister_nonexistent_node_returns_none() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    assert!(mgr.unregister_node("ghost").is_none());
}

#[test]
fn test_unregister_cleans_up_tracking_state() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("cleanup-target")).unwrap();
    mgr.report_failure("cleanup-target");
    mgr.report_failure("cleanup-target");
    assert_eq!(mgr.failure_count("cleanup-target"), Some(2));

    assert!(mgr.unregister_node("cleanup-target").is_some());
    assert_eq!(mgr.failure_count("cleanup-target"), None);
}

// ===========================================================================
// 2. Health Management
// ===========================================================================

#[test]
fn test_health_update_to_healthy_resets_counters() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("health-reset")).unwrap();
    mgr.report_failure("health-reset");
    mgr.report_failure("health-reset");
    assert_eq!(mgr.failure_count("health-reset"), Some(2));

    mgr.update_node_health("health-reset", HealthStatus::Healthy).unwrap();
    assert_eq!(mgr.failure_count("health-reset"), Some(0));
    assert_eq!(mgr.circuit_breaker("health-reset").unwrap(), CircuitState::Closed);
}

#[test]
fn test_health_update_to_unhealthy_increments_counter() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("degrade-me")).unwrap();
    assert_eq!(mgr.failure_count("degrade-me"), Some(0));

    mgr.update_node_health("degrade-me", HealthStatus::Unhealthy).unwrap();
    assert_eq!(mgr.failure_count("degrade-me"), Some(1));

    mgr.update_node_health("degrade-me", HealthStatus::Degraded).unwrap();
    assert_eq!(mgr.failure_count("degrade-me"), Some(2));
}

#[test]
fn test_health_update_unknown_node_returns_error() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    let result = mgr.update_node_health("ghost", HealthStatus::Healthy);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

// ===========================================================================
// 3. Circuit Breaker State Machine
// ===========================================================================

#[test]
fn test_circuit_breaker_trips_at_threshold() {
    let cfg = RelayConfig::builder().circuit_breaker_threshold(2).build();
    let mut mgr = RelayNodeManager::new(cfg);
    mgr.register_node(make_edge_node("trip-target")).unwrap();

    mgr.report_failure("trip-target"); // count=1 < threshold
    assert_eq!(mgr.circuit_breaker("trip-target").unwrap(), CircuitState::Closed);

    mgr.report_failure("trip-target"); // count=2 >= threshold => trip
    assert_eq!(mgr.circuit_breaker("trip-target").unwrap(), CircuitState::Open);
    assert!(!mgr.is_available("trip-target"));
}

#[test]
fn test_circuit_breaker_threshold_zero_disables_tripping() {
    let cfg = RelayConfig::builder().circuit_breaker_threshold(0).build();
    let mut mgr = RelayNodeManager::new(cfg);
    mgr.register_node(make_edge_node("no-trip")).unwrap();
    for _ in 0..10 { mgr.report_failure("no-trip"); }
    assert_eq!(mgr.circuit_breaker("no-trip").unwrap(), CircuitState::Closed);
}

#[test]
fn test_circuit_breaker_halfopen_to_closed_on_success() {
    let cfg = RelayConfig::builder()
        .circuit_breaker_threshold(1)
        .heartbeat_interval_secs(0) // Instant cooldown for testing.
        .build();
    let mut mgr = RelayNodeManager::new(cfg);
    mgr.register_node(make_edge_node("recover-node")).unwrap();

    mgr.report_failure("recover-node"); // Trip.
    assert_eq!(mgr.circuit_breaker("recover-node").unwrap(), CircuitState::Open);

    // Cooldown=0 => immediate HalfOpen transition on next call.
    assert_eq!(mgr.circuit_breaker("recover-node").unwrap(), CircuitState::HalfOpen);

    mgr.report_success("recover-node"); // Probe success => close.
    assert_eq!(mgr.circuit_breaker("recover-node").unwrap(), CircuitState::Closed);
}

#[test]
fn test_circuit_breaker_halfopen_failure_reopens() {
    let cfg = RelayConfig::builder()
        .circuit_breaker_threshold(1)
        .heartbeat_interval_secs(0)
        .build();
    let mut mgr = RelayNodeManager::new(cfg);
    mgr.register_node(make_edge_node("reopen-node")).unwrap();

    mgr.report_failure("reopen-node"); // Trip -> Open.
    mgr.circuit_breaker("reopen-node").unwrap(); // Open -> HalfOpen.

    mgr.report_failure("reopen-node"); // Failure in HalfOpen => re-open.
    assert_eq!(mgr.circuit_breaker("reopen-node").unwrap(), CircuitState::Open);
}

#[test]
fn test_circuit_breaker_unknown_node_returns_error() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    let result = mgr.circuit_breaker("ghost");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no circuit breaker entry"));
}

// ===========================================================================
// 4. Node Selection Queries
// ===========================================================================

#[test]
fn test_get_healthy_nodes_filters_unhealthy_and_open() {
    let mut mgr = RelayNodeManager::new(RelayConfig::builder()
        .circuit_breaker_threshold(1).build());

    mgr.register_node(make_edge_node("healthy-a")).unwrap();
    mgr.register_node(make_edge_node("unhealthy-b")).unwrap();
    mgr.register_node(make_edge_node("tripped-c")).unwrap();

    mgr.update_node_health("unhealthy-b", HealthStatus::Unhealthy).unwrap();
    mgr.report_failure("tripped-c"); // Trip c's circuit breaker.

    let healthy = mgr.get_healthy_nodes();
    assert_eq!(healthy.len(), 1);
    assert_eq!(healthy[0].node_id, "healthy-a");
}

#[test]
fn test_get_healthy_nodes_sorted_by_tier_ascending() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_hub_node("hub-first")).unwrap();   // tier=3
    mgr.register_node(make_edge_node("edge-second")).unwrap(); // tier=1
    mgr.register_node(make_hub_node("hub-third")).unwrap();   // tier=3

    let healthy = mgr.get_healthy_nodes();
    assert_eq!(healthy.len(), 3);
    assert_eq!(healthy[0].tier, 1); // Edge first.
    assert_eq!(healthy[1].tier, 3); // Hubs after.
    assert_eq!(healthy[2].tier, 3);
}

#[test]
fn test_get_routable_nodes_excludes_unhealthy_only() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("routable-healthy")).unwrap();
    mgr.register_node(make_edge_node("routable-degraded")).unwrap();
    mgr.register_node(make_edge_node("routable-unhealthy")).unwrap();

    mgr.update_node_health("routable-degraded", HealthStatus::Degraded).unwrap();
    mgr.update_node_health("routable-unhealthy", HealthStatus::Unhealthy).unwrap();

    let routable = mgr.get_routable_nodes();
    assert_eq!(routable.len(), 2); // Healthy + Degraded; Unhealthy excluded.
}

// ===========================================================================
// 5. Success / Failure Reporting
// ===========================================================================

#[test]
fn test_report_success_resets_failure_counter() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("success-reset")).unwrap();

    for _ in 0..3 { mgr.report_failure("success-reset"); }
    assert_eq!(mgr.failure_count("success-reset"), Some(3));

    mgr.report_success("success-reset");
    assert_eq!(mgr.failure_count("success-reset"), Some(0));
}

#[test]
fn test_report_failure_increments_and_trips_at_threshold() {
    let cfg = RelayConfig::builder().circuit_breaker_threshold(3).build();
    let mut mgr = RelayNodeManager::new(cfg);
    mgr.register_node(make_edge_node("fail-trip")).unwrap();

    mgr.report_failure("fail-trip");
    mgr.report_failure("fail-trip");
    assert_eq!(mgr.failure_count("fail-trip"), Some(2));
    assert_eq!(mgr.circuit_breaker("fail-trip").unwrap(), CircuitState::Closed);

    mgr.report_failure("fail-trip"); // Third failure hits threshold.
    assert_eq!(mgr.failure_count("fail-trip"), Some(3));
    assert_eq!(mgr.circuit_breaker("fail-trip").unwrap(), CircuitState::Open);
}

// ===========================================================================
// 6. Availability Checks
// ===========================================================================

#[test]
fn test_is_available_correct_state() {
    let cfg = RelayConfig::builder().circuit_breaker_threshold(2).build();
    let mut mgr = RelayNodeManager::new(cfg);
    mgr.register_node(make_edge_node("avail-check")).unwrap();

    assert!(mgr.is_available("avail-check")); // Initial state.

    mgr.report_failure("avail-check"); // count=1 < threshold.
    assert!(mgr.is_available("avail-check"));

    mgr.report_failure("avail-check"); // count=2 => trip.
    assert!(!mgr.is_available("avail-check"));
}

#[test]
fn test_is_available_nonexistent_returns_false() {
    let mgr = RelayNodeManager::new(RelayConfig::default());
    assert!(!mgr.is_available("ghost"));
}

#[test]
fn test_is_available_unhealthy_node_returns_false() {
    let mut mgr = RelayNodeManager::new(RelayConfig::default());
    mgr.register_node(make_edge_node("sick-node")).unwrap();
    mgr.update_node_health("sick-node", HealthStatus::Unhealthy).unwrap();
    assert!(!mgr.is_available("sick-node"));
}

// ===========================================================================
// 7. Full Lifecycle Integration Test
// ===========================================================================

#[test]
fn test_full_lifecycle_register_degrade_trip_recover() {
    let cfg = RelayConfig::builder()
        .circuit_breaker_threshold(2)
        .heartbeat_interval_secs(0) // Instant cooldown for testability.
        .build();
    let mut mgr = RelayNodeManager::new(cfg);

    // Phase 1: Register.
    assert!(mgr.register_node(make_edge_node("lifecycle-node")).is_ok());
    assert_eq!(mgr.node_count(), 1);
    assert!(mgr.is_available("lifecycle-node"));
    assert_eq!(mgr.failure_count("lifecycle-node"), Some(0));
    assert_eq!(mgr.circuit_breaker("lifecycle-node").unwrap(), CircuitState::Closed);

    // Phase 2: Degrade (counter increments but below threshold).
    mgr.update_node_health("lifecycle-node", HealthStatus::Degraded).unwrap();
    assert_eq!(mgr.failure_count("lifecycle-node"), Some(1));
    assert!(mgr.is_available("lifecycle-node")); // Still available.

    // Push counter to threshold via second degradation.
    mgr.update_node_health("lifecycle-node", HealthStatus::Unhealthy).unwrap();
    assert_eq!(mgr.failure_count("lifecycle-node"), Some(2));

    // Phase 3: Trip.
    assert_eq!(mgr.circuit_breaker("lifecycle-node").unwrap(), CircuitState::Open);
    assert!(!mgr.is_available("lifecycle-node"));

    // Phase 4: Recover (HalfOpen probe success).
    assert_eq!(mgr.circuit_breaker("lifecycle-node").unwrap(), CircuitState::HalfOpen);
    mgr.report_success("lifecycle-node");

    assert_eq!(mgr.circuit_breaker("lifecycle-node").unwrap(), CircuitState::Closed);
    assert_eq!(mgr.failure_count("lifecycle-node"), Some(0));
    assert!(mgr.is_available("lifecycle-node"));

    // Phase 5: Unregister.
    assert!(mgr.unregister_node("lifecycle-node").is_some());
    assert_eq!(mgr.node_count(), 0);
}

// ===========================================================================
// 8. Constructor & Accessor Tests
// ===========================================================================

#[test]
fn test_new_creates_empty_manager() {
    let mgr = RelayNodeManager::new(RelayConfig::default());
    assert_eq!(mgr.node_count(), 0);
}

#[test]
fn test_with_topology_preserves_existing_nodes() {
    let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);
    topo.add_node(make_edge_node("pre-existing")).unwrap();
    let mgr = RelayNodeManager::with_topology(RelayConfig::default(), topo);
    assert_eq!(mgr.node_count(), 1);
}

#[test]
fn test_get_topology_returns_shared_arc() {
    let mgr = RelayNodeManager::new(RelayConfig::default());
    assert!(Arc::ptr_eq(&mgr.get_topology(), &mgr.get_topology()));
}

#[test]
fn test_config_accessor() {
    let cfg = RelayConfig::builder().max_hops(10).circuit_breaker_threshold(5).build();
    let mgr = RelayNodeManager::new(cfg);
    assert_eq!(mgr.config().max_hops(), 10);
    assert_eq!(mgr.config().circuit_breaker_threshold(), 5);
}
