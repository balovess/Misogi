//! Comprehensive unit tests for [`RoutePlanner`] and supporting types.
//!
//! Test organization follows the AAA (Arrange-Act-Assert) pattern with
//! descriptive test names that document expected behavior. Each test is
//! independent and does not rely on execution order.
//!
//! # Topology Fixture
//!
//! Most tests use a common helper function `make_linear_topology()` that
//! constructs a simple 4-node chain:
//!
//! ```text
//! edge-a --> proxy-b --> hub-c --> terminal-d
//! ```
//!
//! Additional fixtures are provided for specialized scenarios (star topology,
//! disconnected graph, etc.).

use super::*;

// ===========================================================================
// Test Fixtures / Helpers
// ===========================================================================

/// Constructs a linear 4-node topology: A -> B -> C -> D.
///
/// All nodes are created with default healthy status and no local egress
/// targets (unless explicitly added by the caller).
///
/// # Returns
///
/// A tuple of `(RelayTopology, RoutePlanner)` ready for immediate use.
fn make_linear_topology() -> (RelayTopology, RoutePlanner) {
    let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);

    let edge_a = RelayNode::new(
        "edge-a",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.0.1", 8000),
        1,
        CapacityLimits::new(100, 1000),
    );
    let proxy_b = RelayNode::new(
        "proxy-b",
        NodeRole::Proxy,
        EndpointConfig::new("tcp", "10.0.0.2", 8001),
        2,
        CapacityLimits::new(500, 5000),
    );
    let hub_c = RelayNode::new(
        "hub-c",
        NodeRole::Hub,
        EndpointConfig::new("tls", "10.0.0.3", 9443),
        3,
        CapacityLimits::new(5000, 50_000),
    );
    let terminal_d = RelayNode::new(
        "terminal-d",
        NodeRole::Terminal,
        EndpointConfig::new("tls", "10.0.0.4", 9444"),
        4,
        CapacityLimits::new(10_000, 100_000),
    );

    topo.add_node(edge_a).unwrap();
    topo.add_node(proxy_b).unwrap();
    topo.add_node(hub_c).unwrap();
    topo.add_node(terminal_d).unwrap();

    // Edges: linear chain A -> B -> C -> D
    topo.add_edge(RelayEdge::new("edge-a", "proxy-b")).unwrap();
    topo.add_edge(RelayEdge::new("proxy-b", "hub-c")).unwrap();
    topo.add_edge(RelayEdge::new("hub-c", "terminal-d")).unwrap();

    let planner = RoutePlanner::with_topology(topo.clone());
    (topo, planner)
}

// ===========================================================================
// Test Group 1: Basic Path Finding (find_path)
// ===========================================================================

#[test]
fn test_direct_path_between_connected_nodes() {
    // Arrange: Linear topology with A -> B edge.
    let (_, planner) = make_linear_topology();

    // Act: Find path from adjacent nodes.
    let result = planner.find_path("edge-a", "proxy-b");

    // Assert: Single-hop path returned successfully.
    let path = result.expect("direct path should exist");
    assert_eq!(path.hops, vec!["edge-a", "proxy-b"]);
    assert_eq!(path.total_hops, 1);
}

#[test]
fn test_multi_hop_path_through_intermediate_nodes() {
    // Arrange: Linear topology A -> B -> C -> D.
    let (_, planner) = make_linear_topology();

    // Act: Find path from first to last node (3 hops).
    let result = planner.find_path("edge-a", "terminal-d");

    // Assert: Full chain path with correct hop count.
    let path = result.expect("multi-hop path should exist");
    assert_eq!(
        path.hops,
        vec!["edge-a", "proxy-b", "hub-c", "terminal-d"]
    );
    assert_eq!(path.total_hops, 3);
}

#[test]
fn test_no_path_exists_returns_error() {
    // Arrange: Build a topology where D has no incoming edges from A.
    let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);

    topo.add_node(RelayNode::new(
        "isolated",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.99.0.1", 8000),
        1,
        CapacityLimits::new(100, 1000),
    ))
    .unwrap();
    topo.add_node(RelayNode::new(
        "edge-a",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.0.1", 8000"),
        1,
        CapacityLimits::new(100, 1000),
    ))
    .unwrap();
    // No edge between isolated and edge-a.

    let planner = RoutePlanner::with_topology(topo);

    // Act & Assert: NoPath error for disconnected nodes.
    let err = planner
        .find_path("isolated", "edge-a")
        .expect_err("should return NoPath error");

    match err {
        RouteError::NoPath { from_node, to_node } => {
            assert_eq!(from_node, "isolated");
            assert_eq!(to_node, "edge-a");
        }
        other => panic!("expected NoPath error, got: {other}"),
    }
}

#[test]
fn test_source_node_not_found_returns_error() {
    let (_, planner) = make_linear_topology();

    let err = planner
        .find_path("nonexistent-source", "edge-a")
        .expect_err("should return NodeNotFound error");

    match err {
        RouteError::NodeNotFound(id) => {
            assert_eq!(id, "nonexistent-source");
        }
        other => panic!("expected NodeNotFound, got: {other}"),
    }
}

#[test]
fn test_target_node_not_found_returns_error() {
    let (_, planner) = make_linear_topology();

    let err = planner
        .find_path("edge-a", "nonexistent-target")
        .expect_err("should return NodeNotFound error");

    match err {
        RouteError::NodeNotFound(id) => {
            assert_eq!(id, "nonexistent-target");
        }
        other => panic!("expected NodeNotFound, got: {other}"),
    }
}

// ===========================================================================
// Test Group 2: Hop Count Constraints
// ===========================================================================

#[test]
fn test_path_within_max_hops_limit_succeeds() {
    // Arrange: max_hops=5, actual path needs only 3 hops.
    let (topo, _) = make_linear_topology();
    let planner = RoutePlanner::new(topo, RouteStrategy::ShortestPath, 5);

    // Act: Request path that requires 3 hops (within limit of 5).
    let result = planner.find_path("edge-a", "terminal-d");

    // Assert: Path computed successfully.
    assert!(result.is_ok());
    let path = result.unwrap();
    assert_eq!(path.total_hops, 3);
    assert!(path.total_hops <= planner.max_hops());
}

#[test]
fn test_path_exceeding_max_hops_returns_error() {
    // Arrange: max_hops=2, but shortest path requires 3 hops.
    let (topo, _) = make_linear_topology();
    let planner = RoutePlanner::new(topo, RouteStrategy::ShortestPath, 2);

    // Act: Request path needing 3 hops but limit is 2.
    let err = planner
        .find_path("edge-a", "terminal-d")
        .expect_err("should fail due to max_hops exceeded");

    // Assert: MaxHopsExceeded error with correct values.
    match err {
        RouteError::MaxHopsExceeded { max, actual } => {
            assert_eq!(max, 2);
            assert_eq!(actual, 3); // BFS finds it but rejects on length check.
        }
        other => panic!("expected MaxHopsExceeded, got: {other}"),
    }
}

// ===========================================================================
// Test Group 3: LocalEgressFirst Strategy
// ===========================================================================

#[test]
fn test_local_egress_first_direct_egress_available() {
    // Arrange: Source has target in its local_egress_targets AND direct edge.
    let mut topo = RelayTopology::new(RouteStrategy::LocalEgressFirst);

    let mut source = RelayNode::new(
        "edge-local",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.0.1", 8000"),
        1,
        CapacityLimits::new(100, 1000),
    );
    source.add_egress_target("target-local");

    let target = RelayNode::new(
        "target-local",
        NodeRole::Terminal,
        EndpointConfig::new("tcp", "10.0.0.2", 9000"),
        4,
        CapacityLimits::new(1000, 10_000),
    );

    topo.add_node(source).unwrap();
    topo.add_node(target).unwrap();
    topo.add_edge(RelayEdge::new("edge-local", "target-local")).unwrap();

    let planner = RoutePlanner::new(topo, RouteStrategy::LocalEgressFirst, 5);

    // Act: Check local egress.
    let result = planner.check_local_egress("edge-local", "target-local");

    // Assert: Should return Some(path) with single hop.
    let path = result
        .expect("check_local_egress should not error")
        .expect("direct egress path should be available");

    assert_eq!(path.hops, vec!["edge-local", "target-local"]);
    assert_eq!(path.total_hops, 1);
}

#[test]
fn test_local_egress_first_no_direct_egress_falls_back_to_normal_routing() {
    // Arrange: Source does NOT have target in local_egress_targets.
    let mut topo = RelayTopology::new(RouteStrategy::LocalEgressFirst);

    let source = RelayNode::new(
        "edge-no-egress",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.0.1", 8000"),
        1,
        CapacityLimits::new(100, 1000),
    );
    // Note: no add_egress_target call -- empty egress list.

    let mid = RelayNode::new(
        "mid-hop",
        NodeRole::Proxy,
        EndpointConfig::new("tcp", "10.0.0.2", 8001"),
        2,
        CapacityLimits::new(500, 5000),
    );
    let dest = RelayNode::new(
        "dest-far",
        NodeRole::Terminal,
        EndpointConfig::new("tcp", "10.0.0.3", 9000"),
        4,
        CapacityLimits::new(1000, 10_000),
    );

    topo.add_node(source).unwrap();
    topo.add_node(mid).unwrap();
    topo.add_node(dest).unwrap();
    topo.add_edge(RelayEdge::new("edge-no-egress", "mid-hop")).unwrap();
    topo.add_edge(RelayEdge::new("mid-hop", "dest-far")).unwrap();

    let planner = RoutePlanner::new(topo, RouteStrategy::LocalEgressFirst, 5);

    // Act: LocalEgressFirst strategy dispatches to find_path when no local egress.
    let result = planner.find_path_with_strategy("edge-no-egress", "dest-far");

    // Assert: Falls back to normal routing and returns multi-hop path.
    let path = result.expect("fallback routing should succeed");
    assert_eq!(path.hops, vec!["edge-no-egress", "mid-hop", "dest-far"]);
    assert_eq!(path.total_hops, 2);
}

// ===========================================================================
// Test Group 4: ForceHub Strategy
// ===========================================================================

#[test]
fn test_force_hub_path_goes_through_required_hub() {
    // Arrange: Star topology where all paths must go through hub-center.
    let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);

    topo.add_node(RelayNode::new(
        "edge-x",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.1.1", 8000"),
        1,
        CapacityLimits::new(100, 1000),
    ))
    .unwrap();
    topo.add_node(RelayNode::new(
        "edge-y",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.1.2", 8000"),
        1,
        CapacityLimits::new(100, 1000),
    ))
    .unwrap();
    topo.add_node(RelayNode::new(
        "hub-center",
        NodeRole::Hub,
        EndpointConfig::new("tls", "10.0.1.3", 9443"),
        3,
        CapacityLimits::new(5000, 50_000),
    ))
    .unwrap();
    topo.add_node(RelayNode::new(
        "terminal-z",
        NodeRole::Terminal,
        EndpointConfig::new("tls", "10.0.1.4", 9444"),
        4,
        CapacityLimits::new(10_000, 100_000),
    ))
    .unwrap();

    topo.add_edge(RelayEdge::new("edge-x", "hub-center")).unwrap();
    topo.add_edge(RelayEdge::new("edge-y", "hub-center")).unwrap();
    topo.add_edge(RelayEdge::new("hub-center", "terminal-z")).unwrap();

    let mut force_planner = RoutePlanner::new(
        topo,
        RouteStrategy::ForceHub(vec!["hub-center".to_string()]),
        10,
    );

    // Act: Find path that must traverse hub-center.
    let result = force_planner.find_path_with_strategy("edge-x", "terminal-z");

    // Assert: Path includes hub-center as intermediate node.
    let path = result.expect("force-hub path should exist");
    assert!(
        path.hops.contains(&"hub-center".to_string()),
        "path must include required hub: {:?}",
        path.hops
    );
    assert_eq!(path.hops, vec!["edge-x", "hub-center", "terminal-z"]);
}

// ===========================================================================
// Test Group 5: Path Validation
// ===========================================================================

#[test]
fn test_validate_valid_path_passes() {
    let (_, planner) = make_linear_topology();

    // Compute a valid path first.
    let path = planner.find_path("edge-a", "terminal-d").unwrap();

    // Validate should succeed without errors.
    assert!(planner.validate_path(&path).is_ok());
}

#[test]
fn test_validate_broken_path_fails() {
    let (_, planner) = make_linear_topology();

    // Construct a path with a non-existent edge: edge-a -> terminal-d (no direct edge).
    let invalid_path = RoutePath {
        hops: vec!["edge-a".to_string(), "terminal-d".to_string()],
        total_hops: 1,
        estimated_latency_ms: 10,
        requires_encryption: false,
        requires_approval: false,
    };

    let err = planner
        .validate_path(&invalid_path)
        .expect_err("broken path should fail validation");

    match err {
        RouteError::InvalidPath(msg) => {
            assert!(msg.contains("no edge"), "error should mention missing edge: {msg}");
        }
        other => panic!("expected InvalidPath, got: {other}"),
    }
}

// ===========================================================================
// Test Group 6: Edge Cases
// ===========================================================================

#[test]
fn test_empty_topology_returns_node_not_found() {
    let empty_topo = RelayTopology::new(RouteStrategy::ShortestPath);
    let planner = RoutePlanner::with_topology(empty_topo);

    let err = planner
        .find_path("any-node", "any-other")
        .expect_err("empty topology should yield NodeNotFound");

    match err {
        RouteError::NodeNotFound(_) => (), // Expected.
        other => panic!("expected NodeNotFound for empty topology, got: {other}"),
    }
}

#[test]
fn test_single_node_topology_trivial_path() {
    let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);
    topo.add_node(RelayNode::new(
        "solo",
        NodeRole::Terminal,
        EndpointConfig::new("tcp", "127.0.0.1", 9999"),
        4,
        CapacityLimits::new(100, 1000),
    ))
    .unwrap();

    let planner = RoutePlanner::with_topology(topo);

    // Path from node to itself should be trivial (0 hops).
    let path = planner
        .find_path("solo", "solo")
        .expect("trivial self-path should succeed");

    assert_eq!(path.hops, vec!["solo"]);
    assert_eq!(path.total_hops, 0);
    assert!(path.is_trivial());
}

// ===========================================================================
// Test Group 7: Runtime Mutation
// ===========================================================================

#[test]
fn test_strategy_update_works() {
    let (topo, _) = make_linear_topology();

    // Start with ShortestPath strategy.
    let mut planner = RoutePlanner::new(topo, RouteStrategy::ShortestPath, 5);
    assert!(matches!(planner.strategy(), RouteStrategy::ShortestPath));

    // Update to LocalEgressFirst.
    planner.update_strategy(RouteStrategy::LocalEgressFirst);
    assert!(matches!(planner.strategy(), RouteStrategy::LocalEgressFirst));

    // Verify the planner still functions correctly after update.
    let result = planner.find_path_with_strategy("edge-a", "proxy-b");
    assert!(result.is_ok());
}

#[test]
fn test_update_topology_replaces_graph() {
    let (_, mut planner) = make_linear_topology();

    // Original topology has 4 nodes; verify a path exists.
    assert!(planner.find_path("edge-a", "terminal-d").is_ok());

    // Replace with an empty topology.
    let empty = RelayTopology::new(RouteStrategy::ShortestPath);
    planner.update_topology(empty);

    // Now the old nodes should not be found.
    let err = planner
        .find_path("edge-a", "terminal-d")
        .expect_err("old nodes should not exist after topology replacement");

    assert!(matches!(err, RouteError::NodeNotFound(_)));
}

// ===========================================================================
// Test Group 8: Edge Metadata Aggregation
// ===========================================================================

#[test]
fn test_path_aggregates_encryption_and_approval_flags() {
    let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);

    topo.add_node(RelayNode::new(
        "a",
        NodeRole::Edge,
        EndpointConfig::new("tcp", "10.0.0.1", 8000"),
        1,
        CapacityLimits::new(100, 1000),
    ))
    .unwrap();
    topo.add_node(RelayNode::new(
        "b",
        NodeRole::Proxy,
        EndpointConfig::new("tcp", "10.0.0.2", 8001"),
        2,
        CapacityLimits::new(500, 5000),
    ))
    .unwrap();
    topo.add_node(RelayNode::new(
        "c",
        NodeRole::Terminal,
        EndpointConfig::new("tcp", "10.0.0.3", 9000"),
        4,
        CapacityLimits::new(1000, 10_000),
    ))
    .unwrap();

    // Edge a->b requires encryption and approval.
    let enc_edge = RelayEdgeBuilder::new("a", "b")
        .require_encryption(true)
        .require_approval(true)
        .build();
    topo.add_edge(enc_edge).unwrap();

    // Edge b->c requires nothing special.
    topo.add_edge(RelayEdge::new("b", "c")).unwrap();

    let planner = RoutePlanner::with_topology(topo);

    let path = planner.find_path("a", "c").unwrap();

    // At least one edge requires encryption/approval.
    assert!(
        path.requires_encryption,
        "path should require encryption due to a->b edge"
    );
    assert!(
        path.requires_approval,
        "path should require approval due to a->b edge"
    );
}

#[test]
fn test_custom_strategy_returns_unsupported_error() {
    let (topo, _) = make_linear_topology();
    let custom_planner = RoutePlanner::new(
        topo,
        RouteStrategy::Custom("my-custom-strat".to_string()),
        5,
    );

    let err = custom_planner
        .find_path_with_strategy("edge-a", "proxy-b")
        .expect_err("Custom strategy should be rejected");

    match err {
        RouteError::UnsupportedStrategy(msg) => {
            assert!(msg.contains("my-custom-strat"));
        }
        other => panic!("expected UnsupportedStrategy, got: {other}"),
    }
}
