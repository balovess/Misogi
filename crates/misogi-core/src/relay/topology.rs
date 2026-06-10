// ===========================================================================
// Relay Topology — Graph Management
// ===========================================================================
//
// Provides the `RelayTopology` data structure which maintains a directed graph
// of relay nodes (`RelayNode`) and their interconnections (`RelayEdge`).
//
// This module is responsible for:
//   - Graph mutation (add/remove nodes and edges) with referential integrity.
//   - Graph querying (node lookup, edge traversal, adjacency queries).
//   - Topology validation (detecting dangling edges, duplicate nodes).
//   - Route strategy declaration (policy for path selection algorithms).
//
// The topology is intentionally kept as a simple adjacency-list model without
// heavyweight graph library dependencies. This ensures:
//   - Zero external dependencies beyond core + serde.
//   - Predictable O(N+E) complexity for all operations.
//   - Easy serialization for configuration persistence.

use serde::{Deserialize, Serialize};

use crate::relay::node::{CapacityLimits, EndpointConfig, HealthStatus, RelayEdge, RelayNode, NodeRole};

/// Routing strategy that governs how paths are selected through the relay
/// topology graph.
///
/// Each variant represents a distinct optimization objective or policy
/// constraint applied during route computation:
///
/// | Strategy            | Objective                              |
/// |---------------------|----------------------------------------|
/// | `ShortestPath`      | Minimize hop count (Dijkstra-like).    |
/// | `LowestLatency`     | Minimize end-to-end RTT.               |
/// | `LocalEgressFirst`  | Prefer local egress before upstreaming.|
/// | `ForceHub`          | Constrain to specific hub node IDs.    |
/// | `Custom`            | User-supplied strategy identifier.     |
///
/// # Serialization
///
/// Serialized as a tagged enum with snake_case variant names.
/// The `ForceHub` variant serializes its inner `Vec<String>` as a JSON array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "strategy", content = "params", rename_all = "snake_case")]
pub enum RouteStrategy {
    /// Selects the path with the fewest intermediate hops.
    ///
    /// Optimal when bandwidth is uniform across edges and latency is not a
    /// primary concern. Equivalent to unweighted shortest-path in graph theory.
    ShortestPath,

    /// Selects the path with the lowest measured round-trip time.
    ///
    /// Requires real-time latency measurements from the monitoring subsystem.
    /// Falls back to [`Self::ShortestPath`] if no latency data is available.
    LowestLatency,

    /// Prefers routing to local egress targets before forwarding traffic
    /// to upstream (higher-tier) nodes.
    ///
    /// This is the default strategy for most deployments because it minimizes
    /// cross-region bandwidth consumption and reduces latency for local clients.
    LocalEgressFirst,

    /// Constrains all routes to pass through one of the specified hub node IDs.
    ///
    /// Useful for compliance scenarios where all inter-organizational traffic
    /// must traverse an inspection/audit gateway.
    ///
    /// # Invariants
    ///
    /// The inner `Vec<String>` must contain at least one valid hub node ID
    /// at evaluation time; empty vectors are rejected by the router.
    ForceHub(Vec<String>),

    /// User-defined strategy identified by a string name.
    ///
    /// Interpretation is delegated to a pluggable strategy resolver registered
    /// at runtime. The core topology layer treats this as opaque.
    Custom(String),
}

impl RouteStrategy {
    /// Returns the default route strategy recommended for general-purpose
    /// relay deployments.
    ///
    /// Currently returns [`Self::LocalEgressFirst`] as it provides the best
    /// balance between performance and cost for typical edge-to-cloud patterns.
    pub fn default_strategy() -> Self {
        Self::LocalEgressFirst
    }

    /// Parses a route strategy from its string representation.
    ///
    /// # Supported Names
    ///
    /// | Name              | Variant              |
    /// |-------------------|----------------------|
    /// | `"shortest_path"` | `ShortestPath`       |
    /// | `"lowest_latency"`| `LowestLatency`      |
    /// | `"local_egress_first"` | `LocalEgressFirst` |
    /// | `"force_hub"`     | `ForceHub(vec![])`   |
    /// | `"custom"`        | `Custom(name)`       |
    ///
    /// Returns `None` for unrecognized names.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "shortest_path" => Some(Self::ShortestPath),
            "lowest_latency" => Some(Self::LowestLatency),
            "local_egress_first" => Some(Self::LocalEgressFirst),
            "force_hub" => Some(Self::ForceHub(vec![])),
            other if other.starts_with("custom:") => {
                Some(Self::Custom(other.strip_prefix("custom:").unwrap().to_string()))
            }
            _ => None,
        }
    }
}

/// Directed graph representing the complete relay network topology.
///
/// Maintains two collections:
/// - **nodes**: All [`RelayNode`] instances indexed by `node_id`.
/// - **edges**: All [`RelayEdge`] instances defining directed connections.
///
/// The topology enforces referential integrity at mutation time: edges may only
/// reference nodes that exist in the `nodes` collection at the time of insertion.
/// However, removing a node does NOT automatically remove its incident edges;
/// callers must explicitly clean up edges or invoke [`Self::validate`] to detect
/// orphaned references.
///
/// # Thread Safety
///
/// `RelayTopology` is `Clone` (shallow copy of Vec contents). For concurrent
/// access, wrap in `Arc<RwLock<RelayTopology>>` or equivalent synchronization
/// primitive. The topology is designed for read-heavy workloads where route
/// computation occurs far more frequently than topology updates.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::*;
///
/// let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);
/// let node = RelayNode::new("edge-01", NodeRole::Edge,
///     EndpointConfig::new("tcp", "10.0.0.1", 8443), 1,
///     CapacityLimits::new(100, 1000));
/// topo.add_node(node).unwrap();
/// assert!(topo.get_node("edge-01").is_some());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTopology {
    /// Ordered collection of all relay nodes in this topology.
    ///
    /// Ordering is insertion-order stable; iteration order matches the order
    /// in which nodes were added via [`Self::add_node`].
    pub nodes: Vec<RelayNode>,

    /// Ordered collection of all directed edges in this topology.
    ///
    /// Multiple edges between the same ordered pair of nodes are permitted
    /// (directed multigraph semantics).
    pub edges: Vec<RelayEdge>,

    /// Default routing strategy used when no per-transfer override is specified.
    pub default_route: RouteStrategy,
}

impl RelayTopology {
    /// Constructs an empty topology with the specified default routing strategy.
    ///
    /// # Parameters
    ///
    /// - `default_route`: Strategy applied to transfers that do not specify
    ///   an explicit route preference.
    ///
    /// # Returns
    ///
    /// A new [`RelayTopology`] instance with empty `nodes` and `edges` vectors.
    pub fn new(default_route: RouteStrategy) -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            default_route,
        }
    }

    /// Adds a new node to the topology.
    ///
    /// # Parameters
    ///
    /// - `node`: The [`RelayNode`] to insert.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if a node with the same `node_id` already exists
    /// in the topology. Node IDs must be globally unique within a single
    /// topology instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use misogi_core::relay::*;
    /// let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
    /// let node = RelayNode::new("unique-id", NodeRole::Edge,
    ///     EndpointConfig::new("tcp", "127.0.0.1", 8080), 1,
    ///     CapacityLimits::new(10, 100));
    /// assert!(topo.add_node(node).is_ok());
    /// ```
    pub fn add_node(&mut self, node: RelayNode) -> Result<(), String> {
        let id = &node.node_id;
        if self.nodes.iter().any(|n| n.node_id == *id) {
            return Err(format!(
                "duplicate node_id detected: '{id}'. Each node must have a unique identifier."
            ));
        }
        self.nodes.push(node);
        Ok(())
    }

    /// Removes a node from the topology by its identifier.
    ///
    /// # Parameters
    ///
    /// - `node_id`: The unique identifier of the node to remove.
    ///
    /// # Returns
    ///
    /// - `Some(RelayNode)` if the node was found and removed.
    /// - `None` if no node with the given ID exists.
    ///
    /// # Note on Edge Cleanup
    ///
    /// Removing a node does **not** automatically remove edges referencing it.
    /// Callers should invoke [`Self::validate`] after removal to detect
    /// orphaned edges, or manually clean up via [`Self::edges`].
    pub fn remove_node(&mut self, node_id: &str) -> Option<RelayNode> {
        if let Some(pos) = self.nodes.iter().position(|n| n.node_id == node_id) {
            return Some(self.nodes.remove(pos));
        }
        None
    }

    /// Adds a directed edge to the topology.
    ///
    /// # Parameters
    ///
    /// - `edge`: The [`RelayEdge`] to insert.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if either `from_node` or `to_node` does not
    /// reference an existing node in the topology's `nodes` collection.
    /// This enforces referential integrity: every edge must have both
    /// endpoints present at insertion time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use misogi_core::relay::*;
    /// # let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
    /// # topo.add_node(RelayNode::new("a", NodeRole::Edge,
    /// #     EndpointConfig::new("tcp", "1.1.1.1", 80), 1,
    /// #     CapacityLimits::new(10, 100))).unwrap();
    /// # topo.add_node(RelayNode::new("b", NodeRole::Proxy,
    /// #     EndpointConfig::new("tcp", "2.2.2.2", 80), 2,
    /// #     CapacityLimits::new(10, 100))).unwrap();
    /// let edge = RelayEdge::new("a", "b");
    /// assert!(topo.add_edge(edge).is_ok());
    /// ```
    pub fn add_edge(&mut self, edge: RelayEdge) -> Result<(), String> {
        let from_exists = self.nodes.iter().any(|n| n.node_id == edge.from_node);
        let to_exists = self.nodes.iter().any(|n| n.node_id == edge.to_node);

        if !from_exists {
            return Err(format!(
                "edge references non-existent source node: '{}'",
                edge.from_node
            ));
        }
        if !to_exists {
            return Err(format!(
                "edge references non-existent destination node: '{}'",
                edge.to_node
            ));
        }

        self.edges.push(edge);
        Ok(())
    }

    /// Retrieves an immutable reference to a node by its identifier.
    ///
    /// # Parameters
    ///
    /// - `node_id`: The unique identifier to look up.
    ///
    /// # Returns
    ///
    /// - `Some(&RelayNode)` if found.
    /// - `None` if no matching node exists.
    ///
    /// # Complexity
    ///
    /// O(N) linear scan over the nodes vector. For topologies with >1000 nodes,
    /// consider maintaining a secondary HashMap index.
    #[inline]
    pub fn get_node(&self, node_id: &str) -> Option<&RelayNode> {
        self.nodes.iter().find(|n| n.node_id == node_id)
    }

    /// Returns all outgoing edges originating from the specified node.
    ///
    /// # Parameters
    ///
    /// - `node_id`: The source node identifier to query.
    ///
    /// # Returns
    ///
    /// A `Vec<&RelayEdge>` containing all edges whose `from_node` equals
    /// the given `node_id`. Returns an empty vector if the node has no
    /// outgoing edges or does not exist.
    ///
    /// # Use Cases
    ///
    /// - Route expansion: discovering next-hop candidates from current position.
    /// - Topology visualization: building adjacency lists for graph rendering.
    /// - Health propagation: cascading status updates downstream.
    pub fn get_edges_from(&self, node_id: &str) -> Vec<&RelayEdge> {
        self.edges
            .iter()
            .filter(|e| e.from_node == node_id)
            .collect()
    }

    /// Returns all incoming edges terminating at the specified node.
    ///
    /// # Parameters
    ///
    /// - `node_id`: The destination node identifier to query.
    ///
    /// # Returns
    ///
    /// A `Vec<&RelayEdge>` containing all edges whose `to_node` equals
    /// the given `node_id`.
    pub fn get_edges_to(&self, node_id: &str) -> Vec<&RelayEdge> {
        self.edges
            .iter()
            .filter(|e| e.to_node == node_id)
            .collect()
    }

    /// Validates the entire topology for structural consistency.
    ///
    /// Performs the following checks:
    ///
    /// 1. **Edge endpoint validity**: Every edge's `from_node` and `to_node`
    ///    must reference existing nodes in the `nodes` collection.
    /// 2. **Duplicate node detection** (informational): Reports any nodes
    ///    sharing the same `node_id` (should be impossible after proper
    ///    [`Self::add_node`] usage but checked defensively).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the topology passes all validation checks.
    /// - `Err(Vec<String>)` containing human-readable descriptions of each
    ///   violation found. An empty error vector indicates success (but callers
    ///   should prefer checking `is_ok()`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use misogi_core::relay::*;
    /// # let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
    /// match topo.validate() {
    ///     Ok(()) => println!("Topology is consistent"),
    ///     Err(violations) => {
    ///         for v in &violations { eprintln!("VIOLATION: {v}"); }
    ///     }
    /// }
    /// ```
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();

        // Check 1: Every edge must reference existing nodes.
        let node_ids: std::collections::HashSet<&str> =
            self.nodes.iter().map(|n| n.node_id.as_str()).collect();

        for edge in &self.edges {
            if !node_ids.contains(edge.from_node.as_str()) {
                violations.push(format!(
                    "edge '{}'->'{}' references non-existent source node '{}'",
                    edge.from_node, edge.to_node, edge.from_node
                ));
            }
            if !node_ids.contains(edge.to_node.as_str()) {
                violations.push(format!(
                    "edge '{}'->'{}' references non-existent destination node '{}'",
                    edge.from_node, edge.to_node, edge.to_node
                ));
            }
        }

        // Check 2: Duplicate node IDs (defensive check).
        let mut seen = std::collections::HashSet::new();
        for node in &self.nodes {
            if !seen.insert(&node.node_id) {
                violations.push(format!(
                    "duplicate node_id detected: '{}'",
                    node.node_id
                ));
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    /// Returns the number of nodes currently in the topology.
    #[inline]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of edges currently in the topology.
    #[inline]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns `true` if the topology contains no nodes and no edges.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::RelayEdgeBuilder;

    // Helper: construct a minimal Edge node for testing.
    fn make_test_node(id: &str, role: NodeRole) -> RelayNode {
        let tier = role.tier();
        RelayNode::new(
            id,
            role,
            EndpointConfig::new("tcp", "127.0.0.1", 8080),
            tier,
            CapacityLimits::new(100, 1000),
        )
    }

    // -----------------------------------------------------------------------
    // RouteStrategy tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_route_strategy_default_is_local_egress_first() {
        match RouteStrategy::default_strategy() {
            RouteStrategy::LocalEgressFirst => {}
            other => panic!("expected LocalEgressFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_route_strategy_force_hub_serialization() {
        let strategy = RouteStrategy::ForceHub(vec!["hub-1".to_string(), "hub-2".to_string()]);
        let json = serde_json::to_string(&strategy).unwrap();
        let decoded: RouteStrategy = serde_json::from_str(&json).unwrap();
        match decoded {
            RouteStrategy::ForceHub(hubs) => {
                assert_eq!(hubs.len(), 2);
                assert_eq!(hubs[0], "hub-1");
                assert_eq!(hubs[1], "hub-2");
            }
            _ => panic!("expected ForceHub variant"),
        }
    }

    #[test]
    fn test_route_strategy_custom_roundtrip() {
        let strategy = RouteStrategy::Custom("geo-weighted".to_string());
        let json = serde_json::to_string(&strategy).unwrap();
        let decoded: RouteStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, strategy);
    }

    // -----------------------------------------------------------------------
    // RelayTopology construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_topology_new_is_empty() {
        let topo = RelayTopology::new(RouteStrategy::ShortestPath);
        assert!(topo.is_empty());
        assert_eq!(topo.node_count(), 0);
        assert_eq!(topo.edge_count(), 0);
    }

    #[test]
    fn test_topology_new_preserves_default_route() {
        let topo = RelayTopology::new(RouteStrategy::LowestLatency);
        assert_eq!(topo.default_route, RouteStrategy::LowestLatency);
    }

    // -----------------------------------------------------------------------
    // Node management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_single_node_success() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        let node = make_test_node("node-a", NodeRole::Edge);
        assert!(topo.add_node(node).is_ok());
        assert_eq!(topo.node_count(), 1);
        assert!(topo.get_node("node-a").is_some());
    }

    #[test]
    fn test_add_multiple_nodes_all_roles() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());

        let roles = [
            (NodeRole::Edge, "edge-01"),
            (NodeRole::Proxy, "proxy-01"),
            (NodeRole::Hub, "hub-01"),
            (NodeRole::Terminal, "terminal-01"),
        ];

        for (role, id) in &roles {
            let node = make_test_node(id, role.clone());
            assert!(topo.add_node(node).is_ok(), "failed to add {id}");
        }

        assert_eq!(topo.node_count(), 4);

        for (_, id) in &roles {
            assert!(topo.get_node(id).is_some(), "{id} should exist");
        }
    }

    #[test]
    fn test_add_duplicate_node_id_rejected() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        let node_a = make_test_node("dup-id", NodeRole::Edge);
        let node_b = make_test_node("dup-id", NodeRole::Proxy);

        assert!(topo.add_node(node_a).is_ok());
        let result = topo.add_node(node_b);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
        assert_eq!(topo.node_count(), 1); // Original node still present
    }

    #[test]
    fn test_remove_existing_node_returns_it() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("removable", NodeRole::Edge))
            .unwrap();
        let removed = topo.remove_node("removable");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().node_id, "removable");
        assert_eq!(topo.node_count(), 0);
        assert!(topo.get_node("removable").is_none());
    }

    #[test]
    fn test_remove_nonexistent_node_returns_none() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        assert!(topo.remove_node("ghost").is_none());
    }

    // -----------------------------------------------------------------------
    // Edge management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_edge_both_nodes_exist() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("src", NodeRole::Edge)).unwrap();
        topo.add_node(make_test_node("dst", NodeRole::Proxy)).unwrap();

        let edge = RelayEdge::new("src", "dst");
        assert!(topo.add_edge(edge).is_ok());
        assert_eq!(topo.edge_count(), 1);
    }

    #[test]
    fn test_add_edge_missing_source_rejected() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("dst", NodeRole::Terminal)).unwrap();

        // Note: "ghost-src" is NOT added to the topology.
        let edge = RelayEdge::new("ghost-src", "dst");
        let err = topo.add_edge(edge).unwrap_err();
        assert!(err.contains("non-existent source"), "error: {err}");
    }

    #[test]
    fn test_add_edge_missing_destination_rejected() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("src", NodeRole::Edge)).unwrap();

        let edge = RelayEdge::new("src", "ghost-dst");
        let err = topo.add_edge(edge).unwrap_err();
        assert!(err.contains("non-existent destination"), "error: {err}");
    }

    #[test]
    fn test_get_edges_from_returns_outgoing_only() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("a", NodeRole::Edge)).unwrap();
        topo.add_node(make_test_node("b", NodeRole::Proxy)).unwrap();
        topo.add_node(make_test_node("c", NodeRole::Hub)).unwrap();

        topo.add_edge(RelayEdge::new("a", "b")).unwrap();
        topo.add_edge(RelayEdge::new("b", "c")).unwrap();
        topo.add_edge(RelayEdge::new("c", "a")).unwrap(); // cycle

        let from_a = topo.get_edges_from("a");
        assert_eq!(from_a.len(), 1);
        assert_eq!(from_a[0].to_node(), "b");

        let from_b = topo.get_edges_from("b");
        assert_eq!(from_b.len(), 1);
        assert_eq!(from_b[0].to_node(), "c");
    }

    #[test]
    fn test_get_edges_from_nonexistent_returns_empty() {
        let topo = RelayTopology::new(RouteStrategy::default_strategy());
        assert!(topo.get_edges_from("ghost").is_empty());
    }

    #[test]
    fn test_get_edges_to_returns_incoming_only() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("x", NodeRole::Edge)).unwrap();
        topo.add_node(make_test_node("y", NodeRole::Hub)).unwrap();
        topo.add_node(make_test_node("z", NodeRole::Terminal)).unwrap();

        topo.add_edge(RelayEdge::new("x", "y")).unwrap();
        topo.add_edge(RelayEdge::new("z", "y")).unwrap();

        let to_y = topo.get_edges_to("y");
        assert_eq!(to_y.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_clean_topology_succeeds() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("n1", NodeRole::Edge)).unwrap();
        topo.add_node(make_test_node("n2", NodeRole::Proxy)).unwrap();
        topo.add_edge(RelayEdge::new("n1", "n2")).unwrap();
        assert!(topo.validate().is_ok());
    }

    #[test]
    fn test_validate_detects_dangling_edge_source() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("real-dst", NodeRole::Terminal))
            .unwrap();
        // Manually insert an edge referencing a nonexistent source node.
        topo.edges.push(RelayEdge::new("phantom-src", "real-dst"));

        let errs = topo.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("phantom-src")));
    }

    #[test]
    fn test_validate_detects_dangling_edge_destination() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        topo.add_node(make_test_node("real-src", NodeRole::Edge)).unwrap();
        topo.edges.push(RelayEdge::new("real-src", "phantom-dst"));

        let errs = topo.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("phantom-dst")));
    }

    #[test]
    fn test_validate_detects_multiple_violations() {
        let mut topo = RelayTopology::new(RouteStrategy::default_strategy());
        // No nodes at all, but we'll insert two bad edges.
        topo.edges.push(RelayEdge::new("ghost-a", "ghost-b"));
        topo.edges.push(RelayEdge::new("ghost-c", "ghost-d"));

        let errs = topo.validate().unwrap_err();
        // Should report both missing source AND missing dest for each edge.
        assert!(errs.len() >= 4); // 2 edges x 2 endpoints
    }

    // -----------------------------------------------------------------------
    // Topology serialization test
    // -----------------------------------------------------------------------

    #[test]
    fn test_topology_serialization_roundtrip() {
        let mut topo = RelayTopology::new(RouteStrategy::LocalEgressFirst);
        topo.add_node(
            RelayNode::new(
                "ser-node",
                NodeRole::Hub,
                EndpointConfig::new("tls", "10.0.0.99", 9443),
                3,
                CapacityLimits::new(9999, 100_000),
            ),
        )
        .unwrap();
        // Add the destination node so the edge can be added successfully.
        topo.add_node(
            RelayNode::new(
                "some-other",
                NodeRole::Terminal,
                EndpointConfig::new("tcp", "10.0.0.100", 8080),
                4,
                CapacityLimits::new(100, 1000),
            ),
        )
        .unwrap();
        topo.add_edge(
            RelayEdgeBuilder::new("ser-node", "some-other")
                .protocol("quic")
                .build(),
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&topo).unwrap();
        let decoded: RelayTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node_count(), topo.node_count());
        assert_eq!(decoded.edge_count(), topo.edge_count());
        assert_eq!(decoded.default_route, RouteStrategy::LocalEgressFirst);
    }
}
