//! RelayMesh — Integrated Multi-Tier Relay Orchestration Container.
//!
//! This module provides [`RelayMesh`], a unified container that integrates the three
//! core components of the multi-tier relay subsystem:
//!
//! | Component         | Role                                              |
//! |-------------------|---------------------------------------------------|
//! | `RelayForwarder`  | Executes chunk forwarding through computed paths. |
//! | `RelayNodeManager`| Manages node lifecycle, health, and circuit breakers. |
//! | `RoutePlanner`    | Computes optimal paths through the topology graph. |
//!
//! # Architecture Overview
//!
//! `RelayMesh` serves as the single entry point for relay operations, providing:
//!
//! - **Unified initialization**: All three components are constructed together with
//!   consistent configuration and topology.
//! - **Simplified API**: Callers interact with one `Arc<RelayMesh>` instead of
//!   managing three separate `Arc` references.
//! - **Consistent state**: The forwarder, node manager, and route planner share
//!   the same topology snapshot, ensuring routing decisions align with health state.
//!
//! # Thread Safety
//!
//! All internal components are wrapped in `Arc` for safe concurrent access from
//! multiple async tasks. The mesh itself is immutable after construction.
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_core::relay::*;
//!
//! // Build topology.
//! let mut topo = RelayTopology::new(RouteStrategy::LocalEgressFirst);
//! topo.add_node(RelayNode::new("edge", NodeRole::Edge, ...))?;
//! topo.add_node(RelayNode::new("hub", NodeRole::Hub, ...))?;
//! topo.add_edge(RelayEdge::new("edge", "hub"))?;
//!
//! // Create mesh with configuration.
//! let config = RelayConfig::builder().enabled(true).max_hops(10).build();
//! let mesh = RelayMesh::new(topo, config);
//!
//! // Forward a file through the mesh.
//! let result = mesh.forwarder().forward_file("edge", "hub", "file-123", &chunks).await?;
//! ```

use std::sync::{Arc, RwLock};

use super::config::RelayConfig;
use super::forwarder::RelayForwarder;
use super::node_manager::RelayNodeManager;
use super::route_planner::RoutePlanner;
use super::topology::RelayTopology;

// ===========================================================================
// RelayMesh
// ===========================================================================

/// Integrated container for multi-tier relay operations.
///
/// Combines [`RelayForwarder`], [`RelayNodeManager`], and [`RoutePlanner`] into
/// a single cohesive unit, simplifying integration into Sender/Receiver state
/// containers.
///
/// # Component Relationships
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                        RelayMesh                            │
/// ├─────────────────────────────────────────────────────────────┤
/// │  RoutePlanner ◄─────┐                                       │
/// │       │             │                                       │
/// │       ▼             │                                       │
/// │  RelayForwarder ────┼──► Path Computation                   │
/// │       │             │                                       │
/// │       ▼             │                                       │
/// │  RelayNodeManager ──┘──► Health/Circuit Breaker Updates     │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// The forwarder uses the route planner to compute paths, and reports hop
/// outcomes to the node manager for health tracking and circuit breaker
/// state transitions.
///
/// # Construction
///
/// Use [`Self::new`] to create a mesh from a topology and configuration.
/// All internal components are initialized with consistent references.
///
/// # Backward Compatibility
///
/// `RelayMesh` is **optional** in Sender/Receiver state. When the relay
/// subsystem is disabled (`RelayConfig::enabled = false`), the `relay_mesh`
/// field is `None`, and the system operates in direct transfer mode.
#[derive(Debug)]
pub struct RelayMesh {
    /// Forwarding engine for executing chunk-level transfers through paths.
    forwarder: Arc<RelayForwarder>,

    /// Node lifecycle manager with health tracking and circuit breakers.
    node_manager: Arc<RwLock<RelayNodeManager>>,

    /// Route computation engine for optimal path selection.
    route_planner: Arc<RoutePlanner>,

    /// Configuration snapshot for reference.
    config: RelayConfig,
}

impl RelayMesh {
    /// Constructs a new `RelayMesh` from topology and configuration.
    ///
    /// Initializes all three internal components with consistent references:
    ///
    /// 1. Creates a [`RoutePlanner`] from the topology.
    /// 2. Creates a [`RelayNodeManager`] from the configuration.
    /// 3. Creates a [`RelayForwarder`] linking the planner and manager.
    ///
    /// # Parameters
    ///
    /// - `topology`: The relay topology graph defining nodes and edges.
    /// - `config`: Global relay configuration governing behavior thresholds.
    ///
    /// # Returns
    ///
    /// A fully initialized `RelayMesh` ready for forwarding operations.
    ///
    /// # Example
    ///
    /// ```
    /// # use misogi_core::relay::*;
    /// let topo = RelayTopology::new(RouteStrategy::default_strategy());
    /// let config = RelayConfig::default();
    /// let mesh = RelayMesh::new(topo, config);
    /// assert!(mesh.forwarder().max_retries() == 3);
    /// ```
    pub fn new(topology: RelayTopology, config: RelayConfig) -> Self {
        // Create route planner from topology.
        let route_planner = Arc::new(RoutePlanner::with_topology(topology.clone()));

        // Create node manager from configuration and register all topology nodes.
        let mut node_manager = RelayNodeManager::new(config.clone());
        for node in &topology.nodes {
            let _ = node_manager.register_node(node.clone());
        }
        let node_manager = Arc::new(RwLock::new(node_manager));

        // Create forwarder using with_defaults which handles internal Arc creation.
        let forwarder = Arc::new(RelayForwarder::with_defaults(topology));

        Self {
            forwarder,
            node_manager,
            route_planner,
            config,
        }
    }

    /// Constructs a `RelayMesh` with explicit retry configuration.
    ///
    /// Allows customization of the forwarder's retry limit, which controls
    /// how many attempts are made for failed hops before giving up.
    ///
    /// # Parameters
    ///
    /// - `topology`: The relay topology graph.
    /// - `config`: Global relay configuration.
    /// - `max_retries`: Maximum retry attempts per failed hop.
    ///
    /// # Returns
    ///
    /// A `RelayMesh` with the specified retry limit.
    pub fn with_max_retries(topology: RelayTopology, config: RelayConfig, max_retries: u32) -> Self {
        let route_planner = Arc::new(RoutePlanner::with_topology(topology.clone()));

        // Create node manager and register all topology nodes.
        let mut node_manager = RelayNodeManager::new(config.clone());
        for node in &topology.nodes {
            let _ = node_manager.register_node(node.clone());
        }

        // Create forwarder with custom retry count using the same node manager.
        let forwarder = Arc::new(RelayForwarder::new(
            RoutePlanner::with_topology(topology.clone()),
            node_manager,
            max_retries,
        ));
        // Get a reference to the forwarder's internal node manager for consistency.
        let node_manager = Arc::clone(forwarder.node_manager());

        Self {
            forwarder,
            node_manager,
            route_planner,
            config,
        }
    }

    /// Constructs a `RelayMesh` with a pre-populated node manager.
    ///
    /// Used when nodes have already been registered (e.g., loaded from
    /// configuration) and should be preserved during mesh construction.
    ///
    /// # Parameters
    ///
    /// - `topology`: The relay topology graph.
    /// - `node_manager`: Pre-populated node manager with registered nodes.
    /// - `config`: Global relay configuration.
    ///
    /// # Returns
    ///
    /// A `RelayMesh` using the provided node manager.
    pub fn with_node_manager(
        topology: RelayTopology,
        node_manager: RelayNodeManager,
        config: RelayConfig,
    ) -> Self {
        let route_planner = Arc::new(RoutePlanner::with_topology(topology.clone()));
        let node_manager = Arc::new(RwLock::new(node_manager));

        let forwarder = Arc::new(RelayForwarder::with_defaults(topology));

        Self {
            forwarder,
            node_manager,
            route_planner,
            config,
        }
    }

    // =======================================================================
    // Accessor Methods
    // =======================================================================

    /// Returns a reference to the forwarding engine.
    ///
    /// Use this to execute file/chunk transfers through computed paths.
    #[inline]
    pub fn forwarder(&self) -> &Arc<RelayForwarder> {
        &self.forwarder
    }

    /// Returns a reference to the node lifecycle manager.
    ///
    /// Use this to register/unregister nodes, update health status,
    /// and query node availability.
    #[inline]
    pub fn node_manager(&self) -> &Arc<RwLock<RelayNodeManager>> {
        &self.node_manager
    }

    /// Returns a reference to the route computation engine.
    ///
    /// Use this to compute paths, validate routes, and query topology metadata.
    #[inline]
    pub fn route_planner(&self) -> &Arc<RoutePlanner> {
        &self.route_planner
    }

    /// Returns a reference to the relay configuration.
    #[inline]
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// Returns `true` if the relay subsystem is enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns the maximum allowed hop count for paths.
    #[inline]
    pub fn max_hops(&self) -> u8 {
        self.config.max_hops
    }

    /// Returns the circuit breaker failure threshold.
    #[inline]
    pub fn circuit_breaker_threshold(&self) -> u32 {
        self.config.circuit_breaker_threshold
    }

    // =======================================================================
    // Convenience Methods
    // =======================================================================

    /// Computes a path from source to target using the route planner.
    ///
    /// Convenience method that delegates to [`RoutePlanner::find_path`].
    ///
    /// # Errors
    ///
    /// Returns [`RouteError`](super::route_planner::RouteError) if:
    /// - Source or target node does not exist.
    /// - No path exists between the nodes.
    /// - Path exceeds `max_hops` limit.
    pub fn find_path(
        &self,
        source: &str,
        target: &str,
    ) -> Result<super::route_planner::RoutePath, super::route_planner::RouteError> {
        self.route_planner.find_path(source, target)
    }

    /// Checks if a node is available for routing.
    ///
    /// A node is available if:
    /// - It exists in the topology.
    /// - Its health status is not `Unhealthy`.
    /// - Its circuit breaker is not `Open`.
    pub fn is_node_available(&self, node_id: &str) -> bool {
        let manager = self.node_manager.read().unwrap();
        manager.is_available(node_id)
    }

    /// Returns the number of registered nodes in the topology.
    pub fn node_count(&self) -> usize {
        let manager = self.node_manager.read().unwrap();
        manager.node_count()
    }
}

// ===========================================================================
// Clone Implementation
// ===========================================================================

impl Clone for RelayMesh {
    /// Clones the `RelayMesh` by incrementing `Arc` reference counts.
    ///
    /// This is a cheap operation (O(1)) since it only clones the `Arc`
    /// pointers, not the underlying data.
    fn clone(&self) -> Self {
        Self {
            forwarder: Arc::clone(&self.forwarder),
            node_manager: Arc::clone(&self.node_manager),
            route_planner: Arc::clone(&self.route_planner),
            config: self.config.clone(),
        }
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::node::{CapacityLimits, EndpointConfig, NodeRole, RelayEdge, RelayNode};
    use crate::relay::topology::RouteStrategy;

    /// Helper: Creates a minimal 2-node topology (source -> target).
    fn make_simple_topology() -> RelayTopology {
        let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);
        topo.add_node(RelayNode::new(
            "src",
            NodeRole::Edge,
            EndpointConfig::new("tcp", "127.0.0.1", 8000),
            1,
            CapacityLimits::new(100, 1000),
        ))
        .unwrap();
        topo.add_node(RelayNode::new(
            "dst",
            NodeRole::Terminal,
            EndpointConfig::new("tcp", "127.0.0.1", 9000),
            4,
            CapacityLimits::new(100, 1000),
        ))
        .unwrap();
        topo.add_edge(RelayEdge::new("src", "dst")).unwrap();
        topo
    }

    /// Helper: Creates a 3-node topology for multi-hop testing.
    fn make_multi_hop_topology() -> RelayTopology {
        let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);
        topo.add_node(RelayNode::new(
            "edge",
            NodeRole::Edge,
            EndpointConfig::new("tcp", "10.0.0.1", 8000),
            1,
            CapacityLimits::new(100, 1000),
        ))
        .unwrap();
        topo.add_node(RelayNode::new(
            "proxy",
            NodeRole::Proxy,
            EndpointConfig::new("tcp", "10.0.0.2", 8080),
            2,
            CapacityLimits::new(500, 5000),
        ))
        .unwrap();
        topo.add_node(RelayNode::new(
            "terminal",
            NodeRole::Terminal,
            EndpointConfig::new("tcp", "10.0.0.3", 9000),
            4,
            CapacityLimits::new(100, 1000),
        ))
        .unwrap();
        topo.add_edge(RelayEdge::new("edge", "proxy")).unwrap();
        topo.add_edge(RelayEdge::new("proxy", "terminal")).unwrap();
        topo
    }

    // -----------------------------------------------------------------------
    // Test 1: Basic construction succeeds
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_construction_succeeds() {
        let topo = make_simple_topology();
        let config = RelayConfig::default();
        let mesh = RelayMesh::new(topo, config);

        assert!(mesh.forwarder().max_retries() == 3);
        assert_eq!(mesh.node_count(), 2);
        assert!(!mesh.is_enabled()); // Default config has enabled = false
    }

    // -----------------------------------------------------------------------
    // Test 2: Construction with custom max_retries
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_with_custom_max_retries() {
        let topo = make_simple_topology();
        let config = RelayConfig::default();
        let mesh = RelayMesh::with_max_retries(topo, config, 5);

        assert!(mesh.forwarder().max_retries() == 5);
    }

    // -----------------------------------------------------------------------
    // Test 3: Path computation through mesh
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_find_path_succeeds() {
        let topo = make_simple_topology();
        let config = RelayConfig::builder().enabled(true).build();
        let mesh = RelayMesh::new(topo, config);

        let path = mesh.find_path("src", "dst").unwrap();
        assert_eq!(path.total_hops, 1);
        assert_eq!(path.hops.len(), 2);
        assert_eq!(path.hops[0], "src");
        assert_eq!(path.hops[1], "dst");
    }

    // -----------------------------------------------------------------------
    // Test 4: Multi-hop path computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_multi_hop_path() {
        let topo = make_multi_hop_topology();
        let config = RelayConfig::builder().enabled(true).build();
        let mesh = RelayMesh::new(topo, config);

        let path = mesh.find_path("edge", "terminal").unwrap();
        assert_eq!(path.total_hops, 2);
        assert_eq!(path.hops.len(), 3);
        assert_eq!(path.hops[0], "edge");
        assert_eq!(path.hops[1], "proxy");
        assert_eq!(path.hops[2], "terminal");
    }

    // -----------------------------------------------------------------------
    // Test 5: Node availability check
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_node_availability() {
        let topo = make_simple_topology();
        let config = RelayConfig::default();
        let mesh = RelayMesh::new(topo, config);

        // Nodes start as Healthy by default.
        assert!(mesh.is_node_available("src"));
        assert!(mesh.is_node_available("dst"));
        assert!(!mesh.is_node_available("nonexistent"));
    }

    // -----------------------------------------------------------------------
    // Test 6: Clone is cheap (Arc reference increment)
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_clone() {
        let topo = make_simple_topology();
        let config = RelayConfig::default();
        let mesh = RelayMesh::new(topo, config);

        let cloned = mesh.clone();

        // Both should point to the same underlying data.
        assert_eq!(mesh.node_count(), cloned.node_count());
        assert!(mesh.find_path("src", "dst").is_ok());
        assert!(cloned.find_path("src", "dst").is_ok());
    }

    // -----------------------------------------------------------------------
    // Test 7: Configuration accessors
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_config_accessors() {
        let topo = make_simple_topology();
        let config = RelayConfig::builder()
            .enabled(true)
            .max_hops(10)
            .circuit_breaker_threshold(5)
            .build();
        let mesh = RelayMesh::new(topo, config);

        assert!(mesh.is_enabled());
        assert_eq!(mesh.max_hops(), 10);
        assert_eq!(mesh.circuit_breaker_threshold(), 5);
    }

    // -----------------------------------------------------------------------
    // Test 8: No path returns error
    // -----------------------------------------------------------------------

    #[test]
    fn test_mesh_no_path_returns_error() {
        let mut topo = RelayTopology::new(RouteStrategy::ShortestPath);
        topo.add_node(RelayNode::new(
            "isolated-a",
            NodeRole::Edge,
            EndpointConfig::new("tcp", "10.0.0.1", 8000),
            1,
            CapacityLimits::new(100, 1000),
        ))
        .unwrap();
        topo.add_node(RelayNode::new(
            "isolated-b",
            NodeRole::Terminal,
            EndpointConfig::new("tcp", "10.0.0.2", 9000),
            4,
            CapacityLimits::new(100, 1000),
        ))
        .unwrap();
        // No edge between them — disconnected components.

        let config = RelayConfig::default();
        let mesh = RelayMesh::new(topo, config);

        let result = mesh.find_path("isolated-a", "isolated-b");
        assert!(result.is_err());
    }
}
