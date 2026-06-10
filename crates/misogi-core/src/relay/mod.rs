// ===========================================================================
// Relay Module — Multi-Tier Core Data Structures
// ===========================================================================
//
// This module provides the foundational data types for Misogi's multi-tier
// relay subsystem. It is organized into three sub-modules:
//
// ## Sub-Modules
//
// | Module          | Contents                                                      |
// |-----------------|---------------------------------------------------------------|
// | `node`          | Node roles, endpoints, capacity, health, nodes, and edges.    |
// | `topology`      | Directed graph management (CRUD, validation, route strategy). |
// | `config`        | Global relay configuration with builder pattern.              |
// | `node_manager`  | Node lifecycle, health tracking, circuit breaker orchestration.|
// | `route_planner` | Path computation engine (BFS, strategy dispatch, validation).  |
//
// ## Design Principles
//
// 1. **Pure data types**: All structs are serializable, cloneable, and
//    contain no async runtime dependencies. They can be used in WASM
//    compilation targets and synchronous contexts alike.
// 2. **Referential integrity**: The topology enforces that edges may only
//    reference existing nodes at insertion time. Validation methods detect
//    structural inconsistencies introduced by out-of-band mutations.
// 3. **Defense in depth**: Security policy flags (`require_encryption`,
//    `require_approval`) are attached to edges, enabling fine-grained
//    per-link security controls.
// 4. **Tiered architecture**: Nodes are classified into four tiers (Edge,
//    Proxy, Hub, Terminal) with monotonically increasing responsibility
//    and trust levels.
//
// ## Usage Example
//
// ```ignore
// use misogi_core::relay::*;
//
// // Build a simple edge -> hub topology.
// let mut topo = RelayTopology::new(RouteStrategy::LocalEgressFirst);
// let edge = RelayNode::new("edge-tokyo", NodeRole::Edge,
//     EndpointConfig::new("tls", "10.0.0.1", 8443), 1,
//     CapacityLimits::new(500, 10_000));
// let hub = RelayNode::new("hub-global", NodeRole::Hub,
//     EndpointConfig::new("tls", "10.0.0.100", 9443), 3,
//     CapacityLimits::new(5000, 100_000));
// topo.add_node(edge).unwrap();
// topo.add_node(hub).unwrap();
// topo.add_edge(RelayEdge::new("edge-tokyo", "hub-global")).unwrap();
// assert!(topo.validate().is_ok());
// ```

pub mod config;
#[cfg(test)]
mod config_tests;
pub mod forwarder;
pub mod mesh;
pub mod node;
pub mod node_manager;
pub mod route_planner;
pub mod topology;

// ===========================================================================
// Public Re-exports — Crate-Level Convenience
// ===========================================================================
//
// All public types are re-exported at the module root so consumers can write:
//   `use misogi_core::relay::{RelayNode, RelayTopology};`
// instead of the more verbose:
//   `use misogi_core::relay::node::RelayNode;`

// -- Node & Edge types --
pub use node::{
    CapacityLimits, EndpointConfig, HealthStatus, NodeRole, RelayEdge, RelayEdgeBuilder,
    RelayNode,
};

// -- Topology & Routing types --
pub use topology::{RelayTopology, RouteStrategy};

// -- Configuration types --
pub use config::{ConfigError, RelayConfig, RelayConfigBuilder};

// -- Node Manager types --
pub use node_manager::{CircuitState, RelayNodeManager};

// -- Route Planner types --
pub use route_planner::{RouteError, RoutePath, RoutePlanner};

// -- Forwarder types --
pub use forwarder::{ForwardFileResult, HopResult, RelayForwarder};

// -- Mesh types --
pub use mesh::RelayMesh;
