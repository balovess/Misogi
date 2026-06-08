//! Route Planner — Path Computation Engine for Relay Topology Graph.
//!
//! This module provides [`RoutePlanner`], a deterministic path-finding engine
//! that computes optimal routes through the directed relay topology graph.
//! It supports multiple routing strategies, hop-count constraints, and
//! local egress optimization.
//!
//! # Architecture Overview
//!
//! The planner operates on an immutable snapshot of [`RelayTopology`] held
//! behind `Arc<RwLock<>>`, enabling safe concurrent reads from multiple
//! async tasks without blocking topology mutation operations.
//!
//! # Algorithm Selection
//!
//! | Strategy            | Algorithm                              |
//! |---------------------|----------------------------------------|
//! | `ShortestPath`      | Unweighted BFS (hop-count optimal).    |
//! | `LowestLatency`     | BFS fallback; latency proxy not yet.   |
//! | `LocalEgressFirst`  | Direct-egress probe then BFS fallback. |
//! | `ForceHub`          | Two-phase BFS via mandatory hub(s).    |
//! | `Custom`            | Rejected (not yet implemented).        |
//!
//! # Thread Safety
//!
//! All public methods that read the topology acquire a shared (`read`) lock
//! on the internal `RwLock`. Topology replacement via [`Self::update_topology`]
//! acquires an exclusive (`write`) lock. The lock granularity is at the
//! entire-topology level; fine-grained per-node locking is unnecessary for
//! typical deployment sizes (< 10 000 nodes).
//!
//! # Examples
//!
//! ```ignore
//! use misogi_core::relay::*;
//! use std::sync::Arc;
//!
//! let mut topo = RelayTopology::new(RouteStrategy::LocalEgressFirst);
//! // ... populate nodes and edges ...
//! let planner = RoutePlanner::with_topology(topo);
//! let path = planner.find_path("edge-tokyo", "terminal-s3")?;
//! println!("Route: {:?}", path.hops);
//! ```

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

use thiserror::Error;

use crate::relay::node::RelayEdge;
use crate::relay::topology::{RelayTopology, RouteStrategy};

// ===========================================================================
// RoutePath
// ===========================================================================

/// Computed route through the relay topology graph.
///
/// Represents an ordered sequence of node identifiers forming a valid
/// path from source to destination, along with aggregate metadata about
/// the path's characteristics.
///
/// # Invariants
///
/// - `hops` is never empty (minimum length is 1 for source == target).
/// - `total_hops` equals `hops.len().saturating_sub(1)` (edge count).
/// - `hops[0]` is the source node; `hops[last]` is the target node.
///
/// # Serialization
///
/// This struct derives `Clone` but intentionally does **not** derive
/// `Serialize`/`Deserialize`. Paths are computed ephemeral results;
/// persisting them would create stale routing state if the topology
/// changes between serialization and deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePath {
    /// Ordered list of node identifiers from source to target (inclusive).
    ///
    /// Each consecutive pair `(hops[i], hops[i+1])` must have a corresponding
    /// directed edge in the topology graph.
    pub hops: Vec<String>,

    /// Number of edges traversed (hops.len() - 1).
    ///
    /// A value of `0` indicates the degenerate case where source equals target.
    pub total_hops: u8,

    /// Estimated end-to-end latency in milliseconds.
    ///
    /// Currently computed as a placeholder value (`total_hops * 10`) since
    /// real-time latency measurements are not yet integrated. Future versions
    /// will query the monitoring subsystem for per-edge RTT data.
    pub estimated_latency_ms: u64,

    /// Indicates whether any edge in this path mandates encryption.
    ///
    /// Set to `true` if at least one traversed edge has
    /// [`RelayEdge::require_encryption`] equal to `true`.
    pub requires_encryption: bool,

    /// Indicates whether any edge in this path requires administrative approval.
    ///
    /// Set to `true` if at least one traversed edge has
    /// [`RelayEdge::require_approval`] equal to `true`.
    pub requires_approval: bool,
}

impl RoutePath {
    /// Returns `true` if this path consists of a single node (source == target).
    #[inline]
    pub fn is_trivial(&self) -> bool {
        self.total_hops == 0
    }
}

// ===========================================================================
// RouteError
// ===========================================================================

/// Error type returned by all [`RoutePlanner`] path-computation methods.
///
/// These errors represent structural or logical failures during route
/// computation, distinct from system-level errors (I/O failures, timeout,
/// etc.). Every variant carries sufficient context for operator diagnostics
/// and automated retry/orchestration logic.
#[derive(Error, Debug)]
pub enum RouteError {
    /// The specified node identifier was not found in the current topology.
    ///
    /// This typically indicates a stale node reference (node was removed
    /// after the caller cached its ID) or a typo in the identifier string.
    #[error("node '{0}' not found in topology")]
    NodeNotFound(String),

    /// No valid path exists between the specified source and target nodes.
    ///
    /// This occurs when the source and target are in disconnected components
    /// of the directed graph, or when all paths exceed the configured
    /// [`RoutePlanner::max_hops`] limit.
    #[error("no path exists from '{source}' to '{target}'")]
    NoPath {
        /// Source node identifier that was queried.
        source: String,
        /// Target node identifier that was queried.
        target: String,
    },

    /// The computed path exceeds the maximum allowed hop count.
    ///
    /// This is a policy violation rather than a graph connectivity issue:
    /// a path exists but is rejected because it is too long. Operators
    /// should consider adding shortcut edges or relaxing the limit.
    #[error("path exceeds maximum allowed hops (max={max}, actual={actual})")]
    MaxHopsExceeded {
        /// Configured maximum hop count (from [`RoutePlanner::max_hops`]).
        max: u8,
        /// Actual hop count of the computed path.
        actual: u8,
    },

    /// The provided path fails structural validation against the topology.
    ///
    /// Possible causes: missing edge between consecutive nodes, non-existent
    /// node reference, or empty hop list.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// The requested routing strategy is not supported by this planner version.
    ///
    /// Currently only triggered by [`RouteStrategy::Custom(_)`]; all other
    /// variants are fully implemented.
    #[error("routing strategy '{0}' not supported")]
    UnsupportedStrategy(String),
}

// ===========================================================================
// RoutePlanner
// ===========================================================================

/// Deterministic path computation engine for relay topology graphs.
///
/// Encapsulates a snapshot of [`RelayTopology`] behind `Arc<RwLock<>>`
/// and provides strategy-dispatched path-finding methods. All public
/// API methods are safe for concurrent invocation from multiple threads
/// or async tasks.
///
/// # Lifecycle
///
/// 1. Construct via [`Self::new`] or [`Self::with_topology`].
/// 2. Query paths via [`Self::find_path`] or [`Self::find_path_with_strategy`].
/// 3. Optionally validate computed paths via [`Self::validate_path`].
/// 4. Update topology/strategy at runtime via [`Self::update_topology`] /
///    [`Self::update_strategy`].
///
/// # Hop Count Limit
///
/// The `max_hops` field constrains all computed paths to at most `max_hops`
/// edges. This prevents runaway path expansion in dense topologies and
/// enforces operational policy limits. The default value is `5`; values
/// in the range `3..=15` are typical for production deployments.
///
/// # Performance Characteristics
//!
/// | Operation              | Complexity         | Lock Type |
/// |------------------------|--------------------|-----------|
/// | `find_path`            | O(V + E)           | Read      |
/// | `find_path_with_strategy` | O(V + E)       | Read      |
/// | `check_local_egress`   | O(E_from_source)   | Read      |
/// | `validate_path`        | O(P * E_lookup)    | Read      |
/// | `update_topology`      | O(1)               | Write     |
/// | `update_strategy`      | O(1)               | None      |
///
/// Where V = node count, E = edge count, P = path length.
pub struct RoutePlanner {
    /// Shared topology graph protected by reader-writer lock.
    ///
    /// `RwLock` (std) is used instead of `parking_lot::RwLock` to avoid
    /// adding a dependency solely for this module. Poisoning is recovered
    /// via `unwrap()` on lock acquisition (poison indicates a panic in
    /// a prior holder, which is a bug that should be surfaced immediately).
    topology: Arc<RwLock<RelayTopology>>,

    /// Active routing strategy used by [`Self::find_path_with_strategy`].
    ///
    /// May be updated at runtime via [`Self::update_strategy`] without
    /// acquiring any lock (atomic swap on a `Copy` type).
    strategy: RouteStrategy,

    /// Maximum number of edges permitted in any computed path.
    ///
    /// Paths exceeding this limit are rejected with
    /// [`RouteError::MaxHopsExceeded`]. Must be >= 1.
    max_hops: u8,
}

impl RoutePlanner {
    /// Constructs a new route planner with explicit parameters.
    ///
    /// # Parameters
    ///
    /// - `topology`: Initial topology graph. Cloned into `Arc<RwLock<>>`
    ///   for thread-safe sharing.
    /// - `strategy`: Default routing strategy for
    ///   [`Self::find_path_with_strategy`].
    /// - `max_hops`: Maximum permissible edge count per path. Values < 1
    ///   are clamped to 1 (single-hop-only mode).
    ///
    /// # Returns
    ///
    /// A fully initialized [`RoutePlanner`] ready for path queries.
    pub fn new(topology: RelayTopology, strategy: RouteStrategy, max_hops: u8) -> Self {
        Self {
            topology: Arc::new(RwLock::new(topology)),
            strategy,
            max_hops: max_hops.max(1),
        }
    }

    /// Constructs a route planner with sensible defaults.
    ///
    /// Uses [`RouteStrategy::LocalEgressFirst`] as the default strategy
    /// and `5` as the maximum hop count. This constructor is recommended
    /// for most deployments that do not require custom tuning.
    ///
    /// # Parameters
    ///
    /// - `topology`: Initial topology graph.
    ///
    /// # Returns
    ///
    /// A [`RoutePlanner`] equivalent to:
    /// ```ignore
    /// RoutePlanner::new(topology, RouteStrategy::LocalEgressFirst, 5)
    /// ```
    pub fn with_topology(topology: RelayTopology) -> Self {
        Self::new(topology, RouteStrategy::LocalEgressFirst, 5)
    }

    // -----------------------------------------------------------------------
    // Core Path Finding — Unweighted BFS (Dijkstra for uniform cost)
    // -----------------------------------------------------------------------

    /// Computes the shortest path (by hop count) between two nodes.
    ///
    /// Uses breadth-first search (BFS) over the directed adjacency list,
    /// which yields the optimal unweighted shortest path in O(V + E) time.
    /// This is equivalent to Dijkstra's algorithm with uniform edge weight = 1.
    ///
    /// # Parameters
    ///
    /// - `source`: Identifier of the starting node.
    /// - `target`: Identifier of the destination node.
    ///
    /// # Errors
    ///
    /// - [`RouteError::NodeNotFound`] if either endpoint does not exist.
    /// - [`RouteError::NoPath`] if no directed path connects the endpoints.
    /// - [`RouteError::MaxHopsExceeded`] if the shortest path exceeds
    ///   [`self.max_hops`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let path = planner.find_path("edge-tokyo", "hub-global")?;
    /// assert!(path.total_hops <= planner.max_hops());
    /// ```
    pub fn find_path(&self, source: &str, target: &str) -> Result<RoutePath, RouteError> {
        let topo = self.topology.read().unwrap();

        // Validate existence of both endpoints.
        if topo.get_node(source).is_none() {
            return Err(RouteError::NodeNotFound(source.to_string()));
        }
        if topo.get_node(target).is_none() {
            return Err(RouteError::NodeNotFound(target.to_string()));
        }

        // Degenerate case: source equals target.
        if source == target {
            return Ok(RoutePath {
                hops: vec![source.to_string()],
                total_hops: 0,
                estimated_latency_ms: 0,
                requires_encryption: false,
                requires_approval: false,
            });
        }

        // Build adjacency map for O(1) neighbor lookup during BFS.
        let adj: HashMap<&str, Vec<&RelayEdge>> = topo
            .nodes
            .iter()
            .map(|n| (n.node_id.as_str(), topo.get_edges_from(&n.node_id)))
            .collect();

        // BFS traversal: (current_node, path_so_far)
        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<(Vec<String>, u8)> = VecDeque::new();

        visited.insert(source);
        queue.push_back((vec![source.to_string()], 0));

        while let Some((mut current_path, depth)) = queue.pop_front() {
            let current = current_path.last().expect("non-empty path");

            // Explore neighbors.
            if let Some(neighbors) = adj.get(current.as_str()) {
                for edge in neighbors {
                    let next = &edge.to_node;

                    if visited.contains(next.as_str()) {
                        continue;
                    }

                    let new_depth = depth + 1;

                    // Early termination if we've exceeded max_hops.
                    if new_depth > self.max_hops {
                        continue;
                    }

                    // Check if we reached the target.
                    if next == target {
                        current_path.push(next.clone());

                        // Aggregate edge metadata along the final path.
                        let (requires_encryption, requires_approval) =
                            self.aggregate_edge_metadata(&topo, &current_path);

                        return Ok(RoutePath {
                            total_hops: new_depth,
                            estimated_latency_ms: (new_depth as u64) * 10,
                            requires_encryption,
                            requires_approval,
                            hops: current_path,
                        });
                    }

                    visited.insert(next.as_str());
                    let mut extended = current_path.clone();
                    extended.push(next.clone());
                    queue.push_back((extended, new_depth));
                }
            }
        }

        // BFS exhausted without finding target.
        Err(RouteError::NoPath {
            source: source.to_string(),
            target: target.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Strategy-Dispatched Path Finding
    // -----------------------------------------------------------------------

    /// Computes a path using the planner's currently configured strategy.
    ///
    /// Dispatches to the appropriate algorithm based on [`self.strategy`]:
    ///
    /// | Strategy             | Behavior                                           |
    /// |----------------------|----------------------------------------------------|
    /// | `ShortestPath`       | Delegates to [`Self::find_path`].                  |
    /// | `LowestLatency`      | Delegates to [`Self::find_lowest_latency_path`].  |
    /// | `LocalEgressFirst`   | Tries [`Self::check_local_egress`] first; falls   |
    /// |                      | back to [`Self::find_path`] on `None`.            |
    /// | `ForceHub(hub_ids)`  | Two-phase path through a mandatory hub node.       |
    /// | `Custom(name)`       | Returns [`RouteError::UnsupportedStrategy`].       |
    ///
    /// # Parameters
    ///
    /// - `source`: Identifier of the starting node.
    /// - `target`: Identifier of the destination node.
    ///
    /// # Errors
    ///
    /// Propagates errors from the dispatched method, plus
    /// [`RouteError::UnsupportedStrategy`] for unimplemented strategies.
    pub fn find_path_with_strategy(
        &self,
        source: &str,
        target: &str,
    ) -> Result<RoutePath, RouteError> {
        match &self.strategy {
            RouteStrategy::ShortestPath => self.find_path(source, target),
            RouteStrategy::LowestLatency => self.find_lowest_latency_path(source, target),
            RouteStrategy::LocalEgressFirst => {
                match self.check_local_egress(source, target)? {
                    Some(path) => Ok(path),
                    None => self.find_path(source, target),
                }
            }
            RouteStrategy::ForceHub(hub_ids) => {
                self.find_forced_hub_path(source, target, hub_ids)
            }
            RouteStrategy::Custom(name) => Err(RouteError::UnsupportedStrategy(
                format!("custom routing '{name}' not yet implemented"),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Local Egress Check
    // -----------------------------------------------------------------------

    /// Checks whether the source node has a direct local-egress edge to target.
    ///
    /// A local egress path is eligible when **both** conditions hold:
    ///
    /// 1. A directed edge exists from `source` -> `target` in the topology.
    /// 2. `target` appears in the source node's `local_egress_targets` list.
    ///
    /// When both conditions are satisfied, returns `Some(RoutePath)` representing
    /// a single-hop path. Otherwise returns `None`, indicating the caller
    /// should fall back to general-purpose routing (e.g., [`Self::find_path`]).
    ///
    /// # Parameters
    ///
    /// - `source`: Identifier of the source node to check egress targets for.
    /// - `target`: Identifier of the potential egress destination.
    ///
    /// # Errors
    ///
    /// - [`RouteError::NodeNotFound`] if `source` does not exist in topology.
    ///
    /// # Design Rationale
    ///
    /// Local egress optimization avoids multi-hop upstreaming for traffic
    /// destined to nearby peers (same datacenter, same LAN segment). This
    /// reduces both latency and cross-region bandwidth consumption, which is
    /// the primary cost driver for large-scale relay deployments.
    pub fn check_local_egress(
        &self,
        source: &str,
        target: &str,
    ) -> Result<Option<RoutePath>, RouteError> {
        let topo = self.topology.read().unwrap();

        let source_node = topo
            .get_node(source)
            .ok_or_else(|| RouteError::NodeNotFound(source.to_string()))?;

        // Condition 1: target must be in source's local_egress_targets.
        let is_local_target = source_node
            .local_egress_targets
            .iter()
            .any(|t| t == target);

        if !is_local_target {
            return Ok(None);
        }

        // Condition 2: directed edge must exist from source -> target.
        let direct_edge = topo
            .get_edges_from(source)
            .into_iter()
            .find(|e| e.to_node == target);

        match direct_edge {
            Some(edge) => Ok(Some(RoutePath {
                hops: vec![source.to_string(), target.to_string()],
                total_hops: 1,
                estimated_latency_ms: 10,
                requires_encryption: edge.require_encryption,
                requires_approval: edge.require_approval,
            })),
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Path Validation
    // -----------------------------------------------------------------------

    /// Validates a computed path against the current topology state.
    ///
    /// Performs three categories of checks:
    ///
    /// 1. **Connectivity**: Every consecutive pair `(hops[i], hops[i+1])`
    ///    must have a corresponding directed edge in the topology.
    /// 2. **Policy compliance**: Logs a warning if any edge requires
    ///    encryption (cannot cryptographically verify at this layer).
    /// 3. **Length constraint**: Total hop count must not exceed
    ///    [`self.max_hops`].
    ///
    /// # Parameters
    ///
    /// - `path`: The [`RoutePath`] to validate.
    ///
    /// # Errors
    ///
    /// - [`RouteError::InvalidPath`] if any check fails.
    ///
    /// # Note on Encryption Verification
    ///
    /// Encryption requirement is flagged via `log::warn!` rather than
    /// returning an error. The route planner operates at the graph-theoretic
    /// layer and cannot perform cryptographic handshake verification.
    /// That responsibility belongs to the transport/session layer.
    pub fn validate_path(&self, path: &RoutePath) -> Result<(), RouteError> {
        let topo = self.topology.read().unwrap();

        // Check 1: Empty path is invalid.
        if path.hops.is_empty() {
            return Err(RouteError::InvalidPath(
                "path contains no hops".to_string(),
            ));
        }

        // Check 2: Length constraint.
        if path.total_hops > self.max_hops {
            return Err(RouteError::MaxHopsExceeded {
                max: self.max_hops,
                actual: path.total_hops,
            });
        }

        // Check 3: Edge-by-edge connectivity verification.
        for window in path.hops.windows(2) {
            let from = &window[0];
            let to = &window[1];

            let edge_exists = topo
                .get_edges_from(from)
                .into_iter()
                .any(|e| e.to_node == *to);

            if !edge_exists {
                return Err(RouteError::InvalidPath(format!(
                    "no edge from '{from}' to '{to}'"
                )));
            }

            // Policy warning: log (do not error) for encryption requirements.
            if let Some(edge) = topo.get_edges_from(from).into_iter().find(|e| e.to_node == *to) {
                if edge.require_encryption {
                    log::warn!(
                        "route_planner: edge '{}'->'{}' requires encryption; \
                         ensure transport layer negotiates TLS",
                        from, to
                    );
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Runtime Mutation
    // -----------------------------------------------------------------------

    /// Replaces the active routing strategy.
    ///
    /// This is a lock-free operation (strategy field is not protected by
    /// `RwLock`). Concurrent readers may observe either the old or new
    /// strategy during the transition window; this is acceptable because
    /// strategy changes are infrequent (operator-initiated) and the
    /// inconsistency window is sub-nanosecond.
    ///
    /// # Parameters
    ///
    /// - `strategy`: New routing strategy to install.
    pub fn update_strategy(&mut self, strategy: RouteStrategy) {
        self.strategy = strategy;
    }

    /// Atomically replaces the entire topology graph.
    ///
    /// Acquires an exclusive write lock on the internal `RwLock`, swaps
    /// the topology contents, and releases the lock. Readers blocked on
    /// the read lock will observe the new topology once they acquire it.
    ///
    /// # Parameters
    ///
    /// - `topology`: New topology graph to install.
    ///
    /// # Warning
    ///
    /// Callers must ensure the new topology is validated (via
    /// [`RelayTopology::validate`]) before passing it here. Installing
    /// an invalid topology will cause all subsequent path computations
    /// to fail or produce incorrect results.
    pub fn update_topology(&self, topology: RelayTopology) {
        let mut guard = self.topology.write().unwrap();
        *guard = topology;
    }

    /// Returns the current maximum hop count setting.
    #[inline]
    pub fn max_hops(&self) -> u8 {
        self.max_hops
    }

    /// Returns the current routing strategy (clone for inspection).
    #[inline]
    pub fn strategy(&self) -> &RouteStrategy {
        &self.strategy
    }

    // ======================================================================
    // Private Helper Methods
    // ======================================================================

    /// Computes lowest-latency path using hop count as proxy metric.
    ///
    /// Currently delegates to [`Self::find_path`] because real-time
    /// per-edge latency measurements are not yet available from the
    /// monitoring subsystem. Future integration points:
    ///
    /// - Query `LatencyRegistry` for per-edge RTT samples.
    /// - Apply weighted Dijkstra with RTT as edge weight.
    /// - Fall back to hop-count BFS when latency data is stale (> 30 s).
    fn find_lowest_latency_path(
        &self,
        source: &str,
        target: &str,
    ) -> Result<RoutePath, RouteError> {
        // TODO(#route-latency): Integrate with monitoring subsystem to obtain
        // per-edge RTT measurements. For now, hop-count BFS serves as a
        // reasonable proxy: fewer hops generally correlate with lower latency.
        self.find_path(source, target)
    }

    /// Computes a path that passes through at least one mandatory hub node.
    ///
    /// Implements two-phase BFS:
    ///
    /// **Phase 1**: Find shortest path from `source` to any hub in `hub_ids`.
    /// **Phase 2**: Find shortest path from that hub to `target`.
    ///
    /// The two phases are concatenated (deduplicating the hub node) to form
    /// the complete path. If multiple hubs are viable, the one yielding the
    /// minimum total hop count is selected.
    ///
    /// # Parameters
    ///
    /// - `source`: Starting node.
    /// - `target`: Destination node.
    /// - `hub_ids`: Ordered list of candidate hub node IDs (tried in order;
    ///   first feasible hub wins for performance; exhaustive search would
    ///   try all hubs and pick the globally optimal one).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::find_path`] if either phase fails.
    fn find_forced_hub_path(
        &self,
        source: &str,
        target: &str,
        hub_ids: &[String],
    ) -> Result<RoutePath, RouteError> {
        if hub_ids.is_empty() {
            return Err(RouteError::InvalidPath(
                "ForceHub strategy requires at least one hub ID".to_string(),
            ));
        }

        let mut best_path: Option<RoutePath> = None;
        let mut best_hop_count: u8 = u8::MAX;

        for hub_id in hub_ids {
            // Phase 1: source -> hub
            let phase1 = match self.find_path(source, hub_id) {
                Ok(p) => p,
                Err(_) => continue, // This hub unreachable; try next.
            };

            // Phase 2: hub -> target
            let phase2 = match self.find_path(hub_id, target) {
                Ok(p) => p,
                Err(_) => continue, // Target unreachable from this hub.
            };

            // Concatenate phases (deduplicate hub at boundary).
            let combined = self.concatenate_paths(phase1, phase2);

            // Track the best (shortest) path across all hub candidates.
            if combined.total_hops < best_hop_count {
                best_hop_count = combined.total_hops;
                best_path = Some(combined);
            }
        }

        best_path.ok_or(RouteError::NoPath {
            source: source.to_string(),
            target: target.to_string(),
        })
    }

    /// Concatenates two paths, deduplicating the overlapping junction node.
    ///
    /// Given `phase1 = [A, B, C]` and `phase2 = [C, D, E]`, produces
    /// `[A, B, C, D, E]` (the shared node `C` appears once).
    ///
    /// # Preconditions
    ///
    /// - `phase1.hops.last() == phase2.hops.first()` (junction node match).
    /// - Both paths are non-empty.
    fn concatenate_paths(&self, mut phase1: RoutePath, phase2: RoutePath) -> RoutePath {
        let junction = phase2.hops.first().expect("non-empty phase2");

        // Sanity check: last node of phase1 must equal first of phase2.
        debug_assert_eq!(
            phase1.hops.last().expect("non-empty phase1"),
            junction,
            "concatenate_paths: junction mismatch"
        );

        // Append phase2's tail (skip the duplicated junction node).
        for hop in phase2.hops.iter().skip(1) {
            phase1.hops.push(hop.clone());
        }

        // Recompute aggregate metadata.
        let (requires_encryption, requires_approval) = {
            let topo = self.topology.read().unwrap();
            self.aggregate_edge_metadata(&topo, &phase1.hops)
        };

        RoutePath {
            total_hops: (phase1.hops.len().saturating_sub(1)) as u8,
            estimated_latency_ms: (phase1.total_hops as u64 + phase2.total_hops as u64) * 10,
            requires_encryption,
            requires_approval,
            hops: phase1.hops,
        }
    }

    /// Aggregates encryption and approval flags across all edges in a path.
    ///
    /// Scans each consecutive pair in `hops` and checks whether the
    /// corresponding edge has `require_encryption` or `require_approval`
    /// set to `true`. Returns a tuple of booleans indicating whether
    /// ANY edge in the path triggers each flag.
    ///
    /// # Parameters
    ///
    /// - `topo`: Topology read lock guard (borrowed).
    /// - `hops`: Ordered node ID list defining the path.
    ///
    /// # Returns
    ///
    /// `(requires_encryption, requires_approval)` where each is `true`
    /// if at least one traversed edge has the corresponding flag set.
    fn aggregate_edge_metadata<'a>(
        &self,
        topo: &RelayTopology,
        hops: &[String],
    ) -> (bool, bool) {
        let mut enc = false;
        let mut appr = false;

        for window in hops.windows(2) {
            if let Some(edge) = topo
                .get_edges_from(&window[0])
                .into_iter()
                .find(|e| e.to_node == window[1])
            {
                enc = enc || edge.require_encryption;
                appr = appr || edge.require_approval;
            }
        }

        (enc, appr)
    }
}
