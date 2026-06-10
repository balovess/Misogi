// ===========================================================================
// Relay Node Manager — Lifecycle, Health, and Circuit Breaker Orchestration
// ===========================================================================
//
// Provides `RelayNodeManager`, the central orchestrator for managing relay
// node lifecycles within a multi-tier relay mesh.
//
// # Responsibilities
//
//   - Node registration / deregistration with topology integration.
//   - Per-node failure counting and circuit breaker state machine.
//   - Health status propagation with automatic counter/circuit-breaker updates.
//   - Node availability queries combining health + circuit-breaker state.
//   - Healthy/routable node filtering for route computation consumers.
//
// # Circuit Breaker State Machine (per-node)
//
// ```text
//                  threshold reached          cooldown elapsed
//   Closed ──────────────► Open ───────────────────► HalfOpen
//      ▲                       │                        │
//      │                       │  failure in probe       │ success in probe
//      └───────────────────────┴────────────────────────┘
//              (reset / recovery confirmed)
// ```
//
// # Thread Safety
//
// `RelayNodeManager` is NOT thread-safe; wrap in `Arc<RwLock<...>>` for
// concurrent access. The topology is exposed as `Arc<RwLock<RelayTopology>>`
// for shared read access across routing tasks.

#[cfg(test)]
#[path = "node_manager_tests.rs"]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use super::config::RelayConfig;
use super::node::{HealthStatus, RelayNode};
use super::topology::{RelayTopology, RouteStrategy};

// ===========================================================================
// CircuitState
// ===========================================================================

/// Current state of a per-node circuit breaker.
///
/// Implements the classic three-state pattern used to prevent cascading
/// failures across the relay mesh when individual nodes become unresponsive.
///
/// | From      | To        | Trigger                                      |
/// |-----------|-----------|----------------------------------------------|
/// | `Closed`  | `Open`    | Consecutive failures >= threshold             |
/// | `Open`    | `HalfOpen`| Cooldown period elapsed since last trip       |
/// | `HalfOpen`| `Closed`  | Probe request succeeded                     |
/// | `HalfOpen`| `Open`    | Probe request failed                         |
/// | *any*     | `Closed`  | Explicit health reset via [`HealthStatus::Healthy`] |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation; all requests forwarded. Counter increments on each
    /// failure but routing is unaffected until threshold is reached.
    Closed,

    /// Blocking state; requests rejected without reaching the node.
    /// Transitions to [`Self::HalfOpen`] after cooldown elapses.
    Open,

    /// Probing state; one request allowed to test recovery.
    /// On success -> [`Self::Closed`]; on failure -> [`Self::Open`].
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "CLOSED"),
            Self::Open => write!(f, "OPEN"),
            Self::HalfOpen => write!(f, "HALF_OPEN"),
        }
    }
}

// ===========================================================================
// CircuitBreakerEntry (internal)
// ===========================================================================

/// Internal bookkeeping combining [`CircuitState`] with timing metadata for
/// automatic Open -> HalfOpen transitions based on elapsed time.
#[derive(Debug)]
struct CircuitBreakerEntry {
    state: CircuitState,
    opened_at: Option<Instant>,
}

impl CircuitBreakerEntry {
    fn closed() -> Self {
        Self { state: CircuitState::Closed, opened_at: None }
    }

    fn trip(&mut self) {
        self.state = CircuitState::Open;
        self.opened_at = Some(Instant::now());
    }

    fn enter_half_open(&mut self) {
        self.state = CircuitState::HalfOpen;
        self.opened_at = None;
    }

    fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.opened_at = None;
    }

    #[inline]
    fn state(&self) -> &CircuitState { &self.state }

    fn open_duration(&self) -> Option<std::time::Duration> {
        self.opened_at.map(|i| i.elapsed())
    }
}

// ===========================================================================
// RelayNodeManager
// ===========================================================================

/// Central orchestrator for relay node lifecycle management.
///
/// Wraps a [`RelayTopology`] and augments it with per-node failure tracking,
/// circuit breaker state machines, and health-aware node selection APIs.
/// This is the primary interface used by the relay routing layer to obtain
/// candidate nodes for path computation.
///
/// # Ownership Model
///
/// The manager owns the topology exclusively via `Arc<RwLock<...>>` and provides
/// accessor methods for read-only sharing. All mutations go through the manager's
/// own methods which maintain consistency between the topology graph and auxiliary
/// tracking maps (`failure_counters`, `circuit_breaker_state`).
///
/// # Two-Layer Protection
///
/// 1. **Failure counters** (`HashMap<String, u32>`): Integer counts of consecutive
///    failures per node. Reset on success or healthy status update.
/// 2. **Circuit breakers**: State machines that block traffic once the failure
///    counter exceeds `circuit_breaker_threshold`. Auto-recovers via HalfOpen.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::*;
///
/// let mut mgr = RelayNodeManager::new(RelayConfig::default());
/// let node = RelayNode::new("edge-tokyo", NodeRole::Edge,
///     EndpointConfig::new("tls", "10.0.0.1", 8443), 1,
///     CapacityLimits::new(500, 10_000));
/// assert!(mgr.register_node(node).is_ok());
/// assert!(mgr.is_available("edge-tokyo"));
/// ```
#[derive(Debug)]
pub struct RelayNodeManager {
    /// Managed topology graph (shared read access via `Arc<RwLock<...>>`).
    topology: Arc<RwLock<RelayTopology>>,
    /// Global relay configuration governing behavior thresholds.
    config: RelayConfig,
    /// Per-node consecutive failure counters (reset on success/healthy recovery).
    failure_counters: HashMap<String, u32>,
    /// Per-node circuit breaker state machines with timing metadata.
    circuit_breaker_state: HashMap<String, CircuitBreakerEntry>,
}

// -----------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Constructs a new manager with an empty topology using
    /// [`RouteStrategy::default_strategy()`] (`LocalEgressFirst`).
    ///
    /// No nodes are present initially; call [`Self::register_node`] to populate.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            topology: Arc::new(RwLock::new(RelayTopology::new(
                RouteStrategy::default_strategy(),
            ))),
            config,
            failure_counters: HashMap::new(),
            circuit_breaker_state: HashMap::new(),
        }
    }

    /// Constructs a new manager wrapping an existing pre-populated topology.
    ///
    /// Failure counters and circuit breaker states are NOT pre-populated
    /// for existing nodes; they are initialized lazily on first operation.
    pub fn with_topology(config: RelayConfig, topology: RelayTopology) -> Self {
        Self {
            topology: Arc::new(RwLock::new(topology)),
            config,
            failure_counters: HashMap::new(),
            circuit_breaker_state: HashMap::new(),
        }
    }
}

// -----------------------------------------------------------------------
// Node Registration / Deregistration
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Registers a node into the topology, initializing its failure counter to 0
    /// and circuit breaker to [`CircuitState::Closed`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if a node with the same `node_id` already exists.
    pub fn register_node(&mut self, node: RelayNode) -> Result<(), String> {
        let id = node.node_id.clone();
        self.topology.write().unwrap().add_node(node)?;
        self.failure_counters.insert(id.clone(), 0);
        self.circuit_breaker_state.insert(id, CircuitBreakerEntry::closed());
        Ok(())
    }

    /// Removes a node from the topology and cleans up all tracking state.
    ///
    /// Returns `Some(RelayNode)` if found, `None` otherwise.
    /// Does **not** remove edges referencing this node; callers must handle
    /// edge cleanup separately.
    pub fn unregister_node(&mut self, node_id: &str) -> Option<RelayNode> {
        let removed = self.topology.write().unwrap().remove_node(node_id)?;
        self.failure_counters.remove(node_id);
        self.circuit_breaker_state.remove(node_id);
        Some(removed)
    }
}

// -----------------------------------------------------------------------
// Health Management
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Updates a node's health status and propagates effects:
    ///
    /// | Status       | Failure Counter | Circuit Breaker               |
    /// |-------------|-----------------|------------------------------|
    /// | `Healthy`    | Reset to 0      | Force to `Closed`             |
    /// | `Degraded`   | Increment +1    | Trip if >= threshold         |
    /// | `Unhealthy`  | Increment +1    | Trip if >= threshold         |
    ///
    /// # Errors
    ///
    /// Returns `Err` if `node_id` is not found in the topology.
    pub fn update_node_health(&mut self, node_id: &str, status: HealthStatus) -> Result<(), String> {
        let mut topo = self.topology.write().unwrap();
        let node = topo.nodes.iter_mut()
            .find(|n| n.node_id == node_id)
            .ok_or_else(|| format!("node '{node_id}' not found in topology"))?;
        node.health_status = status.clone();
        drop(topo); // Release lock before touching tracking maps.

        match status {
            HealthStatus::Healthy => self.reset_node_tracking(node_id),
            HealthStatus::Degraded | HealthStatus::Unhealthy => self.increment_and_maybe_trip(node_id),
        }
        Ok(())
    }

    /// Resets both failure counter (to 0) and circuit breaker (to Closed).
    fn reset_node_tracking(&mut self, node_id: &str) {
        if let Some(c) = self.failure_counters.get_mut(node_id) { *c = 0; }
        if let Some(e) = self.circuit_breaker_state.get_mut(node_id) { e.reset(); }
    }

    /// Increments failure counter; trips circuit breaker if >= threshold.
    fn increment_and_maybe_trip(&mut self, node_id: &str) {
        let count = self.failure_counters.entry(node_id.to_string()).or_insert(0);
        *count += 1;
        let threshold = self.config.circuit_breaker_threshold;
        if *count >= threshold && threshold > 0 {
            if let Some(entry) = self.circuit_breaker_state.get_mut(node_id) {
                if entry.state() != &CircuitState::Open { entry.trip(); }
            }
        }
    }
}

// -----------------------------------------------------------------------
// Node Selection Queries
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Returns nodes where health != Unhealthy AND circuit breaker != Open,
    /// sorted by tier ascending (owned clones).
    pub fn get_healthy_nodes(&self) -> Vec<RelayNode> {
        let topo = self.topology.read().unwrap();
        let mut result: Vec<RelayNode> = topo.nodes.iter()
            .filter(|n| !n.health_status.is_unhealthy()
                && !self.is_circuit_open(&n.node_id))
            .cloned()
            .collect();
        result.sort_by_key(|n| n.tier);
        result
    }

    /// Returns references to nodes that are Healthy OR Degraded (not Unhealthy)
    /// AND whose circuit breakers are not Open.
    ///
    /// Note: Returns cloned nodes to avoid lifetime issues with the RwLock guard.
    /// For large topologies, consider using [`Self::get_routable_nodes_sorted`] instead.
    pub fn get_routable_nodes(&self) -> Vec<RelayNode> {
        let topo = self.topology.read().unwrap();
        topo.nodes.iter()
            .filter(|n| !n.health_status.is_unhealthy()
                && !self.is_circuit_open(&n.node_id))
            .cloned()
            .collect()
    }

    /// Returns true if the given node's circuit breaker is in Open state.
    fn is_circuit_open(&self, node_id: &str) -> bool {
        self.circuit_breaker_state.get(node_id)
            .map_or(false, |e| e.state() == &CircuitState::Open)
    }
}

// -----------------------------------------------------------------------
// Success / Failure Reporting
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Reports success against a node: resets failure counter to 0,
    /// and closes the circuit if currently HalfOpen (recovery confirmed).
    ///
    /// Silent no-op if the node is not registered.
    pub fn report_success(&mut self, node_id: &str) {
        if let Some(c) = self.failure_counters.get_mut(node_id) { *c = 0; }
        if let Some(e) = self.circuit_breaker_state.get_mut(node_id) {
            if e.state() == &CircuitState::HalfOpen { e.reset(); }
        }
    }

    /// Reports failure against a node: increments failure counter,
    /// trips circuit breaker at threshold, and re-trips immediately if
    /// currently in HalfOpen (probe failed).
    ///
    /// Silent no-op if the node is not registered.
    pub fn report_failure(&mut self, node_id: &str) {
        let count = self.failure_counters.entry(node_id.to_string()).or_insert(0);
        *count += 1;

        // Immediate re-trip from HalfOpen.
        if let Some(e) = self.circuit_breaker_state.get_mut(node_id) {
            if e.state() == &CircuitState::HalfOpen { e.trip(); return; }
        }

        // Threshold-based trip.
        let threshold = self.config.circuit_breaker_threshold;
        if threshold > 0 {
            if let Some(cv) = self.failure_counters.get(node_id) {
                if *cv >= threshold {
                    if let Some(e) = self.circuit_breaker_state.get_mut(node_id) {
                        if e.state() != &CircuitState::Open { e.trip(); }
                    }
                }
            }
        }
    }
}

// -----------------------------------------------------------------------
// Circuit Breaker Inspection & Availability
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Returns the current circuit breaker state, applying automatic
    /// Open -> HalfOpen transition if cooldown has elapsed.
    ///
    /// **Cooldown policy**: The circuit remains Open for
    /// `3 * heartbeat_interval_secs` seconds before transitioning to HalfOpen.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the node has no circuit breaker entry (not registered).
    pub fn circuit_breaker(&mut self, node_id: &str) -> Result<CircuitState, String> {
        let entry = self.circuit_breaker_state.get_mut(node_id)
            .ok_or_else(|| format!("node '{node_id}' has no circuit breaker entry"))?;

        if entry.state() == &CircuitState::Open {
            if let Some(dur) = entry.open_duration() {
                let cooldown = std::time::Duration::from_secs(
                    self.config.heartbeat_interval_secs.saturating_mul(3));
                if dur >= cooldown { entry.enter_half_open(); }
            }
        }
        Ok(entry.state().clone())
    }

    /// Returns true if the node exists, is not Unhealthy, and its circuit
    /// breaker is not Open.
    pub fn is_available(&self, node_id: &str) -> bool {
        let topo = self.topology.read().unwrap();
        let node = match topo.nodes.iter().find(|n| n.node_id == node_id) {
            Some(n) => n, None => return false,
        };
        if node.health_status.is_unhealthy() { return false; }
        if self.is_circuit_open(node_id) { return false; }
        true
    }
}

// -----------------------------------------------------------------------
// Accessors
// -----------------------------------------------------------------------

impl RelayNodeManager {
    /// Total number of registered nodes in the topology.
    #[inline]
    pub fn node_count(&self) -> usize { self.topology.read().unwrap().nodes.len() }

    /// Clones the `Arc` wrapping the topology's `RwLock` for shared read access.
    #[inline]
    pub fn get_topology(&self) -> Arc<RwLock<RelayTopology>> { Arc::clone(&self.topology) }

    /// Reference to the global relay configuration.
    #[inline] 
    pub fn config(&self) -> &RelayConfig { &self.config }

    /// Current failure count for a specific node, or `None` if untracked.
    pub fn failure_count(&self, node_id: &str) -> Option<u32> {
        self.failure_counters.get(node_id).copied()
    }
}
