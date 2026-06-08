// ===========================================================================
// Relay Node & Edge Types
// ===========================================================================
//
// Core data structures representing individual relay nodes, their roles,
// endpoint configurations, capacity constraints, health states, and the
// directed edges (connections) that form the relay topology graph.
//
// These types are designed to be:
//   - Serializable (serde) for configuration persistence and gRPC transport.
//   - Clone-able for cheap topology snapshot copies during route computation.
//   - Zero-dependency on async runtime (pure data types).

use serde::{Deserialize, Serialize};

/// Role classification of a relay node within the multi-tier architecture.
///
/// Each role determines the node's routing responsibilities, security
/// requirements, and position in the tier hierarchy:
///
/// | Role     | Tier | Description                                           |
/// |----------|------|-------------------------------------------------------|
/// | `Edge`   | 1    | Entry/exit point; closest to client endpoints.         |
/// | `Proxy`  | 2    | Intermediate forwarding node with optional caching.    |
/// | `Hub`    | 3    | Central aggregation point; cross-region routing.      |
/// | `Terminal`| 4   | Final destination or egress gateway (external-facing). |
///
/// # Serialization
///
/// Serialized as lowercase strings via `#[serde(rename_all = "snake_case")]`
/// for human-readable configuration files and wire formats.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::NodeRole;
///
/// let edge = NodeRole::Edge;
/// let hub = NodeRole::Hub;
/// assert_eq!(edge.as_str(), "Edge");
/// assert_eq!(hub.tier(), 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Tier-1 entry/exit node. Handles direct client connections.
    Edge,

    /// Tier-2 intermediate forwarding node. May perform protocol translation
    /// or content inspection before passing traffic upstream.
    Proxy,

    /// Tier-3 central aggregation node. Responsible for cross-region
    /// routing decisions and global load balancing.
    Hub,

    /// Tier-4 final destination or external egress gateway. Represents
    /// the ultimate sink of a relay path or an exit point to non-relay networks.
    Terminal,
}

impl NodeRole {
    /// Returns the tier level associated with this role.
    ///
    /// Tier levels are monotonically increasing from Edge (1) to Terminal (4),
    /// enabling ordinal comparisons for routing policy enforcement.
    ///
    /// # Returns
    ///
    /// A `u8` value in the range `[1, 4]` corresponding to the role's tier.
    pub fn tier(&self) -> u8 {
        match self {
            Self::Edge => 1,
            Self::Proxy => 2,
            Self::Hub => 3,
            Self::Terminal => 4,
        }
    }

    /// Returns a static string representation of this role variant name.
    ///
    /// Useful for logging, metrics labeling, and diagnostic output where
    /// a human-readable identifier is preferred over Debug formatting.
    ///
    /// # Returns
    ///
    /// A `&'static str` containing the exact variant name (e.g., `"Edge"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Edge => "Edge",
            Self::Proxy => "Proxy",
            Self::Hub => "Hub",
            Self::Terminal => "Terminal",
        }
    }
}

/// Network endpoint configuration for a relay node.
///
/// Encapsulates the transport-layer addressing information required to
/// establish connections to a relay node. This is intentionally kept simple
/// (host + port) to avoid coupling to specific transport protocols at the
/// data-model layer; protocol selection is delegated to [`RelayEdge`].
///
/// # Invariants
///
/// - `port` must be in the valid range `[1, 65535]`. Port `0` is reserved
///   for dynamic allocation and is explicitly disallowed here since relay
///   nodes must have well-known, statically configured listening ports.
/// - `host` may be an IPv4 address, IPv6 address, or DNS hostname.
///   Validation of address format is deferred to connection establishment.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::EndpointConfig;
///
/// let ep = EndpointConfig::new("tcp", "10.0.0.1", 8443);
/// assert_eq!(ep.port(), 8443);
/// assert_eq!(ep.host(), "10.0.0.1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Transport endpoint type identifier (e.g., `"tcp"`, `"tls"`, `"quic"`).
    ///
    /// This field serves as a hint for the connection manager to select the
    /// appropriate transport implementation. It does not enforce protocol
    /// correctness at the type level — that responsibility belongs to the
    /// edge/connection layer.
    pub endpoint_type: String,

    /// Host address: IPv4 literal, IPv6 literal (with brackets), or DNS FQDN.
    pub host: String,

    /// TCP/UDP port number in range `[1, 65535]`.
    pub port: u16,
}

impl EndpointConfig {
    /// Constructs a new [`EndpointConfig`] with the given parameters.
    ///
    /// # Parameters
    ///
    /// - `endpoint_type`: Transport type identifier (e.g., `"tcp"`, `"tls"`).
    /// - `host`: Hostname or IP address string.
    /// - `port`: Port number (must be non-zero).
    ///
    /// # Returns
    ///
    /// A fully initialized [`EndpointConfig`] instance.
    pub fn new(endpoint_type: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            endpoint_type: endpoint_type.into(),
            host: host.into(),
            port,
        }
    }

    /// Returns the host address as a string slice.
    #[inline]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port number.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the endpoint type identifier.
    #[inline]
    pub fn endpoint_type(&self) -> &str {
        &self.endpoint_type
    }
}

/// Resource capacity limits imposed on a single relay node.
///
/// Defines the upper bounds on concurrent transfer operations and bandwidth
/// consumption that a node is willing to accept. These limits are enforced
/// by the admission control layer before accepting new transfer requests.
///
/// # Design Rationale
///
/// Capacity limits are expressed as absolute values rather than percentages
/// because relay nodes may have heterogeneous hardware profiles. A Hub node
/// with 40 Gbps NICs will have vastly different limits than an Edge node
/// running on commodity hardware.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::CapacityLimits;
///
/// let limits = CapacityLimits::new(100, 10_000);
/// assert_eq!(limits.max_concurrent_transfers(), 100);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityLimits {
    /// Maximum number of concurrent transfer sessions this node can handle.
    ///
    /// When this limit is reached, the node should return transient errors
    /// to new connection attempts, signaling clients to retry via alternate paths.
    pub max_concurrent_transfers: u32,

    /// Maximum allowed bandwidth in megabits per second (Mbps).
    ///
    /// This is the aggregate bandwidth ceiling across all transfers. Individual
    /// transfer rate limiting is handled separately by per-transfer QoS policies.
    pub bandwidth_mbps: u32,
}

impl CapacityLimits {
    /// Constructs a new [`CapacityLimits`] instance.
    ///
    /// # Parameters
    ///
    /// - `max_concurrent_transfers`: Upper bound on simultaneous transfer sessions.
    /// - `bandwidth_mbps`: Aggregate bandwidth cap in megabits per second.
    ///
    /// # Panics
    ///
    /// This constructor does not panic. However, consumers should treat
    /// `max_concurrent_transfers == 0` as "unlimited" if that semantics
    /// is desired, or reject it as invalid depending on policy.
    pub fn new(max_concurrent_transfers: u32, bandwidth_mbps: u32) -> Self {
        Self {
            max_concurrent_transfers,
            bandwidth_mbps,
        }
    }

    /// Returns the maximum number of concurrent transfers.
    #[inline]
    pub fn max_concurrent_transfers(&self) -> u32 {
        self.max_concurrent_transfers
    }

    /// Returns the bandwidth limit in megabits per second.
    #[inline]
    pub fn bandwidth_mbps(&self) -> u32 {
        self.bandwidth_mbps
    }
}

/// Health status of a relay node as observed by the monitoring subsystem.
///
/// The three-state model (Healthy / Degraded / Unhealthy) provides sufficient
/// granularity for routing decisions without introducing the complexity of
/// continuous numeric scoring:
///
/// - **Healthy**: Fully operational; eligible for all routing strategies.
/// - **Degraded**: Partially operational; may be used as a last resort or
///   for low-priority traffic only.
/// - **Unhealthy**: Not operational; excluded from all routing computations.
///
/// # State Machine
///
/// ```text
/// Healthy --> Degraded --> Unhealthy
///    ^                   |
///    |___________________|
///       (recovery path)
/// ```
///
/// Recovery from Unhealthy always passes through Degraded to prevent
/// immediate re-admission of a previously failed node into hot paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Node is fully operational within normal parameters.
    ///
    /// All health checks pass, latency is within SLA, error rates are below threshold.
    Healthy,

    /// Node exhibits degraded performance but remains partially functional.
    ///
    /// Possible causes: elevated latency, intermittent packet loss,
    /// reduced available bandwidth, or partial subsystem failure.
    Degraded,

    /// Node is non-operational and must be excluded from routing.
    ///
    /// Possible causes: heartbeat timeout, critical subsystem failure,
    /// or administrative shutdown.
    Unhealthy,
}

impl HealthStatus {
    /// Returns `true` if the node is considered routable under normal conditions.
    ///
    /// Only [`Self::Healthy`] returns `true`; both [`Self::Degraded`] and
    /// [`Self::Unhealthy`] return `false`.
    #[inline]
    pub fn is_routable(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns `true` if the node is completely unavailable.
    #[inline]
    pub fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy)
    }
}

/// Complete representation of a single relay node in the topology graph.
///
/// A `RelayNode` aggregates all static and dynamic attributes needed for
/// routing decisions: identity, role/tier placement, network endpoint,
/// resource constraints, current health, and local egress targets.
///
/// # Identity Model
///
/// Each node carries a globally unique `node_id` which serves as the primary
/// key for all topology operations (addition, removal, edge attachment).
/// The ID format is opaque to the core data model but conventionally follows
/// the pattern `{region}-{role}-{sequence}` (e.g., `"tokyo-edge-001"`).
///
/// # Thread Safety
///
/// `RelayNode` is `Clone + Send + Sync` (via `String` fields), enabling
/// safe sharing across async tasks and lock-free reads during route planning.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::*;
///
/// let node = RelayNode::new(
///     "tokyo-edge-001",
///     NodeRole::Edge,
///     EndpointConfig::new("tls", "10.0.1.10", 8443),
///     1,
///     CapacityLimits::new(500, 10_000),
/// );
/// assert_eq!(node.node_id(), "tokyo-edge-001");
/// assert_eq!(node.role().tier(), 1);
/// assert!(node.health_status().is_routable());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNode {
    /// Globally unique node identifier (primary key in the topology graph).
    pub node_id: String,

    /// Functional role determining tier placement and routing responsibilities.
    pub role: NodeRole,

    /// Network endpoint configuration for inbound/outbound connections.
    pub endpoint: EndpointConfig,

    /// Tier level (should match `role.tier()`; stored denormalized for
    /// query efficiency and serialization independence).
    pub tier: u8,

    /// Resource capacity constraints enforced by admission control.
    pub capacity: CapacityLimits,

    /// Current health status as last reported by the monitoring subsystem.
    ///
    /// Defaults to [`HealthStatus::Healthy`] upon construction; updated
    /// asynchronously by the heartbeat/health-check monitor.
    pub health_status: HealthStatus,

    /// List of local egress target identifiers reachable directly from this
    /// node without traversing additional relay hops.
    ///
    /// For Edge nodes, this typically contains downstream client IDs or
    /// local network segments. For Terminal nodes, this contains external
    /// system identifiers (e.g., S3 bucket names, partner API endpoints).
    pub local_egress_targets: Vec<String>,
}

impl RelayNode {
    /// Constructs a new [`RelayNode`] with default healthy status and empty
    /// egress target list.
    ///
    /// # Parameters
    ///
    /// - `node_id`: Globally unique identifier for this node.
    /// - `role`: Role classification (determines tier semantics).
    /// - `endpoint`: Network endpoint configuration.
    /// - `tier`: Explicit tier level (should equal `role.tier()`).
    /// - `capacity`: Resource capacity limits.
    ///
    /// # Returns
    ///
    /// A fully initialized [`RelayNode`] with:
    /// - `health_status` set to [`HealthStatus::Healthy`].
    /// - `local_egress_targets` set to an empty vector.
    pub fn new(
        node_id: impl Into<String>,
        role: NodeRole,
        endpoint: EndpointConfig,
        tier: u8,
        capacity: CapacityLimits,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            role,
            endpoint,
            tier,
            capacity,
            health_status: HealthStatus::Healthy,
            local_egress_targets: Vec::new(),
        }
    }

    /// Returns the node's unique identifier.
    #[inline]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Returns the node's role classification.
    #[inline]
    pub fn role(&self) -> &NodeRole {
        &self.role
    }

    /// Returns the node's network endpoint configuration.
    #[inline]
    pub fn endpoint(&self) -> &EndpointConfig {
        &self.endpoint
    }

    /// Returns the node's tier level.
    #[inline]
    pub fn tier(&self) -> u8 {
        self.tier
    }

    /// Returns a mutable reference to the node's capacity limits.
    #[inline]
    pub fn capacity(&self) -> &CapacityLimits {
        &self.capacity
    }

    /// Returns the node's current health status.
    #[inline]
    pub fn health_status(&self) -> &HealthStatus {
        &self.health_status
    }

    /// Returns a mutable reference to the health status for monitoring updates.
    #[inline]
    pub fn health_status_mut(&mut self) -> &mut HealthStatus {
        &mut self.health_status
    }

    /// Returns the list of local egress target identifiers.
    #[inline]
    pub fn local_egress_targets(&self) -> &[String] {
        &self.local_egress_targets
    }

    /// Adds a local egress target identifier to this node.
    ///
    /// Duplicate target IDs are silently accepted; deduplication is the
    /// caller's responsibility if uniqueness is required.
    pub fn add_egress_target(&mut self, target: impl Into<String>) {
        self.local_egress_targets.push(target.into());
    }
}

/// Directed edge representing a unidirectional communication channel between
/// two relay nodes.
///
/// Edges define the allowable traffic flow within the relay topology graph.
/// Each edge is directed (`from_node` -> `to_node`) and annotated with
/// protocol and security policy metadata.
///
/// # Graph Semantics
///
/// The collection of [`RelayEdge`] instances forms a directed multigraph:
/// multiple edges between the same ordered pair of nodes are permitted
/// (e.g., one TCP edge and one QUIC edge for different traffic classes).
///
/// # Security Policy
///
/// Two orthogonal policy flags control edge behavior:
/// - `require_encryption`: Mandates TLS/QUIC-level encryption for all
///   payloads traversing this edge. When `true`, plaintext protocols
///   (raw TCP) are rejected at the connection-establishment phase.
/// - `require_approval`: Mandates explicit administrator approval before
///   the first transfer session is established across this edge. Used for
///   cross-organizational or high-sensitivity inter-node links.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::{RelayEdge, RelayEdgeBuilder};
///
/// let edge = RelayEdgeBuilder::new("edge-001", "proxy-001")
///     .protocol("tls")
///     .require_encryption(true)
///     .build();
/// assert_eq!(edge.from_node(), "edge-001");
/// assert!(edge.require_encryption());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEdge {
    /// Source node identifier (tail of the directed edge).
    pub from_node: String,

    /// Destination node identifier (head of the directed edge).
    pub to_node: String,

    /// Protocol identifier for traffic on this edge (e.g., `"tcp"`, `"tls"`,
    /// `"quic"`, `"grpc"`). This is informational; actual protocol negotiation
    /// occurs at the transport layer.
    pub protocol: String,

    /// When `true`, mandates encrypted transport for all payloads on this edge.
    ///
    /// Default: `true` (defense-in-depth: encrypt unless explicitly exempted).
    pub require_encryption: bool,

    /// When `true`, requires explicit administrator approval before the first
    /// transfer session can be established across this edge.
    ///
    /// Default: `false` (intra-organizational edges typically do not require approval).
    pub require_approval: bool,
}

/// Builder for constructing [`RelayEdge`] instances with fluent API.
///
/// Provides a structured, readable alternative to direct struct initialization,
/// ensuring all required fields are supplied and sensible defaults are applied.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::RelayEdgeBuilder;
///
/// let edge = RelayEdgeBuilder::new("node-a", "node-b")
///     .protocol("quic")
///     .require_encryption(true)
///     .require_approval(false)
///     .build();
/// ```
pub struct RelayEdgeBuilder {
    inner: RelayEdge,
}

impl RelayEdgeBuilder {
    /// Creates a new builder with the required source and destination node IDs.
    ///
    /// # Parameters
    ///
    /// - `from_node`: Source node identifier.
    /// - `to_node`: Destination node identifier.
    ///
    /// # Returns
    ///
    /// A builder instance with default protocol `"tcp"`, encryption required,
    /// and no approval requirement.
    pub fn new(from_node: impl Into<String>, to_node: impl Into<String>) -> Self {
        Self {
            inner: RelayEdge {
                from_node: from_node.into(),
                to_node: to_node.into(),
                protocol: String::from("tcp"),
                require_encryption: true,
                require_approval: false,
            },
        }
    }

    /// Sets the protocol identifier for this edge.
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.inner.protocol = protocol.into();
        self
    }

    /// Sets whether encryption is required on this edge.
    pub fn require_encryption(mut self, required: bool) -> Self {
        self.inner.require_encryption = required;
        self
    }

    /// Sets whether administrator approval is required for this edge.
    pub fn require_approval(mut self, required: bool) -> Self {
        self.inner.require_approval = required;
        self
    }

    /// Consumes the builder and returns the constructed [`RelayEdge`].
    pub fn build(self) -> RelayEdge {
        self.inner
    }
}

impl RelayEdge {
    /// Creates a new edge using the builder pattern.
    ///
    /// Shorthand for [`RelayEdgeBuilder::new(from, to).build()`].
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        RelayEdgeBuilder::new(from, to).build()
    }

    /// Returns the source node identifier.
    #[inline]
    pub fn from_node(&self) -> &str {
        &self.from_node
    }

    /// Returns the destination node identifier.
    #[inline]
    pub fn to_node(&self) -> &str {
        &self.to_node
    }

    /// Returns the protocol identifier.
    #[inline]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Returns `true` if encryption is mandatory on this edge.
    #[inline]
    pub fn require_encryption(&self) -> bool {
        self.require_encryption
    }

    /// Returns `true` if admin approval is required for this edge.
    #[inline]
    pub fn require_approval(&self) -> bool {
        self.require_approval
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // NodeRole tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_edge_role_tier_is_one() {
        assert_eq!(NodeRole::Edge.tier(), 1);
    }

    #[test]
    fn test_proxy_role_tier_is_two() {
        assert_eq!(NodeRole::Proxy.tier(), 2);
    }

    #[test]
    fn test_hub_role_tier_is_three() {
        assert_eq!(NodeRole::Hub.tier(), 3);
    }

    #[test]
    fn test_terminal_role_tier_is_four() {
        assert_eq!(NodeRole::Terminal.tier(), 4);
    }

    #[test]
    fn test_role_as_str_returns_variant_name() {
        assert_eq!(NodeRole::Edge.as_str(), "Edge");
        assert_eq!(NodeRole::Proxy.as_str(), "Proxy");
        assert_eq!(NodeRole::Hub.as_str(), "Hub");
        assert_eq!(NodeRole::Terminal.as_str(), "Terminal");
    }

    #[test]
    fn test_role_serialization_roundtrip() {
        let roles = vec![
            NodeRole::Edge,
            NodeRole::Proxy,
            NodeRole::Hub,
            NodeRole::Terminal,
        ];
        for role in &roles {
            let json = serde_json::to_string(role).unwrap();
            let decoded: NodeRole = serde_json::from_str(&json).unwrap();
            assert_eq!(*role, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // EndpointConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_endpoint_config_new() {
        let ep = EndpointConfig::new("tls", "192.168.1.1", 8443);
        assert_eq!(ep.endpoint_type(), "tls");
        assert_eq!(ep.host(), "192.168.1.1");
        assert_eq!(ep.port(), 8443);
    }

    #[test]
    fn test_endpoint_config_clone() {
        let ep = EndpointConfig::new("quic", "[::1]", 443);
        let cloned = ep.clone();
        assert_eq!(ep, cloned);
    }

    #[test]
    fn test_endpoint_config_serialization() {
        let ep = EndpointConfig::new("tcp", "relay.example.com", 9000);
        let json = serde_json::to_string_pretty(&ep).unwrap();
        let decoded: EndpointConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.endpoint_type, "tcp");
        assert_eq!(decoded.host, "relay.example.com");
        assert_eq!(decoded.port, 9000);
    }

    // -----------------------------------------------------------------------
    // CapacityLimits tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_capacity_limits_new() {
        let caps = CapacityLimits::new(200, 5_000);
        assert_eq!(caps.max_concurrent_transfers(), 200);
        assert_eq!(caps.bandwidth_mbps(), 5_000);
    }

    #[test]
    fn test_capacity_limits_zero_values() {
        let caps = CapacityLimits::new(0, 0);
        assert_eq!(caps.max_concurrent_transfers(), 0);
        assert_eq!(caps.bandwidth_mbps(), 0);
    }

    // -----------------------------------------------------------------------
    // HealthStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_healthy_is_routable() {
        assert!(HealthStatus::Healthy.is_routable());
    }

    #[test]
    fn test_degraded_is_not_routable() {
        assert!(!HealthStatus::Degraded.is_routable());
    }

    #[test]
    fn test_unhealthy_is_not_routable() {
        assert!(!HealthStatus::Unhealthy.is_routable());
    }

    #[test]
    fn test_unhealthy_flag() {
        assert!(HealthStatus::Unhealthy.is_unhealthy());
        assert!(!HealthStatus::Healthy.is_unhealthy());
        assert!(!HealthStatus::Degraded.is_unhealthy());
    }

    #[test]
    fn test_health_status_serialization() {
        for status in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: HealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // RelayNode tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relay_node_creation_edge_role() {
        let node = RelayNode::new(
            "edge-tokyo-01",
            NodeRole::Edge,
            EndpointConfig::new("tls", "10.0.0.1", 8443),
            1,
            CapacityLimits::new(500, 10_000),
        );
        assert_eq!(node.node_id(), "edge-tokyo-01");
        assert_eq!(node.role(), &NodeRole::Edge);
        assert_eq!(node.tier(), 1);
        assert!(node.health_status().is_routable());
        assert!(node.local_egress_targets().is_empty());
    }

    #[test]
    fn test_relay_node_creation_hub_role() {
        let node = RelayNode::new(
            "hub-global-01",
            NodeRole::Hub,
            EndpointConfig::new("tls", "10.0.0.100", 9443),
            3,
            CapacityLimits::new(5000, 100_000),
        );
        assert_eq!(node.role(), &NodeRole::Hub);
        assert_eq!(node.tier(), 3);
        assert_eq!(node.capacity().max_concurrent_transfers(), 5000);
    }

    #[test]
    fn test_relay_node_creation_terminal_role() {
        let node = RelayNode::new(
            "terminal-egress-01",
            NodeRole::Terminal,
            EndpointConfig::new("tcp", "10.0.0.255", 8080),
            4,
            CapacityLimits::new(1000, 40_000),
        );
        assert_eq!(node.role(), &NodeRole::Terminal);
        assert_eq!(node.tier(), 4);
    }

    #[test]
    fn test_relay_node_add_egress_target() {
        let mut node = RelayNode::new(
            "edge-01",
            NodeRole::Edge,
            EndpointConfig::new("tcp", "127.0.0.1", 3000),
            1,
            CapacityLimits::new(10, 100),
        );
        node.add_egress_target("client-alpha");
        node.add_egress_target("client-beta");
        assert_eq!(node.local_egress_targets().len(), 2);
        assert_eq!(node.local_egress_targets()[0], "client-alpha");
    }

    #[test]
    fn test_relay_node_health_update() {
        let mut node = RelayNode::new(
            "node-01",
            NodeRole::Proxy,
            EndpointConfig::new("tcp", "127.0.0.1", 3000),
            2,
            CapacityLimits::new(50, 1000),
        );
        assert!(node.health_status().is_routable());
        *node.health_status_mut() = HealthStatus::Degraded;
        assert!(!node.health_status().is_routable());
        assert!(!node.health_status().is_unhealthy());
    }

    #[test]
    fn test_relay_node_serialization() {
        let node = RelayNode::new(
            "serialized-node",
            NodeRole::Proxy,
            EndpointConfig::new("quic", "192.168.50.5", 443),
            2,
            CapacityLimits::new(999, 25_000),
        );
        let json = serde_json::to_string_pretty(&node).unwrap();
        let decoded: RelayNode = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node_id, "serialized-node");
        assert_eq!(decoded.role, NodeRole::Proxy);
        assert_eq!(decoded.capacity.max_concurrent_transfers, 999);
    }

    // -----------------------------------------------------------------------
    // RelayEdge tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relay_edge_new_default() {
        let edge = RelayEdge::new("a", "b");
        assert_eq!(edge.from_node(), "a");
        assert_eq!(edge.to_node(), "b");
        assert_eq!(edge.protocol(), "tcp");
        assert!(edge.require_encryption());
        assert!(!edge.require_approval());
    }

    #[test]
    fn test_relay_edge_builder_full() {
        let edge = RelayEdgeBuilder::new("edge-01", "hub-01")
            .protocol("tls")
            .require_encryption(true)
            .require_approval(true)
            .build();
        assert_eq!(edge.from_node(), "edge-01");
        assert_eq!(edge.to_node(), "hub-01");
        assert_eq!(edge.protocol(), "tls");
        assert!(edge.require_encryption());
        assert!(edge.require_approval());
    }

    #[test]
    fn test_relay_edge_builder_no_encryption() {
        let edge = RelayEdgeBuilder::new("internal-a", "internal-b")
            .require_encryption(false)
            .build();
        assert!(!edge.require_encryption());
    }

    #[test]
    fn test_relay_edge_serialization() {
        let edge = RelayEdgeBuilder::new("src", "dst")
            .protocol("quic")
            .require_encryption(true)
            .require_approval(false)
            .build();
        let json = serde_json::to_string(&edge).unwrap();
        let decoded: RelayEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, edge);
    }

    #[test]
    fn test_relay_edge_equality() {
        let a = RelayEdgeBuilder::new("x", "y").protocol("tcp").build();
        let b = RelayEdgeBuilder::new("x", "y").protocol("tcp").build();
        let c = RelayEdgeBuilder::new("x", "y").protocol("quic").build();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
