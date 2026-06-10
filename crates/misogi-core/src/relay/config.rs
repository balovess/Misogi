// ===========================================================================
// Relay Configuration
// ===========================================================================
//
// Runtime configuration parameters for the relay subsystem.
//
// This module defines `RelayConfig`, a flat struct holding all tunable knobs
// that control relay behavior at the system level (as opposed to per-node or
// per-edge parameters which live in their respective data structures).
//
// Design principles:
//   - All fields have sensible defaults suitable for production deployment.
//   - The struct is fully serializable for TOML/JSON/YAML config file loading.
//   - No field validation beyond type-level constraints; semantic validation
//     (e.g., `max_hops > 0`) is performed by the consumer at config-load time.

use serde::{Deserialize, Serialize};

use crate::relay::node::{CapacityLimits, EndpointConfig, NodeRole, RelayEdge, RelayNode};
use crate::relay::topology::{RelayTopology, RouteStrategy};

/// Global runtime configuration for the multi-tier relay subsystem.
///
/// Encapsulates all system-wide parameters that govern relay behavior,
/// independent of any specific topology graph instance. A single `RelayConfig`
/// is typically loaded from a configuration file at process startup and shared
/// across all relay-related components via `Arc<RelayConfig>`.
///
/// # Field Summary
///
/// | Field                     | Type  | Default        | Purpose                              |
/// |---------------------------|-------|----------------|--------------------------------------|
/// | `enabled`                 | bool  | `false`        | Master on/off switch for relay mode. |
/// | `default_strategy`        | String| `"local_egress_first"` | Fallback route strategy name.    |
/// | `max_hops`                | u8    | `5`            | Maximum allowed path length.         |
/// | `heartbeat_interval_secs` | u64   | `15`           | Health probe cadence in seconds.      |
/// | `circuit_breaker_threshold`| u32  | `3`            | Consecutive failures before trip.     |
///
/// # Safety Considerations
///
/// - `max_hops = 0` disables all routing (effectively equivalent to
///   `enabled = false`). Values > 20 are discouraged as they indicate
///   pathological topology design.
/// - `circuit_breaker_threshold = 0` disables circuit breaking entirely,
///   which may cause cascading failure propagation in degraded networks.
/// - `heartbeat_interval_secs` should be chosen relative to the expected
///   RTT between nodes: too aggressive (< 5s) generates unnecessary load;
///   too lax (> 60s) delays failure detection.
///
/// # Examples
///
/// ```
/// use misogi_core::relay::RelayConfig;
///
/// // Use defaults — relay disabled, safe for non-relay deployments.
/// let cfg = RelayConfig::default();
/// assert!(!cfg.enabled());
///
/// // Enable with custom settings.
/// let cfg = RelayConfig::builder()
///     .enabled(true)
///     .max_hops(10)
///     .heartbeat_interval_secs(30)
///     .build();
/// assert!(cfg.enabled());
/// assert_eq!(cfg.max_hops(), 10);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Master enable flag for the entire relay subsystem.
    ///
    /// When `false`, the relay layer behaves as a pass-through no-op:
    /// all transfer requests are handled locally without topology lookup.
    /// This allows the same binary to operate in both direct and relay modes
    /// depending solely on configuration.
    ///
    /// Default: `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Name of the default routing strategy applied when a transfer request
    /// does not specify an explicit strategy preference.
    ///
    /// The value must match one of the known strategy identifiers:
    /// `"shortest_path"`, `"lowest_latency"`, `"local_egress_first"`,
    /// or a custom registered strategy name.
    ///
    /// Default: `"local_egress_first"`.
    #[serde(default = "default_strategy")]
    pub default_strategy: String,

    /// Upper bound on the number of hops (intermediate nodes) permitted in
    /// any computed relay path.
    ///
    /// Paths exceeding this limit are rejected at route-planning time with
    /// a clear error indicating the constraint violation. This prevents
    /// routing loops from causing unbounded traversal and limits attack surface
    /// for path-length-based denial-of-service.
    ///
    /// Range: `[0, 255]`. Value of `0` effectively disables routing.
    ///
    /// Default: `5`.
    #[serde(default = "default_max_hops")]
    pub max_hops: u8,

    /// Interval in seconds between consecutive heartbeat probes sent by each
    /// node to its immediate neighbors (and upstream health aggregator).
    ///
    /// The heartbeat mechanism is the primary input for [`HealthStatus`]
    /// transitions: missing `circuit_breaker_threshold` consecutive heartbeats
    /// triggers a Healthy -> Degraded -> Unhealthy progression.
    ///
    /// Range: `[1, u64::MAX]`. Recommended range: `[5, 60]`.
    ///
    /// Default: `15`.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Number of consecutive heartbeat failures (or health-check violations)
    /// required before the circuit breaker trips and the node is marked
    /// [`HealthStatus::Unhealthy`](super::node::HealthStatus::Unhealthy).
    ///
    /// This threshold provides hysteresis against transient network blips:
    /// a single missed heartbeat does not immediately degrade service quality.
    ///
    /// Range: `[0, u32::MAX]`. Value of `0` disables circuit breaking.
    ///
    /// Default: `3`.
    #[serde(default = "default_circuit_breaker_threshold")]
    pub circuit_breaker_threshold: u32,
}

// Default value functions for serde(default) attributes
fn default_strategy() -> String {
    String::from("local_egress_first")
}
fn default_max_hops() -> u8 { 5 }
fn default_heartbeat_interval() -> u64 { 15 }
fn default_circuit_breaker_threshold() -> u32 { 3 }

impl Default for RelayConfig {
    /// Returns a `RelayConfig` with all fields set to their documented defaults.
    ///
    /// The resulting configuration has relay **disabled** (`enabled = false`),
    /// making it safe to construct and hold even in deployments that do not use
    /// the relay subsystem.
    fn default() -> Self {
        Self {
            enabled: false,
            default_strategy: String::from("local_egress_first"),
            max_hops: 5,
            heartbeat_interval_secs: 15,
            circuit_breaker_threshold: 3,
        }
    }
}

impl RelayConfig {
    /// Creates a new builder for constructing a customized `RelayConfig`.
    ///
    /// The builder starts with all default values; only override the fields
    /// you need to change.
    ///
    /// # Returns
    ///
    /// A [`RelayConfigBuilder`] instance with default initial state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use misogi_core::relay::RelayConfig;
    /// let cfg = RelayConfig::builder()
    ///     .enabled(true)
    ///     .max_hops(8)
    ///     .build();
    /// ```
    pub fn builder() -> RelayConfigBuilder {
        RelayConfigBuilder::new()
    }

    /// Returns `true` if the relay subsystem is enabled.
    #[inline]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the default routing strategy name.
    #[inline]
    pub fn default_strategy(&self) -> &str {
        &self.default_strategy
    }

    /// Returns the maximum allowed hop count for relay paths.
    #[inline]
    pub fn max_hops(&self) -> u8 {
        self.max_hops
    }

    /// Returns the heartbeat interval in seconds.
    #[inline]
    pub fn heartbeat_interval_secs(&self) -> u64 {
        self.heartbeat_interval_secs
    }

    /// Returns the circuit breaker failure threshold.
    #[inline]
    pub fn circuit_breaker_threshold(&self) -> u32 {
        self.circuit_breaker_threshold
    }

    /// Validates this configuration for semantic correctness.
    ///
    /// Performs checks that go beyond type-level constraints:
    ///
    /// - `max_hops` should be > 0 when `enabled` is true (otherwise routing
    ///   is impossible).
    /// - `heartbeat_interval_secs` should be >= 1.
    /// - `default_strategy` should be a non-empty string.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all semantic constraints are satisfied.
    /// - `Err(String)` describing the first validation violation found.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.max_hops == 0 {
            return Err(
                "relay is enabled but max_hops is 0, which prevents any routing".into(),
            );
        }
        if self.heartbeat_interval_secs == 0 {
            return Err("heartbeat_interval_secs must be >= 1".into());
        }
        if self.default_strategy.is_empty() {
            return Err("default_strategy must not be empty".into());
        }
        Ok(())
    }
}

/// Builder for constructing [`RelayConfig`] instances with a fluent API.
///
/// Starts from default values; only call setters for fields you wish to override.
///
/// # Examples
///
/// ```
/// # use misogi_core::relay::RelayConfig;
/// let cfg = RelayConfig::builder()
///     .enabled(true)
///     .default_strategy("shortest_path")
///     .max_hops(10)
///     .heartbeat_interval_secs(30)
///     .circuit_breaker_threshold(5)
///     .build();
/// assert_eq!(cfg.max_hops(), 10);
/// ```
pub struct RelayConfigBuilder {
    inner: RelayConfig,
}

impl RelayConfigBuilder {
    /// Creates a new builder pre-populated with default values.
    fn new() -> Self {
        Self {
            inner: RelayConfig::default(),
        }
    }

    /// Sets whether the relay subsystem is enabled.
    pub fn enabled(mut self, value: bool) -> Self {
        self.inner.enabled = value;
        self
    }

    /// Sets the default routing strategy name.
    pub fn default_strategy(mut self, value: impl Into<String>) -> Self {
        self.inner.default_strategy = value.into();
        self
    }

    /// Sets the maximum allowed hop count.
    pub fn max_hops(mut self, value: u8) -> Self {
        self.inner.max_hops = value;
        self
    }

    /// Sets the heartbeat interval in seconds.
    pub fn heartbeat_interval_secs(mut self, value: u64) -> Self {
        self.inner.heartbeat_interval_secs = value;
        self
    }

    /// Sets the circuit breaker failure threshold.
    pub fn circuit_breaker_threshold(mut self, value: u32) -> Self {
        self.inner.circuit_breaker_threshold = value;
        self
    }

    /// Consumes the builder and returns the constructed [`RelayConfig`].
    ///
    /// Note: This does **not** invoke [`RelayConfig::validate`]. Callers
    /// who want strict validation should call `cfg.validate()` after building.
    pub fn build(self) -> RelayConfig {
        self.inner
    }
}

impl Default for RelayConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// TOML Configuration Loading
// ===========================================================================

impl RelayConfig {
    /// Deserializes a [`RelayConfig`] from a TOML-formatted string.
    ///
    /// Parses the provided TOML string and constructs a fully populated
    /// configuration instance. This is the primary method for loading
    /// relay configuration from embedded strings or user-provided input.
    ///
    /// # Parameters
    ///
    /// - `toml_str`: A string containing valid TOML with a `[relay]` table
    ///   (or top-level keys matching the struct fields).
    ///
    /// # Returns
    ///
    /// - `Ok(RelayConfig)` on successful parsing.
    /// - `Err(ConfigError)` if the TOML is malformed or missing required fields.
    ///
    /// # Examples
    ///
    /// ```
    /// # use misogi_core::relay::RelayConfig;
    /// let toml = r#"
    /// enabled = true
    /// max_hops = 10
    /// "#;
    /// let cfg = RelayConfig::from_toml_str(toml).unwrap();
    /// assert!(cfg.enabled());
    /// assert_eq!(cfg.max_hops(), 10);
    /// ```
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml_str).map_err(ConfigError::Parse)
    }

    /// Reads a file from disk and deserializes it as TOML into [`RelayConfig`].
    ///
    /// Convenience wrapper around [`Self::from_toml_str`] that handles file I/O.
    /// The file must contain valid TOML matching the [`RelayConfig`] schema.
    ///
    /// # Parameters
    ///
    /// - `path`: Path to the TOML configuration file.
    ///
    /// # Returns
    ///
    /// - `Ok(RelayConfig)` on success.
    /// - `Err(ConfigError)` if the file cannot be read or contains invalid TOML.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the file does not exist or cannot be read.
    /// Returns [`ConfigError::Parse`] if the TOML content is invalid.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::path::Path;
    /// let cfg = RelayConfig::load_from_file(Path::new("config/relay.toml"))?;
    /// ```
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::from_toml_str(&content)
    }

    /// Validates this configuration and returns all violations found.
    ///
    /// Unlike [`Self::validate`] which returns only the first error, this method
    /// collects **all** validation issues into a vector, enabling batch reporting
    /// of configuration problems to operators.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if no violations are found.
    /// - `Err(Vec<String>)` containing human-readable descriptions of each issue.
    pub fn validate_all(&self) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();

        if self.enabled && self.max_hops == 0 {
            violations.push(
                "relay is enabled but max_hops is 0, which prevents any routing".into(),
            );
        }
        if self.heartbeat_interval_secs == 0 {
            violations.push("heartbeat_interval_secs must be >= 1".into());
        }
        if self.default_strategy.is_empty() {
            violations.push("default_strategy must not be empty".into());
        }

        // Validate strategy name against known strategies.
        let known_strategies = [
            "shortest_path",
            "lowest_latency",
            "local_egress_first",
            "force_hub",
        ];
        if !known_strategies.contains(&self.default_strategy.as_str())
            && !self.default_strategy.starts_with("custom:")
        {
            violations.push(format!(
                "unknown default_strategy '{}'. Valid options: {}",
                self.default_strategy,
                known_strategies.join(", ")
            ));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    /// Builds a [`RelayTopology`] from separate TOML fragments for nodes and edges.
    ///
    /// This factory method enables topology definition in external configuration
    /// files while keeping the relay config struct flat and focused on behavioral
    /// parameters (not structural graph data).
    ///
    /// # Parameters
    ///
    /// - `nodes_toml`: TOML array of node definitions (each must have `node_id`,
    ///   `role`, `host`, `port` at minimum).
    /// - `edges_toml`: TOML array of edge definitions (each must have `from_node`,
    ///   `to_node`).
    ///
    /// # Returns
    ///
    /// - `Ok(RelayTopology)` with all nodes and edges loaded.
    /// - `Err(String)` describing the first parsing or insertion error.
    ///
    /// # Example TOML Format
    ///
    /// ```text
    /// [[nodes]]
    /// node_id = "edge-tokyo"
    /// role = "edge"
    /// host = "10.0.0.1"
    /// port = 8443
    /// tier = 1
    ///
    /// [[edges]]
    /// from_node = "edge-tokyo"
    /// to_node = "hub-global"
    /// ```
    pub fn build_topology_from_config(
        &self,
        nodes_toml: &str,
        edges_toml: &str,
    ) -> Result<RelayTopology, String> {
        use crate::relay::node::{NodeRole, RelayEdge};

        // Parse nodes - support both direct array and [[nodes]] table array format.
        let raw_nodes: Vec<toml::Value> = if nodes_toml.trim().starts_with("[[nodes]]") {
            // Table array format: parse as map and extract "nodes" key
            let map: toml::map::Map<String, toml::Value> =
                toml::from_str(nodes_toml).map_err(|e| format!("failed to parse nodes TOML: {}", e))?;
            map.get("nodes")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        } else {
            // Direct array format
            toml::from_str(nodes_toml).map_err(|e| format!("failed to parse nodes TOML: {}", e))?
        };

        // Parse edges - support both direct array and [[edges]] table array format.
        let raw_edges: Vec<toml::Value> = if edges_toml.trim().starts_with("[[edges]]") {
            // Table array format: parse as map and extract "edges" key
            let map: toml::map::Map<String, toml::Value> =
                toml::from_str(edges_toml).map_err(|e| format!("failed to parse edges TOML: {}", e))?;
            map.get("edges")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        } else {
            // Direct array format (or empty)
            if edges_toml.trim().is_empty() {
                Vec::new()
            } else {
                toml::from_str(edges_toml).map_err(|e| format!("failed to parse edges TOML: {}", e))?
            }
        };

        let mut topo = RelayTopology::new(
            RouteStrategy::from_name(&self.default_strategy)
                .unwrap_or_else(RouteStrategy::default_strategy),
        );

        // Insert nodes.
        for node_val in &raw_nodes {
            let node_id = node_val
                .get("node_id")
                .and_then(|v| v.as_str())
                .ok_or("missing 'node_id' in node definition")?;

            let role_str = node_val
                .get("role")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("missing 'role' in node '{}'", node_id))?;

            let host = node_val
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1");

            let port = node_val
                .get("port")
                .and_then(|v| v.as_integer())
                .unwrap_or(8080) as u16;

            let tier = node_val
                .get("tier")
                .and_then(|v| v.as_integer())
                .unwrap_or(1) as u8;

            let role = match role_str {
                "edge" => NodeRole::Edge,
                "proxy" => NodeRole::Proxy,
                "hub" => NodeRole::Hub,
                "terminal" => NodeRole::Terminal,
                other => return Err(format!("unknown role '{}' in node '{}'", other, node_id)),
            };

            let endpoint_type = node_val
                .get("endpoint_type")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp");

            let max_concurrent_sessions = node_val
                .get("max_concurrent_sessions")
                .and_then(|v| v.as_integer())
                .unwrap_or(100) as u32;

            let max_bandwidth_mbps = node_val
                .get("max_bandwidth_mbps")
                .and_then(|v| v.as_integer())
                .unwrap_or(1000) as u32;

            let node = RelayNode::new(
                node_id,
                role,
                EndpointConfig::new(endpoint_type, host, port),
                tier,
                CapacityLimits::new(max_concurrent_sessions, max_bandwidth_mbps),
            );

            topo.add_node(node)
                .map_err(|e| format!("failed to add node '{}': {}", node_id, e))?;
        }

        // Insert edges.
        for edge_val in &raw_edges {
            let from = edge_val
                .get("from_node")
                .and_then(|v| v.as_str())
                .ok_or("missing 'from_node' in edge definition")?;

            let to = edge_val
                .get("to_node")
                .and_then(|v| v.as_str())
                .ok_or("missing 'to_node' in edge definition")?;

            // Build edge using RelayEdgeBuilder for fluent API.
            let mut builder = crate::relay::node::RelayEdgeBuilder::new(from, to);

            // Optional edge attributes.
            if let Some(protocol) = edge_val.get("protocol").and_then(|v| v.as_str()) {
                builder = builder.protocol(protocol);
            }
            if let Some(enc) = edge_val.get("require_encryption").and_then(|v| v.as_bool()) {
                builder = builder.require_encryption(enc);
            }
            if let Some(app) = edge_val.get("require_approval").and_then(|v| v.as_bool()) {
                builder = builder.require_approval(app);
            }

            let edge = builder.build();
            topo.add_edge(edge)
                .map_err(|e| format!("failed to add edge '{}'->'{}': {}", from, to, e))?;
        }

        Ok(topo)
    }
}

/// Error type for configuration loading operations.
///
/// Wraps I/O errors (file not found, permission denied) and parse errors
/// (invalid TOML syntax, missing required fields) into a single enum for
/// ergonomic error handling by callers.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O error reading the configuration file.
    #[error("cannot read config file '{path}': {source}")]
    Io {
        /// Path to the file that could not be read.
        path: std::path::PathBuf,
        /// Underlying OS I/O error.
        #[source]
        source: std::io::Error,
    },

    /// TOML parsing error (syntax or schema validation failure).
    #[error("failed to parse relay config: {0}")]
    Parse(#[source] toml::de::Error),
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Default values tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_is_disabled() {
        let cfg = RelayConfig::default();
        assert!(!cfg.enabled());
    }

    #[test]
    fn test_default_strategy_is_local_egress_first() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.default_strategy(), "local_egress_first");
    }

    #[test]
    fn test_default_max_hops_is_five() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.max_hops(), 5);
    }

    #[test]
    fn test_default_heartbeat_interval_is_fifteen() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.heartbeat_interval_secs(), 15);
    }

    #[test]
    fn test_default_circuit_breaker_threshold_is_three() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.circuit_breaker_threshold(), 3);
    }

    // -----------------------------------------------------------------------
    // Builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_builder_enable_relay() {
        let cfg = RelayConfig::builder().enabled(true).build();
        assert!(cfg.enabled());
    }

    #[test]
    fn test_builder_custom_max_hops() {
        let cfg = RelayConfig::builder().max_hops(12).build();
        assert_eq!(cfg.max_hops(), 12);
    }

    #[test]
    fn test_builder_custom_all_fields() {
        let cfg = RelayConfig::builder()
            .enabled(true)
            .default_strategy("shortest_path")
            .max_hops(20)
            .heartbeat_interval_secs(45)
            .circuit_breaker_threshold(7)
            .build();

        assert!(cfg.enabled());
        assert_eq!(cfg.default_strategy(), "shortest_path");
        assert_eq!(cfg.max_hops(), 20);
        assert_eq!(cfg.heartbeat_interval_secs(), 45);
        assert_eq!(cfg.circuit_breaker_threshold(), 7);
    }

    #[test]
    fn test_builder_defaults_unmodified_fields_remain_default() {
        let cfg = RelayConfig::builder().enabled(true).build();
        // Only `enabled` was changed; other fields should still be defaults.
        assert_eq!(cfg.default_strategy(), "local_egress_first");
        assert_eq!(cfg.max_hops(), 5);
        assert_eq!(cfg.heartbeat_interval_secs(), 15);
        assert_eq!(cfg.circuit_breaker_threshold(), 3);
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_default_config_passes() {
        // Default (disabled) config should always pass validation.
        assert!(RelayConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validate_enabled_with_zero_hops_fails() {
        let cfg = RelayConfig::builder().enabled(true).max_hops(0).build();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_hops"), "error: {err}");
    }

    #[test]
    fn test_validate_zero_heartbeat_fails() {
        let cfg = RelayConfig::builder().heartbeat_interval_secs(0).build();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("heartbeat"), "error: {err}");
    }

    #[test]
    fn test_validate_empty_strategy_fails() {
        let cfg = RelayConfig::builder().default_strategy("").build();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("strategy"), "error: {err}");
    }

    #[test]
    fn test_validate_enabled_with_valid_hops_passes() {
        let cfg = RelayConfig::builder().enabled(true).max_hops(10).build();
        assert!(cfg.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // Serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = RelayConfig::builder()
            .enabled(true)
            .default_strategy("lowest_latency")
            .max_hops(15)
            .heartbeat_interval_secs(60)
            .circuit_breaker_threshold(10)
            .build();

        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let decoded: RelayConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, cfg);
        assert_eq!(decoded.enabled, true);
        assert_eq!(decoded.default_strategy, "lowest_latency");
        assert_eq!(decoded.max_hops, 15);
    }

    #[test]
    fn test_config_deserialize_from_partial_json() {
        let json = r#"{"enabled": true}"#;
        let cfg: RelayConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        // Non-specified fields should be deserialized as their serde defaults
        // (which are None/0 for Option/primitive types without Default).
        // Since we don't use #[serde(default)] on individual fields, absent
        // fields will cause error unless we handle it. Let's verify behavior.
        // Actually serde will error on missing required fields since we don't
        // use #[serde(default)] on fields. Let's test with full JSON instead.
    }

    #[test]
    fn test_config_equality() {
        let a = RelayConfig::default();
        let b = RelayConfig::default();
        let c = RelayConfig::builder().enabled(true).build();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
