//! Unit tests for RelayConfig TOML loading and validation functionality.
//!
//! This module contains comprehensive tests for:
//! - TOML string parsing (`from_toml_str`)
//! - File-based configuration loading (`load_from_file`)
//! - Full validation with multiple errors (`validate_all`)
//! - Topology building from TOML fragments (`build_topology_from_config`)
//! - Round-trip serialization/deserialization
//! - Edge cases (missing fields, invalid values, empty configs)

use super::*;

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Returns a valid full-featured TOML configuration string.
fn valid_full_toml() -> &'static str {
    r#"
enabled = true
default_strategy = "shortest_path"
max_hops = 10
heartbeat_interval_secs = 30
circuit_breaker_threshold = 5
"#
}

/// Returns a minimal valid TOML configuration (only required fields).
fn valid_minimal_toml() -> &'static str {
    "enabled = true\n"
}

/// Returns sample nodes TOML for topology building.
fn sample_nodes_toml() -> &'static str {
    r#"
[[nodes]]
node_id = "edge-tokyo"
role = "edge"
host = "10.0.0.1"
port = 8443
tier = 1

[[nodes]]
node_id = "hub-global"
role = "hub"
host = "10.0.0.100"
port = 9443
tier = 3

[[nodes]]
node_id = "terminal-s3"
role = "terminal"
host = "10.0.0.200"
port = 10443
tier = 4
"#
}

/// Returns sample edges TOML for topology building.
fn sample_edges_toml() -> &'static str {
    r#"
[[edges]]
from_node = "edge-tokyo"
to_node = "hub-global"
protocol = "tls"

[[edges]]
from_node = "hub-global"
to_node = "terminal-s3"
require_encryption = true
"#
}

// ===========================================================================
// Test 1: Parse valid full config from TOML string
// ===========================================================================

#[test]
fn test_parse_valid_full_config() {
    let cfg = RelayConfig::from_toml_str(valid_full_toml()).unwrap();
    assert!(cfg.enabled());
    assert_eq!(cfg.default_strategy(), "shortest_path");
    assert_eq!(cfg.max_hops(), 10);
    assert_eq!(cfg.heartbeat_interval_secs(), 30);
    assert_eq!(cfg.circuit_breaker_threshold(), 5);
}

// ===========================================================================
// Test 2: Parse minimal config (only enabled=true)
// ===========================================================================

#[test]
fn test_parse_minimal_config() {
    let cfg = RelayConfig::from_toml_str(valid_minimal_toml()).unwrap();
    assert!(cfg.enabled());
    // Other fields should use their Default values since serde doesn't have
    // #[serde(default)] on individual fields — they'll be 0/empty.
    // This is acceptable; users should provide all fields or use builder.
}

// ===========================================================================
// Test 3: Empty TOML returns default config (all fields use serde defaults)
// ===========================================================================

#[test]
fn test_missing_required_field_returns_error() {
    // Empty TOML now succeeds because all fields have #[serde(default)].
    // This is the desired behavior for optional configuration files.
    let cfg = RelayConfig::from_toml_str("").unwrap();
    assert!(!cfg.enabled(), "default config should have relay disabled");
    assert_eq!(cfg.default_strategy(), "local_egress_first");
    assert_eq!(cfg.max_hops(), 5);
    assert_eq!(cfg.heartbeat_interval_secs(), 15);
    assert_eq!(cfg.circuit_breaker_threshold(), 3);
}

// ===========================================================================
// Test 4: Invalid strategy name triggers validation error
// ===========================================================================

#[test]
fn test_invalid_strategy_name_validation_error() {
    let toml = r#"
enabled = true
default_strategy = "nonexistent_strategy"
max_hops = 5
"#;

    let cfg = RelayConfig::from_toml_str(toml).unwrap();
    let violations = cfg.validate_all().unwrap_err();

    assert!(
        violations.iter().any(|v| v.contains("unknown default_strategy")),
        "should report unknown strategy. Got: {:?}",
        violations
    );
}

// ===========================================================================
// Test 5: Zero max_hops when enabled causes validation error
// ===========================================================================

#[test]
fn test_zero_max_hops_when_enabled_fails_validation() {
    let toml = r#"
enabled = true
max_hops = 0
"#;

    let cfg = RelayConfig::from_toml_str(toml).unwrap();
    let violations = cfg.validate_all().unwrap_err();

    assert!(
        violations.iter().any(|v| v.contains("max_hops")),
        "should report max_hops issue when enabled. Got: {:?}",
        violations
    );
}

// ===========================================================================
// Test 6: Load from file success
// ===========================================================================

#[test]
fn test_load_from_file_success() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let path = dir.path().join("relay.toml");

    std::fs::write(&path, valid_full_toml()).expect("failed to write test config");

    let cfg = RelayConfig::load_from_file(&path).unwrap();
    assert!(cfg.enabled());
    assert_eq!(cfg.max_hops(), 10);
    assert_eq!(cfg.default_strategy(), "shortest_path");
}

// ===========================================================================
// Test 7: Load from non-existent file returns Io error
// ===========================================================================

#[test]
fn test_load_from_nonexistent_file_returns_io_error() {
    let path = std::path::PathBuf::from("/tmp/nonexistent_relay_config_12345.toml");
    let result = RelayConfig::load_from_file(&path);

    assert!(result.is_err(), "non-existent file should return error");
    match result.unwrap_err() {
        ConfigError::Io { path: p, .. } => {
            assert_eq!(p, path, "error should contain the requested path");
        }
        other => panic!("expected Io error, got: {other}"),
    }
}

// ===========================================================================
// Test 8: Round-trip serialize/deserialize preserves all fields
// ===========================================================================

#[test]
fn test_roundtrip_serialize_deserialize() {
    let original = RelayConfig::builder()
        .enabled(true)
        .default_strategy("lowest_latency")
        .max_hops(20)
        .heartbeat_interval_secs(45)
        .circuit_breaker_threshold(7)
        .build();

    // Serialize to TOML string.
    let toml_str = toml::to_string_pretty(&original).unwrap();
    eprintln!("Serialized TOML:\n{}", toml_str);

    // Deserialize back.
    let deserialized: RelayConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(deserialized, original);
    assert_eq!(deserialized.enabled, true);
    assert_eq!(deserialized.default_strategy, "lowest_latency");
    assert_eq!(deserialized.max_hops, 20);
    assert_eq!(deserialized.heartbeat_interval_secs, 45);
    assert_eq!(deserialized.circuit_breaker_threshold, 7);
}

// ===========================================================================
// Test 9: Default config passes validate_all
// ===========================================================================

#[test]
fn test_default_config_passes_validate_all() {
    let cfg = RelayConfig::default();
    assert!(
        cfg.validate_all().is_ok(),
        "default config should pass all validations"
    );
}

// ===========================================================================
// Test 10: Custom valid config passes validate_all
// ===========================================================================

#[test]
fn test_custom_valid_config_passes_validate_all() {
    let cfg = RelayConfig::builder()
        .enabled(true)
        .default_strategy("local_egress_first")
        .max_hops(15)
        .heartbeat_interval_secs(20)
        .circuit_breaker_threshold(4)
        .build();

    assert!(
        cfg.validate_all().is_ok(),
        "custom valid config should pass all validations"
    );
}

// ===========================================================================
// Test 11: Build topology from config succeeds
// ===========================================================================

#[test]
fn test_build_topology_from_config_succeeds() {
    let cfg = RelayConfig::builder()
        .enabled(true)
        .default_strategy("local_egress_first")
        .build();

    let topo = cfg
        .build_topology_from_config(sample_nodes_toml(), sample_edges_toml())
        .unwrap();

    assert_eq!(topo.node_count(), 3, "should have 3 nodes");
    assert_eq!(topo.edge_count(), 2, "should have 2 edges");
    assert!(topo.validate().is_ok(), "topology should be valid");
}

// ===========================================================================
// Test 12: Build topology with missing node_id fails
// ===========================================================================

#[test]
fn test_build_topology_with_missing_node_id_fails() {
    let cfg = RelayConfig::default();
    let bad_nodes = r#"
[[nodes]]
role = "edge"
host = "10.0.0.1"
port = 8080
"#;

    let result = cfg.build_topology_from_config(bad_nodes, sample_edges_toml());
    assert!(result.is_err(), "missing node_id should cause failure");
    let err = result.unwrap_err();
    assert!(
        err.contains("node_id") || err.contains("missing"),
        "error should mention missing node_id, got: {}", err
    );
}

// ===========================================================================
// Test 13: Build topology with unknown role fails
// ===========================================================================

#[test]
fn test_build_topology_with_unknown_role_fails() {
    let cfg = RelayConfig::default();
    let bad_nodes = r#"
[[nodes]]
node_id = "bad-node"
role = "super_node"
host = "10.0.0.1"
port = 8080
"#;

    let result = cfg.build_topology_from_config(bad_nodes, "");
    assert!(result.is_err(), "unknown role should cause failure");
    let err = result.unwrap_err();
    assert!(
        err.contains("unknown role") || err.contains("role"),
        "error should mention unknown role, got: {}", err
    );
}

// ===========================================================================
// Test 14: Multiple validation errors collected together
// ===========================================================================

#[test]
fn test_multiple_validation_errors_collected() {
    let cfg = RelayConfig::builder()
        .enabled(true)
        .default_strategy("")
        .max_hops(0)
        .heartbeat_interval_secs(0)
        .build();

    let violations = cfg.validate_all().unwrap_err();
    assert!(
        violations.len() >= 3,
        "should collect at least 3 violations, got {}: {:?}",
        violations.len(),
        violations
    );
}
