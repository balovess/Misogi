// Comprehensive unit tests for the transfer mode factory module.
//
// Test coverage (25 tests across 7 groups):
//
// | Group | Count | Coverage |
//|-------|-------|----------|
// | 1. TransferMode FromStr parsing | 7 | push, pull, blind_send, case-insensitive, invalid, Display roundtrip, default |
// | 2. Serde serialization | 2 | config roundtrip, snake_case rename |
// | 3. build_driver() correct type | 3 | Push->DirectTcp, Pull->PullDriver, BlindSend->BlindSendDriver |
// | 4. Missing config / defaults | 3 | Pull default, BlindSend default, Push missing addr error |
// | 5. validate() method | 5 | Push valid/invalid, Pull valid, BlindSend valid/invalid redundancy |
// | 6. Edge cases | 3 | factory defaults, TCP defaults, equality+hash |
// | 7. build_init_config() | 3 | Pull variant, BlindSend variant, validate delegation


// =============================================================================
// Test Group 1: TransferMode Parsing (FromStr)
// =============================================================================

#[test]
fn test_mode_parse_push() {
    let mode: TransferMode = "push".parse().expect("Failed to parse 'push'");
    assert_eq!(mode, TransferMode::Push);
}

#[test]
fn test_mode_parse_pull() {
    let mode: TransferMode = "pull".parse().expect("Failed to parse 'pull'");
    assert_eq!(mode, TransferMode::Pull);
}

#[test]
fn test_mode_parse_blind_send() {
    let mode: TransferMode = "blind_send".parse().expect("Failed to parse 'blind_send'");
    assert_eq!(mode, TransferMode::BlindSend);
}

#[test]
fn test_mode_parse_case_insensitive() {
    assert_eq!("PUSH".parse::<TransferMode>().unwrap(), TransferMode::Push);
    assert_eq!("Pull".parse::<TransferMode>().unwrap(), TransferMode::Pull);
    assert_eq!("BLIND_SEND".parse::<TransferMode>().unwrap(), TransferMode::BlindSend);
}

#[test]
fn test_mode_parse_invalid_string() {
    let result = "ftp".parse::<TransferMode>();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Invalid transfer mode"));
    assert!(err_msg.contains("ftp"));
}

#[test]
fn test_mode_display_roundtrip() {
    for mode in &[TransferMode::Push, TransferMode::Pull, TransferMode::BlindSend] {
        let displayed = format!("{}", mode);
        let parsed: TransferMode = displayed.parse().expect("Roundtrip failed");
        assert_eq!(*mode, parsed);
    }
}

#[test]
fn test_mode_default_is_push() {
    assert_eq!(TransferMode::default(), TransferMode::Push);
}

// =============================================================================
// Test Group 2: Serde Serialization / Deserialization
// =============================================================================

#[test]
fn test_factory_config_serde_roundtrip() {
    let original = TransferFactoryConfig {
        mode: TransferMode::Pull,
        push_config: None,
        pull_config: Some(PullConfig::default()),
        blind_send_config: None,
    };
    let json = serde_json::to_string(&original).expect("Serialize failed");
    let decoded: TransferFactoryConfig =
        serde_json::from_str(&json).expect("Deserialize failed");
    assert_eq!(decoded.mode, TransferMode::Pull);
    assert!(decoded.pull_config.is_some());
}

#[test]
fn test_transfer_mode_serde_snake_case() {
    // Verify serde(rename_all = "snake_case") works correctly
    let json = r#""blind_send""#;
    let mode: TransferMode = serde_json::from_str(json).expect("Deserialize failed");
    assert_eq!(mode, TransferMode::BlindSend);

    let output = serde_json::to_string(&mode).expect("Serialize failed");
    assert_eq!(output, "\"blind_send\"");
}

// =============================================================================
// Test Group 3: Factory build_driver() — Correct Driver Type
// =============================================================================

#[test]
fn test_build_driver_push_returns_direct_tcp() {
    let config = TransferFactoryConfig {
        mode: TransferMode::Push,
        push_config: Some(DirectTcpFactoryConfig {
            receiver_addr: "10.0.0.1:9000".to_string(),
            node_id: "test-push-node".to_string(),
        }),
        pull_config: None,
        blind_send_config: None,
    };

    let driver = config.build_driver().expect("build_driver failed");
    assert_eq!(driver.name(), "direct-tcp-driver");
    // Verify it's the Push variant
    assert!(matches!(driver, BuiltDriver::Push(_)));
}

#[test]
fn test_build_driver_pull_returns_pull_driver() {
    let config = TransferFactoryConfig {
        mode: TransferMode::Pull,
        push_config: None,
        pull_config: Some(PullConfig::default()),
        blind_send_config: None,
    };

    let driver = config.build_driver().expect("build_driver failed");
    assert_eq!(driver.name(), "pull-driver");
    assert!(matches!(driver, BuiltDriver::Pull(_)));
}

#[test]
fn test_build_driver_blind_send_returns_blind_send_driver() {
    let config = TransferFactoryConfig {
        mode: TransferMode::BlindSend,
        push_config: None,
        pull_config: None,
        blind_send_config: Some(BlindSendConfig::default()),
    };

    let driver = config.build_driver().expect("build_driver failed");
    assert_eq!(driver.name(), "blind-send-driver");
    assert!(matches!(driver, BuiltDriver::BlindSend(_)));
}

// =============================================================================
// Test Group 4: Missing Config / Defaults
// =============================================================================

#[test]
fn test_build_driver_pull_with_default_config() {
    // No pull_config provided — should use PullConfig::default()
    let config = TransferFactoryConfig::new(TransferMode::Pull);

    let driver = config.build_driver().expect("build_driver with default config failed");
    assert_eq!(driver.name(), "pull-driver");
}

#[test]
fn test_build_driver_blind_send_with_default_config() {
    let config = TransferFactoryConfig::new(TransferMode::BlindSend);

    let driver = config.build_driver().expect("build_driver with default config failed");
    assert_eq!(driver.name(), "blind-send-driver");
}

#[test]
fn test_build_driver_push_missing_addr_fails() {
    // Push mode without push_config should fail because addr is empty
    let config = TransferFactoryConfig::new(TransferMode::Push);

    let result = config.build_driver();
    assert!(result.is_err());
    let err_msg = format!("{}", result.err().unwrap());
    assert!(err_msg.contains("receiver_addr"));
}

// =============================================================================
// Test Group 5: validate() Method
// =============================================================================

#[test]
fn test_validate_push_valid() {
    let config = TransferFactoryConfig {
        mode: TransferMode::Push,
        push_config: Some(DirectTcpFactoryConfig {
            receiver_addr: "192.168.1.100:9000".to_string(),
            node_id: "node-01".to_string(),
        }),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_push_empty_addr_fails() {
    let config = TransferFactoryConfig {
        mode: TransferMode::Push,
        push_config: Some(DirectTcpFactoryConfig {
            receiver_addr: String::new(),
            node_id: "node-01".to_string(),
        }),
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_validate_pull_valid() {
    let config = TransferFactoryConfig {
        mode: TransferMode::Pull,
        pull_config: Some(PullConfig::default()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_blind_send_valid() {
    let config = TransferFactoryConfig {
        mode: TransferMode::BlindSend,
        blind_send_config: Some(BlindSendConfig::default()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_blind_send_invalid_redundancy_fails() {
    let mut bad_cfg = BlindSendConfig::default();
    bad_cfg.redundancy_factor = 0.5; // Below minimum 1.5
    let config = TransferFactoryConfig {
        mode: TransferMode::BlindSend,
        blind_send_config: Some(bad_cfg),
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

// =============================================================================
// Test Group 6: Edge Cases
// =============================================================================

#[test]
fn test_factory_config_default() {
    let config = TransferFactoryConfig::default();
    assert_eq!(config.mode, TransferMode::Push);
    assert!(config.push_config.is_none());
    assert!(config.pull_config.is_none());
    assert!(config.blind_send_config.is_none());
}

#[test]
fn test_direct_tcp_factory_config_default() {
    let cfg = DirectTcpFactoryConfig::default();
    assert_eq!(cfg.receiver_addr, "127.0.0.1:9000");
    assert_eq!(cfg.node_id, "misogi-node");
}

#[test]
fn test_mode_equality_and_hash() {
    // Verify derived traits work correctly
    assert_eq!(TransferMode::Push, TransferMode::Push);
    assert_ne!(TransferMode::Push, TransferMode::Pull);
    // Hash consistency (used in HashMap keys, etc.)
    use std::collections::HashSet;
    let set: HashSet<TransferMode> = [
        TransferMode::Push,
        TransferMode::Pull,
        TransferMode::BlindSend,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(set.len(), 3);
}

// =============================================================================
// Test Group 7: build_init_config() produces correct variant
// =============================================================================

#[test]
fn test_build_init_config_pull() {
    let config = TransferFactoryConfig {
        mode: TransferMode::Pull,
        pull_config: Some(PullConfig::default()),
        ..Default::default()
    };
    let init_cfg = config.build_init_config().unwrap();
    assert!(matches!(init_cfg, BuiltDriverConfig::Pull(_)));
}

#[test]
fn test_build_init_config_blind_send() {
    let config = TransferFactoryConfig {
        mode: TransferMode::BlindSend,
        blind_send_config: Some(BlindSendConfig::default()),
        ..Default::default()
    };
    let init_cfg = config.build_init_config().unwrap();
    assert!(matches!(init_cfg, BuiltDriverConfig::BlindSend(_)));
}

#[test]
fn test_built_driver_config_validate_delegates() {
    let cfg = BuiltDriverConfig::Pull(PullConfig::default());
    assert!(cfg.validate().is_ok());

    let mut bad_bs = BlindSendConfig::default();
    bad_bs.redundancy_factor = 0.5;
    let bad_cfg = BuiltDriverConfig::BlindSend(bad_bs);
    assert!(bad_cfg.validate().is_err());
}
