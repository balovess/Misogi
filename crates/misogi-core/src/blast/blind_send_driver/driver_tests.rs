//! Integration tests for BlindSendDriver: config, lifecycle, full cycle.
//!
//! Tests are separated into their own file to keep driver.rs under 500 lines
//! per the project's single-file size limit.

use bytes::Bytes;

use crate::traits::{TransferDriver, TransferDriverConfig};

use super::{BlindSendConfig, BlindSendDriver, BlindSendEncoder, BlindSendDecoder};
use super::packet::FecPacket;

// =============================================================================
// Test Group 1: Configuration defaults and validation
// =============================================================================

#[test]
fn test_config_defaults_are_sane() {
    let cfg = BlindSendConfig::default();
    assert_eq!(cfg.udp_port, 9999);
    assert!((cfg.redundancy_factor - 2.0).abs() < f32::EPSILON);
    assert_eq!(cfg.packet_size, 1400);
    assert_eq!(cfg.broadcast_addr, std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST));
    assert_eq!(cfg.fec_data_shards, 16); // Matches FecConfig::standard()
}

#[test]
fn test_config_validate_accepts_valid() {
    assert!(BlindSendConfig::default().validate().is_ok());
}

#[test]
fn test_config_validate_rejects_zero_port() {
    let cfg = BlindSendConfig { udp_port: 0, ..Default::default() };
    assert!(cfg.validate().is_err());
}

#[test]
fn test_config_validate_rejects_low_redundancy() {
    let cfg = BlindSendConfig { redundancy_factor: 1.0, ..Default::default() };
    assert!(cfg.validate().is_err());
}

#[test]
fn test_config_validate_rejects_high_redundancy() {
    let cfg = BlindSendConfig { redundancy_factor: 4.0, ..Default::default() };
    assert!(cfg.validate().is_err());
}

#[test]
fn test_config_compute_parity_for_factor_2() {
    let cfg = BlindSendConfig { redundancy_factor: 2.0, fec_data_shards: 16, ..Default::default() };
    assert_eq!(cfg.compute_parity_shards(), 15); // Capped at data - 1
}

#[test]
fn test_config_compute_parity_for_factor_15() {
    let cfg = BlindSendConfig { redundancy_factor: 1.5, fec_data_shards: 8, ..Default::default() };
    assert_eq!(cfg.compute_parity_shards(), 4);
}

#[test]
fn test_config_to_fec_config_mapping() {
    let cfg = BlindSendConfig {
        redundancy_factor: 2.0, fec_data_shards: 16, packet_size: 1400,
        ..Default::default()
    };
    let fec = cfg.to_fec_config();
    assert_eq!(fec.data_shards, 16);
    assert_eq!(fec.parity_shards, 15);
    assert_eq!(fec.shard_size, 1400);
}

// =============================================================================
// Test Group 2: Driver lifecycle (init / health_check / shutdown)
// =============================================================================

#[tokio::test]
async fn test_driver_init_and_health_check() {
    let config = BlindSendConfig::default();
    let mut driver = BlindSendDriver::new(config.clone());

    let health = driver.health_check().await.expect("Health check");
    assert!(!health.is_healthy);

    driver.init(config).await.expect("Init");

    let health = driver.health_check().await.expect("Health check");
    assert!(health.is_healthy);
    assert_eq!(health.driver_name, "blind-send-driver");
}

#[tokio::test]
async fn test_driver_send_chunk_returns_synthetic_ack() {
    let mut driver = BlindSendDriver::new(BlindSendConfig::default());
    driver.init(BlindSendConfig::default()).await.expect("Init");

    let ack = driver.send_chunk("file-001", 0, Bytes::from_static(b"test"))
        .await.expect("send_chunk");

    assert_eq!(ack.file_id, "file-001");
    assert_eq!(ack.chunk_index, 0);
    assert!(ack.error.is_none());
    assert!(ack.is_success());
}

#[tokio::test]
async fn test_driver_shutdown_is_idempotent() {
    let mut driver = BlindSendDriver::new(BlindSendConfig::default());
    driver.init(BlindSendConfig::default()).await.expect("Init");

    assert!(driver.shutdown().await.is_ok());
    assert!(driver.shutdown().await.is_ok()); // Idempotent

    let health = driver.health_check().await.expect("Health check");
    assert!(!health.is_healthy);
}

#[tokio::test]
async fn test_driver_send_before_init_fails() {
    let driver = BlindSendDriver::new(BlindSendConfig::default());
    let result = driver.send_chunk("f", 0, Bytes::new()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not initialized"));
}

// =============================================================================
// Test Group 3: Full encode-transmit-decode cycle simulation
// =============================================================================

#[tokio::test]
async fn test_full_cycle_simulated_transmission() {
    let config = BlindSendConfig {
        redundancy_factor: 2.0,
        fec_data_shards: 8,
        packet_size: 512,
        ..Default::default()
    };

    let fec_cfg = config.to_fec_config();
    let enc = BlindSendEncoder::new(&fec_cfg).expect("Encoder");
    let dec = BlindSendDecoder::new(&fec_cfg).expect("Decoder");

    let original: Vec<u8> = (0..3000).map(|i| (i * 37 % 256) as u8).collect();
    let packets = enc.encode(&original).expect("Encode");

    let wire_packets: Vec<FecPacket> = packets
        .iter()
        .map(|p| FecPacket::from_bytes(&p.to_bytes()).expect("Wire roundtrip"))
        .collect();

    let decoded = dec.decode(&wire_packets, original.len()).expect("Decode");
    assert_eq!(decoded, original, "Full cycle must reproduce original data");
}

#[tokio::test]
async fn test_full_cycle_with_corrupted_packets_filtered() {
    let config = BlindSendConfig::default();
    let fec_cfg = config.to_fec_config();
    let enc = BlindSendEncoder::new(&fec_cfg).expect("Encoder");
    let dec = BlindSendDecoder::new(&fec_cfg).expect("Decoder");

    let original = b"Integrity check data with corruption simulation".to_vec();
    let packets = enc.encode(&original).expect("Encode");

    let mut corrupted_packets = packets.clone();
    if !corrupted_packets.is_empty() {
        let corrupt_data = {
            let mut d = corrupted_packets[0].data.to_vec();
            if !d.is_empty() { d[0] ^= 0xFF; }
            Bytes::from(d)
        };
        corrupted_packets[0].data = corrupt_data;
    }

    let result = dec.decode(&corrupted_packets, original.len());
    assert!(result.is_ok(), "Should recover despite 1 corrupted packet");
    assert_eq!(result.unwrap(), original);
}
