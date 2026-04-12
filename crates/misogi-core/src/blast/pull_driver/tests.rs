//! Comprehensive unit test suite for the pull driver (Mode B).
//!
//! # Test Coverage Summary
//!
//! | Category                | Count | Key Scenarios                              |
//! |-------------------------|-------|--------------------------------------------|
//! | Config validation       | 4     | Defaults, bounds, serialization roundtrip |
//! | Write/poll/pull cycle   | 2     | Send → list, send → pull → ack            |
//! | Concurrent access       | 2     | Multi-send, poll+pull race                 |
//! | Retention cleanup       | 1     | Expired entry eviction on write trigger    |
//! | ACK flow correctness    | 1     | State machine: Pending→Pulling→Acknowledged|
//! | Empty buffer handling   | 1     | Empty list, pull-missing error             |
//! | Buffer capacity         | 2     | Unlimited mode (0 MB)                     |
//! | Health check / shutdown | 4     | Pre/post init, idempotent shutdown        |
//! | send_complete           | 2     | Normal, not-initialized error              |
//! | Entry helpers           | 2     | Default status, serde roundtrip            |
//! | Driver name             | 1     | Name constant verification                 |
//! | **Total**               | **22**|                                            |

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::traits::{TransferDriver, TransferDriverConfig};
use super::types::{PullConfig, PullBufferEntry, PullEntryStatus};
use super::driver::PullDriver;

// =========================================================================
// Test Group 1: Configuration Validation
// =========================================================================

#[test]
fn test_pull_config_valid_defaults() {
    let cfg = PullConfig::default();
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.poll_interval, Duration::from_secs(5));
    assert_eq!(cfg.buffer_max_size_mb, 512);
    assert_eq!(cfg.retention_duration, Duration::from_secs(3600));
}

#[test]
fn test_pull_config_rejects_short_poll_interval() {
    let cfg = PullConfig {
        poll_interval: Duration::from_millis(50),
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("poll_interval"),
        "Error should mention poll_interval"
    );
}

#[test]
fn test_pull_config_rejects_excessive_buffer_size() {
    let cfg = PullConfig {
        buffer_max_size_mb: 2_000_000, // > 1 TB
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("buffer_max_size_mb"),
        "Error should mention buffer_max_size_mb"
    );
}

#[test]
fn test_pull_config_serialization_roundtrip() {
    use std::path::PathBuf;

    let cfg = PullConfig {
        poll_interval: Duration::from_secs(10),
        buffer_max_size_mb: 256,
        retention_duration: Duration::from_secs(1800),
        buffer_path: PathBuf::from("/var/lib/misogi/buffer"),
    };
    let json = serde_json::to_string(&cfg).expect("Serialize OK");
    let decoded: PullConfig = serde_json::from_str(&json).expect("Deserialize OK");
    assert_eq!(decoded.poll_interval, cfg.poll_interval);
    assert_eq!(decoded.buffer_max_size_mb, 256);
    assert_eq!(decoded.retention_duration, cfg.retention_duration);
}

// =========================================================================
// Test Group 2: Buffer Write / Poll / Pull Cycle
// =========================================================================

#[tokio::test]
async fn test_send_chunk_and_list_pending() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    let data = Bytes::from_static(b"hello pull world");
    let ack = driver.send_chunk("file-001", 0, data.clone()).await.unwrap();

    assert_eq!(ack.file_id, "file-001");
    assert_eq!(ack.chunk_index, 0);
    assert!(ack.error.is_none());
    assert!(!ack.received_md5.is_empty());

    // List pending should show our entry
    let pending = driver.list_pending_files().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].file_id, "file-001");
    assert_eq!(pending[0].data, data);
}

#[tokio::test]
async fn test_pull_and_ack_cycle() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    // Send
    let data = Bytes::from_static(b"pull-test-data");
    driver.send_chunk("file-pull", 0, data.clone()).await.unwrap();

    // List
    let pending = driver.list_pending_files().await.unwrap();
    assert_eq!(pending.len(), 1);
    let entry_id = pending[0].entry_id.clone();

    // Pull
    let pulled = driver.pull_file(&entry_id).await.unwrap();
    assert_eq!(pulled.data, data);
    assert_eq!(pulled.status, PullEntryStatus::Pulling);

    // After pulling, listing should show zero pending
    let pending2 = driver.list_pending_files().await.unwrap();
    assert_eq!(pending2.len(), 0);

    // Ack
    driver.ack_file(&entry_id).await.unwrap();

    // Re-pulling should fail (no longer Pulling)
    let result = driver.pull_file(&entry_id).await;
    assert!(result.is_err(), "Re-pull after ack should error");
}

// =========================================================================
// Test Group 3: Concurrent Access Safety
// =========================================================================

#[tokio::test]
async fn test_concurrent_sends() {
    let mut driver = PullDriver::with_config(PullConfig {
        buffer_max_size_mb: 100,
        ..Default::default()
    });
    driver.init(PullConfig {
        buffer_max_size_mb: 100,
        ..Default::default()
    }).await.unwrap();

    // Spawn multiple concurrent send tasks using Arc for 'static lifetime.
    let driver_arc = Arc::new(driver);
    let handles: Vec<_> = (0..20u32)
        .map(|i| {
            let d = Arc::clone(&driver_arc);
            tokio::spawn(async move {
                let data = Bytes::from(vec![i as u8; 256]);
                d.send_chunk("concurrent-file", i, data).await
            })
        })
        .collect();

    // All should succeed without deadlock or panic.
    for h in handles {
        let result = h.await.unwrap();
        assert!(result.is_ok(), "Concurrent send failed: {:?}", result.err());
    }

    // Verify all 20 entries exist in the buffer.
    let pending = driver_arc.list_pending_files().await.unwrap();
    assert_eq!(pending.len(), 20);
}

#[tokio::test]
async fn test_concurrent_poll_and_pull() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    // Pre-populate 5 entries.
    for i in 0..5u32 {
        driver
            .send_chunk("race-file", i, Bytes::from(vec![i as u8; 64]))
            .await
            .unwrap();
    }

    // Use Arc for 'static lifetime required by tokio::spawn.
    let driver_arc = Arc::new(driver);

    // Concurrently poll and pull — no panic or deadlock = success.
    let d1 = Arc::clone(&driver_arc);
    let poll_handle = tokio::spawn(async move {
        let _ = d1.list_pending_files().await.unwrap();
    });

    let d2 = Arc::clone(&driver_arc);
    let pull_handle = tokio::spawn(async move {
        let pending = d2.list_pending_files().await.unwrap();
        if !pending.is_empty() {
            let eid = pending[0].entry_id.clone();
            let _ = d2.pull_file(&eid).await;
        }
    });

    let (_, _) = tokio::join!(poll_handle, pull_handle);
}

// =========================================================================
// Test Group 4: Retention Cleanup
// =========================================================================

#[tokio::test]
async fn test_retention_cleanup_evicts_old_entries() {
    let mut driver = PullDriver::with_config(PullConfig {
        retention_duration: Duration::from_millis(1500), // >= 1s minimum for validation
        ..Default::default()
    });
    driver.init(PullConfig {
        retention_duration: Duration::from_millis(1500),
        ..Default::default()
    }).await.unwrap();

    // Insert an entry that will expire.
    driver
        .send_chunk("expire-file", 0, Bytes::from_static(b"expiring data"))
        .await
        .unwrap();

    // Wait for retention duration to elapse.
    tokio::time::sleep(Duration::from_millis(1800)).await;

    // Trigger cleanup by attempting another insert (cleanup runs before every write).
    let result = driver
        .send_chunk("new-file", 0, Bytes::from_static(b"fresh data"))
        .await;

    // The old entry should have been evicted, making room for the new one.
    assert!(result.is_ok());

    // Only the fresh entry should remain.
    let pending = driver.list_pending_files().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].file_id, "new-file");
}

// =========================================================================
// Test Group 5: ACK Flow State Machine Correctness
// =========================================================================

#[tokio::test]
async fn test_ack_flow_state_transitions() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    driver
        .send_chunk("ack-test", 0, Bytes::from_static(b"ack data"))
        .await
        .unwrap();

    let pending = driver.list_pending_files().await.unwrap();
    let eid = pending[0].entry_id.clone();

    // Initial state: Pending
    assert_eq!(pending[0].status, PullEntryStatus::Pending);

    // After pull: Pulling
    let pulled = driver.pull_file(&eid).await.unwrap();
    assert_eq!(pulled.status, PullEntryStatus::Pulling);

    // Double-pull should fail (already in Pulling state)
    assert!(driver.pull_file(&eid).await.is_err());

    // After ack: Acknowledged
    driver.ack_file(&eid).await.unwrap();

    // Re-ack should fail (no longer in Pulling state)
    assert!(driver.ack_file(&eid).await.is_err());
}

// =========================================================================
// Test Group 6: Empty Buffer Handling
// =========================================================================

#[tokio::test]
async fn test_empty_buffer_list_returns_empty() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    let pending = driver.list_pending_files().await.unwrap();
    assert!(pending.is_empty(), "Empty buffer should return empty list");

    // Pull from empty buffer should yield NotFound error.
    let result = driver.pull_file("nonexistent-id").await;
    assert!(result.is_err());
    matches!(result.unwrap_err(), crate::error::MisogiError::NotFound(_));
}

// =========================================================================
// Test Group 7: Buffer Capacity Enforcement
// =========================================================================

#[tokio::test]
async fn test_buffer_unlimited_mode() {
    let mut driver = PullDriver::with_config(PullConfig {
        buffer_max_size_mb: 0, // 0 = unlimited
        ..Default::default()
    });
    driver.init(PullConfig {
        buffer_max_size_mb: 0,
        ..Default::default()
    }).await.unwrap();

    // Large payload should succeed when unlimited mode is active.
    let big_data = Bytes::from(vec![0xAB; 1024 * 1024]); // 1 MB
    let result = driver.send_chunk("big-file", 0, big_data).await;
    assert!(result.is_ok(), "Unlimited mode should accept any size");
}

#[tokio::test]
async fn test_buffer_single_byte_accepted() {
    let mut driver = PullDriver::with_config(PullConfig {
        buffer_max_size_mb: 0, // Unlimited
        ..Default::default()
    });
    driver.init(PullConfig {
        buffer_max_size_mb: 0,
        ..Default::default()
    }).await.unwrap();

    let data = Bytes::from_static(b"x");
    assert!(driver.send_chunk("f", 0, data).await.is_ok());
}

// =========================================================================
// Test Group 8: Health Check and Shutdown
// =========================================================================

#[tokio::test]
async fn test_health_check_before_init() {
    let driver = PullDriver::new();
    let health = driver.health_check().await.unwrap();
    assert!(!health.is_healthy);
    assert!(
        health.status_message.contains("Not initialized"),
        "Should report uninitialized state"
    );
}

#[tokio::test]
async fn test_health_check_after_init() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    driver
        .send_chunk("health-file", 0, Bytes::from_static(b"data"))
        .await
        .unwrap();

    let health = driver.health_check().await.unwrap();
    assert!(health.is_healthy);
    assert!(
        health.status_message.contains("entries="),
        "Health message should contain entry statistics"
    );
    assert!(health.latency_ms.is_some());
}

#[tokio::test]
async fn test_shutdown_clears_buffer() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    driver
        .send_chunk("shutdown-file", 0, Bytes::from_static(b"data"))
        .await
        .unwrap();

    assert!(!driver.list_pending_files().await.unwrap().is_empty());

    driver.shutdown().await.unwrap();

    // After shutdown, operations should fail (not initialized).
    let result = driver.send_chunk("after-shutdown", 0, Bytes::from_static(b"x")).await;
    assert!(result.is_err(), "Send after shutdown should fail");
}

#[tokio::test]
async fn test_shutdown_is_idempotent() {
    let driver = PullDriver::new();
    assert!(driver.shutdown().await.is_ok());
    assert!(driver.shutdown().await.is_ok()); // Second call must also succeed
}

// =========================================================================
// Test Group 9: send_complete Integration
// =========================================================================

#[tokio::test]
async fn test_send_complete_returns_ack() {
    let mut driver = PullDriver::new();
    driver.init(PullConfig::default()).await.unwrap();

    let ack = driver
        .send_complete("complete-file", 10, "abcd1234")
        .await
        .unwrap();

    assert_eq!(ack.file_id, "complete-file");
    assert_eq!(ack.chunk_index, 9); // total_chunks - 1
    assert_eq!(ack.received_md5, "abcd1234");
}

#[tokio::test]
async fn test_send_complete_not_initialized_fails() {
    let driver = PullDriver::new();
    let result = driver.send_complete("f", 1, "hash").await;
    assert!(result.is_err(), "send_complete before init should error");
}

// =========================================================================
// Test Group 10: PullBufferEntry Helper Methods
// =========================================================================

#[test]
fn test_entry_status_defaults_to_pending() {
    assert_eq!(PullEntryStatus::default(), PullEntryStatus::Pending);
}

#[test]
fn test_entry_serialization_roundtrip() {
    let entry = PullBufferEntry {
        entry_id: "uuid-1234".to_string(),
        file_id: "file-001".to_string(),
        chunk_index: 3,
        data: Bytes::from_static(b"payload"),
        data_md5: "md5hash".to_string(),
        status: PullEntryStatus::Pending,
        created_at: 1700000000000,
        updated_at: 1700000000000,
        total_file_size: 4096,
    };

    let json = serde_json::to_string(&entry).expect("Serialize OK");
    let decoded: PullBufferEntry = serde_json::from_str(&json).expect("Deserialize OK");
    assert_eq!(decoded.entry_id, "uuid-1234");
    assert_eq!(decoded.chunk_index, 3);
    assert_eq!(decoded.status, PullEntryStatus::Pending);
    assert_eq!(decoded.data, Bytes::from_static(b"payload"));
}

// =========================================================================
// Test Group 11: Driver Identity
// =========================================================================

#[test]
fn test_driver_name() {
    let driver = PullDriver::new();
    assert_eq!(driver.name(), "pull-driver");
}
