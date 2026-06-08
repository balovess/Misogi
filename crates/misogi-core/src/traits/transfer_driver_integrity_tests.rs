// ===========================================================================
// TransferDriver Integrity Layer - Unit Tests
// ===========================================================================
//
// Validates the default implementations of the self-healing integrity
// methods added to the [`TransferDriver`] trait:
//
// - [`send_chunk_integrity()`](crate::traits::TransferDriver::send_chunk_integrity)
// - [`repair_chunks()`](crate::traits::TransferDriver::repair_chunks)
//
// Test strategy:
// 1. Construct a mock [`TransferDriver`] implementation with controllable
//    behavior (success/failure per-chunk).
// 2. Exercise the default method implementations through the trait object.
// 3. Verify return values, error propagation, and edge-case handling.
//
// All tests are synchronous-async (using tokio::test) and require the
// "runtime" feature flag since TransferDriver depends on async_trait.

use bytes::Bytes;
use chrono::Utc;
use md5::Digest;

use crate::error::{MisogiError, Result};
use crate::traits::{
    ChunkAck, IntegrityChunkAck, RepairProgress, TransferDriver, TransferDriverConfig,
};
use crate::types::ChunkMeta;

// ===========================================================================
// Mock Driver Implementation
// ===========================================================================

/// Configuration for the mock driver used in integrity layer tests.
#[derive(Debug, Clone)]
pub struct MockDriverConfig {
    /// If true, `init()` succeeds; if false, it fails.
    pub should_init_succeed: bool,
}

impl TransferDriverConfig for MockDriverConfig {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Controllable mock implementation of [`TransferDriver`] for testing the
/// default integrity methods.
///
/// Behavior is controlled via constructor flags:
/// - `always_succeed` -- `send_chunk()` always returns success.
/// - `fail_on_indices` -- `send_chunk()` fails only for specific chunk indices.
#[derive(Debug)]
pub struct MockIntegrityDriver {
    /// Whether send_chunk should always succeed.
    always_succeed: bool,

    /// Set of chunk indices on which send_chunk should return an error.
    fail_on_indices: std::collections::HashSet<u32>,

    /// Whether init has been called.
    initialized: std::sync::atomic::AtomicBool,
}

impl MockIntegrityDriver {
    /// Create a mock driver where all operations succeed.
    pub fn always_ok() -> Self {
        Self {
            always_succeed: true,
            fail_on_indices: std::collections::HashSet::new(),
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a mock driver that fails on specific chunk indices.
    pub fn failing_on(fail_indices: &[u32]) -> Self {
        Self {
            always_succeed: false,
            fail_on_indices: fail_indices.iter().copied().collect(),
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl TransferDriver for MockIntegrityDriver {
    type Config = MockDriverConfig;

    fn name(&self) -> &str {
        "mock-integrity-driver"
    }

    async fn init(&mut self, _config: Self::Config) -> Result<()> {
        self.initialized
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        if !self.always_succeed && self.fail_on_indices.contains(&chunk_index) {
            return Err(MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                format!(
                    "simulated failure for chunk {} in file {}",
                    chunk_index, file_id
                ),
            )));
        }

        let md5 = format!("{:x}", md5::Md5::digest(&data));
        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5: md5,
            received_size: data.len() as u64,
            ack_timestamp: Utc::now().to_rfc3339(),
            error: None,
        })
    }

    async fn send_complete(
        &self,
        _file_id: &str,
        _total_chunks: u32,
        _file_md5: &str,
    ) -> Result<ChunkAck> {
        Ok(ChunkAck {
            file_id: String::new(),
            chunk_index: 0,
            received_md5: String::new(),
            received_size: 0,
            ack_timestamp: Utc::now().to_rfc3339(),
            error: None,
        })
    }

    async fn health_check(&self) -> Result<crate::traits::DriverHealthStatus> {
        Ok(crate::traits::DriverHealthStatus {
            driver_name: self.name().to_string(),
            is_healthy: true,
            status_message: "mock healthy".to_string(),
            latency_ms: Some(1),
            checked_at: Utc::now(),
            check_sequence: 1,
        })
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

// ===========================================================================
// Helper: construct a minimal ChunkMeta for tests
// ===========================================================================

/// Create a valid [`ChunkMeta`] instance for test use.
fn test_chunk_meta(file_id: &str, chunk_index: u32, data: &[u8]) -> ChunkMeta {
    ChunkMeta {
        file_id: file_id.to_string(),
        chunk_index,
        chunk_md5: format!("{:x}", md5::Md5::digest(data)),
        size: data.len() as u64,
    }
}

// ===========================================================================
// Test Cases
// ===========================================================================

// --- Test 1: Default send_chunk_integrity fallback returns success ack ---

#[tokio::test]
async fn test_default_send_chunk_integrity_fallback_returns_success_ack() {
    let driver = MockIntegrityDriver::always_ok();
    let data = b"hello integrity world";
    let meta = test_chunk_meta("file-001", 0, data);

    let result = driver
        .send_chunk_integrity("file-001", 0, data, &meta, None)
        .await;

    assert!(
        result.is_ok(),
        "send_chunk_integrity should succeed when underlying send_chunk succeeds"
    );

    let ack = result.unwrap();
    assert_eq!(ack.chunk_index, 0, "ack chunk_index should match input");
    assert!(
        ack.received_ok,
        "received_ok should be true when send_chunk returns success"
    );
    assert!(
        ack.error.is_none(),
        "error should be None when send_chunk returns success"
    );
}

// --- Test 2: Default send_chunk_integrity propagates error from send_chunk ---

#[tokio::test]
async fn test_default_send_chunk_integrity_propagates_error_from_send_chunk() {
    // Driver that fails on chunk index 3.
    let driver = MockIntegrityDriver::failing_on(&[3]);
    let data = b"this chunk will fail";
    let meta = test_chunk_meta("file-error", 3, data);

    let result = driver
        .send_chunk_integrity("file-error", 3, data, &meta, None)
        .await;

    assert!(
        result.is_err(),
        "send_chunk_integrity should propagate error when send_chunk fails"
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("simulated failure"),
        "error message should contain the simulated failure description, got: {}",
        err_msg
    );
}

// --- Test 3: Default repair_chunks with valid indices succeeds ---

#[tokio::test]
async fn test_default_repair_chunks_with_valid_indices_succeeds() {
    let driver = MockIntegrityDriver::always_ok();
    let meta = test_chunk_meta("file-repair", 0, &[]);

    let chunk_a = b"chunk-data-alpha";
    let chunk_b = b"chunk-data-beta";
    let chunk_c = b"chunk-data-gamma";

    let result = driver
        .repair_chunks(
            "file-repair",
            &[10, 20, 30],
            &[
                chunk_a.as_slice(),
                chunk_b.as_slice(),
                chunk_c.as_slice(),
            ],
            &meta,
        )
        .await;

    assert!(result.is_ok(), "repair_chunks should succeed");
    let progress = result.unwrap();

    assert_eq!(progress.total_requested, 3, "total_requested should be 3");
    assert_eq!(progress.completed, 3, "all 3 repairs should complete");
    assert!(
        progress.failed_indices.is_empty(),
        "no failed indices expected, got {:?}",
        progress.failed_indices
    );
    assert!(
        progress.is_finished(),
        "progress should report finished when all repairs complete"
    );

    // Success rate should be 1.0 (100%).
    let rate = progress.success_rate();
    assert!(
        (rate - 1.0).abs() < f64::EPSILON,
        "success_rate should be 1.0, got {}",
        rate
    );
}

// --- Test 4: Default repair_chunks with partial failures ---

#[tokio::test]
async fn test_default_repair_chunks_with_partial_failures() {
    // Driver fails on index 42 but succeeds on others.
    let driver = MockIntegrityDriver::failing_on(&[42]);
    let meta = test_chunk_meta("file-partial", 0, &[]);

    let chunks: Vec<&[u8]> = vec![b"ok-data-1", b"fail-data", b"ok-data-3"];

    let result = driver
        .repair_chunks("file-partial", &[10, 42, 99], &chunks, &meta)
        .await;

    assert!(result.is_ok());
    let progress = result.unwrap();

    assert_eq!(progress.total_requested, 3);
    assert_eq!(progress.completed, 2, "2 of 3 should succeed");
    assert_eq!(
        progress.failed_indices.len(),
        1,
        "exactly 1 failed index expected"
    );
    assert_eq!(progress.failed_indices[0], 42, "failed index should be 42");

    // Success rate should be ~0.667.
    let rate = progress.success_rate();
    assert!(
        (rate - 2.0 / 3.0).abs() < 1e-10,
        "success_rate should be ~0.667, got {}",
        rate
    );
}

// --- Test 5: Default repair_chunks empty indices returns zero progress ---

#[tokio::test]
async fn test_default_repair_chunks_empty_indices_returns_zero_progress() {
    let driver = MockIntegrityDriver::always_ok();
    let meta = test_chunk_meta("file-empty", 0, &[]);

    let result = driver
        .repair_chunks("file-empty", &[], &[] as &[&[u8]], &meta)
        .await;

    assert!(result.is_ok());
    let progress = result.unwrap();

    assert_eq!(progress.total_requested, 0, "total_requested should be 0");
    assert_eq!(progress.completed, 0, "completed should be 0");
    assert!(
        progress.failed_indices.is_empty(),
        "failed_indices should be empty"
    );
    assert!(
        progress.is_finished(),
        "empty repair should be considered finished"
    );
    // Success rate for zero requests is defined as 1.0.
    assert!(
        (progress.success_rate() - 1.0).abs() < f64::EPSILON,
        "success_rate for empty repair should be 1.0"
    );
}

// --- Test 6: Backward compatibility - existing trait users compile ---

#[tokio::test]
async fn test_backward_compatibility_existing_impl_compiles() {
    // This test verifies that a minimal TransferDriver implementation
    // which does NOT override the new integrity methods still compiles
    // and functions correctly through the default implementations.

    #[derive(Debug)]
    struct MinimalDriver;

    #[async_trait::async_trait]
    impl TransferDriver for MinimalDriver {
        type Config = MockDriverConfig;

        fn name(&self) -> &str {
            "minimal-driver"
        }

        async fn init(&mut self, _config: Self::Config) -> Result<()> {
            Ok(())
        }

        async fn send_chunk(
            &self,
            file_id: &str,
            chunk_index: u32,
            data: Bytes,
        ) -> Result<ChunkAck> {
            Ok(ChunkAck {
                file_id: file_id.to_string(),
                chunk_index,
                received_md5: format!("{:x}", md5::Md5::digest(&data)),
                received_size: data.len() as u64,
                ack_timestamp: Utc::now().to_rfc3339(),
                error: None,
            })
        }

        async fn send_complete(
            &self,
            _file_id: &str,
            _total_chunks: u32,
            _file_md5: &str,
        ) -> Result<ChunkAck> {
            Ok(ChunkAck {
                file_id: String::new(),
                chunk_index: 0,
                received_md5: String::new(),
                received_size: 0,
                ack_timestamp: Utc::now().to_rfc3339(),
                error: None,
            })
        }

        async fn health_check(&self) -> Result<crate::traits::DriverHealthStatus> {
            Ok(crate::traits::DriverHealthStatus {
                driver_name: self.name().to_string(),
                is_healthy: true,
                status_message: "ok".to_string(),
                latency_ms: Some(0),
                checked_at: Utc::now(),
                check_sequence: 0,
            })
        }

        async fn shutdown(&self) -> Result<()> {
            Ok(())
        }
        // NOTE: No override of send_chunk_integrity or repair_chunks.
        // The trait defaults must be used.
    }

    let driver = MinimalDriver;
    let data = b"backward-compat-test";
    let meta = test_chunk_meta("bc-file", 0, data);

    // Exercise the default send_chunk_integrity.
    let ack_result = driver
        .send_chunk_integrity("bc-file", 0, data, &meta, None)
        .await;
    assert!(ack_result.is_ok(), "default send_chunk_integrity must work");
    let ack = ack_result.unwrap();
    assert!(ack.received_ok);
    assert_eq!(ack.chunk_index, 0);

    // Exercise the default repair_chunks.
    let repair_result = driver.repair_chunks("bc-file", &[0], &[data], &meta).await;
    assert!(repair_result.is_ok(), "default repair_chunks must work");
    let progress = repair_result.unwrap();
    assert_eq!(progress.completed, 1);
    assert!(progress.failed_indices.is_empty());
}

// --- Test 7: IntegrityAck construction ---

#[tokio::test]
async fn test_integrity_ack_construction() {
    // Verify IntegrityChunkAck can be constructed and its fields are correct.

    // Success case.
    let ok_ack = IntegrityChunkAck {
        chunk_index: 7,
        received_ok: true,
        error: None,
    };
    assert_eq!(ok_ack.chunk_index, 7);
    assert!(ok_ack.received_ok);
    assert!(ok_ack.error.is_none());

    // Failure case.
    let fail_ack = IntegrityChunkAck {
        chunk_index: 99,
        received_ok: false,
        error: Some("hash mismatch detected".to_string()),
    };
    assert_eq!(fail_ack.chunk_index, 99);
    assert!(!fail_ack.received_ok);
    assert_eq!(
        fail_ack.error.as_deref(),
        Some("hash mismatch detected")
    );

    // Ack produced by default send_chunk_integrity should carry the chunk_index.
    let driver = MockIntegrityDriver::always_ok();
    let data = b"ack-construction-test";
    let meta = test_chunk_meta("ack-test", 42, data);

    let result = driver
        .send_chunk_integrity("ack-test", 42, data, &meta, None)
        .await
        .expect("should succeed");

    assert_eq!(result.chunk_index, 42);
    assert!(result.received_ok);
}

// --- Test 8: RepairProgress construction ---

#[tokio::test]
async fn test_repair_progress_construction() {
    // Verify RepairProgress struct fields and helper methods.

    // All-succeeded case.
    let all_ok = RepairProgress {
        total_requested: 5,
        completed: 5,
        failed_indices: vec![],
    };
    assert_eq!(all_ok.total_requested, 5);
    assert_eq!(all_ok.completed, 5);
    assert!(all_ok.failed_indices.is_empty());
    assert!(all_ok.is_finished());
    assert!((all_ok.success_rate() - 1.0).abs() < f64::EPSILON);

    // Partial failure case.
    let partial = RepairProgress {
        total_requested: 10,
        completed: 7,
        failed_indices: vec![2, 5, 8],
    };
    assert_eq!(partial.total_requested, 10);
    assert_eq!(partial.completed, 7);
    assert_eq!(partial.failed_indices.len(), 3);
    assert_eq!(partial.failed_indices, vec![2, 5, 8]);
    assert!(partial.is_finished()); // 7 + 3 = 10 == total
    assert!(
        (partial.success_rate() - 0.7).abs() < 1e-10,
        "success_rate should be 0.7, got {}",
        partial.success_rate()
    );

    // Total failure case.
    let total_fail = RepairProgress {
        total_requested: 3,
        completed: 0,
        failed_indices: vec![0, 1, 2],
    };
    assert_eq!(total_fail.completed, 0);
    assert!(total_fail.is_finished());
    assert!(
        (total_fail.success_rate()).abs() < f64::EPSILON,
        "success_rate should be 0.0 for total failure"
    );

    // Incomplete (not yet finished) case.
    let incomplete = RepairProgress {
        total_requested: 10,
        completed: 3,
        failed_indices: vec![1],
    }; // 3 + 1 = 4 < 10
    assert!(
        !incomplete.is_finished(),
        "incomplete progress should not be finished"
    );
}

// --- Test 9: repair_chunks with mismatched indices/chunks lengths ---

#[tokio::test]
async fn test_default_repair_chunks_mismatched_lengths_handles_gracefully() {
    let driver = MockIntegrityDriver::always_ok();
    let meta = test_chunk_meta("file-mismatch", 0, &[]);

    // 3 indices but only 2 chunks provided - third index has no data.
    let result = driver
        .repair_chunks(
            "file-mismatch",
            &[100, 200, 300],
            &[b"data-a", b"data-b"],
            &meta,
        )
        .await;

    assert!(result.is_ok());
    let progress = result.unwrap();

    assert_eq!(progress.total_requested, 3);
    assert_eq!(progress.completed, 2, "only 2 had corresponding data");
    assert_eq!(
        progress.failed_indices.len(),
        1,
        "index without data should be recorded as failed"
    );
    assert_eq!(
        progress.failed_indices[0], 300,
        "third index (300) should fail"
    );
}
