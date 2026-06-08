//! Unit tests for session management types.
//!
//! Tests cover transport state machine, capabilities, session handle
//! lifecycle, confirmation tracking, pending indices, verification
//! reports, and repair progress. Total: 20 tests.

use super::*;

// ===========================================================================
// TransportState Tests
// ===========================================================================

#[test]
fn test_terminal_states() {
    assert!(TransportState::Completed.is_terminal());
    assert!(TransportState::Failed.is_terminal());
    assert!(!TransportState::Negotiating.is_terminal());
    assert!(!TransportState::Transferring.is_terminal());
    assert!(!TransportState::Paused.is_terminal());
    assert!(!TransportState::Repairing.is_terminal());
    assert!(!TransportState::Verifying.is_terminal());
}

#[test]
fn test_active_states() {
    assert!(!TransportState::Completed.is_active());
    assert!(!TransportState::Failed.is_active());
    assert!(TransportState::Transferring.is_active());
    assert!(TransportState::Repairing.is_active());
}

#[test]
fn test_state_display() {
    assert_eq!(format!("{}", TransportState::Completed), "COMPLETED");
    assert_eq!(format!("{}", TransportState::Failed), "FAILED");
    assert_eq!(format!("{}", TransportState::Transferring), "TRANSFERRING");
}

#[test]
fn test_state_serialization_roundtrip() {
    let states = [
        TransportState::Negotiating,
        TransportState::Transferring,
        TransportState::Paused,
        TransportState::Repairing,
        TransportState::Verifying,
        TransportState::Completed,
        TransportState::Failed,
    ];
    for state in &states {
        let json = serde_json::to_string(state).unwrap();
        let deserialized: TransportState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, *state);
    }
}

// ===========================================================================
// TransportCapabilities Tests
// ===========================================================================

#[test]
fn test_capabilities_default() {
    let caps = TransportCapabilities::default();
    assert!(caps.supports_integrity);
    assert!(caps.supports_repair);
    assert!(caps.supports_checkpoint);
    assert_eq!(caps.max_chunk_size_bytes, 4 * 1024 * 1024);
    assert!(caps.supports_algorithm(&HashAlgorithm::Sha256));
}

#[test]
fn test_full_support_capabilities() {
    let caps = TransportCapabilities::full_support(vec![
        HashAlgorithm::Sha256,
        HashAlgorithm::Blake3,
    ]);
    assert!(caps.supports_integrity);
    assert!(caps.supports_algorithm(&HashAlgorithm::Sha256));
    assert!(caps.supports_algorithm(&HashAlgorithm::Blake3));
    assert!(!caps.supports_algorithm(&HashAlgorithm::Sha512));
}

// ===========================================================================
// SessionHandle Tests
// ===========================================================================

fn make_test_metadata(total_chunks: u32) -> SessionMetadata {
    SessionMetadata {
        session_id: "test-session-001".to_string(),
        total_chunks,
        file_size_bytes: total_chunks as u64 * 1024,
        file_hash: "abc123".to_string(),
        created_at: 1000000,
        capabilities: TransportCapabilities::default(),
    }
}

#[test]
fn test_handle_initial_state_is_negotiating() {
    let handle = SessionHandle::new(make_test_metadata(10));
    assert_eq!(handle.state(), TransportState::Negotiating);
}

#[test]
fn test_state_transition() {
    let handle = SessionHandle::new(make_test_metadata(5));
    handle.set_state(TransportState::Transferring);
    assert_eq!(handle.state(), TransportState::Transferring);

    handle.set_state(TransportState::Verifying);
    assert_eq!(handle.state(), TransportState::Verifying);

    handle.set_state(TransportState::Completed);
    assert_eq!(handle.state(), TransportState::Completed);
}

#[test]
fn test_confirm_and_check_chunk() {
    let handle = SessionHandle::new(make_test_metadata(10));

    assert!(!handle.is_confirmed(0));
    handle.confirm_chunk(0);
    assert!(handle.is_confirmed(0));

    // Idempotent: confirming again does not change anything.
    handle.confirm_chunk(0);
    assert!(handle.is_confirmed(0));
}

#[test]
fn test_confirmed_count_increments() {
    let handle = SessionHandle::new(make_test_metadata(10));
    assert_eq!(handle.confirmed_count(), 0);

    handle.confirm_chunk(0);
    assert_eq!(handle.confirmed_count(), 1);

    handle.confirm_chunk(1);
    handle.confirm_chunk(2);
    assert_eq!(handle.confirmed_count(), 3);
}

#[test]
fn test_pending_indices_returns_unconfirmed() {
    let handle = SessionHandle::new(make_test_metadata(5));

    // Initially all pending.
    let pending = handle.pending_indices();
    assert_eq!(pending, vec![0, 1, 2, 3, 4]);

    // Confirm some chunks.
    handle.confirm_chunk(0);
    handle.confirm_chunk(2);
    handle.confirm_chunk(4);

    let pending = handle.pending_indices();
    assert_eq!(pending, vec![1, 3]);
}

#[test]
fn test_is_complete_when_all_confirmed() {
    let handle = SessionHandle::new(make_test_metadata(3));
    assert!(!handle.is_complete());

    handle.confirm_chunk(0);
    handle.confirm_chunk(1);
    handle.confirm_chunk(2);
    assert!(handle.is_complete());
}

#[test]
fn test_session_id_accessors() {
    let meta = make_test_metadata(8);
    let handle = SessionHandle::new(meta);
    assert_eq!(handle.session_id(), "test-session-001");
    assert_eq!(handle.metadata().total_chunks, 8);
}

// ===========================================================================
// VerificationReport Tests
// ===========================================================================

#[test]
fn test_verification_report_ok() {
    let report = VerificationReport::ok(Some("filehash".to_string()));
    assert!(report.all_ok);
    assert!(report.missing_indices.is_empty());
    assert!(report.corrupt_indices.is_empty());
    assert_eq!(report.issue_count(), 0);
    assert!(!report.needs_repair());
}

#[test]
fn test_verification_report_with_issues() {
    let report = VerificationReport::with_issues(vec![3, 7], vec![5], None);
    assert!(!report.all_ok);
    assert_eq!(report.missing_indices, vec![3, 7]);
    assert_eq!(report.corrupt_indices, vec![5]);
    assert_eq!(report.issue_count(), 3);
    assert!(report.needs_repair());
}

// ===========================================================================
// RepairProgress Tests
// ===========================================================================

#[test]
fn test_repair_progress_initial() {
    let progress = RepairProgress::new(5);
    assert_eq!(progress.total_requested, 5);
    assert_eq!(progress.completed, 0);
    assert!(progress.failed_indices.is_empty());
    assert!(!progress.is_finished());
}

#[test]
fn test_repair_progress_completion_tracking() {
    let mut progress = RepairProgress::new(4);
    progress.mark_completed();
    progress.mark_completed();
    progress.mark_failed(2);
    progress.mark_failed(3);

    assert_eq!(progress.completed, 2);
    assert_eq!(progress.failed_indices.len(), 2);
    assert!(progress.is_finished());

    // Success rate: 2/4 = 0.5
    assert!((progress.success_rate() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn test_repair_progress_zero_total() {
    let progress = RepairProgress::new(0);
    assert!(progress.is_finished());
    assert_eq!(progress.success_rate(), 1.0);
}
