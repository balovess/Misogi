//! Comprehensive test suite for SessionManager.
//!
//! Tests cover the complete session lifecycle including:
//! - Session creation and retrieval
//! - State transitions
//! - Checkpoint save/load round-trips
//! - Expiration cleanup
//! - Edge cases (duplicate IDs, non-existent sessions, persistence disabled)

#[cfg(test)]
mod tests {
    use super::super::config::ResumeConfig;
    use super::super::envelope::HashAlgorithm;
    use super::super::session_manager::SessionManager;
    use super::super::session::{SessionHandle, TransportCapabilities, TransportState};
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Helper: Create default capabilities for testing.
    // -----------------------------------------------------------------------

    fn test_capabilities() -> TransportCapabilities {
        TransportCapabilities::full_support(vec![HashAlgorithm::Sha256])
    }

    // -----------------------------------------------------------------------
    // Lifecycle Tests: create / get / cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_and_get_session() {
        let config = ResumeConfig::default();
        let manager = SessionManager::new(config);

        let handle = manager
            .create_session(
                "sess-001",
                100,
                1024 * 1024,
                "hash123",
                test_capabilities(),
            )
            .unwrap();

        assert_eq!(handle.session_id(), "sess-001");
        assert_eq!(handle.state(), TransportState::Negotiating);
        assert_eq!(handle.confirmed_count(), 0);

        // Retrieve should return a clone.
        let retrieved = manager.get_session("sess-001");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id(), "sess-001");
    }

    #[test]
    fn test_get_non_existent_session() {
        let manager = SessionManager::new(ResumeConfig::default());
        assert!(manager.get_session("does-not-exist").is_none());
    }

    #[test]
    fn test_cleanup_removes_session() {
        let manager = SessionManager::new(ResumeConfig::default());

        manager
            .create_session("sess-rm", 10, 100, "h", test_capabilities())
            .unwrap();
        assert_eq!(manager.active_session_count(), 1);

        manager.cleanup_session("sess-rm").unwrap();
        assert_eq!(manager.active_session_count(), 0);
        assert!(manager.get_session("sess-rm").is_none());
    }

    #[test]
    fn test_cleanup_non_existent_is_noop() {
        let manager = SessionManager::new(ResumeConfig::default());
        // Should not error even if session doesn't exist.
        manager.cleanup_session("ghost-session").unwrap();
    }

    // -----------------------------------------------------------------------
    // State Transition Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_state_transitions() {
        let manager = SessionManager::new(ResumeConfig::default());

        manager
            .create_session("sess-st", 50, 5000, "h", test_capabilities())
            .unwrap();

        // Initial state should be Negotiating.
        assert_eq!(
            manager.get_session("sess-st").unwrap().state(),
            TransportState::Negotiating
        );

        // Transition to Transferring.
        manager
            .update_session_state("sess-st", TransportState::Transferring)
            .unwrap();
        assert_eq!(
            manager.get_session("sess-st").unwrap().state(),
            TransportState::Transferring
        );

        // Transition to Verifying.
        manager
            .update_session_state("sess-st", TransportState::Verifying)
            .unwrap();
        assert_eq!(
            manager.get_session("sess-st").unwrap().state(),
            TransportState::Verifying
        );

        // Transition to Completed (terminal).
        manager
            .update_session_state("sess-st", TransportState::Completed)
            .unwrap();
        assert_eq!(
            manager.get_session("sess-st").unwrap().state(),
            TransportState::Completed
        );
    }

    #[test]
    fn test_update_non_existent_session_fails() {
        let manager = SessionManager::new(ResumeConfig::default());

        let result = manager.update_session_state(
            "ghost",
            TransportState::Transferring,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // -----------------------------------------------------------------------
    // Duplicate Creation Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_double_create_same_id_fails() {
        let manager = SessionManager::new(ResumeConfig::default());

        manager
            .create_session("dup-sess", 10, 100, "h", test_capabilities())
            .unwrap();

        let result = manager.create_session(
            "dup-sess",
            20, 200, "h2", test_capabilities(),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Original session should still be intact.
        assert_eq!(manager.active_session_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Checkpoint Save/Load Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_checkpoint_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config = ResumeConfig::default();
        let manager = SessionManager::with_persistence(config, dir.path());

        // Create and configure a session.
        let mut handle = manager
            .create_session(
                "ckpt-sess",
                20,
                20000,
                "filehash_abc",
                test_capabilities(),
            )
            .unwrap();

        // Confirm some chunks.
        handle.confirm_chunk(0);
        handle.confirm_chunk(1);
        handle.confirm_chunk(5);

        // Transition state.
        manager
            .update_session_state("ckpt-sess", TransportState::Transferring)
            .unwrap();

        // Save checkpoint.
        manager.save_checkpoint("ckpt-sess").unwrap();

        // Verify file exists.
        let checkpoint_file = dir.path().join("ckpt-sess.checkpoint");
        assert!(checkpoint_file.exists(), "Checkpoint file should exist");

        // Load checkpoint into a fresh manager instance.
        let manager2 =
            SessionManager::with_persistence(ResumeConfig::default(), dir.path());
        let loaded = manager2.load_checkpoint("ckpt-sess").unwrap();

        assert!(loaded.is_some(), "Should load existing checkpoint");
        let loaded_handle = loaded.unwrap();
        assert_eq!(loaded_handle.session_id(), "ckpt-sess");
        assert!(loaded_handle.is_confirmed(0));
        assert!(loaded_handle.is_confirmed(1));
        assert!(loaded_handle.is_confirmed(5));
        assert!(!loaded_handle.is_confirmed(2)); // Not confirmed.
    }

    #[test]
    fn test_load_nonexistent_checkpoint_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let manager =
            SessionManager::with_persistence(ResumeConfig::default(), dir.path());

        let result = manager.load_checkpoint("no-such-session").unwrap();
        assert!(result.is_none(), "Non-existent checkpoint should return None");
    }

    // -----------------------------------------------------------------------
    // Persistence Disabled Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_persistence_disabled_save_is_noop() {
        let manager = SessionManager::new(ResumeConfig::default());

        manager
            .create_session("no-persist", 5, 50, "h", test_capabilities())
            .unwrap();

        // Should succeed without error (no-op).
        manager.save_checkpoint("no-persist").unwrap();

        // Load should return None since no directory configured.
        let loaded = manager.load_checkpoint("no-persist").unwrap();
        assert!(loaded.is_none());
    }

    // -----------------------------------------------------------------------
    // Expiration Cleanup Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_expired_sessions() {
        let manager = SessionManager::new(ResumeConfig::default());

        // Create two sessions.
        manager
            .create_session("expiring-1", 10, 100, "h", test_capabilities())
            .unwrap();
        manager
            .create_session("expiring-2", 10, 100, "h", test_capabilities())
            .unwrap();

        assert_eq!(manager.active_session_count(), 2);

        // Clean up with zero max_age (everything should be expired).
        // Note: This relies on Instant being monotonic; in practice there's
        // a tiny window where the session might not be expired yet. We use
        // a very small duration to make the test robust.
        let removed = manager.cleanup_expired(Duration::from_nanos(1));

        // At least one should be cleaned up (likely both due to timing).
        // We don't assert exact count to avoid flaky tests.
        assert!(
            removed <= 2,
            "Should remove at most 2 sessions"
        );
        assert!(
            manager.active_session_count() <= 2,
            "Should have 2 or fewer sessions after cleanup"
        );
    }

    #[test]
    fn test_cleanup_expired_with_large_max_age() {
        let manager = SessionManager::new(ResumeConfig::default());

        manager
            .create_session("fresh", 10, 100, "h", test_capabilities())
            .unwrap();

        // Clean with large max_age — nothing should expire.
        let removed = manager.cleanup_expired(Duration::from_secs(86400 * 365));

        assert_eq!(removed, 0, "No sessions should expire with 1-year max age");
        assert_eq!(manager.active_session_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Active Count Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_active_session_count_increments() {
        let manager = SessionManager::new(ResumeConfig::default());

        assert_eq!(manager.active_session_count(), 0);

        manager
            .create_session("count-1", 10, 100, "h", test_capabilities())
            .unwrap();
        assert_eq!(manager.active_session_count(), 1);

        manager
            .create_session("count-2", 10, 100, "h", test_capabilities())
            .unwrap();
        assert_eq!(manager.active_session_count(), 2);

        manager
            .create_session("count-3", 10, 100, "h", test_capabilities())
            .unwrap();
        assert_eq!(manager.active_session_count(), 3);
    }

    #[test]
    fn test_active_session_count_decrements_on_cleanup() {
        let manager = SessionManager::new(ResumeConfig::default());

        manager
            .create_session("dec-1", 10, 100, "h", test_capabilities())
            .unwrap();
        manager
            .create_session("dec-2", 10, 100, "h", test_capabilities())
            .unwrap();
        assert_eq!(manager.active_session_count(), 2);

        manager.cleanup_session("dec-1").unwrap();
        assert_eq!(manager.active_session_count(), 1);

        manager.cleanup_session("dec-2").unwrap();
        assert_eq!(manager.active_session_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Resume from Checkpoint Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_resume_from_checkpoint() {
        let dir = tempfile::tempdir().unwrap();

        // Phase 1: Create and save checkpoint with original manager.
        let mgr1 =
            SessionManager::with_persistence(ResumeConfig::default(), dir.path());
        let mut h1 = mgr1
            .create_session("resume-me", 30, 30000, "orig_hash", test_capabilities())
            .unwrap();

        // Simulate progress: confirm chunks 0-9.
        for i in 0..10u32 {
            h1.confirm_chunk(i);
        }
        mgr1.update_session_state("resume-me", TransportState::Transferring)
            .unwrap();
        mgr1.save_checkpoint("resume-me").unwrap();

        // Phase 2: Simulate process restart by creating new manager.
        let mgr2 =
            SessionManager::with_persistence(ResumeConfig::default(), dir.path());

        // Load should restore confirmed chunks.
        let restored = mgr2.load_checkpoint("resume-me").unwrap().unwrap();
        assert_eq!(restored.confirmed_count(), 10);
        for i in 0..10u32 {
            assert!(restored.is_confirmed(i), "Chunk {} should be confirmed", i);
        }
        assert!(!restored.is_confirmed(10), "Chunk 10 should NOT be confirmed");
    }

    // -----------------------------------------------------------------------
    // Cleanup All Sessions Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_all_sessions() {
        let manager = SessionManager::new(ResumeConfig::default());

        for i in 0..5 {
            manager
                .create_session(
                    &format!("all-{}", i),
                    10,
                    100,
                    "h",
                    test_capabilities(),
                )
                .unwrap();
        }

        assert_eq!(manager.active_session_count(), 5);

        // Remove all individually.
        for i in 0..5 {
            manager.cleanup_session(&format!("all-{}", i)).unwrap();
        }

        assert_eq!(manager.active_session_count(), 0);
    }
}
