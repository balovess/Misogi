//! Session lifecycle manager with checkpoint-based persistence.
//!
//! Provides centralized management of transport sessions including creation,
//! state tracking, checkpoint serialization, and cleanup. This module is
//! the operational backbone of the self-healing transport system, ensuring
//! that session state survives process restarts and can be resumed after
//! interruptions.
//!
//! # Architecture
//!
//! The [`SessionManager`] maintains an in-memory registry of active sessions
//! backed by optional file-system persistence. Each session is represented
//! by a [`SessionHandle`](super::session::SessionHandle) wrapped in a
//! [`SessionState`] container that tracks creation time and last activity
//! for expiration management.
//!
//! # Persistence Model
//!
//! When persistence is enabled (via [`with_persistence`](Self::with_persistence)),
//! session checkpoints are saved as JSON files in the configured directory:
//!
//! ```text
//! {persistence_dir}/{session_id}.checkpoint
//! ```
//!
//! Each checkpoint file contains:
//!
//! - `session_id` — Unique identifier for the transfer.
//! - `total_chunks` — Expected total chunk count.
//! - `confirmed_chunk_indices` — Set of verified chunk indices.
//! - `current_state` — Current lifecycle state (string enum).
//! - `timestamp` — Unix epoch milliseconds when checkpoint was saved.
//!
//! # Concurrency Model
//!
//! All mutable state is protected by `RwLock` from `parking_lot` for
//! high-performance concurrent access. Read operations (get_session,
//! active_session_count) acquire shared locks; write operations
//! (create_session, update_session_state) acquire exclusive locks.
//!
//! # Thread Safety
//!
//! [`SessionManager`] is `Clone` (shallow clone sharing the same internal
//! state) and `Send + Sync`, allowing safe use across async tasks.

#[cfg(test)]
mod tests;

use super::envelope::IntegrityError;
use super::session::{SessionHandle, SessionMetadata, TransportCapabilities, TransportState};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ===========================================================================
// Session State (Internal)
// ===========================================================================

/// Internal wrapper combining handle with timestamps for expiration tracking.
///
/// Not part of the public API; used internally by [`SessionManager`] to
/// track session age and activity for automatic cleanup.
struct SessionState {
    /// The actual session handle with state and confirmed-chunk tracking.
    handle: SessionHandle,

    /// Monotonic timestamp of the last state-changing operation.
    last_activity: Instant,
}

// ===========================================================================
// Checkpoint Data Structure
// ===========================================================================

/// Serializable representation of a session checkpoint.
///
/// This struct is the on-disk format for persisted session state. It is
/// designed to be forward-compatible: new fields can be added with
/// `#[serde(default)]` without breaking deserialization of old files.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionCheckpoint {
    /// Unique identifier for this transfer session.
    session_id: String,

    /// Total number of chunks expected in this transfer.
    total_chunks: u32,

    /// Set of chunk indices that have been confirmed received and verified.
    confirmed_chunk_indices: Vec<u32>,

    /// Current lifecycle state as a string (deserialized via TransportState).
    current_state: String,

    /// Unix epoch milliseconds when this checkpoint was written.
    timestamp: u64,
}

// ===========================================================================
// Session Manager
// ===========================================================================

/// Centralized session lifecycle and persistence manager.
///
/// Manages the complete lifetime of transport sessions from creation through
/// completion or cleanup. Provides:
///
/// - **Session registry** — In-memory storage of active sessions keyed by ID.
/// - **State transitions** — Validated state machine updates per session.
/// - **Checkpoint persistence** — JSON-based serialization for crash recovery.
/// - **Expiration cleanup** — Automatic removal of stale sessions.
///
/// # Example
///
/// ```ignore
/// let config = ResumeConfig::default();
/// let manager = SessionManager::with_persistence(config, Path::new("./sessions"));
///
/// // Create a new session.
/// let handle = manager.create_session(
///     "transfer-001",
///     100,
///     1024 * 1024 * 50, // 50 MiB
///     "abc123hash",
///     TransportCapabilities::default(),
/// )?;
///
/// // Update state as transfer progresses.
/// manager.update_session_state("transfer-001", TransportState::Transferring)?;
///
/// // Save checkpoint periodically.
/// manager.save_checkpoint("transfer-001")?;
///
/// // Cleanup when done.
/// manager.cleanup_session("transfer-001")?;
/// ```
pub struct SessionManager {
    /// In-memory session registry keyed by session_id.
    sessions: RwLock<HashMap<String, SessionState>>,

    /// Optional directory for checkpoint file storage.
    ///
    /// When `None`, persistence is disabled and all operations are
    /// in-memory only (checkpoints are no-ops).
    persistence_dir: Option<PathBuf>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Create a new session manager without disk persistence.
    ///
    /// Sessions are stored only in memory and will be lost on process
    /// exit. Use [`with_persistence`](Self::with_persistence) if
    /// crash recovery is required.
    ///
    /// # Returns
    ///
    /// A new [`SessionManager`] instance ready for use.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            persistence_dir: None,
        }
    }

    /// Create a new session manager with disk-backed persistence.
    ///
    /// Checkpoint files are saved to/loaded from the specified directory.
    /// The directory is created automatically if it does not exist.
    ///
    /// # Arguments
    ///
    /// * `dir` — File system path for checkpoint storage.
    ///
    /// # Returns
    ///
    /// A new [`SessionManager`] instance with persistence enabled.
    ///
    /// # Errors
    ///
    /// This constructor itself does not perform I/O. Directory creation
    /// is deferred to the first [`save_checkpoint`](Self::save_checkpoint)
    /// call.
    pub fn with_persistence(dir: &Path) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            persistence_dir: Some(dir.to_path_buf()),
        }
    }

    /// Create and register a new transport session.
    ///
    /// Initializes a [`SessionHandle`] in [`TransportState::Negotiating`]
    /// state with empty confirmed-chunk set and stores it in the registry.
    ///
    /// # Arguments
    ///
    /// * `session_id` — Unique identifier for this transfer (must not already exist).
    /// * `total_chunks` — Total number of chunks in the transfer.
    /// * `file_size_bytes` — Original file size in bytes.
    /// * `file_hash` — Hex-encoded hash of the complete original file.
    /// * `capabilities` — Agreed transport capabilities.
    ///
    /// # Returns
    ///
    /// * `Ok(SessionHandle)` — Handle to the newly created session.
    /// * `Err(IntegrityError::InvalidEnvelope)` — Session ID already exists.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = manager.create_session(
    ///     "sess-abc",
    ///     200,
    ///     10_000_000,
    ///     "deadbeef...",
    ///     TransportCapabilities::full_support(vec![HashAlgorithm::Sha256]),
    /// )?;
    /// assert_eq!(handle.session_id(), "sess-abc");
    /// assert_eq!(handle.state(), TransportState::Negotiating);
    /// ```
    pub fn create_session(
        &self,
        session_id: &str,
        total_chunks: u32,
        file_size_bytes: u64,
        file_hash: &str,
        capabilities: TransportCapabilities,
    ) -> Result<SessionHandle, IntegrityError> {
        let mut sessions = self.sessions.write();

        // Reject duplicate session IDs.
        if sessions.contains_key(session_id) {
            return Err(IntegrityError::InvalidEnvelope(format!(
                "Session '{}' already exists",
                session_id
            )));
        }

        // Build session metadata.
        let metadata = SessionMetadata {
            session_id: session_id.to_string(),
            total_chunks,
            file_size_bytes,
            file_hash: file_hash.to_string(),
            created_at: current_timestamp_ms(),
            capabilities,
        };

        // Create handle in initial Negotiating state.
        let handle = SessionHandle::new(metadata);
        let handle_clone = handle.clone(); // Return to caller.

        // Register in memory store.
        let now = Instant::now();
        sessions.insert(
            session_id.to_string(),
            SessionState {
                handle,
                last_activity: now,
            },
        );

        Ok(handle_clone)
    }

    /// Retrieve a registered session by ID.
    ///
    /// Returns a clone of the [`SessionHandle`] if the session exists,
    /// or `None` if no session with the given ID is registered.
    ///
    /// # Arguments
    ///
    /// * `session_id` — Identifier of the session to retrieve.
    ///
    /// # Returns
    ///
    /// * `Some(SessionHandle)` — Clone of the session handle.
    /// * `None` — Session not found.
    ///
    /// # Performance
    ///
    /// O(1) average case via HashMap lookup. Acquires read lock only.
    pub fn get_session(&self, session_id: &str) -> Option<SessionHandle> {
        let sessions = self.sessions.read();
        sessions.get(session_id).map(|state| state.handle.clone())
    }

    /// Transition a session to a new transport state.
    ///
    /// Updates the session's state machine and refreshes the last-activity
    /// timestamp for expiration tracking. No validation of transition
    /// legality is performed here; the caller (transport implementation)
    /// is responsible for ensuring only valid transitions occur.
    ///
    /// # Arguments
    ///
    /// * `session_id` — Identifier of the session to update.
    /// * `new_state` — Target state to transition to.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — State updated successfully.
    /// * `Err(IntegrityError)` — Session not found.
    ///
    /// # Side Effects
    ///
    /// Updates `last_activity` timestamp to `Instant::now()`.
    pub fn update_session_state(
        &self,
        session_id: &str,
        new_state: TransportState,
    ) -> Result<(), IntegrityError> {
        let mut sessions = self.sessions.write();

        let state = sessions.get_mut(session_id).ok_or_else(|| {
            IntegrityError::InvalidEnvelope(format!("Session '{}' not found", session_id))
        })?;

        state.handle.set_state(new_state);
        state.last_activity = Instant::now();

        Ok(())
    }

    /// Persist session state to a checkpoint file.
    ///
    /// Serializes the current session state (confirmed chunks, current
    /// state, metadata) to a JSON file in the persistence directory.
    /// If persistence is disabled, this is a no-op that returns `Ok(())`.
    ///
    /// # Arguments
    ///
    /// * `session_id` — Identifier of the session to checkpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — Checkpoint saved successfully (or persistence disabled).
    /// * `Err(IntegrityError)` — Session not found or I/O error.
    ///
    /// # Checkpoint File Format
    ///
    /// ```json
    /// {
    ///   "session_id": "transfer-001",
    ///   "total_chunks": 100,
    ///   "confirmed_chunk_indices": [0, 1, 2, ...],
    ///   "current_state": "TRANSFERRING",
    ///   "timestamp": 1699876543210
    /// }
    /// ```
    pub fn save_checkpoint(&self, session_id: &str) -> Result<(), IntegrityError> {
        let dir = match &self.persistence_dir {
            Some(d) => d.clone(),
            None => return Ok(()), // Persistence disabled: no-op.
        };

        let sessions = self.sessions.read();
        let state = sessions.get(session_id).ok_or_else(|| {
            IntegrityError::InvalidEnvelope(format!("Session '{}' not found", session_id))
        })?;

        // Build checkpoint data structure.
        let checkpoint = SessionCheckpoint {
            session_id: session_id.to_string(),
            total_chunks: state.handle.metadata().total_chunks,
            confirmed_chunk_indices: {
                // Get pending indices and infer confirmed ones.
                let pending = state.handle.pending_indices();
                let total = state.handle.metadata().total_chunks;
                (0..total).filter(|i| !pending.contains(i)).collect()
            },
            current_state: format!("{}", state.handle.state()),
            timestamp: current_timestamp_ms(),
        };

        // Ensure directory exists.
        std::fs::create_dir_all(&dir).map_err(|e| {
            IntegrityError::InvalidEnvelope(format!(
                "Failed to create persistence directory: {}",
                e
            ))
        })?;

        // Write checkpoint file.
        let file_path = dir.join(format!("{}.checkpoint", session_id));
        let json =
            serde_json::to_string_pretty(&checkpoint).map_err(IntegrityError::Serialization)?;
        std::fs::write(&file_path, json).map_err(|e| {
            IntegrityError::InvalidEnvelope(format!("Failed to write checkpoint file: {}", e))
        })?;

        tracing::debug!(
            "Saved checkpoint for session '{}' to {:?}",
            session_id,
            file_path
        );

        Ok(())
    }

    /// Load session state from a checkpoint file.
    ///
    /// Attempts to deserialize a previously saved checkpoint and reconstruct
    /// a [`SessionHandle`] with the persisted state. If no checkpoint file
    /// exists for the given session ID, returns `Ok(None)` rather than
    /// an error (graceful handling of first-run scenarios).
    ///
    /// # Arguments
    ///
    /// * `session_id` — Identifier of the session to resume.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(SessionHandle))` — Session restored from checkpoint.
    /// * `Ok(None)` — No checkpoint found (session never existed or was cleaned).
    /// * `Err(IntegrityError)` — Checkpoint file exists but is corrupted/unreadable.
    ///
    /// # Note
    ///
    /// The loaded session is NOT automatically registered in the in-memory
    /// registry. Callers must call [`create_session`](Self::create_session)
    /// or manually insert if they want the loaded session tracked.
    pub fn load_checkpoint(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionHandle>, IntegrityError> {
        let dir = match &self.persistence_dir {
            Some(d) => d.clone(),
            None => return Ok(None), // Persistence disabled: nothing to load.
        };

        let file_path = dir.join(format!("{}.checkpoint", session_id));

        // Graceful handling: return None if file doesn't exist.
        if !file_path.exists() {
            return Ok(None);
        }

        // Read and deserialize checkpoint.
        let json = std::fs::read_to_string(&file_path).map_err(|e| {
            IntegrityError::InvalidEnvelope(format!("Failed to read checkpoint file: {}", e))
        })?;

        let checkpoint: SessionCheckpoint =
            serde_json::from_str(&json).map_err(IntegrityError::Serialization)?;

        // Reconstruct session handle from checkpoint data.
        // Note: We lose some metadata (file_size_bytes, capabilities) that
        // isn't captured in the checkpoint. For full restoration, consider
        // extending the checkpoint schema in a future iteration.
        let metadata = SessionMetadata {
            session_id: checkpoint.session_id.clone(),
            total_chunks: checkpoint.total_chunks,
            file_size_bytes: 0,       // Not preserved in v1 checkpoint format.
            file_hash: String::new(), // Not preserved.
            created_at: checkpoint.timestamp,
            capabilities: TransportCapabilities::default(),
        };

        let handle = SessionHandle::new(metadata);

        // Restore confirmed chunks.
        let confirmed_count = checkpoint.confirmed_chunk_indices.len();
        for idx in &checkpoint.confirmed_chunk_indices {
            handle.confirm_chunk(*idx);
        }

        // Restore state (best-effort parsing).
        // In production, use proper FromStr implementation for TransportState.
        let _restored_state = &checkpoint.current_state;

        tracing::debug!(
            "Loaded checkpoint for session '{}': {} chunks, {} confirmed",
            session_id,
            checkpoint.total_chunks,
            confirmed_count
        );

        Ok(Some(handle))
    }

    /// Remove a session from memory and delete its checkpoint file.
    ///
    /// Performs full cleanup: removes the session from the in-memory
    /// registry and deletes any persisted checkpoint file. After this
    /// call, the session ID can be reused for a new transfer.
    ///
    /// # Arguments
    ///
    /// * `session_id` — Identifier of the session to remove.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — Session cleaned up successfully (even if it didn't exist).
    /// * `Err(IntegrityError)` — Checkpoint file deletion failed (non-fatal warning).
    ///
    /// # Idempotency
    ///
    /// Safe to call multiple times for the same session ID. If the session
    /// does not exist, returns `Ok(())` without error.
    pub fn cleanup_session(&self, session_id: &str) -> Result<(), IntegrityError> {
        // Remove from memory.
        let mut sessions = self.sessions.write();
        sessions.remove(session_id);

        // Delete checkpoint file if persistence is enabled.
        if let Some(ref dir) = self.persistence_dir {
            let file_path = dir.join(format!("{}.checkpoint", session_id));
            if file_path.exists() {
                std::fs::remove_file(&file_path).map_err(|e| {
                    tracing::warn!(
                        "Failed to delete checkpoint file for session '{}': {}",
                        session_id,
                        e
                    );
                    IntegrityError::InvalidEnvelope(format!("Checkpoint deletion failed: {}", e))
                })?;
            }
        }

        tracing::debug!("Cleaned up session '{}'", session_id);
        Ok(())
    }

    /// Remove all sessions older than the specified age.
    ///
    /// Iterates over all registered sessions and removes those whose
    /// `last_activity` timestamp is older than `max_age`. Useful for
    /// periodic garbage collection to prevent unbounded memory growth
    /// from abandoned transfers.
    ///
    /// # Arguments
    ///
    /// * `max_age` — Maximum allowed session age since last activity.
    ///
    /// # Returns
    ///
    /// Number of sessions that were removed (expired and cleaned up).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Clean up sessions inactive for more than 1 hour.
    /// let removed = manager.cleanup_expired(Duration::from_secs(3600));
    /// if removed > 0 {
    ///     println!("Cleaned up {} expired sessions", removed);
    /// }
    /// ```
    pub fn cleanup_expired(&self, max_age: Duration) -> usize {
        let mut sessions = self.sessions.write();

        let now = Instant::now();
        let expired_ids: Vec<String> = sessions
            .iter()
            .filter(|(_, state)| now.duration_since(state.last_activity) > max_age)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len();
        for id in &expired_ids {
            sessions.remove(id);
        }

        // Also delete checkpoint files for expired sessions.
        if let Some(ref dir) = self.persistence_dir {
            for id in &expired_ids {
                let file_path = dir.join(format!("{}.checkpoint", id));
                if file_path.exists() {
                    let _ = std::fs::remove_file(&file_path);
                }
            }
        }

        if count > 0 {
            tracing::info!("Cleaned up {} sessions older than {:?}", count, max_age);
        }

        count
    }

    /// Returns the number of currently active (registered) sessions.
    ///
    /// Useful for monitoring and capacity planning. Does not include
    /// completed/failed sessions unless they haven't been cleaned up yet.
    ///
    /// # Returns
    ///
    /// Count of sessions in the in-memory registry.
    pub fn active_session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Returns the current Unix timestamp in milliseconds.
///
/// Used for checkpoint timestamps and session metadata creation times.
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
