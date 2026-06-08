//! Session management types for self-healing transport lifecycle.
//!
//! Defines the state machine, metadata tracking, and confirmation bookkeeping
//! that govern the lifetime of a transport session from negotiation through
//! completion or failure.
//!
//! # State Machine
//!
//! The [`TransportState`] enum models the complete session lifecycle:
//!
//! ```text
//!     Negotiating → Transferring → Verifying → Completed
//!                    ↓            ↓
//!                  Paused      Repairing
//!                    ↓            ↓
//!                  Failed ←-------┘
//! ```
//!
//! # Concurrency Model
//!
//! [`SessionHandle`] uses `Arc<RwLock<T>>` (via `parking_lot`) for all mutable
//! state, enabling safe concurrent access from multiple async tasks without
//! blocking the tokio runtime thread pool.

use crate::integrity::envelope::HashAlgorithm;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

// ===========================================================================
// Transport State
// ===========================================================================

/// Lifecycle state of a transport session.
///
/// Models the complete state machine for a single file transfer session,
/// from initial capability negotiation through final completion or failure.
/// Each transition is governed by the [`HealingTransport`](super::transport::HealingTransport)
/// implementation and must follow valid paths as documented below.
///
/// # State Transitions (Valid Paths)
///
/// | From | To | Trigger |
/// |------|----|---------|
/// | `Negotiating` | `Transferring` | Capabilities agreed |
/// | `Transferring` | `Verifying` | All chunks sent |
/// | `Transferring` | `Paused` | User pause / throttle |
/// | `Transferring` | `Repairing` | Missing chunks detected |
/// | `Paused` | `Transferring` | Resume requested |
/// | `Repairing` | `Verifying` | Repair completed |
/// | `Repairing` | `Failed` | Repair exhausted |
/// | `Verifying` | `Completed` | Full verification passed |
/// | `Verifying` | `Repairing` | Corrupt chunks found |
/// | `Verifying` | `Failed` | Unrecoverable corruption |
/// | *any* | `Failed` | Fatal error |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportState {
    /// Initial state: negotiating capabilities with remote peer.
    Negotiating,

    /// Active data transfer in progress.
    Transferring,

    /// Transfer temporarily suspended (resumable).
    Paused,

    /// Automatic repair of missing/corrupted chunks in progress.
    Repairing,

    /// Post-transfer full verification phase.
    Verifying,

    /// Transfer completed successfully (terminal state).
    Completed,

    /// Transfer failed unrecoverably (terminal state).
    Failed,
}

impl TransportState {
    /// Returns true if this is a terminal (final) state.
    ///
    /// Terminal states (`Completed`, `Failed`) indicate that no further
    /// state transitions are possible. The session should be considered
    /// closed and its resources eligible for cleanup.
    ///
    /// # Returns
    /// `true` for [`Completed`](Self::Completed) or [`Failed`](Self::Failed),
    /// `false` for all other states.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }

    /// Returns true if the session is in an active (non-terminal) state.
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }
}

impl std::fmt::Display for TransportState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Negotiating => write!(f, "NEGOTIATING"),
            Self::Transferring => write!(f, "TRANSFERRING"),
            Self::Paused => write!(f, "PAUSED"),
            Self::Repairing => write!(f, "REPAIRING"),
            Self::Verifying => write!(f, "VERIFYING"),
            Self::Completed => write!(f, "COMPLETED"),
            Self::Failed => write!(f, "FAILED"),
        }
    }
}

// ===========================================================================
// Transport Capabilities
// ===========================================================================

/// Declared capabilities of a transport endpoint.
///
/// Exchanged during the negotiation phase to determine which features
/// both peers support. Mismatched capabilities may result in degraded
/// functionality (e.g., disabling repair if one side lacks support).
///
/// # Fields
///
/// - `supports_integrity` — Peer can generate/verify integrity envelopes.
/// - `max_chunk_size_bytes` — Maximum payload size per chunk the peer accepts.
/// - `supported_algorithms` — Hash algorithms the peer understands.
/// - `supports_repair` — Peer can participate in chunk retransmission.
/// - `supports_checkpoint` — Peer can serialize session state for resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCapabilities {
    /// Whether the remote peer supports integrity envelope verification.
    pub supports_integrity: bool,

    /// Maximum chunk payload size in bytes accepted by this peer.
    pub max_chunk_size_bytes: u64,

    /// Hash algorithms supported by this peer for integrity verification.
    pub supported_algorithms: Vec<HashAlgorithm>,

    /// Whether the peer supports automatic chunk repair/retransmission.
    pub supports_repair: bool,

    /// Whether the peer supports checkpoint-based session resume.
    pub supports_checkpoint: bool,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            supports_integrity: true,
            max_chunk_size_bytes: 4 * 1024 * 1024, // 4 MiB default
            supported_algorithms: vec![HashAlgorithm::Sha256],
            supports_repair: true,
            supports_checkpoint: true,
        }
    }
}

impl TransportCapabilities {
    /// Create capabilities with full feature support using given algorithms.
    pub fn full_support(algorithms: Vec<HashAlgorithm>) -> Self {
        Self {
            supports_integrity: true,
            max_chunk_size_bytes: 4 * 1024 * 1024,
            supported_algorithms: algorithms,
            supports_repair: true,
            supports_checkpoint: true,
        }
    }

    /// Check whether the given hash algorithm is supported by both peers.
    pub fn supports_algorithm(&self, algo: &HashAlgorithm) -> bool {
        self.supported_algorithms.contains(algo)
    }
}

// ===========================================================================
// Session Metadata
// ===========================================================================

/// Immutable metadata describing a transfer session.
///
/// Created at session initialization and remains unchanged throughout
/// the session lifetime. Contains all information needed to identify
/// and describe the transfer for logging, persistence, and debugging.
///
/// # Fields
///
/// - `session_id` — Unique identifier for this transfer session.
/// - `total_chunks` — Total number of chunks in the transfer.
/// - `file_size_bytes` — Original file size in bytes.
/// - `file_hash` — Cryptographic hash of the complete file (for end-to-end verify).
/// - `created_at` — Unix epoch milliseconds when session was created.
/// - `capabilities` — Agreed transport capabilities after negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Unique identifier for this transfer session (UUID v4).
    pub session_id: String,

    /// Total number of chunks the file was split into.
    pub total_chunks: u32,

    /// Original file size in bytes before chunking.
    pub file_size_bytes: u64,

    /// Hex-encoded cryptographic hash of the complete original file.
    pub file_hash: String,

    /// Unix timestamp (milliseconds) when this session was created.
    pub created_at: u64,

    /// Transport capabilities agreed upon during negotiation.
    pub capabilities: TransportCapabilities,
}

// ===========================================================================
// Session Handle
// ===========================================================================

/// Thread-safe handle to an active transport session.
///
/// Provides atomic access to session state and confirmed-chunk tracking.
/// Internally uses `Arc<RwLock<T>>` via `parking_lot` for high-performance
/// concurrent access without blocking the tokio runtime. This type is
/// `Clone + Send + Sync` and can be freely shared across async tasks.
///
/// # Confirmed Chunks Tracking
///
/// Maintains a `HashSet<u32>` of chunk indices that have been successfully
/// received and verified by the remote peer. This set drives the repair
/// system's missing-chunk detection and the progress reporting.
///
/// # Example
///
/// ```ignore
/// let handle = SessionHandle::new(metadata);
/// handle.set_state(TransportState::Transferring);
/// handle.confirm_chunk(0);
/// assert!(handle.is_confirmed(0));
/// assert_eq!(handle.confirmed_count(), 1);
/// ```
pub struct SessionHandle {
    /// Unique session identifier (from metadata, duplicated for convenience).
    session_id: String,

    /// Current lifecycle state of this session.
    state: Arc<RwLock<TransportState>>,

    /// Immutable session metadata.
    metadata: SessionMetadata,

    /// Set of chunk indices confirmed received and verified by receiver.
    confirmed_chunks: Arc<RwLock<HashSet<u32>>>,
}

impl SessionHandle {
    /// Create a new session handle from the given metadata.
    ///
    /// Initializes the session in [`TransportState::Negotiating`] state
    /// with an empty confirmed-chunk set.
    ///
    /// # Arguments
    /// * `metadata` — Session metadata describing the transfer.
    ///
    /// # Returns
    /// A new [`SessionHandle`] ready for use.
    pub fn new(metadata: SessionMetadata) -> Self {
        let session_id = metadata.session_id.clone();
        Self {
            session_id,
            state: Arc::new(RwLock::new(TransportState::Negotiating)),
            metadata,
            confirmed_chunks: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Returns the current transport state (cheap snapshot read).
    pub fn state(&self) -> TransportState {
        self.state.read().clone()
    }

    /// Transition the session to a new state.
    ///
    /// # Arguments
    /// * `new_state` — Target state to transition to.
    pub fn set_state(&self, new_state: TransportState) {
        *self.state.write() = new_state;
    }

    /// Mark a chunk index as confirmed (received and verified).
    ///
    /// Idempotent: calling multiple times for the same index has no effect.
    ///
    /// # Arguments
    /// * `index` — Zero-based chunk index to confirm.
    pub fn confirm_chunk(&self, index: u32) {
        self.confirmed_chunks.write().insert(index);
    }

    /// Check whether a specific chunk index has been confirmed.
    ///
    /// # Arguments
    /// * `index` — Zero-based chunk index to check.
    ///
    /// # Returns
    /// `true` if the chunk is in the confirmed set.
    pub fn is_confirmed(&self, index: u32) -> bool {
        self.confirmed_chunks.read().contains(&index)
    }

    /// Returns the total number of confirmed chunks.
    pub fn confirmed_count(&self) -> u32 {
        self.confirmed_chunks.read().len() as u32
    }

    /// Compute the list of unconfirmed (pending) chunk indices.
    ///
    /// Returns all indices from `0..total_chunks` that are not present
    /// in the confirmed set. Used by the repair system to identify
    /// chunks requiring retransmission.
    ///
    /// # Returns
    /// A vector of unconfirmed chunk indices, sorted ascending.
    pub fn pending_indices(&self) -> Vec<u32> {
        let confirmed = self.confirmed_chunks.read();
        let total = self.metadata.total_chunks;
        (0..total)
            .filter(|i| !confirmed.contains(i))
            .collect()
    }

    /// Returns a reference to the session metadata.
    pub fn metadata(&self) -> &SessionMetadata {
        &self.metadata
    }

    /// Returns the session identifier string.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Check whether all chunks have been confirmed.
    pub fn is_complete(&self) -> bool {
        self.confirmed_count() >= self.metadata.total_chunks
    }
}

// ===========================================================================
// Verification Report
// ===========================================================================

/// Result of a full-session verification pass.
///
/// Produced by [`HealingTransport::verify_session`](super::transport::HealingTransport::verify_session)
/// after checking all transferred chunks against their integrity envelopes.
/// Drives the decision between completion and repair initiation.
///
/// # Fields
///
/// - `all_ok` — True if every chunk passed verification.
/// - `missing_indices` — Chunk indices never received (gaps in sequence).
/// - `corrupt_indices` — Chunk indices received but failed hash verification.
/// - `total_hash` — Optional recomputed hash of reassembled file.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// True if no issues were detected across all chunks.
    pub all_ok: bool,

    /// Indices of chunks that were never received (absent from confirmed set).
    pub missing_indices: Vec<u32>,

    /// Indices of chunks that were received but failed integrity checks.
    pub corrupt_indices: Vec<u32>,

    /// Optional hex-encoded hash of the fully reassembled file data.
    pub total_hash: Option<String>,
}

impl VerificationReport {
    /// Create a report indicating successful verification (no issues).
    pub fn ok(total_hash: Option<String>) -> Self {
        Self {
            all_ok: true,
            missing_indices: vec![],
            corrupt_indices: vec![],
            total_hash,
        }
    }

    /// Create a report indicating failures with specific issue indices.
    pub fn with_issues(
        missing: Vec<u32>,
        corrupt: Vec<u32>,
        total_hash: Option<String>,
    ) -> Self {
        Self {
            all_ok: missing.is_empty() && corrupt.is_empty(),
            missing_indices: missing,
            corrupt_indices: corrupt,
            total_hash,
        }
    }

    /// Total count of problematic chunks (missing + corrupt).
    pub fn issue_count(&self) -> usize {
        self.missing_indices.len() + self.corrupt_indices.len()
    }

    /// Returns true if there are any issues requiring repair.
    pub fn needs_repair(&self) -> bool {
        !self.all_ok
    }
}

// ===========================================================================
// Repair Progress
// ===========================================================================

/// Progress tracker for an ongoing chunk repair operation.
///
/// Updated incrementally as individual chunk repairs succeed or fail.
/// Used to provide real-time feedback on repair operation status and
/// to determine when all repairs have been attempted.
///
/// # Fields
///
/// - `total_requested` — Total number of repair requests issued.
/// - `completed` — Number of repairs successfully completed so far.
/// - `failed_indices` — Indices of chunks whose repair attempts failed.
#[derive(Debug, Clone)]
pub struct RepairProgress {
    /// Total number of chunk repairs requested.
    pub total_requested: u32,

    /// Number of repairs successfully completed.
    pub completed: u32,

    /// Indices of chunks that could not be repaired after all attempts.
    pub failed_indices: Vec<u32>,
}

impl RepairProgress {
    /// Create a new repair progress tracker.
    ///
    /// # Arguments
    /// * `total_requested` — Expected total number of repairs.
    pub fn new(total_requested: u32) -> Self {
        Self {
            total_requested,
            completed: 0,
            failed_indices: vec![],
        }
    }

    /// Record a successful repair completion.
    pub fn mark_completed(&mut self) {
        self.completed += 1;
    }

    /// Record a failed repair attempt for a specific chunk index.
    pub fn mark_failed(&mut self, index: u32) {
        self.failed_indices.push(index);
    }

    /// Returns true if all requested repairs have been processed.
    pub fn is_finished(&self) -> bool {
        (self.completed + self.failed_indices.len() as u32) >= self.total_requested
    }

    /// Returns the success rate as a value between 0.0 and 1.0.
    pub fn success_rate(&self) -> f64 {
        if self.total_requested == 0 {
            return 1.0;
        }
        self.completed as f64 / self.total_requested as f64
    }
}

// ===========================================================================
// Clone Implementation for SessionHandle
// ===========================================================================

impl Clone for SessionHandle {
    /// Create a shallow clone of the session handle.
    ///
    /// The cloned handle shares the same underlying `Arc` pointers for
    /// state and confirmed-chunks, so mutations through either handle
    /// are visible to both. This is the desired behavior for concurrent
    /// access patterns where multiple tasks need read/write access to
    /// the same session.
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            state: Arc::clone(&self.state),
            metadata: self.metadata.clone(),
            confirmed_chunks: Arc::clone(&self.confirmed_chunks),
        }
    }
}

#[cfg(test)]
mod tests;
