//! Self-healing transport trait definition.
//!
//! Defines the async interface that all transport backends must implement
//! to provide self-healing capabilities. Implementations of this trait
//! handle the full lifecycle: session negotiation, integrity-wrapped chunk
//! transfer, verification, and automatic repair.
//!
//! # Implementation Contract
//!
//! Transport implementations MUST guarantee:
//!
//! 1. **Envelope fidelity** — Each chunk sent via `send_chunk_integrity`
//!    must be wrapped in a valid [`IntegrityEnvelope`](super::envelope::IntegrityEnvelope)
//!    before transmission and verified upon receipt.
//! 2. **State transitions** — The [`SessionHandle`](super::session::SessionHandle)
//!    state must be updated to reflect actual transport progress.
//! 3. **Confirmation tracking** — Successfully received chunks must be
//!    recorded via `confirm_chunk()` on the session handle.
//! 4. **Graceful shutdown** — `shutdown()` must release all resources
//!    including network connections, file handles, and temporary buffers.

use crate::integrity::envelope::{IntegrityAck, IntegrityError};
use crate::integrity::session::{
    RepairProgress, SessionHandle, TransportCapabilities, VerificationReport,
};
use async_trait::async_trait;

// ===========================================================================
// Healing Transport Trait
// ===========================================================================

/// Async trait for self-healing transport implementations.
///
/// Abstracts the transport layer behind a uniform interface that supports
/// integrity-verified chunk transfer, post-transfer verification, and
/// automatic repair of missing or corrupted chunks. All methods are async
/// and the trait is object-safe (can be used as `dyn HealingTransport`).
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync`, enabling safe sharing across
/// tokio tasks. Internal state should use `Arc<RwLock<T>>` or equivalent
/// synchronization primitives.
///
/// # Lifecycle
///
/// ```text
/// begin_session() → [send_chunk_integrity()*] → verify_session()
///       ↓                                              ↓
///   [repair_chunks()*] ←── needs repair ──────────────┘
///       ↓
///   shutdown()
/// ```
#[async_trait]
pub trait HealingTransport: Send + Sync {
    /// Returns the human-readable name of this transport implementation.
    ///
    /// Used for logging, metrics labeling, and debugging. Examples:
    /// `"grpc-bidirectional"`, `"http-multipart"`, `"udp-blast"`.
    fn name(&self) -> &str;

    /// Initialize a new transfer session with the remote peer.
    ///
    /// Performs capability negotiation, allocates resources, and returns
    /// a [`SessionHandle`] that tracks the session's lifetime. The handle
    /// is the primary reference passed to all subsequent operations.
    ///
    /// # Arguments
    /// * `session_id` — Unique identifier for this transfer session.
    /// * `total_chunks` — Total number of chunks that will be transferred.
    /// * `capabilities` — Local capabilities offered to the remote peer.
    ///
    /// # Returns
    /// A [`SessionHandle`] in [`TransportState::Negotiating`](super::session::TransportState::Negotiating)
    /// state, ready for data transfer.
    ///
    /// # Errors
    /// - [`IntegrityError::SerializationError`] if session metadata cannot be serialized.
    /// - [`IntegrityError::InvalidEnvelope`] if negotiation fails.
    async fn begin_session(
        &self,
        session_id: &str,
        total_chunks: u32,
        capabilities: TransportCapabilities,
    ) -> Result<SessionHandle, IntegrityError>;

    /// Send a single chunk with integrity envelope to the remote peer.
    ///
    /// Wraps the payload in an [`IntegrityEnvelope`], transmits it, and
    /// waits for an acknowledgment from the receiver. On success, the chunk
    /// index should be recorded in the session's confirmed set.
    ///
    /// # Arguments
    /// * `session` — Active session handle for this transfer.
    /// * `chunk` — Raw payload bytes of the chunk to send.
    /// * `index` — Zero-based position of this chunk within the transfer.
    ///
    /// # Returns
    /// An [`IntegrityAck`] indicating whether the receiver accepted the chunk.
    ///
    /// # Errors
    /// - [`IntegrityError::HashComputationFailed`] if envelope construction fails.
    /// - [`IntegrityError::SerializationError`] if envelope cannot be serialized.
    async fn send_chunk_integrity(
        &self,
        session: &SessionHandle,
        chunk: &[u8],
        index: u32,
    ) -> Result<IntegrityAck, IntegrityError>;

    /// Perform full-session verification after all chunks are transferred.
    ///
    /// Checks every confirmed chunk's integrity envelope against the stored
    /// data, identifies missing chunks (gaps in confirmation), and optionally
    /// recomputes the total file hash from reassembled data.
    ///
    /// The session state should transition to [`TransportState::Verifying`](super::session::TransportState::Verifying)
    /// during execution and to either `Completed` or `Repairing`/`Failed`
    /// based on results.
    ///
    /// # Arguments
    /// * `session` — Active session handle whose chunks to verify.
    ///
    /// # Returns
    /// A [`VerificationReport`] detailing the outcome of the check.
    async fn verify_session(
        &self,
        session: &SessionHandle,
    ) -> Result<VerificationReport, IntegrityError>;

    /// Request retransmission of specific missing or corrupted chunks.
    ///
    /// Initiates repair by requesting the remote peer to resend the chunks
    /// at the given indices. Progress is tracked via [`RepairProgress`].
    /// The session state should transition to
    /// [`TransportState::Repairing`](super::session::TransportState::Repairing).
    ///
    /// # Arguments
    /// * `session` — Active session handle requiring repair.
    /// * `missing_indices` — Chunk indices that need retransmission.
    ///
    /// # Returns
    /// A [`RepairProgress`] indicating how many repairs succeeded/failed.
    ///
    /// # Errors
    /// - [`IntegrityError::InvalidEnvelope`] if repair request is malformed.
    async fn repair_chunks(
        &self,
        session: &SessionHandle,
        missing_indices: &[u32],
    ) -> Result<RepairProgress, IntegrityError>;

    /// Gracefully shut down the transport and release all resources.
    ///
    /// Must be called exactly once per session to ensure clean teardown.
    /// After shutdown, the session handle should not be used for further
    /// operations. Implementations should:
    ///
    /// 1. Flush any pending write buffers.
    /// 2. Close network connections / release sockets.
    /// 3. Release temporary files and memory buffers.
    /// 4. Transition session state to terminal if not already there.
    ///
    /// # Errors
    /// - [`IntegrityError::InvalidEnvelope`] if cleanup encounters unexpected state.
    async fn shutdown(&self) -> Result<(), IntegrityError>;
}
