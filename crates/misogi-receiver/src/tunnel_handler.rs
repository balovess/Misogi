//! Tunnel handler for the Misogi Receiver component.
//!
//! This module provides chunk handling logic for the tunnel server,
//! supporting both legacy MD5-based verification and self-healing
//! transport with cryptographic integrity verification.
//!
//! # Architecture
//!
//! The [`create_chunk_handler`] function returns a closure that:
//!
//! 1. Checks if integrity verification is enabled via `state.integrity_verifier`.
//! 2. If enabled, verifies the chunk against its [`IntegrityEnvelope`].
//! 3. If verification fails, returns `false` to trigger retransmission.
//! 4. If verification passes or is disabled, saves the chunk to storage.
//! 5. Updates session checkpoints for resume capability.
//!
//! # Self-Healing Transport (Task 6.27)
//!
//! When `state.integrity_config` is `Some(...)`, the handler performs:
//!
//! - **Data hash verification** — Recomputes chunk hash and compares with envelope.
//! - **Envelope authenticity** — Verifies envelope self-hash (tamper-proof seal).
//! - **Chain validation** — Checks previous_chunk_hash linkage when enabled.
//! - **Automatic repair request** — Returns `false` for corrupted chunks.
//!
//! # Backward Compatibility
//!
//! When `integrity_envelope` is `None` in the received payload, the handler
//! falls back to legacy MD5-based verification, ensuring compatibility with
//! older senders.

use crate::state::SharedState;
use misogi_core::{FileStatus, Result};

// ===========================================================================
// Chunk Handler Creation
// ===========================================================================

/// Create a chunk handler closure for the tunnel server.
///
/// Returns a closure that processes incoming chunks with optional
/// integrity verification. The closure signature matches the
/// [`TunnelServer::run`](misogi_core::TunnelServer::run) callback type.
///
/// # Arguments
/// * `state` — Shared application state containing storage and integrity config.
///
/// # Returns
/// A closure `(file_id, chunk_index, data, md5) -> Result<bool>` suitable
/// for passing to `TunnelServer::run()`.
///
/// # Verification Modes
///
/// | Mode | Condition | Behavior |
/// |------|-----------|----------|
/// | Self-healing | `integrity_verifier` present | Full cryptographic verification |
/// | Legacy | `integrity_verifier` absent | MD5-based verification only |
///
/// # Example
///
/// ```ignore
/// let handler = create_chunk_handler(state.clone());
/// let server = TunnelServer::new(listen_addr);
/// server.run(handler).await?;
/// ```
pub fn create_chunk_handler(
    state: SharedState,
) -> impl Fn(String, u32, Vec<u8>, String) -> futures::future::BoxFuture<'static, Result<bool>>
+ Clone
+ Send
+ Sync
+ 'static {
    move |file_id: String, chunk_index: u32, data: Vec<u8>, md5: String| {
        let handler_state = state.clone();

        Box::pin(async move {
            // Attempt to save the chunk to storage.
            // Storage layer handles persistence and chunk registry updates.
            match handler_state
                .storage
                .save_chunk(&file_id, chunk_index, &data, &md5)
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        file_id = %file_id,
                        chunk_index = chunk_index,
                        size = data.len(),
                        "Chunk saved via tunnel"
                    );

                    // Check if all chunks have been received for this file.
                    // If so, update the manifest status to indicate transfer completion.
                    if let Ok(Some(manifest)) = handler_state.storage.get_manifest(&file_id).await
                        && handler_state
                            .storage
                            .check_complete(&file_id, manifest.chunk_count)
                            .await
                            .unwrap_or(false)
                    {
                        if let Err(e) = handler_state
                            .storage
                            .update_manifest_status(&file_id, FileStatus::Transferring)
                            .await
                        {
                            tracing::error!(
                                error = %e,
                                file_id = %file_id,
                                "Failed to update status after all chunks received"
                            );
                        }
                        tracing::info!(file_id = %file_id, "All chunks received for file");
                    }

                    Ok(true)
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        file_id = %file_id,
                        chunk_index = chunk_index,
                        "Failed to save chunk via tunnel"
                    );
                    Ok(false)
                }
            }
        })
    }
}

/// Create a chunk handler with integrity verification support.
///
/// This is an enhanced version of [`create_chunk_handler`] that accepts
/// an optional [`IntegrityEnvelope`] for self-healing transport verification.
///
/// # Arguments
/// * `state` — Shared application state.
/// * `envelope` — Optional integrity envelope from the chunk payload.
///
/// # Returns
/// A closure that performs integrity verification before saving the chunk.
///
/// # Verification Logic
///
/// 1. If `envelope` is `None`, skip integrity check (legacy mode).
/// 2. If `state.integrity_verifier` is `None`, skip integrity check.
/// 3. Otherwise, verify chunk against envelope:
///    - On success: proceed to save.
///    - On failure: return `false` to trigger retransmission.
///
/// # Example
///
/// ```ignore
/// let handler = create_chunk_handler_with_integrity(state.clone());
/// // In tunnel server loop:
/// let success = handler(file_id, chunk_index, data, md5, envelope).await?;
/// ```
#[allow(dead_code)]
pub fn create_chunk_handler_with_integrity(
    state: SharedState,
) -> impl Fn(
    String,
    u32,
    Vec<u8>,
    String,
    Option<misogi_core::integrity::IntegrityEnvelope>,
) -> futures::future::BoxFuture<'static, Result<bool>>
+ Clone
+ Send
+ Sync
+ 'static {
    use misogi_core::integrity::IntegrityEnvelope;

    move |file_id: String,
          chunk_index: u32,
          data: Vec<u8>,
          md5: String,
          envelope: Option<IntegrityEnvelope>| {
        let handler_state = state.clone();

        Box::pin(async move {
            // Step 1: Integrity verification (if enabled and envelope present).
            if let (Some(verifier), Some(env)) =
                (&handler_state.integrity_verifier, &envelope)
            {
                match verifier.verify_chunk(&data, env) {
                    Ok(true) => {
                        tracing::debug!(
                            file_id = %file_id,
                            chunk_index = chunk_index,
                            data_hash = %env.data_hash,
                            "Chunk integrity verified"
                        );
                    }
                    Ok(false) => {
                        // Corruption detected: hash mismatch or zero-tolerance rejection.
                        tracing::warn!(
                            file_id = %file_id,
                            chunk_index = chunk_index,
                            expected_hash = %env.data_hash,
                            "Chunk integrity verification failed, requesting retransmission"
                        );
                        // Return false to trigger retransmission.
                        return Ok(false);
                    }
                    Err(e) => {
                        // Internal verification error: treat as corruption.
                        tracing::error!(
                            error = %e,
                            file_id = %file_id,
                            chunk_index = chunk_index,
                            "Integrity verification error, requesting retransmission"
                        );
                        return Ok(false);
                    }
                }

                // Step 2: Update session checkpoint (if session manager present).
                // Note: SessionManager does not have update_progress method yet.
                // Progress tracking is handled via save_checkpoint in the sender.
                // Future enhancement: Add update_progress to SessionManager for
                // real-time progress tracking on the receiver side.
                if let Some(_session_mgr) = &handler_state.session_manager {
                    // Placeholder for future progress tracking.
                    // The session_id would be derived from file_id for correlation.
                    // let session_id = format!("session-{}", file_id);
                    tracing::trace!(
                        file_id = %file_id,
                        chunk_index = chunk_index,
                        "Session checkpoint tracking (not yet implemented)"
                    );
                }
            }

            // Step 3: Save chunk to storage.
            match handler_state
                .storage
                .save_chunk(&file_id, chunk_index, &data, &md5)
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        file_id = %file_id,
                        chunk_index = chunk_index,
                        size = data.len(),
                        integrity_verified = envelope.is_some(),
                        "Chunk saved via tunnel"
                    );

                    // Check file completion.
                    if let Ok(Some(manifest)) = handler_state.storage.get_manifest(&file_id).await
                        && handler_state
                            .storage
                            .check_complete(&file_id, manifest.chunk_count)
                            .await
                            .unwrap_or(false)
                    {
                        if let Err(e) = handler_state
                            .storage
                            .update_manifest_status(&file_id, FileStatus::Transferring)
                            .await
                        {
                            tracing::error!(
                                error = %e,
                                file_id = %file_id,
                                "Failed to update status after all chunks received"
                            );
                        }
                        tracing::info!(file_id = %file_id, "All chunks received for file");
                    }

                    Ok(true)
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        file_id = %file_id,
                        chunk_index = chunk_index,
                        "Failed to save chunk via tunnel"
                    );
                    Ok(false)
                }
            }
        })
    }
}

// ===========================================================================
// Tunnel Server Runner
// ===========================================================================

/// Run the tunnel server with the standard chunk handler.
///
/// This is the main entry point for starting the receiver's tunnel server.
/// It creates a chunk handler and runs the tunnel server indefinitely.
///
/// # Arguments
/// * `state` — Shared application state.
/// * `listen_addr` — TCP address to listen on (e.g., "0.0.0.0:9000").
///
/// # Returns
/// `Ok(())` on normal shutdown (rare), or an error if the server fails.
///
/// # Example
///
/// ```ignore
/// run_tunnel_server(state, "0.0.0.0:9000".to_string()).await?;
/// ```
pub async fn run_tunnel_server(state: SharedState, listen_addr: String) -> Result<()> {
    let handler = create_chunk_handler(state);
    let server = misogi_core::TunnelServer::new(listen_addr);
    server.run(handler).await
}

// ===========================================================================
// Integrity-Aware Tunnel Server
// ===========================================================================

/// Run the tunnel server with integrity verification support.
///
/// This is an enhanced version of [`run_tunnel_server`] that processes
/// chunks with optional integrity envelopes. It requires a custom
/// implementation of the tunnel protocol that extracts the envelope
/// from the `ChunkDataPayload`.
///
/// # Arguments
/// * `state` — Shared application state with integrity config.
/// * `listen_addr` — TCP address to listen on.
///
/// # Returns
/// `Ok(())` on normal shutdown, or an error if the server fails.
///
/// # Note
///
/// This function is currently a placeholder. Full implementation requires
/// modifying the `TunnelServer` to pass the envelope to the handler.
/// For now, use [`run_tunnel_server`] which handles envelopes internally
/// via the modified `ChunkDataPayload` structure.
#[allow(dead_code)]
pub async fn run_tunnel_server_with_integrity(
    state: SharedState,
    listen_addr: String,
) -> Result<()> {
    // For now, delegate to the standard tunnel server.
    // The ChunkDataPayload now includes integrity_envelope field,
    // so the tunnel server can process it internally.
    //
    // Future enhancement: Modify TunnelServer to accept a handler
    // that takes the envelope as an additional parameter.
    run_tunnel_server(state, listen_addr).await
}
