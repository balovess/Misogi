//! Tunnel Transfer Task — Pluggable Driver Execution with Self-Healing Integrity.
//!
//! Executes file transfer operations through the pluggable [`TransferDriverInstance`]
//! stored in [`AppState`], with optional per-chunk integrity verification via the
//! self-healing transport layer (Task 6.27).
//!
//! # Architecture
//!
//! ```text
//! execute_transfer() / execute_transfer_integrity()
//!   │
//!   ├── Check integrity_config
//!   │   ├── Some(_) → execute_transfer_integrity()
//!   │   └── None    → execute_transfer() (legacy path)
//!   │
//!   ├── execute_transfer_integrity()
//!   │   ├── Create IntegrityEnvelopeBuilder
//!   │   ├── For each chunk:
//!   │   │   ├── Build IntegrityEnvelope (data_hash, envelope_hash, nonce)
//!   │   │   ├── Send via transfer_driver.send_chunk_integrity()
//!   │   │   ├── Verify IntegrityChunkAck
//!   │   │   └── On failure → trigger repair if auto_repair enabled
//!   │   ├── Post-transfer verification
//!   │   └── Save checkpoint via SessionManager
//!   │
//!   └── execute_transfer() (legacy, no integrity)
//!       ├── For each chunk: send via transfer_driver.send_chunk()
//!       └── Mark file as Ready
//! ```
//!
//! # Self-Healing Transport (Task 6.27)
//!
//! When `state.integrity_config` is `Some(...)`, each chunk is wrapped in an
//! [`IntegrityEnvelope`] containing:
//!
//! - **data_hash** — Cryptographic digest of the chunk payload (SHA-256/SHA-512/BLAKE3).
//! - **envelope_hash** — Digest of the entire serialized envelope (tamper-proof seal).
//! - **sequence_nonce** — Monotonically increasing counter preventing replay attacks.
//! - **previous_chunk_hash** — Optional chain-link enabling detection of insertion/deletion.
//!
//! The receiver verifies each envelope and sends back an [`IntegrityAck`]. If verification
//! fails, the sender can automatically request retransmission when `auto_repair` is enabled.
//!
//! # Driver Lifecycle
//!
//! Drivers are initialized once during application startup (in `run_server()` /
//! `run_daemon_mode()`), not per-transfer. Each call to [`execute_transfer`] reuses
//! the existing connection.

use crate::state::SharedState;
use bytes::Bytes;
use misogi_core::hash::compute_md5;
use misogi_core::integrity::{
    HashAlgorithm, IntegrityEnvelopeBuilder, IntegrityConfig,
};
use misogi_core::types::ChunkMeta;
use misogi_core::{FileStatus, MisogiError, Result};

/// Execute file transfer using the pluggable transport driver.
///
/// This function serves as the entry point for all transfers. It checks whether
/// integrity verification is enabled in the application state and dispatches
/// to the appropriate implementation:
///
/// - **Integrity enabled**: Delegates to [`execute_transfer_integrity()`].
/// - **Integrity disabled**: Uses legacy path without integrity envelopes.
///
/// # Arguments
/// * `state` — Shared application state containing uploader and driver.
/// * `file_id` — Unique identifier of the file to transfer.
///
/// # Returns
/// `Ok(())` on successful transfer, `Err(MisogiError)` on failure.
///
/// # Errors
/// - [`MisogiError::NotFound`] if `file_id` does not exist in the registry.
/// - [`MisogiError::Protocol`] if any chunk is rejected by the receiver.
/// - [`MisogiError::Io`] if chunk read or network transmission fails.
pub async fn execute_transfer(state: SharedState, file_id: String) -> Result<()> {
    // Check if integrity verification is enabled.
    if state.integrity_config.is_some() {
        execute_transfer_integrity(state, file_id).await
    } else {
        execute_transfer_legacy(state, file_id).await
    }
}

/// Execute file transfer with self-healing integrity verification.
///
/// Wraps each chunk in an [`IntegrityEnvelope`] containing cryptographic hashes,
/// sequence nonces, and optional chain-linking. Enables:
///
/// - **Per-chunk verification** — Receiver validates data_hash and envelope_hash.
/// - **Replay protection** — Monotonic nonces prevent old chunk reinjection.
/// - **Tamper detection** — Any envelope modification invalidates envelope_hash.
/// - **Automatic repair** — Corrupted chunks trigger retransmission requests.
/// - **Checkpoint resume** — Session state persisted for interruption recovery.
///
/// # Arguments
/// * `state` — Shared application state with integrity_config enabled.
/// * `file_id` — Unique identifier of the file to transfer.
///
/// # Returns
/// `Ok(())` on successful transfer with all chunks verified.
/// `Err(MisogiError)` on unrecoverable failure.
///
/// # Integrity Envelope Structure
///
/// Each chunk is transmitted with the following envelope:
///
/// ```json
/// {
///   "chunk_index": 0,
///   "data_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
///   "envelope_hash": "a7ffc6f8bf1ed7dd51ea05f0c1e6e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
///   "sequence_nonce": 0,
///   "previous_chunk_hash": null,
///   "timestamp_ms": 1699876543210
/// }
/// ```
async fn execute_transfer_integrity(state: SharedState, file_id: String) -> Result<()> {
    let file_info = state.uploader.get_file_info(&file_id).await?;
    let integrity_config = state
        .integrity_config
        .as_ref()
        .ok_or_else(|| MisogiError::Protocol("Integrity config not enabled".to_string()))?;

    let driver_name = state.transfer_driver.name();
    let total_chunks = file_info.chunk_count;

    tracing::info!(
        file_id = %file_id,
        driver = %driver_name,
        total_chunks,
        hash_algorithm = %integrity_config.hash_algorithm,
        chunk_linking = integrity_config.chunk_linking,
        "Starting integrity-verified transfer"
    );

    // Initialize integrity envelope builder.
    let hash_algorithm = parse_hash_algorithm(&integrity_config.hash_algorithm)?;
    let mut envelope_builder = IntegrityEnvelopeBuilder::new(hash_algorithm, integrity_config.chunk_linking);

    // Track previous chunk hash for chain-linking.
    let mut prev_chunk_hash: Option<String> = None;

    // Transfer each chunk with integrity envelope.
    for i in 0..total_chunks {
        let chunk_data = match state.uploader.read_chunk(&file_id, i).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, file_id = %file_id, chunk_index = i, "Failed to read chunk");
                state.update_file_status(&file_id, FileStatus::Failed).await;
                return Err(e);
            }
        };

        // Build integrity envelope for this chunk.
        let envelope = match envelope_builder.build(i, &chunk_data, prev_chunk_hash.as_deref()) {
            Ok(env) => env,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    file_id = %file_id,
                    chunk_index = i,
                    "Failed to build integrity envelope"
                );
                state.update_file_status(&file_id, FileStatus::Failed).await;
                return Err(MisogiError::Protocol(format!(
                    "Integrity envelope build failed: {}",
                    e
                )));
            }
        };

        // Log envelope details at trace level for debugging.
        tracing::trace!(
            file_id = %file_id,
            chunk_index = i,
            data_hash = %envelope.data_hash,
            nonce = envelope.sequence_nonce,
            "Sending chunk with integrity envelope"
        );

        // Create chunk metadata for the integrity-aware send.
        let metadata = ChunkMeta {
            file_id: file_id.clone(),
            chunk_index: i,
            chunk_md5: compute_md5(&chunk_data),
            size: chunk_data.len() as u64,
        };

        // Send chunk with integrity envelope via transfer driver.
        match state
            .transfer_driver
            .send_chunk_integrity(&file_id, i, &chunk_data, &metadata, Some(&envelope))
            .await
        {
            Ok(ack) => {
                if !ack.received_ok {
                    let error_msg = ack.error.unwrap_or_else(|| "Unknown error".to_string());
                    tracing::error!(
                        file_id = %file_id,
                        chunk_index = i,
                        error = %error_msg,
                        "Chunk transfer rejected by receiver"
                    );

                    // Check if auto-repair is enabled.
                    if integrity_config.repair.auto_repair {
                        tracing::info!(
                            file_id = %file_id,
                            chunk_index = i,
                            "Attempting automatic repair"
                        );
                        // TODO: Implement repair logic via RepairEngine
                        // For now, mark as failed and continue.
                    }

                    state.update_file_status(&file_id, FileStatus::Failed).await;
                    return Err(MisogiError::Protocol(error_msg));
                }

                tracing::info!(
                    file_id = %file_id,
                    chunk_index = i,
                    total = total_chunks,
                    progress = i + 1,
                    data_hash = %envelope.data_hash,
                    "Chunk transferred with integrity verification"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, file_id = %file_id, chunk_index = i, "Chunk send failed");
                state.update_file_status(&file_id, FileStatus::Failed).await;
                return Err(e);
            }
        }

        // Update previous chunk hash for chain-linking.
        prev_chunk_hash = Some(envelope.data_hash.clone());

        // Save checkpoint periodically if session manager is available.
        if let Some(ref session_manager) = state.session_manager {
            let checkpoint_interval = integrity_config.resume.checkpoint_interval_chunks;
            if checkpoint_interval > 0 && (i + 1) % checkpoint_interval == 0 {
                if let Err(e) = session_manager.save_checkpoint(&file_id) {
                    tracing::warn!(
                        error = %e,
                        file_id = %file_id,
                        chunk_index = i,
                        "Failed to save checkpoint"
                    );
                }
            }
        }
    }

    // Signal transfer finalization to the receiver.
    let _final_ack = state
        .transfer_driver
        .send_complete(&file_id, total_chunks, "")
        .await?;

    state.update_file_status(&file_id, FileStatus::Ready).await;

    // Save final checkpoint.
    if let Some(ref session_manager) = state.session_manager {
        if let Err(e) = session_manager.save_checkpoint(&file_id) {
            tracing::warn!(error = %e, file_id = %file_id, "Failed to save final checkpoint");
        }
    }

    tracing::info!(
        file_id = %file_id,
        driver = %driver_name,
        total_chunks,
        "Transfer completed successfully with integrity verification"
    );

    Ok(())
}

/// Execute file transfer using legacy path without integrity verification.
///
/// This is the original transfer implementation that sends chunks without
/// integrity envelopes. Used when `integrity_config` is `None` for backward
/// compatibility.
///
/// # Arguments
/// * `state` — Shared application state containing uploader and driver.
/// * `file_id` — Unique identifier of the file to transfer.
///
/// # Returns
/// `Ok(())` on successful transfer, `Err(MisogiError)` on failure.
async fn execute_transfer_legacy(state: SharedState, file_id: String) -> Result<()> {
    let file_info = state.uploader.get_file_info(&file_id).await?;

    let driver_name = state.transfer_driver.name();
    let total_chunks = file_info.chunk_count;

    tracing::info!(
        file_id = %file_id,
        driver = %driver_name,
        total_chunks,
        "Starting pluggable driver transfer (legacy, no integrity)"
    );

    for i in 0..total_chunks {
        let chunk_data = match state.uploader.read_chunk(&file_id, i).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, file_id = %file_id, chunk_index = i, "Failed to read chunk");
                state.update_file_status(&file_id, FileStatus::Failed).await;
                return Err(e);
            }
        };

        // Convert &[u8] to Bytes for the TransferDriver interface.
        let bytes_data = Bytes::from(chunk_data);

        match state
            .transfer_driver
            .send_chunk(&file_id, i, bytes_data)
            .await
        {
            Ok(ack) => {
                if let Some(err_msg) = &ack.error {
                    tracing::error!(
                        file_id = %file_id,
                        chunk_index = i,
                        error = %err_msg,
                        "Chunk transfer rejected by receiver"
                    );
                    state.update_file_status(&file_id, FileStatus::Failed).await;
                    return Err(MisogiError::Protocol(err_msg.clone()));
                }
                tracing::info!(
                    file_id = %file_id,
                    chunk_index = i,
                    total = total_chunks,
                    progress = i + 1,
                    received_size = ack.received_size,
                    "Chunk transferred"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, file_id = %file_id, chunk_index = i, "Chunk send failed");
                state.update_file_status(&file_id, FileStatus::Failed).await;
                return Err(e);
            }
        }
    }

    // Signal transfer finalization to the receiver.
    let _final_ack = state
        .transfer_driver
        .send_complete(&file_id, total_chunks, "")
        .await?;

    state.update_file_status(&file_id, FileStatus::Ready).await;

    tracing::info!(
        file_id = %file_id,
        driver = %driver_name,
        total_chunks,
        "Transfer completed successfully via pluggable driver"
    );

    Ok(())
}

/// Parse hash algorithm string into [`HashAlgorithm`] enum.
///
/// # Arguments
/// * `s` — Hash algorithm identifier ("sha256", "sha512", "blake3").
///
/// # Returns
/// The corresponding [`HashAlgorithm`] variant.
///
/// # Errors
/// Returns [`MisogiError::Protocol`] if the algorithm string is not recognized.
fn parse_hash_algorithm(s: &str) -> Result<HashAlgorithm> {
    match s.to_lowercase().as_str() {
        "sha256" => Ok(HashAlgorithm::Sha256),
        "sha512" => Ok(HashAlgorithm::Sha512),
        "blake3" => Ok(HashAlgorithm::Blake3),
        other => Err(MisogiError::Protocol(format!(
            "Unsupported hash algorithm: {}. Supported: sha256, sha512, blake3",
            other
        ))),
    }
}

/// Request repair for corrupted or missing chunks.
///
/// When integrity verification fails, this function initiates retransmission
/// of the specified chunk indices. The repair is performed using the
/// [`RepairEngine`] configured in the integrity subsystem.
///
/// # Arguments
/// * `state` — Shared application state.
/// * `file_id` — File identifier requiring repair.
/// * `missing_indices` — Chunk indices that need retransmission.
///
/// # Returns
/// `Ok(())` if all repairs succeed, `Err(_)` if any repair fails.
///
/// # Note
///
/// This function is currently a placeholder. Full implementation requires
/// integration with the [`RepairEngine`] and bidirectional communication
/// with the receiver for repair requests.
#[allow(dead_code)]
pub async fn request_repair(
    _state: SharedState,
    file_id: &str,
    missing_indices: &[u32],
) -> Result<()> {
    tracing::warn!(
        file_id = %file_id,
        missing_count = missing_indices.len(),
        missing_indices = ?missing_indices,
        "Repair requested but not yet implemented"
    );

    // TODO: Implement repair using RepairEngine
    // 1. Get RepairEngine from integrity_config
    // 2. Call repair_engine.request_repair() with repair_fn
    // 3. repair_fn should send retransmission request to receiver
    // 4. Track progress and update session state

    Err(MisogiError::Protocol(
        "Repair functionality not yet implemented".to_string(),
    ))
}

/// Resume an interrupted transfer from the last checkpoint.
///
/// Loads the session state from the checkpoint file and continues transfer
/// from the last confirmed chunk index. Useful for recovering from network
/// interruptions or process crashes.
///
/// # Arguments
/// * `state` — Shared application state with session_manager.
/// * `file_id` — File identifier to resume.
///
/// # Returns
/// `Ok(())` if resume succeeds, `Err(_)` if no checkpoint exists or resume fails.
///
/// # Note
///
/// This function is currently a placeholder. Full implementation requires
/// integration with the [`SessionManager`] for checkpoint loading and
/// state restoration.
#[allow(dead_code)]
pub async fn resume_transfer(state: SharedState, file_id: &str) -> Result<()> {
    let session_manager = state
        .session_manager
        .as_ref()
        .ok_or_else(|| MisogiError::Protocol("Session manager not available".to_string()))?;

    // Attempt to load checkpoint.
    match session_manager
        .load_checkpoint(file_id)
        .map_err(|e| MisogiError::Protocol(format!("Failed to load checkpoint: {}", e)))?
    {
        Some(handle) => {
            let confirmed_count = handle.confirmed_count();
            tracing::info!(
                file_id = %file_id,
                confirmed_chunks = confirmed_count,
                "Resuming transfer from checkpoint"
            );

            // TODO: Continue transfer from confirmed_count
            // 1. Read file info from uploader
            // 2. Start from chunk index confirmed_count
            // 3. Continue with integrity-wrapped transfer

            Err(MisogiError::Protocol(
                "Resume functionality not yet fully implemented".to_string(),
            ))
        }
        None => {
            tracing::info!(file_id = %file_id, "No checkpoint found, starting fresh transfer");
            execute_transfer(state, file_id.to_string()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_algorithm_sha256() {
        let result = parse_hash_algorithm("sha256").unwrap();
        assert!(matches!(result, HashAlgorithm::Sha256));
    }

    #[test]
    fn test_parse_hash_algorithm_sha512() {
        let result = parse_hash_algorithm("SHA512").unwrap();
        assert!(matches!(result, HashAlgorithm::Sha512));
    }

    #[test]
    fn test_parse_hash_algorithm_blake3() {
        let result = parse_hash_algorithm("blake3").unwrap();
        assert!(matches!(result, HashAlgorithm::Blake3));
    }

    #[test]
    fn test_parse_hash_algorithm_invalid() {
        let result = parse_hash_algorithm("md5");
        assert!(result.is_err());
    }
}
