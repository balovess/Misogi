//! Tunnel Transfer Task — Pluggable Driver Execution.
//!
//! Executes file transfer operations through the pluggable [`TransferDriverInstance`]
//! stored in [`AppState`], replacing the legacy hardcoded [`TunnelClient`] path.
//!
//! # Data Flow
//!
//! ```text
//! execute_transfer()
//!   ├── state.transfer_driver.send_chunk(file_id, i, data) × N
//!   ├── state.transfer_driver.send_complete(file_id, total, md5)
//!   └── state.update_file_status(Ready)
//! ```
//!
//! # Driver Lifecycle
//!
//! Drivers are initialized once during application startup (in `run_server()` /
//! `run_daemon_mode()`), not per-transfer. Each call to [`execute_transfer`] reuses
//! the existing connection.

use bytes::Bytes;
use crate::state::SharedState;
use misogi_core::{FileStatus, MisogiError, Result};

/// Execute file transfer using the pluggable transport driver.
///
/// Reads all chunks from the upload engine via [`AppState::uploader`],
/// transmits them through [`AppState::transfer_driver`], and marks the file
/// as `Ready` upon successful completion.
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
pub async fn execute_transfer(
    state: SharedState,
    file_id: String,
) -> Result<()> {
    let file_info = state.uploader.get_file_info(&file_id).await?;

    let driver_name = state.transfer_driver.name();
    let total_chunks = file_info.chunk_count;

    tracing::info!(
        file_id = %file_id,
        driver = %driver_name,
        total_chunks,
        "Starting pluggable driver transfer"
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

        match state.transfer_driver.send_chunk(&file_id, i, bytes_data).await {
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
    let _final_ack = state.transfer_driver
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
