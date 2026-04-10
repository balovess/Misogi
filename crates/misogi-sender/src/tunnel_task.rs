use crate::state::SharedState;
use misogi_core::{MisogiError, Result, TunnelClient, FileStatus};

pub async fn execute_transfer(
    state: SharedState,
    file_id: String,
    receiver_addr: String,
) -> Result<()> {
    let file_info = state.uploader.get_file_info(&file_id).await?;
    let node_id = uuid::Uuid::new_v4().to_string();

    let mut client = TunnelClient::new(receiver_addr, node_id);

    tracing::info!(file_id = %file_id, "Connecting to receiver tunnel");

    client.connect().await?;

    tracing::info!(file_id = %file_id, "Tunnel connected, starting chunk transfer");

    for i in 0..file_info.chunk_count {
        let chunk_data = match state.uploader.read_chunk(&file_id, i).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, file_id = %file_id, chunk_index = i, "Failed to read chunk");
                state.update_file_status(&file_id, FileStatus::Failed).await;
                return Err(e);
            }
        };

        let chunk_md5 = misogi_core::hash::compute_md5(&chunk_data);

        match client.send_chunk(&file_id, i, &chunk_data, &chunk_md5).await {
            Ok(ack) => {
                if !ack.success {
                    let err_msg = ack.error.unwrap_or_else(|| "Unknown error".to_string());
                    tracing::error!(
                        file_id = %file_id,
                        chunk_index = i,
                        error = %err_msg,
                        "Chunk transfer rejected by receiver"
                    );
                    state.update_file_status(&file_id, FileStatus::Failed).await;
                    return Err(MisogiError::Protocol(err_msg));
                }
                tracing::info!(
                    file_id = %file_id,
                    chunk_index = i,
                    total = file_info.chunk_count,
                    progress = i + 1,
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

    client.send_complete(&file_id).await?;

    state.update_file_status(&file_id, FileStatus::Ready).await;

    tracing::info!(file_id = %file_id, "Transfer completed successfully");

    Ok(())
}
