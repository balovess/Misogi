use crate::state::SharedState;
use misogi_core::{Result, FileStatus};

pub fn create_chunk_handler(state: SharedState) -> impl Fn(String, u32, Vec<u8>, String) -> futures::future::BoxFuture<'static, Result<bool>> + Clone + Send + Sync + 'static {
    move |file_id: String, chunk_index: u32, data: Vec<u8>, md5: String| {
        let handler_state = state.clone();

        Box::pin(async move {
            match handler_state.storage.save_chunk(&file_id, chunk_index, &data, &md5).await {
                Ok(()) => {
                    tracing::info!(
                        file_id = %file_id,
                        chunk_index = chunk_index,
                        size = data.len(),
                        "Chunk saved via tunnel"
                    );

                    if let Ok(Some(manifest)) = handler_state.storage.get_manifest(&file_id).await {
                        if handler_state.storage.check_complete(&file_id, manifest.chunk_count).await.unwrap_or(false) {
                            if let Err(e) = handler_state.storage.update_manifest_status(&file_id, FileStatus::Transferring).await {
                                tracing::error!(error = %e, file_id = %file_id, "Failed to update status after all chunks received");
                            }
                            tracing::info!(file_id = %file_id, "All chunks received for file");
                        }
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

pub async fn run_tunnel_server(state: SharedState, listen_addr: String) -> Result<()> {
    let handler = create_chunk_handler(state);
    let server = misogi_core::TunnelServer::new(listen_addr);
    server.run(handler).await
}
