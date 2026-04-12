use tonic::{Request, Response, Status};
use tokio_stream::StreamExt;
use crate::state::SharedState;
use misogi_core::proto::sender_service_server::{SenderService, SenderServiceServer};

pub struct SenderGrpcService {
    state: SharedState,
}

impl SenderGrpcService {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> SenderServiceServer<Self> {
        SenderServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl SenderService for SenderGrpcService {
    async fn upload(
        &self,
        request: Request<tonic::Streaming<misogi_core::proto::Chunk>>,
    ) -> Result<Response<misogi_core::proto::UploadResponse>, Status> {
        let mut stream = request.into_inner();
        let state = self.state.clone();

        let first_chunk = match stream.next().await {
            Some(Ok(chunk)) => chunk,
            Some(Err(e)) => return Err(Status::internal(e.to_string())),
            None => return Err(Status::invalid_argument("Empty stream")),
        };

        let file_id = if !first_chunk.file_id.is_empty() {
            first_chunk.file_id.clone()
        } else {
            let (id, _) = state.uploader
                .create_session("grpc_upload".to_string(), &state)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            id
        };

        let mut chunk_index = 0u32;

        if !first_chunk.data.is_empty() {
            state.uploader
                .write_chunk(&file_id, chunk_index, &first_chunk.data)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            chunk_index += 1;
        }

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| Status::internal(e.to_string()))?;

            if !chunk.data.is_empty() {
                state.uploader
                    .write_chunk(&file_id, chunk_index, &chunk.data)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                chunk_index += 1;
            }
        }

        state.uploader
            .complete_upload(&file_id, &state)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(misogi_core::proto::UploadResponse {
            file_id,
            status: "ready".to_string(),
        }))
    }

    async fn get_file_status(
        &self,
        request: Request<misogi_core::proto::FileIdRequest>,
    ) -> Result<Response<misogi_core::proto::FileStatusResponse>, Status> {
        let file_id = request.into_inner().file_id;

        let info = self.state.uploader
            .get_file_info(&file_id)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        let completed_chunks = if info.status == misogi_core::FileStatus::Uploading {
            let manifest_dir = self.state.uploader.storage_dir()
                .join(&file_id);
            let mut count = 0u32;
            if manifest_dir.exists() {
                for i in 0..info.chunk_count {
                    let chunk_path = manifest_dir.join(format!("chunk_{}.bin", i));
                    if chunk_path.exists() {
                        count += 1;
                    }
                }
            }
            count
        } else {
            info.chunk_count
        };

        Ok(Response::new(misogi_core::proto::FileStatusResponse {
            file_id: info.file_id,
            filename: info.filename,
            total_size: info.total_size,
            chunk_count: info.chunk_count,
            completed_chunks,
            status: format!("{:?}", info.status).to_lowercase(),
            created_at: info.created_at,
        }))
    }

    async fn list_files(
        &self,
        _request: Request<misogi_core::proto::ListFilesRequest>,
    ) -> Result<Response<misogi_core::proto::ListFilesResponse>, Status> {
        let all_files = self.state.uploader
            .list_files()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let files: Vec<_> = all_files
            .into_iter()
            .map(|info| misogi_core::proto::FileStatusResponse {
                file_id: info.file_id,
                filename: info.filename,
                total_size: info.total_size,
                chunk_count: info.chunk_count,
                completed_chunks: info.chunk_count,
                status: format!("{:?}", info.status).to_lowercase(),
                created_at: info.created_at,
            })
            .collect();

        let total = files.len() as i32;

        Ok(Response::new(misogi_core::proto::ListFilesResponse {
            files,
            total,
        }))
    }

    async fn trigger_transfer(
        &self,
        request: Request<misogi_core::proto::FileIdRequest>,
    ) -> Result<Response<misogi_core::proto::TransferResponse>, Status> {
        let file_id = request.into_inner().file_id;

        let exists = self.state.get_file(&file_id).await.ok_or_else(|| {
            Status::not_found(format!("File not found: {}", file_id))
        })?;

        if exists.status != misogi_core::FileStatus::Ready {
            return Err(Status::failed_precondition(format!(
                "File is not ready. Current status: {:?}",
                exists.status
            )));
        }

        self.state
            .update_file_status(&file_id, misogi_core::FileStatus::Transferring)
            .await;

        tracing::info!(file_id = %file_id, "gRPC transfer triggered");

        Ok(Response::new(misogi_core::proto::TransferResponse {
            file_id: file_id.clone(),
            status: "transferring".to_string(),
            message: format!("Transfer initiated for file {}", file_id),
        }))
    }
}
