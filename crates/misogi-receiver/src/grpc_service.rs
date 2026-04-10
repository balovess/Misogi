use tonic::{Request, Response, Status, Streaming};
use misogi_core::proto::receiver_service_server::{
    ReceiverService,
    ReceiverServiceServer,
};
use misogi_core::proto::*;
use crate::state::SharedState;
use std::pin::Pin;
use futures::stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;

pub struct ReceiverGrpcService {
    pub state: SharedState,
}

impl ReceiverGrpcService {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> ReceiverServiceServer<Self> {
        ReceiverServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl ReceiverService for ReceiverGrpcService {
    type ReceiveChunkStream = ReceiverStream<Result<ChunkAck, Status>>;
    type DownloadFileStream = Pin<Box<dyn Stream<Item = Result<FileChunk, Status>> + Send>>;

    async fn receive_chunk(
        &self,
        request: Request<Streaming<ChunkData>>,
    ) -> Result<Response<Self::ReceiveChunkStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(256);
        let state = self.state.clone();

        tokio::spawn(async move {
            while let Ok(Some(chunk_data)) = stream.message().await {
                let file_id = chunk_data.file_id.clone();
                let chunk_index = chunk_data.chunk_index;
                let data = chunk_data.data;
                let expected_md5 = chunk_data.chunk_md5;

                let result = state.storage
                    .save_chunk(&file_id, chunk_index, &data, &expected_md5)
                    .await;

                match result {
                    Ok(_) => {
                        let ack = ChunkAck {
                            file_id,
                            chunk_index,
                            success: true,
                            error: String::new(),
                        };
                        if tx.send(Ok(ack)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let ack = ChunkAck {
                            file_id,
                            chunk_index,
                            success: false,
                            error: e.to_string(),
                        };
                        if tx.send(Ok(ack)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn download_file(
        &self,
        request: Request<FileIdRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let file_id = request.into_inner().file_id;

        let file_info = self.state.storage.get_file_info(&file_id).await.map_err(|e| {
            Status::internal(format!("Failed to get file info: {}", e))
        })?;

        let file_info = match file_info {
            Some(info) => info,
            None => return Err(Status::not_found("File not found")),
        };

        let download_path = self.state.storage.get_download_path(&file_id, &file_info.filename);

        if !download_path.exists() {
            return Err(Status::not_found("File not ready for download"));
        }

        let (tx, rx) = mpsc::channel(64);
        let path = download_path.clone();
        let total_size = file_info.total_size as u32;

        tokio::spawn(async move {
            if let Ok(mut file) = tokio::fs::File::open(&path).await {
                const CHUNK_SIZE: usize = 8 * 1024 * 1024;
                let mut offset: u32 = 0;
                let mut buf = vec![0u8; CHUNK_SIZE];
                use tokio::io::AsyncReadExt;

                loop {
                    match file.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = buf[..n].to_vec();
                            let chunk = FileChunk {
                                data,
                                offset,
                                total_size,
                            };
                            offset += n as u32;
                            if tx.send(Ok(chunk)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output_stream) as Self::DownloadFileStream))
    }

    async fn list_files(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ListFilesResponse>, Status> {
        let files = self.state.storage.list_ready_files().await.map_err(|e| {
            Status::internal(format!("Failed to list files: {}", e))
        })?;

        let file_responses: Vec<FileStatusResponse> = files
            .into_iter()
            .map(|f| FileStatusResponse {
                file_id: f.file_id,
                filename: f.filename,
                total_size: f.total_size,
                chunk_count: f.chunk_count,
                completed_chunks: f.chunk_count,
                status: format!("{:?}", f.status).to_lowercase(),
                created_at: f.created_at,
            })
            .collect();

        let total = file_responses.len() as i32;

        Ok(Response::new(ListFilesResponse {
            files: file_responses,
            total,
        }))
    }
}
