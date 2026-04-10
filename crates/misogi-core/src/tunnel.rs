use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use serde::{Deserialize, Serialize};
use crate::error::{MisogiError, Result};
use crate::protocol::{ProtocolFrame, FrameType};
use crate::types::HandshakePayload;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAckResponse {
    pub file_id: String,
    pub chunk_index: u32,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkDataPayload {
    pub file_id: String,
    pub chunk_index: u32,
    pub data: Vec<u8>,
    pub md5: String,
}

pub struct TunnelClient {
    stream: Option<TcpStream>,
    receiver_addr: String,
    node_id: String,
}

impl TunnelClient {
    pub fn new(receiver_addr: String, node_id: String) -> Self {
        Self {
            stream: None,
            receiver_addr,
            node_id,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let mut stream = TcpStream::connect(&self.receiver_addr).await?;

        let handshake_payload = HandshakePayload {
            version: "0.1.0".to_string(),
            node_id: self.node_id.clone(),
            node_role: "sender".to_string(),
        };
        let payload_bytes = serde_json::to_vec(&handshake_payload)?;
        let frame = ProtocolFrame::new(FrameType::Handshake, payload_bytes);
        stream.write_all(&frame.encode()).await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_frame = ProtocolFrame::decode_from_stream(&mut stream, &len_buf).await?;
        if response_frame.frame_type != FrameType::HandshakeAck {
            return Err(MisogiError::Protocol("Expected HandshakeAck".to_string()));
        }

        self.stream = Some(stream);
        Ok(())
    }

    pub async fn send_chunk(
        &mut self,
        file_id: &str,
        chunk_index: u32,
        data: &[u8],
        md5: &str,
    ) -> Result<ChunkAckResponse> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| MisogiError::Protocol("Not connected".to_string()))?;

        let payload = ChunkDataPayload {
            file_id: file_id.to_string(),
            chunk_index,
            data: data.to_vec(),
            md5: md5.to_string(),
        };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let frame = ProtocolFrame::new(FrameType::ChunkData, payload_bytes);
        stream.write_all(&frame.encode()).await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let ack_frame = ProtocolFrame::decode_from_stream(stream, &len_buf).await?;

        if ack_frame.frame_type != FrameType::ChunkAck {
            return Err(MisogiError::Protocol("Expected ChunkAck".to_string()));
        }

        let ack: ChunkAckResponse = serde_json::from_slice(&ack_frame.payload)?;
        Ok(ack)
    }

    pub async fn send_complete(&mut self, file_id: &str) -> Result<()> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| MisogiError::Protocol("Not connected".to_string()))?;

        let complete_payload = serde_json::json!({
            "file_id": file_id,
        });
        let payload_bytes = serde_json::to_vec(&complete_payload)?;
        let frame = ProtocolFrame::new(FrameType::FileComplete, payload_bytes);
        stream.write_all(&frame.encode()).await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let _response = ProtocolFrame::decode_from_stream(stream, &len_buf).await?;

        Ok(())
    }

    pub async fn send_heartbeat(&mut self) -> Result<()> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| MisogiError::Protocol("Not connected".to_string()))?;

        let frame = ProtocolFrame::new(FrameType::Heartbeat, vec![]);
        stream.write_all(&frame.encode()).await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let _response = ProtocolFrame::decode_from_stream(stream, &len_buf).await?;

        Ok(())
    }

    pub fn start_heartbeat(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                let mut guard = match Arc::try_unwrap(Arc::clone(&client)) {
                    Err(_) => continue,
                    Ok(c) => c,
                };
                if let Err(e) = guard.send_heartbeat().await {
                    tracing::error!(error = %e, "Heartbeat failed");
                    break;
                }
            }
        })
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

pub struct TunnelServer {
    listen_addr: String,
}

impl TunnelServer {
    pub fn new(listen_addr: String) -> Self {
        Self { listen_addr }
    }

    pub async fn run<F>(&self, on_chunk: F) -> Result<()>
    where
        F: Fn(String, u32, Vec<u8>, String) -> futures::future::BoxFuture<'static, Result<bool>>
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let listener = TcpListener::bind(&self.listen_addr).await?;

        tracing::info!(addr = %self.listen_addr, "Tunnel server listening");

        loop {
            let (stream, addr) = listener.accept().await?;
            tracing::info!(peer = %addr, "Tunnel connection accepted");

            let handler = on_chunk.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, handler).await {
                    tracing::error!(error = %e, peer = %addr, "Connection error");
                }
            });
        }
    }

    async fn handle_connection<F>(
        mut stream: TcpStream,
        on_chunk: F,
    ) -> Result<()>
    where
        F: Fn(String, u32, Vec<u8>, String) -> futures::future::BoxFuture<'static, Result<bool>>
            + Send
            + Sync,
    {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let handshake_frame = ProtocolFrame::decode_from_stream(&mut stream, &len_buf).await?;

        if handshake_frame.frame_type != FrameType::Handshake {
            return Err(MisogiError::Protocol(
                "Expected Handshake frame".to_string(),
            ));
        }

        let _payload: HandshakePayload = serde_json::from_slice(&handshake_frame.payload)?;

        let ack_frame = ProtocolFrame::new(FrameType::HandshakeAck, vec![]);
        stream.write_all(&ack_frame.encode()).await?;

        tracing::info!("Handshake completed, entering receive loop");

        loop {
            let mut len_buf = [0u8; 4];

            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        tracing::info!("Connection closed by peer");
                        break;
                    }
                    return Err(MisogiError::Io(e));
                }
            }

            let frame = match ProtocolFrame::decode_from_stream(&mut stream, &len_buf).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to decode frame");
                    continue;
                }
            };

            match frame.frame_type {
                FrameType::ChunkData => {
                    let chunk_payload: ChunkDataPayload =
                        serde_json::from_slice(&frame.payload)?;

                    let file_id = chunk_payload.file_id.clone();
                    let chunk_index = chunk_payload.chunk_index;
                    let md5 = chunk_payload.md5.clone();

                    let result = on_chunk(
                        file_id.clone(),
                        chunk_index,
                        chunk_payload.data,
                        md5,
                    )
                    .await;

                    let ack = match result {
                        Ok(success) => ChunkAckResponse {
                            file_id,
                            chunk_index,
                            success,
                            error: None,
                        },
                        Err(e) => ChunkAckResponse {
                            file_id,
                            chunk_index,
                            success: false,
                            error: Some(e.to_string()),
                        },
                    };

                    let ack_bytes = serde_json::to_vec(&ack)?;
                    let ack_frame = ProtocolFrame::new(FrameType::ChunkAck, ack_bytes);
                    stream.write_all(&ack_frame.encode()).await?;
                }

                FrameType::Heartbeat => {
                    let heartbeat_ack = ProtocolFrame::new(FrameType::Heartbeat, vec![]);
                    stream.write_all(&heartbeat_ack.encode()).await?;
                }

                FrameType::FileComplete => {
                    let complete_info: serde_json::Value =
                        serde_json::from_slice(&frame.payload).unwrap_or_default();

                    if let Some(file_id) = complete_info.get("file_id").and_then(|v| v.as_str()) {
                        tracing::info!(file_id = %file_id, "File transfer complete notification received");
                    }

                    let ack_frame = ProtocolFrame::new(FrameType::FileComplete, vec![]);
                    stream.write_all(&ack_frame.encode()).await?;
                }

                _ => {
                    tracing::warn!(frame_type = ?frame.frame_type, "Unhandled frame type");
                }
            }
        }

        Ok(())
    }
}
