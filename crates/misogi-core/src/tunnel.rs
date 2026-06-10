use crate::error::{MisogiError, Result};
use crate::integrity::IntegrityEnvelope;
use crate::protocol::{FrameType, ProtocolFrame};
use crate::types::HandshakePayload;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Acknowledgment response for chunk transmission.
///
/// Returned by the receiver after processing each chunk to indicate
/// success or failure. Used by the sender to detect transmission
/// errors and trigger retransmission if necessary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAckResponse {
    /// File identifier for the acknowledged chunk.
    pub file_id: String,
    /// Zero-based index of the acknowledged chunk.
    pub chunk_index: u32,
    /// True if the chunk was successfully received and stored.
    pub success: bool,
    /// Optional error message if success is false.
    pub error: Option<String>,
}

/// Payload for chunk data transmission over the tunnel.
///
/// Carries a single chunk of file data along with its identifier
/// and optional integrity envelope for self-healing transport.
///
/// # Backward Compatibility
///
/// The `integrity_envelope` field is optional:
/// - When `None`: Legacy mode using MD5 hash for basic verification.
/// - When `Some(envelope)`: Self-healing mode with full integrity verification.
///
/// Legacy clients can still send chunks without envelopes, and receivers
/// will fall back to MD5-based verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkDataPayload {
    /// Unique identifier for the file being transferred.
    pub file_id: String,
    /// Zero-based index of this chunk within the file.
    pub chunk_index: u32,
    /// Raw chunk data bytes.
    pub data: Vec<u8>,
    /// MD5 hash of the chunk data (legacy verification).
    pub md5: String,
    /// Optional integrity envelope for self-healing transport.
    ///
    /// When present, enables per-chunk cryptographic verification,
    /// tamper detection, and chain validation. When absent, the
    /// receiver falls back to MD5-based verification only.
    #[serde(default)]
    pub integrity_envelope: Option<IntegrityEnvelope>,
}

#[derive(Debug)]
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

    /// Send a chunk without integrity envelope (legacy mode).
    ///
    /// This method is preserved for backward compatibility with receivers
    /// that do not support self-healing transport. For new deployments,
    /// prefer [`send_chunk_with_envelope`](Self::send_chunk_with_envelope).
    ///
    /// # Arguments
    /// * `file_id` — Unique file identifier.
    /// * `chunk_index` — Zero-based chunk position.
    /// * `data` — Raw chunk bytes.
    /// * `md5` — MD5 hash of the chunk data.
    ///
    /// # Returns
    /// Acknowledgment from the receiver.
    pub async fn send_chunk(
        &mut self,
        file_id: &str,
        chunk_index: u32,
        data: &[u8],
        md5: &str,
    ) -> Result<ChunkAckResponse> {
        self.send_chunk_with_envelope(file_id, chunk_index, data, md5, None)
            .await
    }

    /// Send a chunk with optional integrity envelope (self-healing mode).
    ///
    /// Transmits a single chunk to the connected receiver. When an integrity
    /// envelope is provided, the receiver will perform cryptographic verification
    /// and may request retransmission if corruption is detected.
    ///
    /// # Arguments
    /// * `file_id` — Unique file identifier.
    /// * `chunk_index` — Zero-based chunk position.
    /// * `data` — Raw chunk bytes.
    /// * `md5` — MD5 hash of the chunk data (legacy field, may be empty).
    /// * `envelope` — Optional integrity envelope for self-healing transport.
    ///
    /// # Returns
    /// Acknowledgment from the receiver indicating success or failure.
    ///
    /// # Errors
    /// Returns [`MisogiError::Protocol`] if not connected or if the
    /// receiver returns an unexpected response.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let envelope = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, true)
    ///     .build(0, &chunk_data, None)?;
    /// let ack = client.send_chunk_with_envelope(
    ///     "file-123",
    ///     0,
    ///     &chunk_data,
    ///     "",
    ///     Some(envelope)
    /// ).await?;
    /// ```
    pub async fn send_chunk_with_envelope(
        &mut self,
        file_id: &str,
        chunk_index: u32,
        data: &[u8],
        md5: &str,
        envelope: Option<IntegrityEnvelope>,
    ) -> Result<ChunkAckResponse> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| MisogiError::Protocol("Not connected".to_string()))?;

        let payload = ChunkDataPayload {
            file_id: file_id.to_string(),
            chunk_index,
            data: data.to_vec(),
            md5: md5.to_string(),
            integrity_envelope: envelope,
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
        let stream = self
            .stream
            .as_mut()
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
        let stream = self
            .stream
            .as_mut()
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

    async fn handle_connection<F>(mut stream: TcpStream, on_chunk: F) -> Result<()>
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
                    let chunk_payload: ChunkDataPayload = serde_json::from_slice(&frame.payload)?;

                    let file_id = chunk_payload.file_id.clone();
                    let chunk_index = chunk_payload.chunk_index;
                    let md5 = chunk_payload.md5.clone();

                    // Integrity verification (self-healing transport).
                    // If the chunk carries an integrity envelope, verify it before
                    // passing to the application handler. This enables automatic
                    // corruption detection and retransmission requests.
                    let integrity_ok = if let Some(ref envelope) = chunk_payload.integrity_envelope {
                        // Verify data hash against envelope using SHA-256.
                        match crate::integrity::HashAlgorithm::Sha256.hash(&chunk_payload.data) {
                            Ok(computed) => {
                                let hash_matches = computed == envelope.data_hash;
                                if !hash_matches {
                                    tracing::warn!(
                                        file_id = %file_id,
                                        chunk_index = chunk_index,
                                        expected_hash = %envelope.data_hash,
                                        actual_hash = %computed,
                                        "Chunk integrity verification failed: hash mismatch"
                                    );
                                }
                                hash_matches
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    file_id = %file_id,
                                    chunk_index = chunk_index,
                                    "Failed to compute chunk hash for integrity verification"
                                );
                                // Treat hash computation failure as verification failure.
                                false
                            }
                        }
                    } else {
                        // No envelope present: legacy mode, skip integrity check.
                        true
                    };

                    // If integrity verification failed, return failure ACK immediately.
                    // This signals the sender to retransmit the chunk.
                    let result = if !integrity_ok {
                        Ok(false) // Request retransmission.
                    } else {
                        // Integrity OK (or legacy mode): invoke application handler.
                        on_chunk(file_id.clone(), chunk_index, chunk_payload.data, md5).await
                    };

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
