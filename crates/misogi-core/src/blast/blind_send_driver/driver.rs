//! BlindSendDriver — TransferDriver implementation for Mode C (UDP broadcast + FEC).
//!
//! This is the main driver struct implementing [`TransferDriver`](crate::traits::TransferDriver)
//! for physical unidirectional air-gap (光閘 / data diode) scenarios.
//!
//! # Key Differences from UdpBlastDriver
//!
//! | Aspect              | UdpBlastDriver          | BlindSendDriver (this) |
//! |--------------------|------------------------|----------------------|
//! | Transport           | Unicast UDP            | Broadcast UDP         |
//! | Wire Format         | BlastPacket (55+4B hdr)| FecPacket (24B hdr)   |
//! | ACK Semantics       | Synthetic local ACK    | Synthetic local ACK   |
//! | FEC Integration     | Via UdpBlastSender     | Direct RS codec use   |
//! | Config Model        | Sender/Receiver split  | Single unified config |
//! | Manifest Support    | Yes (JSON metadata)    | No (pure data stream) |

use std::net::IpAddr;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use md5::Digest; // Required for md5::Md5::digest()
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::error::{MisogiError, Result};
use crate::fec::FecConfig;
use crate::traits::{
    TransferDriver, TransferDriverConfig,
    ChunkAck, DriverHealthStatus,
};

use super::encoder::BlindSendEncoder;

// =============================================================================
// Configuration
// =============================================================================

/// Default UDP port for blind send broadcast traffic.
fn default_udp_port() -> u16 { 9999 }

/// Default redundancy factor (total shards / data shards).
fn default_redundancy_factor() -> f32 { 2.0 }

/// Default maximum payload size per packet in bytes.
fn default_packet_size() -> u32 { 1400 }

/// Default broadcast address for UDP transmission.
fn default_broadcast_addr() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

/// Default number of data shards per FEC encoding block.
///
/// Must be > parity_shards (RS codec constraint: parity < data).
/// Using 16 matches FecConfig::standard().
fn default_fec_data_shards() -> usize { 16 }

/// Configuration parameters for [`BlindSendDriver`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSendConfig {
    /// UDP port for broadcast transmission and reception.
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,

    /// Redundancy factor controlling FEC parity ratio (1.5..=3.0).
    #[serde(default = "default_redundancy_factor")]
    pub redundancy_factor: f32,

    /// Maximum payload size per packet in bytes (64..=65507).
    #[serde(default = "default_packet_size")]
    pub packet_size: u32,

    /// Target broadcast address for UDP datagrams.
    #[serde(default = "default_broadcast_addr")]
    pub broadcast_addr: IpAddr,

    /// Number of data shards per FEC block (2..=128).
    #[serde(default = "default_fec_data_shards")]
    pub fec_data_shards: usize,
}

impl Default for BlindSendConfig {
    fn default() -> Self {
        Self {
            udp_port: default_udp_port(),
            redundancy_factor: default_redundancy_factor(),
            packet_size: default_packet_size(),
            broadcast_addr: default_broadcast_addr(),
            fec_data_shards: default_fec_data_shards(),
        }
    }
}

impl TransferDriverConfig for BlindSendConfig {
    fn validate(&self) -> Result<()> {
        if self.udp_port == 0 {
            return Err(MisogiError::Configuration(
                "udp_port must be in range 1..=65535".into(),
            ));
        }
        if !(1.5..=3.0).contains(&self.redundancy_factor) {
            return Err(MisogiError::Configuration(format!(
                "redundancy_factor must be in [1.5, 3.0], got {}",
                self.redundancy_factor,
            )));
        }
        if !(64..=65507).contains(&self.packet_size) {
            return Err(MisogiError::Configuration(format!(
                "packet_size must be in [64, 65507], got {}",
                self.packet_size,
            )));
        }
        if !(2..=128).contains(&self.fec_data_shards) {
            return Err(MisogiError::Configuration(format!(
                "fec_data_shards must be in [2, 128], got {}",
                self.fec_data_shards,
            )));
        }
        Ok(())
    }
}

impl BlindSendConfig {
    /// Compute parity shard count from the configured redundancy factor.
    ///
    /// Capped at `data_shards - 1` to enforce RS constraint `parity < data`.
    pub fn compute_parity_shards(&self) -> usize {
        let raw = ((self.fec_data_shards as f32) * (self.redundancy_factor - 1.0)).ceil() as usize;
        raw.min(self.fec_data_shards.saturating_sub(1))
    }

    /// Build a [`FecConfig`] from this blind send configuration.
    pub fn to_fec_config(&self) -> FecConfig {
        FecConfig {
            data_shards: self.fec_data_shards,
            parity_shards: self.compute_parity_shards(),
            shard_size: self.packet_size as usize,
        }
    }
}

// =============================================================================
// BlindSendDriver — TransferDriver Implementation
// =============================================================================

/// Mode C transport driver: pure fire-and-forget UDP broadcast with FEC protection.
///
/// # Safety Contract
///
/// - **No Confidentiality**: UDP broadcast is plaintext. Encrypt at application layer.
/// - **No Authentication**: Any host on subnet can receive packets. Use isolated networks.
/// - **No Delivery Guarantee**: Extreme loss (> parity ratio) causes permanent data loss.
#[derive(Debug)]
pub struct BlindSendDriver {
    config: BlindSendConfig,
    socket: Option<UdpSocket>,
    encoder: Option<BlindSendEncoder>,
    pending_chunks: Arc<RwLock<HashMap<String, Vec<(u32, Bytes)>>>>,
    initialized: Arc<AtomicBool>,
}

impl BlindSendDriver {
    pub fn new(config: BlindSendConfig) -> Self {
        Self {
            config,
            socket: None,
            encoder: None,
            pending_chunks: Arc::new(RwLock::new(HashMap::new())),
            initialized: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl TransferDriver for BlindSendDriver {
    type Config = BlindSendConfig;

    fn name(&self) -> &str {
        "blind-send-driver"
    }

    async fn init(&mut self, config: Self::Config) -> Result<()> {
        config.validate()?;
        self.config = config;

        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to bind UDP socket: {}", e),
            ))
        })?;

        socket.set_broadcast(true).map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to enable broadcast: {}", e),
            ))
        })?;

        let fec_config = self.config.to_fec_config();
        let encoder = BlindSendEncoder::new(&fec_config)?;

        self.socket = Some(socket);
        self.encoder = Some(encoder);
        self.initialized.store(true, Ordering::SeqCst);

        tracing::info!(
            driver = self.name(),
            port = self.config.udp_port,
            broadcast_addr = %self.config.broadcast_addr,
            redundancy = self.config.redundancy_factor,
            data_shards = self.config.fec_data_shards,
            parity_shards = self.config.compute_parity_shards(),
            packet_size = self.config.packet_size,
            "BlindSendDriver initialized (Mode C: UDP Broadcast + FEC)"
        );

        Ok(())
    }

    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "BlindSendDriver not initialized".to_string(),
            ));
        }

        let md5 = format!("{:x}", md5::Md5::digest(&data));
        let data_len = data.len();

        {
            let mut chunks = self.pending_chunks.write().await;
            chunks.entry(file_id.to_string())
                .or_default()
                .push((chunk_index, data));
        }

        tracing::debug!(
            file_id = %file_id,
            chunk_index = chunk_index,
            size = data_len,
            md5 = %md5,
            "Chunk buffered for blind send (fire-and-forget)"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5: md5,
            received_size: data_len as u64,
            ack_timestamp: Utc::now().to_rfc3339(),
            error: None,
        })
    }

    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        _file_md5: &str,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "BlindSendDriver not initialized".to_string(),
            ));
        }

        let socket = self.socket.as_ref().ok_or_else(|| {
            MisogiError::Protocol("UDP socket not initialized".to_string())
        })?;

        let encoder = self.encoder.as_ref().ok_or_else(|| {
            MisogiError::Protocol("FEC encoder not initialized".to_string())
        })?;

        let chunks = {
            let chunks_map = self.pending_chunks.read().await;
            chunks_map.get(file_id).cloned()
        }.ok_or_else(|| {
            MisogiError::Protocol(format!("No buffered chunks for file_id '{}'", file_id))
        })?;

        let mut sorted = chunks.clone();
        sorted.sort_by_key(|(idx, _)| *idx);

        let mut file_data = Vec::new();
        for (_, data) in &sorted {
            file_data.extend_from_slice(data);
        }

        if file_data.is_empty() {
            return Err(MisogiError::Protocol(
                "Cannot send empty file data".into(),
            ));
        }

        let packets = encoder.encode(&file_data)?;

        let target = std::net::SocketAddr::new(self.config.broadcast_addr, self.config.udp_port);
        let mut sent_count: u64 = 0;
        let mut total_bytes: u64 = 0;

        for pkt in &packets {
            let wire = pkt.to_bytes();
            match socket.send_to(&wire, target).await {
                Ok(_) => {
                    sent_count += 1;
                    total_bytes += wire.len() as u64;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        seq = pkt.sequence,
                        shard_idx = pkt.shard_index,
                        "UDP broadcast send failed (packet may be lost)"
                    );
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_micros(200)).await;
        }

        tracing::info!(
            file_id = %file_id,
            total_chunks = total_chunks,
            packets_sent = sent_count,
            bytes_sent = total_bytes,
            data_shards = encoder.data_shards(),
            target = %target,
            "BlindSend transmission complete (fire-and-forget, delivery unverified)"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index: total_chunks,
            received_md5: format!("{:x}", md5::Md5::digest(&file_data)),
            received_size: file_data.len() as u64,
            ack_timestamp: Utc::now().to_rfc3339(),
            error: None,
        })
    }

    async fn health_check(&self) -> Result<DriverHealthStatus> {
        let is_init = self.initialized.load(Ordering::SeqCst);
        let socket_ok = self.socket.is_some();
        let encoder_ok = self.encoder.is_some();

        let is_healthy = is_init && socket_ok && encoder_ok;
        let status_message = if is_healthy {
            String::from("Operational -- ready for fire-and-forget transmission")
        } else {
            format!(
                "Not ready: initialized={}, socket={}, encoder={}",
                is_init, socket_ok, encoder_ok,
            )
        };

        Ok(DriverHealthStatus {
            driver_name: self.name().to_string(),
            is_healthy,
            status_message,
            latency_ms: None,
            checked_at: Utc::now(),
            check_sequence: 1,
        })
    }

    async fn shutdown(&self) -> Result<()> {
        self.initialized.store(false, Ordering::SeqCst);
        tracing::info!(driver = self.name(), "BlindSendDriver shut down");
        Ok(())
    }
}
