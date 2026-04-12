//! UDP Blast sender — fires file chunks through a unidirectional data diode.
//!
//! The sender has **NO knowledge** of whether packets arrive. It simply:
//!
//! 1. Reads the file from disk
//! 2. Encodes it into FEC shards (data + parity)
//! 3. Interleaves shards to disperse burst losses
//! 4. Fires each shard as an independent UDP datagram
//! 5. Sends manifest + EOF marker (multiple times for redundancy)
//! 6. Done. No waiting. No ACK. No retry loop.
//!
//! # Transmission Strategy
//!
//! To maximize delivery probability without feedback:
//! - Each shard is sent `repeat_count` times (default: 3) with random jitter
//! - Manifest is sent `manifest_repeats` times (default: 5) at end
//! - EOF marker is sent `eof_repeats` times (default: 5)
//! - Send interval is configurable (default: 1ms between packets)
//!
//! This "spray and pray" approach combined with FEC guarantees that
//! the receiver can reconstruct the file even with significant packet loss.

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use md5::Digest;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::error::{MisogiError, Result};
use crate::fec::{
    FecConfig,
    reed_solomon::ReedSolomonCodec,
    interleaver::Interleaver,
};
use super::frame::{
    BlastPacket, BlastManifest, FecConfigInfo,
};

/// Default number of times each shard is repeated.
fn default_repeat_count() -> u32 { 3 }

/// Microseconds between repeated transmissions of the same shard.
fn default_repeat_interval_us() -> u64 { 1000 }

/// Number of times the manifest packet is sent (redundancy).
fn default_manifest_repeats() -> u32 { 5 }

/// Maximum datagram payload size in bytes.
///
/// Must fit within path MTU after accounting for IP+UDP headers (28 bytes)
/// and Blast header+trailer (59 bytes). For standard Ethernet MTU (1500),
/// use ≤ 1413 bytes. Default 1400 provides safety margin.
fn default_max_datagram_size() -> usize { 1400 }

/// Whether adaptive rate control is enabled.
fn default_adaptive_rate() -> bool { true }

/// Number of times EOF marker is repeated.
fn default_eof_repeats() -> u32 { 5 }

/// Configuration parameters for the [`UdpBlastSender`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastSenderConfig {
    /// How many times to repeat each shard transmission.
    ///
    /// Higher values increase delivery probability but multiply bandwidth usage.
    /// Recommended: 3 for typical optical diode environments, 5 for noisy links.
    #[serde(default = "default_repeat_count")]
    pub repeat_count: u32,

    /// Microseconds between repeated transmissions of the same shard.
    ///
    /// Small random jitter is added on top of this base interval to prevent
    /// periodic interference patterns with other network traffic.
    #[serde(default = "default_repeat_interval_us")]
    pub repeat_interval_us: u64,

    /// How many times to send the manifest packet (for redundancy).
    ///
    /// The manifest carries file metadata needed by the receiver to validate
    /// reconstruction. Losing it means the receiver cannot verify MD5.
    #[serde(default = "default_manifest_repeats")]
    pub manifest_repeats: u32,

    /// Maximum datagram payload size in bytes (must fit within path MTU).
    ///
    /// See [`default_max_datagram_size`] for MTU considerations.
    #[serde(default = "default_max_datagram_size")]
    pub max_datagram_size: usize,

    /// Enable adaptive send rate based on estimated link capacity.
    ///
    /// When enabled, the sender monitors socket send errors and backs off
    /// if the OS reports buffer overflows (ENOBUFS).
    #[serde(default = "default_adaptive_rate")]
    pub adaptive_rate: bool,

    /// Number of times to send the EOF end-of-transmission marker.
    #[serde(default = "default_eof_repeats")]
    pub eof_repeats: u32,
}

impl Default for BlastSenderConfig {
    fn default() -> Self {
        Self {
            repeat_count: default_repeat_count(),
            repeat_interval_us: default_repeat_interval_us(),
            manifest_repeats: default_manifest_repeats(),
            max_datagram_size: default_max_datagram_size(),
            adaptive_rate: default_adaptive_rate(),
            eof_repeats: default_eof_repeats(),
        }
    }
}

/// Statistical report returned after a completed blast operation.
///
/// Note: This report reflects what was **sent**, not what was **received**.
/// The sender has no way to confirm delivery over a data diode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastSendReport {
    /// Unique session identifier for this transfer.
    pub session_id: String,

    /// File identifier within the session.
    pub file_id: String,

    /// Original filename (basename only).
    pub filename: String,

    /// Original file size in bytes.
    pub original_size: u64,

    /// Total number of individual shard transmissions sent
    /// (including repeats; i.e., unique_shards × repeat_count).
    pub total_shards_sent: u64,

    /// Number of data shards encoded.
    pub data_shards: u64,

    /// Number of parity (redundancy) shards encoded.
    pub parity_shards: u64,

    /// Total UDP datagrams transmitted (shards + manifests + EOF markers).
    pub total_datagrams: u64,

    /// Total bytes written to the UDP socket (wire-level, including headers).
    pub total_bytes_sent: u64,

    /// Wall-clock time spent encoding (FEC + interleave), in milliseconds.
    pub encode_time_ms: u64,

    /// Wall-clock time spent transmitting all datagrams, in milliseconds.
    pub transmit_time_ms: u64,

    /// FEC configuration used for this transfer.
    pub fec_config: FecConfigInfo,
}

/// UDP Blast sender for air-gap / data-diode file transfer.
///
/// Encodes files into FEC-protected shards and fires them through a
/// unidirectional UDP socket toward a physical data diode receiver.
///
/// # Thread Safety
///
/// This struct is **not** thread-safe for concurrent `blast_file()` calls.
/// Use `Arc<Mutex<UdpBlastSender>>` if concurrent access is needed.
///
/// # Lifecycle
///
/// ```text
/// new() → blast_file() → [BlastSendReport]
///                    ↑ can be called multiple times
/// ```
pub struct UdpBlastSender {
    /// Target address of the receiver's data diode input port.
    target_addr: std::net::SocketAddr,

    /// Bound UDP socket for sending datagrams.
    socket: UdpSocket,

    /// Reed-Solomon codec for FEC encode/decode.
    fec_codec: ReedSolomonCodec,

    /// Interleave width for burst-loss dispersal.
    interleave_width: usize,

    /// Sender configuration controlling repeat behavior and sizing.
    config: BlastSenderConfig,
}

impl UdpBlastSender {
    /// Create a new sender bound to the local interface, targeting the given address.
    ///
    /// # Arguments
    /// * `target` - Receiver's address (e.g., "192.168.254.2:9002").
    /// * `config` - Transmission parameters (or use [`BlastSenderConfig::default()]`).
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if UDP socket binding fails.
    /// - [`MisogiError::Configuration`] if FEC config is invalid.
    pub async fn new(target: &str, config: BlastSenderConfig) -> Result<Self> {
        let target_addr: std::net::SocketAddr = target
            .parse()
            .map_err(|e| MisogiError::Configuration(format!("Invalid target address '{}': {}", target, e)))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to bind UDP socket: {}", e),
            ))
        })?;

        let fec_config = FecConfig {
            data_shards: 16,
            parity_shards: 4,
            shard_size: config.max_datagram_size,
        };
        let fec_codec = ReedSolomonCodec::with_config(fec_config)?;

        Ok(Self {
            target_addr,
            socket,
            fec_codec,
            interleave_width: 4,
            config,
        })
    }

    /// Create sender with custom FEC configuration.
    pub async fn with_fec_config(
        target: &str,
        config: BlastSenderConfig,
        fec_config: FecConfig,
    ) -> Result<Self> {
        let target_addr: std::net::SocketAddr = target.parse().map_err(|e| {
            MisogiError::Configuration(format!("Invalid target address '{}': {}", target, e))
        })?;

        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to bind UDP socket: {}", e),
            ))
        })?;

        let fec_codec = ReedSolomonCodec::with_config(fec_config.clone())?;

        Ok(Self {
            target_addr,
            socket,
            fec_codec,
            interleave_width: 4,
            config,
        })
    }

    /// Blast a complete file through the data diode.
    ///
    /// This is the primary API — reads, encodes, interleaves, and transmits everything.
    ///
    /// # Pipeline
    ///
    /// ```text
    /// File → Read bytes → FEC Encode → Interleave reorder → UDP send (×N) → Manifest (×M) → EOF (×K)
    /// ```
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to transfer.
    /// * `file_id` - Optional file identifier (auto-generated if empty).
    ///
    /// # Returns
    ///
    /// A [`BlastSendReport`] with statistics about what was sent.
    /// **Note:** Success does NOT guarantee the receiver got the data.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if file read fails.
    /// - [`MisogiError::Protocol`] if FEC encoding fails.
    pub async fn blast_file(&self, file_path: &Path, file_id: Option<&str>) -> Result<BlastSendReport> {
        let session_id = Uuid::new_v4().to_string();
        let fid = file_id.unwrap_or(&Uuid::new_v4().to_string()).to_string();
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Phase 1: Read file
        let start_encode = Instant::now();
        let file_data = tokio::fs::read(file_path).await.map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read file {}: {}", file_path.display(), e),
            ))
        })?;
        let original_size = file_data.len() as u64;
        let original_md5 = format!("{:x}", md5::Md5::digest(&file_data));

        // Phase 2: FEC encode
        let block = self.fec_codec.encode(&file_data)?;
        let total_unique_shards = block.total_shards() as u64;
        let data_shard_count = block.data_shards.len() as u64;
        let parity_shard_count = block.parity_shards.len() as u64;

        let encode_elapsed = start_encode.elapsed();

        // Phase 3: Interleave + Transmit
        let start_transmit = Instant::now();
        let interleaver = Interleaver::with_width(total_unique_shards as usize, self.interleave_width);
        let transmit_order = interleaver.compute_transmit_order();

        let mut total_sent: u64 = 0;
        let mut total_bytes: u64 = 0;

        for &logical_idx in &transmit_order {
            let is_parity = logical_idx >= block.data_shards.len();
            let shard_data = block.get_shard(logical_idx).unwrap_or(&[]);

            let pkt = if is_parity {
                let pidx = logical_idx - block.data_shards.len();
                BlastPacket::parity_shard(
                    &session_id, &fid,
                    pidx as u32,
                    total_unique_shards as u32,
                    shard_data,
                )
            } else {
                BlastPacket::data_shard(
                    &session_id, &fid,
                    logical_idx as u32,
                    total_unique_shards as u32,
                    shard_data,
                )
            };

            let wire_bytes = pkt.wire_size() as u64;

            // Repeat each shard `repeat_count` times
            for _repeat in 0..self.config.repeat_count {
                let encoded = pkt.encode();
                match self.socket.send_to(&encoded, self.target_addr).await {
                    Ok(_) => {
                        total_sent += 1;
                        total_bytes += wire_bytes;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            shard_index = logical_idx,
                            repeat = _repeat,
                            "UDP send failed (packet may be lost)"
                        );
                        if self.config.adaptive_rate {
                            tokio::time::sleep(tokio::time::Duration::from_micros(
                                self.config.repeat_interval_us * 2,
                            )).await;
                        }
                    }
                }

                if _repeat > 0 && self.config.repeat_interval_us > 0 {
                    let jitter = rand::random::<u64>() % 500;
                    tokio::time::sleep(tokio::time::Duration::from_micros(
                        self.config.repeat_interval_us + jitter,
                    )).await;
                }
            }

            // Small gap between different shards
            if self.config.repeat_interval_us > 0 {
                tokio::time::sleep(tokio::time::Duration::from_micros(200)).await;
            }
        }

        // Phase 4: Send manifest (repeated for redundancy)
        let manifest = BlastManifest {
            filename: filename.clone(),
            original_size,
            original_md5: original_md5.clone(),
            fec_config: FecConfigInfo::from(self.fec_codec.config()),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        for _ in 0..self.config.manifest_repeats {
            if let Ok(manifest_pkt) = BlastPacket::manifest(&session_id, &fid, &manifest) {
                let encoded = manifest_pkt.encode();
                if self.socket.send_to(&encoded, self.target_addr).await.is_ok() {
                    total_sent += 1;
                    total_bytes += manifest_pkt.wire_size() as u64;
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }

        // Phase 5: Send EOF markers (repeated)
        for _ in 0..self.config.eof_repeats {
            let eof_pkt = BlastPacket::eof_marker(&session_id);
            let encoded = eof_pkt.encode();
            if self.socket.send_to(&encoded, self.target_addr).await.is_ok() {
                total_sent += 1;
                total_bytes += eof_pkt.wire_size() as u64;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        }

        let transmit_elapsed = start_transmit.elapsed();

        tracing::info!(
            session_id = %session_id,
            file_id = %fid,
            filename = %filename,
            original_size = original_size,
            total_shards = total_unique_shards,
            datagrams_sent = total_sent,
            bytes_sent = total_bytes,
            encode_ms = encode_elapsed.as_millis() as u64,
            transmit_ms = transmit_elapsed.as_millis() as u64,
            "UDP Blast transmission complete"
        );

        Ok(BlastSendReport {
            session_id,
            file_id: fid,
            filename,
            original_size,
            total_shards_sent: total_sent,
            data_shards: data_shard_count,
            parity_shards: parity_shard_count,
            total_datagrams: total_sent,
            total_bytes_sent: total_bytes,
            encode_time_ms: encode_elapsed.as_millis() as u64,
            transmit_time_ms: transmit_elapsed.as_millis() as u64,
            fec_config: FecConfigInfo::from(self.fec_codec.config()),
        })
    }

    /// Returns a reference to the current configuration.
    pub fn config(&self) -> &BlastSenderConfig {
        &self.config
    }

    /// Returns the target address this sender fires packets toward.
    pub fn target_addr(&self) -> std::net::SocketAddr {
        self.target_addr
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sender_creation() {
        let config = BlastSenderConfig::default();
        let sender = UdpBlastSender::new("127.0.0.1:0", config).await;
        assert!(sender.is_ok());
        let s = sender.unwrap();
        assert_eq!(s.config().repeat_count, 3);
    }

    #[tokio::test]
    async fn test_blast_small_file() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let file_path = tmp_dir.path().join("test_blast.bin");
        let test_data: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        tokio::fs::write(&file_path, &test_data).await.expect("Failed to write test file");

        let config = BlastSenderConfig {
            repeat_count: 1,
            ..Default::default()
        };

        let sender = UdpBlastSender::new("127.0.0.1:0", config).await.expect("Sender creation");
        let report = sender.blast_file(&file_path, None).await.expect("Blast should succeed");

        assert_eq!(report.original_size, 1000);
        assert!(report.total_datagrams > 0);
        assert!(report.data_shards > 0);
        assert!(report.parity_shards > 0);
        assert!(!report.session_id.is_empty());
        assert!(!report.file_id.is_empty());
    }

    #[test]
    fn test_default_config_values() {
        let cfg = BlastSenderConfig::default();
        assert_eq!(cfg.repeat_count, 3);
        assert_eq!(cfg.manifest_repeats, 5);
        assert_eq!(cfg.max_datagram_size, 1400);
        assert!(cfg.adaptive_rate);
        assert_eq!(cfg.eof_repeats, 5);
    }

    #[test]
    fn test_send_report_serialization() {
        let report = BlastSendReport {
            session_id: "sess-1".to_string(),
            file_id: "file-1".to_string(),
            filename: "test.txt".to_string(),
            original_size: 1024,
            total_shards_sent: 60,
            data_shards: 48,
            parity_shards: 12,
            total_datagrams: 70,
            total_bytes_sent: 98000,
            encode_time_ms: 15,
            transmit_time_ms: 200,
            fec_config: FecConfigInfo {
                data_shards: 16,
                parity_shards: 4,
                shard_size: 1400,
            },
        };

        let json = serde_json::to_string(&report).expect("Serialization");
        let decoded: BlastSendReport = serde_json::from_str(&json).expect("Deserialization");
        assert_eq!(decoded.session_id, "sess-1");
        assert_eq!(decoded.original_size, 1024);
        assert_eq!(decoded.fec_config.parity_shards, 4);
    }

    #[tokio::test]
    async fn test_invalid_target_address_rejected() {
        let config = BlastSenderConfig::default();
        let result = UdpBlastSender::new("not-a-valid-address", config).await;
        assert!(result.is_err());
    }
}
