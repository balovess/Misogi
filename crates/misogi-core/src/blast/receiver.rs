//! UDP Blast receiver — passively collects shards from unidirectional data diode.
//!
//! The receiver has **NO way** to request retransmission. It must work with
//! whatever packets arrive through the physical data diode:
//!
//! 1. Bind to UDP port and listen passively (no handshake)
//! 2. Collect incoming datagrams into per-session shard buffers
//! 3. Track which shard indices have been received
//! 4. When enough shards arrive OR timeout expires, attempt FEC decode
//! 5. Verify MD5 hash against manifest
//! 6. Output reconstructed file
//!
//! # Collection Strategy
//!
//! The receiver maintains a [`SessionState`] for each active transfer session:
//!
//! - `received_shards: HashMap<shard_index, Vec<u8>>` — collected data
//! - `expected_total: Option<u32>` — known from first packet or manifest
//! - `manifest: Option<BlastManifest>` — metadata (may arrive late or not at all)
//! - `start_time: Instant` — session start for timeout calculation
//!
//! Decode is attempted when:
//! - All data shards collected (ideal case)
//! - Timeout reached with sufficient shards for FEC recovery
//! - Manifest arrives with explicit signal to finalize

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use uuid::Uuid;

use md5::Digest;
use crate::error::{MisogiError, Result};
use crate::fec::{
    FecConfig,
    reed_solomon::ReedSolomonCodec,
};
use super::frame::{BlastPacket, BlastManifest};

/// Default UDP port for incoming blast traffic.
fn default_blast_port() -> u16 { 9002 }

/// Maximum seconds to wait for shards before attempting decode.
fn default_session_timeout_secs() -> u64 { 300 }

/// Minimum unique shard count before attempting early decode.
fn default_min_shards_for_decode() -> usize { 16 }

/// Default output directory for reconstructed files.
fn default_output_dir() -> PathBuf {
    PathBuf::from("./blast_received")
}

/// Whether to auto-clean incomplete sessions after timeout.
fn default_auto_cleanup() -> bool { true }

/// Configuration parameters for the [`UdpBlastReceiver`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastReceiverConfig {
    /// UDP port to bind for incoming blast traffic.
    #[serde(default = "default_blast_port")]
    pub listen_port: u16,

    /// Maximum time (seconds) to wait for shards before attempting decode.
    ///
    /// After this timeout, the receiver will attempt FEC reconstruction
    /// with whatever shards have arrived, even if incomplete.
    #[serde(default = "default_session_timeout_secs")]
    pub session_timeout_secs: u64,

    /// Minimum number of unique shard indices before attempting early decode.
    ///
    /// Setting this too low may cause premature decode attempts that fail.
    /// Should typically be >= data_shards count of expected FEC config.
    #[serde(default = "default_min_shards_for_decode")]
    pub min_shards_for_decode: usize,

    /// Directory to write reconstructed files to.
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,

    /// Whether to delete incomplete sessions after timeout expiration.
    #[serde(default = "default_auto_cleanup")]
    pub auto_cleanup: bool,
}

impl Default for BlastReceiverConfig {
    fn default() -> Self {
        Self {
            listen_port: default_blast_port(),
            session_timeout_secs: default_session_timeout_secs(),
            min_shards_for_decode: default_min_shards_for_decode(),
            output_dir: default_output_dir(),
            auto_cleanup: default_auto_cleanup(),
        }
    }
}

/// Statistical report returned after a completed receive + decode operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastReceiveReport {
    /// Session identifier of the received transfer.
    pub session_id: String,

    /// File identifier within the session.
    pub file_id: String,

    /// Whether the file was successfully reconstructed.
    pub success: bool,

    /// Original file size (from manifest).
    pub original_size: u64,

    /// Size of the recovered (decoded) file.
    pub recovered_size: u64,

    /// Number of unique shards collected before decoding.
    pub shards_received: u64,

    /// Total number of shards expected (from header/manifest).
    pub shards_expected: u64,

    /// Total UDP packets received (including duplicates).
    pub packets_received: u64,

    /// Estimated number of lost packets (based on gaps in shard indices).
    pub packets_lost_estimate: f64,

    /// Actual loss rate observed (lost / expected).
    pub loss_rate: f64,

    /// Time spent on FEC decoding (milliseconds).
    pub decode_time_ms: u64,

    /// Total wall-clock time from first packet to completion (milliseconds).
    pub total_session_time_ms: u64,

    /// Path where the reconstructed file was written (if successful).
    pub output_path: Option<PathBuf>,

    /// Whether the decoded file's MD5 matches the manifest.
    pub md5_match: bool,
}

/// Per-session state tracking received shards and metadata.
struct SessionState {
    /// Unique session identifier.
    session_id: String,

    /// File identifier within this session.
    file_id: String,

    /// Collected shard data indexed by logical shard index.
    received_shards: HashMap<u32, Vec<u8>>,

    /// Total expected shards (learned from first packet header).
    expected_total: Option<u32>,

    /// File manifest (arrives after all shards).
    manifest: Option<BlastManifest>,

    /// Timestamp when first packet for this session arrived.
    start_time: Instant,

    /// Running byte counter for all received payload data.
    total_bytes_received: u64,

    /// Running packet counter (including duplicate receptions).
    total_packets_received: u64,

    /// EOF marker has been seen at least once.
    eof_seen: bool,
}

impl SessionState {
    fn new(session_id: &str, file_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            file_id: file_id.to_string(),
            received_shards: HashMap::new(),
            expected_total: None,
            manifest: None,
            start_time: Instant::now(),
            total_bytes_received: 0,
            total_packets_received: 0,
            eof_seen: false,
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    fn unique_shard_count(&self) -> usize {
        self.received_shards.len()
    }
}

/// UDP Blast receiver for passive collection over unidirectional links.
///
/// Binds to a local UDP port and collects incoming [`BlastPacket`] datagrams
/// into per-session buffers. When enough shards arrive, triggers FEC decoding
/// and writes the reconstructed file to disk.
///
/// # Concurrency Model
///
/// The main `run()` loop receives datagrams synchronously on a single
/// task. Decode attempts are spawned as background tasks so they don't
/// block reception of subsequent packets.
///
/// # Thread Safety
///
/// Internal state (`sessions`) is protected by `Arc<RwLock<>>` for safe
/// concurrent access from the receive loop and decode tasks.
pub struct UdpBlastReceiver {
    /// Local address bound for incoming traffic.
    bind_addr: std::net::SocketAddr,

    /// Bound UDP socket.
    socket: UdpSocket,

    /// Reed-Solomon codec for FEC decoding.
    fec_codec: ReedSolomonCodec,

    /// Active transfer sessions keyed by session_id.
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,

    /// Receiver configuration.
    config: BlastReceiverConfig,
}

impl UdpBlastReceiver {
    /// Create receiver bound to the given address.
    ///
    /// # Arguments
    /// * `bind_addr` - Local address to bind (e.g., "0.0.0.0:9002").
    /// * `config` - Receiver parameters.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if socket binding fails.
    pub async fn new(bind_addr: &str, config: BlastReceiverConfig) -> Result<Self> {
        let addr: std::net::SocketAddr = bind_addr.parse().map_err(|e| {
            MisogiError::Configuration(format!("Invalid bind address '{}': {}", bind_addr, e))
        })?;

        let socket = UdpSocket::bind(&addr).await.map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to bind UDP socket to {}: {}", bind_addr, e),
            ))
        })?;

        let fec_codec = ReedSolomonCodec::new()?;

        Ok(Self {
            bind_addr: addr,
            socket,
            fec_codec,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Start the listening loop. Runs indefinitely processing incoming datagrams.
    ///
    /// Each datagram is parsed, classified by session, and stored.
    /// Decode attempts run asynchronously when conditions are met.
    ///
    /// # Returns
    ///
    /// This method runs indefinitely under normal operation.
    /// It only returns on fatal errors.
    pub async fn run(&self) -> Result<()> {
        tracing::info!(
            addr = %self.bind_addr,
            port = self.config.listen_port,
            output_dir = %self.config.output_dir.display(),
            timeout_secs = self.config.session_timeout_secs,
            "UdpBlastReceiver listening"
        );

        let mut buf = vec![0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, source)) => {
                    let data = buf[..len].to_vec();
                    if let Err(e) = self.handle_datagram(&data, source).await {
                        tracing::warn!(error = %e, source = %source, "Failed to handle datagram");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "UDP recv error");
                }
            }
        }
    }

    /// Process a single received datagram.
    async fn handle_datagram(&self, data: &[u8], source: std::net::SocketAddr) -> Result<()> {
        let pkt = match BlastPacket::decode(data) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, source = %source, "Dropping invalid Blast packet");
                return Ok(());
            }
        };

        let session_id = uuid_from_bytes(&pkt.header.session_id);
        let file_id = uuid_from_bytes(&pkt.header.file_id);

        let mut sessions = self.sessions.write().await;

        let session = sessions
            .entry(session_id.clone())
            .or_insert_with(|| SessionState::new(&session_id, &file_id));

        session.total_packets_received += 1;

        if pkt.is_eof() {
            session.eof_seen = true;
            tracing::debug!(session_id = %session_id, "EOF marker received");
        }

        if pkt.is_manifest() {
            if let Ok(manifest) = serde_json::from_slice::<BlastManifest>(&pkt.payload) {
                session.manifest = Some(manifest);
                tracing::debug!(
                    session_id = %session_id,
                    filename = session.manifest.as_ref().map(|m| m.filename.as_str()).unwrap_or("?"),
                    "Manifest received"
                );
            }
        }

        if !pkt.is_manifest() && !pkt.is_eof() && !pkt.payload.is_empty() {
            let idx = pkt.header.shard_index;
            session.total_bytes_received += pkt.payload.len() as u64;

            if !session.received_shards.contains_key(&idx) {
                session.received_shards.insert(idx, pkt.payload);
            }

            let total = pkt.header.total_shards;
            if total > 0 {
                session.expected_total = Some(total);
            }
        }

        drop(sessions);

        let should_attempt_decode = {
            let sessions = self.sessions.read().await;
            if let Some(sess) = sessions.get(&session_id) {
                sess.unique_shard_count() >= self.config.min_shards_for_decode
                    || sess.eof_seen
                    || sess.elapsed_ms() >= self.config.session_timeout_secs * 1000
            } else {
                false
            }
        };

        if should_attempt_decode {
            let sessions_arc = Arc::clone(&self.sessions);
            let fec_config = self.fec_codec.config().clone();
            let output_dir = self.config.output_dir.clone();
            let sid = session_id.clone();

            tokio::spawn(async move {
                let _ = try_decode_session(
                    &sessions_arc, &sid, &fec_config, &output_dir,
                ).await;
            });
        }

        Ok(())
    }

    /// Attempt FEC decode for a specific session with currently available shards.
    ///
    /// # Returns
    ///
    /// `Some(reconstructed_data)` if decoding succeeded, `None` if not yet possible.
    pub async fn try_decode(&self, session_id: &str) -> Result<Option<Vec<u8>>> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id).ok_or_else(|| {
            MisogiError::Protocol(format!("Session '{}' not found", session_id))
        })?;

        if session.unique_shard_count() < self.fec_codec.config().data_shards {
            return Ok(None);
        }

        let received: Vec<(usize, Vec<u8>)> = session
            .received_shards
            .iter()
            .map(|(&idx, data)| (idx as usize, data.clone()))
            .collect();

        let original_len = session
            .manifest
            .as_ref()
            .map(|m| m.original_size as usize)
            .unwrap_or(0);

        drop(sessions);

        match self.fec_codec.decode(&received, original_len) {
            Ok(data) => Ok(Some(data)),
            Err(_) => Ok(None),
        }
    }

    /// Get current session count.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

async fn try_decode_session(
    sessions: &Arc<RwLock<HashMap<String, SessionState>>>,
    session_id: &str,
    fec_config: &FecConfig,
    output_dir: &PathBuf,
) -> Result<BlastReceiveReport> {
    let (shards, _expected, manifest_opt, stats) = {
        let mut sessions = sessions.write().await;
        if let Some(sess) = sessions.get_mut(session_id) {
            let shards: Vec<(usize, Vec<u8>)> = sess
                .received_shards
                .iter()
                .map(|(&idx, data)| (idx as usize, data.clone()))
                .collect();
            let expected = sess.expected_total.unwrap_or(0) as u64;
            let manifest = sess.manifest.take();
            let stats = (
                sess.session_id.clone(),
                sess.file_id.clone(),
                sess.unique_shard_count() as u64,
                expected,
                sess.total_packets_received,
                sess.elapsed_ms(),
            );
            (shards, expected, manifest, stats)
        } else {
            return Err(MisogiError::Protocol("Session disappeared during decode".to_string()));
        }
    };

    let (sid, fid, shards_recv, shards_exp, pkts_recv, elapsed_ms) = stats;

    let codec = ReedSolomonCodec::with_config(fec_config.clone())?;
    let orig_len = manifest_opt.as_ref().map(|m| m.original_size as usize).unwrap_or(0);

    let decode_start = Instant::now();
    let result = codec.decode(&shards, orig_len);
    let decode_ms = decode_start.elapsed().as_millis() as u64;

    match result {
        Ok(decoded_data) => {
            let recovered_md5 = format!("{:x}", md5::Md5::digest(&decoded_data));
            let md5_matches = manifest_opt
                .as_ref()
                .map(|m| m.original_md5 == recovered_md5)
                .unwrap_or(false);

            let filename = manifest_opt
                .as_ref()
                .map(|m| m.filename.clone())
                .unwrap_or_else(|| format!("unknown_{}.bin", &sid[..8]));

            tokio::fs::create_dir_all(output_dir).await.ok();
            let out_path = output_dir.join(&filename);
            tokio::fs::write(&out_path, &decoded_data).await.ok();

            let lost_estimate = shards_exp.saturating_sub(shards_recv);
            let loss_rate = if shards_exp > 0 {
                lost_estimate as f64 / shards_exp as f64
            } else {
                0.0
            };

            let report = BlastReceiveReport {
                session_id: sid,
                file_id: fid,
                success: true,
                original_size: manifest_opt.as_ref().map(|m| m.original_size).unwrap_or(0),
                recovered_size: decoded_data.len() as u64,
                shards_received: shards_recv,
                shards_expected: shards_exp,
                packets_received: pkts_recv,
                packets_lost_estimate: lost_estimate as f64,
                loss_rate,
                decode_time_ms: decode_ms,
                total_session_time_ms: elapsed_ms,
                output_path: Some(out_path),
                md5_match: md5_matches,
            };

            tracing::info!(
                session_id = %report.session_id,
                success = report.success,
                shards_received = report.shards_received,
                loss_rate = report.loss_rate,
                md5_match = report.md5_match,
                output_path = ?report.output_path,
                "File successfully reconstructed via FEC"
            );

            if let Ok(mut sessions) = sessions.try_write() {
                sessions.remove(session_id);
            }

            Ok(report)
        }
        Err(e) => {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                shards_collected = shards_recv,
                "FEC decode failed — waiting for more shards"
            );

            let lost_estimate = shards_exp.saturating_sub(shards_recv);
            Ok(BlastReceiveReport {
                session_id: sid,
                file_id: fid,
                success: false,
                original_size: 0,
                recovered_size: 0,
                shards_received: shards_recv,
                shards_expected: shards_exp,
                packets_received: pkts_recv,
                packets_lost_estimate: lost_estimate as f64,
                loss_rate: if shards_exp > 0 { lost_estimate as f64 / shards_exp as f64 } else { 0.0 },
                decode_time_ms: decode_ms,
                total_session_time_ms: elapsed_ms,
                output_path: None,
                md5_match: false,
            })
        }
    }
}

fn uuid_from_bytes(bytes: &[u8; 16]) -> String {
    match Uuid::from_slice(bytes) {
        Ok(u) => String::from(u),
        Err(_) => format!("{:02x?}", bytes),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_receiver_creation() {
        let config = BlastReceiverConfig::default();
        let receiver = UdpBlastReceiver::new("127.0.0.1:0", config).await;
        assert!(receiver.is_ok());
    }

    #[test]
    fn test_default_receiver_config() {
        let cfg = BlastReceiverConfig::default();
        assert_eq!(cfg.listen_port, 9002);
        assert_eq!(cfg.session_timeout_secs, 300);
        assert_eq!(cfg.min_shards_for_decode, 16);
        assert!(cfg.auto_cleanup);
    }

    #[test]
    fn test_receive_report_serialization() {
        let report = BlastReceiveReport {
            session_id: "sess-1".to_string(),
            file_id: "f-1".to_string(),
            success: true,
            original_size: 50000,
            recovered_size: 50000,
            shards_received: 18,
            shards_expected: 20,
            packets_received: 54,
            packets_lost_estimate: 2.0,
            loss_rate: 0.1,
            decode_time_ms: 50,
            total_session_time_ms: 1200,
            output_path: Some(PathBuf::from("/tmp/received/file.bin")),
            md5_match: true,
        };
        let json = serde_json::to_string(&report).expect("Serialize");
        let decoded: BlastReceiveReport = serde_json::from_str(&json).expect("Deserialize");
        assert_eq!(decoded.success, true);
        assert_eq!(decoded.md5_match, true);
    }

    #[test]
    fn test_session_state_new() {
        let ss = SessionState::new("s1", "f1");
        assert_eq!(ss.unique_shard_count(), 0);
        assert!(!ss.eof_seen);
        assert!(ss.manifest.is_none());
    }

    #[tokio::test]
    async fn test_invalid_bind_address_rejected() {
        let config = BlastReceiverConfig::default();
        let result = UdpBlastReceiver::new("not-valid", config).await;
        assert!(result.is_err());
    }
}
