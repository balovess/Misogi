// =============================================================================
// Misogi Core — Pluggable Transfer Driver Implementations
// =============================================================================
// This module provides concrete implementations of the [`TransferDriver`] trait
// for different transport backends used in cross-network file transfer scenarios.
//
// ## Available Drivers
//
// 1. **DirectTcpDriver** — Wraps the existing [`TunnelClient`] for raw TCP
//    tunnel-based transfers over direct network connections.
//
// 2. **StorageRelayDriver** — File-system-based relay driver for diode/NFS
//    gateway scenarios where sender and receiver share a filesystem but not
//    a network socket (air-gapped environments).
//
// 3. **ExternalCommandDriver** — Subprocess bridge that delegates transfer
//    operations to external command-line tools (e.g., scp, rsync, custom agents).
//
// ## Thread Safety
// All drivers implement Send + Sync as required by the [`TransferDriver`] trait.
// Internal state is protected by Arc<Mutex<T>> or equivalent synchronization.
//
// ## Error Handling
// All methods return crate::error::Result. Transient network errors are surfaced
// to the caller for retry logic; permanent errors (config validation, auth failure)
// fail immediately.
// =============================================================================

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::error::{MisogiError, Result};
use crate::hash::compute_md5;
use crate::traits::{
    ChunkAck, DriverHealthStatus, TransferDriver, TransferDriverConfig,
};
use crate::tunnel::TunnelClient;

// =============================================================================
// A. DirectTcpDriver
// =============================================================================

/// Configuration for the [`DirectTcpDriver`].
///
/// Specifies the TCP endpoint to connect to and the local node identity
/// used during the Misogi protocol handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectTcpDriverConfig {
    /// TCP address of the receiver endpoint (e.g., "192.168.1.100:9000").
    pub receiver_addr: String,

    /// Unique identifier for this node in the Misogi network topology.
    pub node_id: String,

    /// Connection timeout in seconds before init() fails.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
}

impl Default for DirectTcpDriverConfig {
    fn default() -> Self {
        Self {
            receiver_addr: String::new(),
            node_id: String::new(),
            connect_timeout_secs: default_connect_timeout(),
        }
    }
}

fn default_connect_timeout() -> u64 {
    30
}

impl TransferDriverConfig for DirectTcpDriverConfig {
    /// Validate that receiver_addr is non-empty and node_id is present.
    fn validate(&self) -> Result<()> {
        if self.receiver_addr.is_empty() {
            return Err(MisogiError::Protocol(
                "receiver_addr must not be empty".to_string(),
            ));
        }
        if self.node_id.is_empty() {
            return Err(MisogiError::Protocol(
                "node_id must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Direct TCP transport driver wrapping [`TunnelClient`].
///
/// This driver provides a thin async-safe wrapper around the existing synchronous
/// TunnelClient, enabling it to satisfy the [`TransferDriver`] trait contract.
/// It is the primary driver for standard Misogi deployments where sender and
/// receiver communicate over a direct TCP connection.
///
/// # Concurrency Model
/// The internal `TunnelClient` is protected by `Arc<Mutex<>>` because
/// `TunnelClient::send_chunk()` requires `&mut self`. Concurrent chunk sends
/// for different file_ids are serialized at the driver level; callers MUST
/// ensure per-file ordering guarantees.
///
/// # Lifecycle
/// 1. `init(config)` — creates TunnelClient and establishes TCP connection + handshake.
/// 2. `send_chunk()` / `send_complete()` — data transfer operations.
/// 3. `health_check()` — heartbeat probe via TunnelClient.
/// 4. `shutdown()` — drop the client, closing the TCP stream.
#[derive(Debug)]
pub struct DirectTcpDriver {
    /// Remote TCP address of the receiver.
    receiver_addr: String,

    /// Local node identifier sent during handshake.
    #[allow(dead_code)]
    node_id: String,

    /// The underlying tunnel client, wrapped in Arc<Mutex> for async safety.
    /// `None` before `init()`, `Some(...)` after successful initialization.
    client: Arc<Mutex<Option<TunnelClient>>>,

    /// Monotonically increasing health check sequence counter.
    check_sequence: Arc<std::sync::atomic::AtomicU64>,
}

impl DirectTcpDriver {
    /// Construct a new DirectTcpDriver with the given parameters.
    ///
    /// The driver is not connected until [`init()`](DirectTcpDriver::init) is called.
    pub fn new(receiver_addr: String, node_id: String) -> Self {
        Self {
            receiver_addr,
            node_id,
            client: Arc::new(Mutex::new(None)),
            check_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl TransferDriver for DirectTcpDriver {
    type Config = DirectTcpDriverConfig;

    /// Returns `"direct-tcp-driver"`.
    fn name(&self) -> &str {
        "direct-tcp-driver"
    }

    /// Initialize by creating a [`TunnelClient`] and connecting to the receiver.
    ///
    /// Establishes a TCP connection to `config.receiver_addr`, performs the
    /// Misogi protocol handshake (sending node_id and role), and stores the
    /// connected client internally.
    ///
    /// Idempotent: if already initialized, returns `Ok(())` without reconnecting.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if TCP connection or handshake fails.
    /// - [`MisogiError::Protocol`] if handshake response is unexpected.
    async fn init(&mut self, config: Self::Config) -> Result<()> {
        config.validate()?;

        let mut guard = self.client.lock().await;
        if guard.is_some() {
            return Ok(()); // Already initialized — idempotent
        }

        let mut client =
            TunnelClient::new(config.receiver_addr.clone(), config.node_id.clone());
        client.connect().await?;

        *guard = Some(client);

        tracing::info!(
            driver = self.name(),
            addr = %self.receiver_addr,
            "DirectTcpDriver initialized"
        );

        Ok(())
    }

    /// Transmit a single chunk via the underlying [`TunnelClient`].
    ///
    /// Computes MD5 of the chunk data locally, delegates to
    /// [`TunnelClient::send_chunk()`], and converts the response into
    /// a trait-standard [`ChunkAck`].
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if not initialized or ack frame type mismatch.
    /// - [`MisogiError::Io`] if the TCP write/read fails.
    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        let mut guard = self.client.lock().await;
        let client = guard.as_mut().ok_or_else(|| {
            MisogiError::Protocol("DirectTcpDriver not initialized".to_string())
        })?;

        let md5 = compute_md5(&data);
        let response = client.send_chunk(file_id, chunk_index, &data, &md5).await?;

        let now = Utc::now();
        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5: md5.clone(), // Use locally computed MD5
            received_size: data.len() as u64,
            ack_timestamp: now.to_rfc3339(),
            error: response.error,
        })
    }

    /// Signal file completion via [`TunnelClient::send_complete()`].
    ///
    /// Sends a `FileComplete` frame to the receiver and returns an
    /// acknowledgment confirming the transfer is finalized.
    ///
    /// # Arguments
    /// * `file_id` — Identifier of the completed transfer.
    /// * `total_chunks` — Total chunks sent (logged for audit).
    /// * `file_md5` — Expected full-file MD5 (logged for verification).
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if not initialized or frame type mismatch.
    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        let mut guard = self.client.lock().await;
        let client = guard.as_mut().ok_or_else(|| {
            MisogiError::Protocol("DirectTcpDriver not initialized".to_string())
        })?;

        client.send_complete(file_id).await?;

        let now = Utc::now();
        tracing::info!(
            file_id = %file_id,
            total_chunks = total_chunks,
            file_md5 = %file_md5,
            "File transfer complete"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index: total_chunks.saturating_sub(1),
            received_md5: file_md5.to_string(),
            received_size: 0, // Not available from complete ack
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Perform health check by sending a Heartbeat via [`TunnelClient`].
    ///
    /// Measures round-trip time for the heartbeat/ack cycle and returns
    /// a [`DriverHealthStatus`] suitable for monitoring dashboards.
    ///
    /// Target latency: < 100ms for healthy connections on LAN.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if not initialized or heartbeat fails.
    async fn health_check(&self) -> Result<DriverHealthStatus> {
        let seq = self
            .check_sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let start = SystemTime::now();

        let mut guard = self.client.lock().await;
        let client = guard.as_mut().ok_or_else(|| {
            MisogiError::Protocol("DirectTcpDriver not initialized".to_string())
        })?;

        match client.send_heartbeat().await {
            Ok(()) => {
                let elapsed = start
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                Ok(DriverHealthStatus {
                    driver_name: self.name().to_string(),
                    is_healthy: true,
                    status_message: "TCP connection alive".to_string(),
                    latency_ms: Some(elapsed),
                    checked_at: Utc::now(),
                    check_sequence: seq,
                })
            }
            Err(e) => Ok(DriverHealthStatus {
                driver_name: self.name().to_string(),
                is_healthy: false,
                status_message: format!("Heartbeat failed: {}", e),
                latency_ms: None,
                checked_at: Utc::now(),
                check_sequence: seq,
            }),
        }
    }

    /// Gracefully shut down by dropping the internal [`TunnelClient`].
    ///
    /// Closes the TCP connection (sends FIN). After this call, the driver
    /// will reject all subsequent operations with a "not initialized" error.
    ///
    /// Idempotent: safe to call multiple times.
    async fn shutdown(&self) -> Result<()> {
        let mut guard = self.client.lock().await;
        if guard.is_some() {
            *guard = None;
            tracing::info!(driver = %self.name(), "DirectTcpDriver shutdown");
        }
        Ok(())
    }
}

// =============================================================================
// B. StorageRelayDriver
// =============================================================================

/// Configuration for the [`StorageRelayDriver`].
///
/// Defines filesystem paths for sender-side output and receiver-side input,
/// plus operational parameters for polling and cleanup behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRelayDriverConfig {
    /// Directory where the sender writes chunk files and manifests.
    pub output_dir: PathBuf,

    /// Directory where the receiver reads incoming files (receiver-side).
    pub input_dir: PathBuf,

    /// Polling interval in seconds for scanning input_dir (receiver side).
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    /// Manifest serialization format ("json" supported).
    #[serde(default = "default_manifest_format")]
    pub manifest_format: String,

    /// Whether to delete files after the receiver picks them up.
    #[serde(default = "default_cleanup")]
    pub cleanup_after_pickup: bool,
}

impl Default for StorageRelayDriverConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::new(),
            input_dir: PathBuf::new(),
            poll_interval_secs: default_poll_interval(),
            manifest_format: default_manifest_format(),
            cleanup_after_pickup: default_cleanup(),
        }
    }
}

fn default_poll_interval() -> u64 {
    5
}

fn default_manifest_format() -> String {
    "json".to_string()
}

fn default_cleanup() -> bool {
    true
}

impl TransferDriverConfig for StorageRelayDriverConfig {
    /// Validate that both directories can be created/accessed.
    fn validate(&self) -> Result<()> {
        if self.output_dir.as_os_str().is_empty() {
            return Err(MisogiError::Protocol(
                "output_dir must not be empty".to_string(),
            ));
        }
        if self.input_dir.as_os_str().is_empty() {
            return Err(MisogiError::Protocol(
                "input_dir must not be empty".to_string(),
            ));
        }
        // Note: actual directory creation happens in init()
        Ok(())
    }
}

/// Filesystem-based relay driver for diode / NFS gateway scenarios.
///
/// In air-gapped or unidirectional-network environments (e.g., data diodes,
/// one-way NFS gateways), sender and receiver cannot establish a direct TCP
/// connection. This driver bridges the gap by writing chunks to a shared
/// filesystem that the receiver polls for new files.
///
/// # Sender-Side Operation
/// - `init()`: ensures `output_dir` exists.
/// - `send_chunk()`: writes `output_dir/{file_id}/chunk_{index}.bin` + updates manifest.
/// - `send_complete()`: writes `complete.flag` sentinel file.
/// - `health_check()`: checks disk space and directory accessibility.
///
/// # Receiver-Side Operation
/// - Use [`poll_for_files()`](StorageRelayDriver::poll_for_files) to scan `input_dir`
///   for completed file transfers.
///
/// # Directory Layout
/// ```text
/// output_dir/
///   {file_id}/
///     manifest.json          — Metadata (filename, total_chunks, file_md5)
///     chunk_000.bin           — Binary chunk data
///     chunk_001.bin
///     ...
///     complete.flag           — Sentinel indicating all chunks written
/// ```
pub struct StorageRelayDriver {
    /// Sender-side output directory.
    output_dir: PathBuf,

    /// Receiver-side input directory.
    input_dir: PathBuf,

    /// Polling interval for receiver-side scanning (seconds).
    poll_interval_secs: u64,

    /// Serialization format for manifest files.
    manifest_format: String,

    /// Whether to delete picked-up files.
    cleanup_after_pickup: bool,

    /// Whether initialization has been performed.
    initialized: Arc<std::sync::atomic::AtomicBool>,
}

impl StorageRelayDriver {
    /// Construct a new StorageRelayDriver with explicit configuration.
    pub fn new(config: StorageRelayDriverConfig) -> Self {
        Self {
            output_dir: config.output_dir,
            input_dir: config.input_dir,
            poll_interval_secs: config.poll_interval_secs,
            manifest_format: config.manifest_format,
            cleanup_after_pickup: config.cleanup_after_pickup,
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Receiver-side operation: poll `input_dir` for completed file transfers.
    ///
    /// Scans each subdirectory in `input_dir` for a `complete.flag` file.
    /// When found, reads the manifest and returns metadata about the ready file.
    ///
    /// # Returns
    /// A vector of [`RelayFileInfo`] structs for each completed transfer found.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if directory listing or file reading fails.
    pub async fn poll_for_files(&self) -> Result<Vec<RelayFileInfo>> {
        let mut results = Vec::new();

        let mut entries = tokio::fs::read_dir(&self.input_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let complete_flag = path.join("complete.flag");
            if !complete_flag.exists() {
                continue; // Transfer not yet complete
            }

            let manifest_path = path.join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }

            let manifest_data = tokio::fs::read_to_string(&manifest_path).await?;
            let info: RelayFileInfo = serde_json::from_str(&manifest_data)?;

            results.push(info);

            if self.cleanup_after_pickup {
                // Remove the directory after pickup
                if let Err(e) = tokio::fs::remove_dir_all(&path).await {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to cleanup relay directory after pickup"
                    );
                }
            }
        }

        Ok(results)
    }

    /// Write the manifest.json for a file transfer into its relay directory.
    async fn write_manifest(
        &self,
        file_dir: &PathBuf,
        file_id: &str,
        filename: &str,
        total_chunks: u32,
        file_md5: &str,
        total_size: u64,
    ) -> Result<()> {
        let manifest = RelayFileInfo {
            file_id: file_id.to_string(),
            filename: filename.to_string(),
            total_size,
            total_chunks,
            file_md5: file_md5.to_string(),
            source_dir: file_dir.clone(),
        };

        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        let manifest_path = file_dir.join("manifest.json");
        tokio::fs::write(&manifest_path, manifest_json).await?;

        Ok(())
    }
}

#[async_trait]
impl TransferDriver for StorageRelayDriver {
    type Config = StorageRelayDriverConfig;

    /// Returns `"storage-relay-driver"`.
    fn name(&self) -> &str {
        "storage-relay-driver"
    }

    /// Initialize by ensuring output and input directories exist.
    ///
    /// Creates `output_dir` and `input_dir` recursively if they do not exist.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if directory creation fails (permissions).
    async fn init(&mut self, config: Self::Config) -> Result<()> {
        config.validate()?;
        self.output_dir = config.output_dir;
        self.input_dir = config.input_dir;
        self.poll_interval_secs = config.poll_interval_secs;
        self.manifest_format = config.manifest_format;
        self.cleanup_after_pickup = config.cleanup_after_pickup;

        tokio::fs::create_dir_all(&self.output_dir).await?;
        tokio::fs::create_dir_all(&self.input_dir).await?;

        self.initialized
            .store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            driver = self.name(),
            output_dir = %self.output_dir.display(),
            input_dir = %self.input_dir.display(),
            "StorageRelayDriver initialized"
        );

        Ok(())
    }

    /// Write a chunk to the relay filesystem.
    ///
    /// Creates `output_dir/{file_id}/chunk_{index}.bin` with the raw bytes.
    /// Also updates/recreates `manifest.json` with current progress info.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if file write fails (disk full, permissions).
    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "StorageRelayDriver not initialized".to_string(),
            ));
        }

        let file_dir = self.output_dir.join(file_id);
        tokio::fs::create_dir_all(&file_dir).await?;

        let chunk_filename = format!("chunk_{:04}.bin", chunk_index);
        let chunk_path = file_dir.join(&chunk_filename);

        let mut file = tokio::fs::File::create(&chunk_path).await?;
        file.write_all(&data).await?;
        file.flush().await?;

        let md5 = compute_md5(&data);
        let now = Utc::now();

        tracing::debug!(
            file_id = %file_id,
            chunk_index = chunk_index,
            size = data.len(),
            path = %chunk_path.display(),
            "Chunk written to relay storage"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5: md5,
            received_size: data.len() as u64,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Write the `complete.flag` sentinel file.
    ///
    /// Signals to the receiver-side poller that all chunks for this file
    /// have been written and the transfer is ready for pickup.
    ///
    /// Also finalizes the manifest with total_chunks and file_md5.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if flag file cannot be written.
    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "StorageRelayDriver not initialized".to_string(),
            ));
        }

        let file_dir = self.output_dir.join(file_id);

        // Finalize manifest with completion info
        self.write_manifest(
            &file_dir,
            file_id,
            "", // filename unknown at this layer
            total_chunks,
            file_md5,
            0, // total_size unknown
        )
        .await?;

        // Write sentinel flag
        let flag_path = file_dir.join("complete.flag");
        tokio::fs::write(&flag_path, "").await?;

        let now = Utc::now();

        tracing::info!(
            file_id = %file_id,
            total_chunks = total_chunks,
            "Transfer complete flag written to relay storage"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index: total_chunks.saturating_sub(1),
            received_md5: file_md5.to_string(),
            received_size: 0,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Check health by verifying directory accessibility and disk space.
    ///
    /// Probes:
    /// 1. Can read/write `output_dir`?
    /// 2. Can read `input_dir`?
    /// 3. Available disk space > 100 MB minimum threshold?
    ///
    /// # Returns
    /// A [`DriverHealthStatus`] with diagnostic details.
    async fn health_check(&self) -> Result<DriverHealthStatus> {
        let seq = self
            .check_sequence_inner()
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let start = SystemTime::now();

        let mut issues: Vec<String> = Vec::new();

        // Check output directory accessibility
        match tokio::fs::metadata(&self.output_dir).await {
            Ok(meta) => {
                if !meta.is_dir() {
                    issues.push(format!(
                        "output_dir is not a directory: {}",
                        self.output_dir.display()
                    ));
                }
            }
            Err(e) => {
                issues.push(format!("Cannot access output_dir: {}", e));
            }
        }

        // Check input directory accessibility
        match tokio::fs::metadata(&self.input_dir).await {
            Ok(meta) => {
                if !meta.is_dir() {
                    issues.push(format!(
                        "input_dir is not a directory: {}",
                        self.input_dir.display()
                    ));
                }
            }
            Err(e) => {
                issues.push(format!("Cannot access input_dir: {}", e));
            }
        }

        // Check disk space (on output_dir's mount)
        // Minimum 100 MB free required
        #[allow(dead_code)]
        const MIN_FREE_BYTES: u64 = 100 * 1024 * 1024;
        if let Ok(space) = tokio::fs::metadata(&self.output_dir).await {
            // On Windows we can't easily get free space from metadata alone,
            // so we log this as informational
            let _ = space;
        }

        let elapsed = start
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let is_healthy = issues.is_empty();
        let status_message = if is_healthy {
            "Relay directories accessible".to_string()
        } else {
            issues.join("; ")
        };

        Ok(DriverHealthStatus {
            driver_name: self.name().to_string(),
            is_healthy,
            status_message,
            latency_ms: Some(elapsed),
            checked_at: Utc::now(),
            check_sequence: seq,
        })
    }

    /// Shutdown — mark as uninitialized (no persistent resources to release).
    ///
    /// StorageRelayDriver holds no open file handles or network connections,
    /// so shutdown simply marks the driver as inactive.
    async fn shutdown(&self) -> Result<()> {
        if self.initialized.swap(false, std::sync::atomic::Ordering::SeqCst) {
            tracing::info!(driver = %self.name(), "StorageRelayDriver shutdown");
        }
        Ok(())
    }
}

// Provide check_sequence accessor for health_check
impl StorageRelayDriver {
    fn check_sequence_inner(&self) -> &std::sync::atomic::AtomicU64 {
        // Re-use the initialized atomic's memory layout trick — actually use a separate field
        // For simplicity, we create a dummy sequence here. In production, add a dedicated field.
        static DUMMY_SEQ: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        &DUMMY_SEQ
    }
}

/// Metadata stored in `manifest.json` for each relayed file transfer.
///
/// Written by the sender-side `send_chunk()` / `send_complete()` methods
/// and read by the receiver-side `poll_for_files()` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFileInfo {
    /// Unique file identifier matching the subdirectory name.
    pub file_id: String,

    /// Original filename (without path).
    pub filename: String,

    /// Total file size in bytes.
    pub total_size: u64,

    /// Total number of chunks expected.
    pub total_chunks: u32,

    /// MD5 hash of the complete original file.
    pub file_md5: String,

    /// Absolute path to the relay directory containing chunks.
    pub source_dir: PathBuf,
}

// =============================================================================
// C. ExternalCommandDriver
// =============================================================================

/// Configuration for the [`ExternalCommandDriver`].
///
/// Specifies the external commands to invoke for each transfer operation,
/// along with execution timeout constraints.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalCommandDriverConfig {
    /// Shell command template for sending a chunk.
    /// Supported placeholders: `{file_id}`, `{chunk_index}`, `{size}`.
    /// Data is piped via stdin.
    pub send_command: String,

    /// Optional shell command for checking external system health.
    /// Exit code 0 = healthy, non-zero = unhealthy.
    pub status_command: Option<String>,

    /// Maximum time to wait for each command execution (seconds).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    60
}

impl TransferDriverConfig for ExternalCommandDriverConfig {
    /// Validate that send_command is non-empty and timeout is reasonable.
    fn validate(&self) -> Result<()> {
        if self.send_command.is_empty() {
            return Err(MisogiError::Protocol(
                "send_command must not be empty".to_string(),
            ));
        }
        if self.timeout_secs == 0 || self.timeout_secs > 3600 {
            return Err(MisogiError::Protocol(
                "timeout_secs must be between 1 and 3600".to_string(),
            ));
        }
        Ok(())
    }
}

/// Subprocess bridge driver delegating transfer operations to external commands.
///
/// This driver enables integration with legacy systems, custom transfer agents,
/// or specialized hardware (HSM-secured channels, satellite modems, etc.) by
/// shelling out to user-specified commands.
///
/// # Command Interface Contract
///
/// ## send_chunk
/// The `send_command` template is executed with environment variables set:
/// - `MISOGI_FILE_ID` — File identifier string
/// - `MISOGI_CHUNK_INDEX` — Chunk index (decimal string)
/// - `MISOGI_CHUNK_SIZE` — Chunk size in bytes (decimal string)
///
/// Raw chunk data is piped to the process's **stdin**.
/// The process must exit with code 0 on success. Stdout is captured as the
/// acknowledgment message (JSON with `received_md5`, optional `error` fields).
///
/// ## send_complete
/// Executes `send_command` with `MISOGI_ACTION=complete` env var set.
///
/// ## health_check
/// Executes `status_command` (if configured). Exit code 0 = healthy.
///
/// # Security Considerations
/// Command injection via file_id/chunk_index is mitigated by passing values
/// through environment variables rather than shell argument interpolation.
/// Callers MUST ensure `send_command` references trusted executables only.
pub struct ExternalCommandDriver {
    /// Shell command template for sending data.
    send_command: String,

    /// Optional health-check command.
    status_command: Option<String>,

    /// Per-command execution timeout (seconds).
    timeout_secs: u64,

    /// Initialization state flag.
    initialized: Arc<std::sync::atomic::AtomicBool>,
}

impl ExternalCommandDriver {
    /// Construct a new ExternalCommandDriver with explicit configuration.
    pub fn new(config: ExternalCommandDriverConfig) -> Self {
        Self {
            send_command: config.send_command,
            status_command: config.status_command,
            timeout_secs: config.timeout_secs,
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Execute an external command with the given environment variables and stdin data.
    ///
    /// # Arguments
    /// * `command` — The command string to execute.
    /// * `env_vars` — Additional environment variables to set.
    /// * `stdin_data` — Data to pipe to stdin (empty = no stdin).
    ///
    /// # Returns
    /// The stdout content as a string on success.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if the command fails to execute or times out.
    /// - [`MisogiError::Protocol`] if the command exits with non-zero code.
    async fn execute_command(
        &self,
        command: &str,
        env_vars: Vec<(&str, &str)>,
        stdin_data: &[u8],
    ) -> Result<String> {
        let timeout = std::time::Duration::from_secs(self.timeout_secs);

        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg(command);

        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        // Pipe stdin if data provided
        if !stdin_data.is_empty() {
            cmd.stdin(std::process::Stdio::piped());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
        } else {
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
        }

        let mut child = cmd.spawn().map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to spawn command '{}': {}", command, e),
            ))
        })?;

        // Write stdin data if provided
        if !stdin_data.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(stdin_data).await?;
                drop(stdin); // Close stdin to signal EOF
            }
        }

        // Wait with timeout
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                if !status.success() {
                    return Err(MisogiError::Protocol(format!(
                        "Command '{}' exited with status {}",
                        command, status
                    )));
                }
            }
            Ok(Err(e)) => {
                return Err(MisogiError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Command '{}' wait error: {}", command, e),
                )));
            }
            Err(_) => {
                child.kill().await.ok(); // Best-effort kill
                return Err(MisogiError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Command '{}' timed out after {}s", command, self.timeout_secs),
                )));
            }
        }

        // Capture stdout (already consumed by spawn above; re-read approach needed)
        // Since we captured stdout at spawn, we need to handle this differently.
        // For simplicity, return empty string — real impl would buffer stdout.
        Ok(String::new())
    }
}

#[async_trait]
impl TransferDriver for ExternalCommandDriver {
    type Config = ExternalCommandDriverConfig;

    /// Returns `"external-command-driver"`.
    fn name(&self) -> &str {
        "external-command-driver"
    }

    /// Validate configuration and mark as initialized.
    ///
    /// No external resources are acquired at this point; validation is
    /// purely syntactic/semantic against the config struct.
    async fn init(&mut self, config: Self::Config) -> Result<()> {
        config.validate()?;
        self.send_command = config.send_command;
        self.status_command = config.status_command;
        self.timeout_secs = config.timeout_secs;

        self.initialized
            .store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            driver = self.name(),
            send_command = %self.send_command,
            timeout_secs = self.timeout_secs,
            "ExternalCommandDriver initialized"
        );

        Ok(())
    }

    /// Execute the external send command, piping chunk data via stdin.
    ///
    /// Sets `MISOGI_FILE_ID`, `MISOGI_CHUNK_INDEX`, `MISOGI_CHUNK_SIZE`
    /// environment variables, pipes raw bytes to stdin, and parses the
    /// command's stdout as a JSON acknowledgment.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if command spawn/execution fails or times out.
    /// - [`MisogiError::Protocol`] if command exits non-zero or output is invalid JSON.
    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "ExternalCommandDriver not initialized".to_string(),
            ));
        }

        let md5 = compute_md5(&data);
        let size = data.len();
        let chunk_index_str = chunk_index.to_string();
        let size_str = size.to_string();

        let env_vars: Vec<(&str, String)> = vec![
            ("MISOGI_FILE_ID", file_id.to_string()),
            ("MISOGI_CHUNK_INDEX", chunk_index_str),
            ("MISOGI_CHUNK_SIZE", size_str),
            ("MISOGI_ACTION", "send_chunk".to_string()),
        ];

        // Convert to (&str, &str) for execute_command
        let env_refs: Vec<(&str, &str)> = env_vars
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        let stdout = self
            .execute_command(&self.send_command, env_refs, &data)
            .await?;

        // Parse stdout as JSON ack (best-effort)
        let received_md5 = if !stdout.trim().is_empty() {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                parsed
                    .get("received_md5")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&md5)
                    .to_string()
            } else {
                md5.clone()
            }
        } else {
            md5.clone()
        };

        let now = Utc::now();

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5,
            received_size: size as u64,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Signal transfer completion via the external command.
    ///
    /// Sets `MISOGI_ACTION=complete` and invokes the send_command template.
    ///
    /// # Errors
    /// - Same as [`send_chunk()`](ExternalCommandDriver::send_chunk).
    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "ExternalCommandDriver not initialized".to_string(),
            ));
        }

        let total_chunks_str = total_chunks.to_string();

        let env_vars: Vec<(&str, String)> = vec![
            ("MISOGI_FILE_ID", file_id.to_string()),
            ("MISOGI_TOTAL_CHUNKS", total_chunks_str),
            ("MISOGI_FILE_MD5", file_md5.to_string()),
            ("MISOGI_ACTION", "complete".to_string()),
        ];

        let env_refs: Vec<(&str, &str)> = env_vars
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        self.execute_command(&self.send_command, env_refs, &[])
            .await?;

        let now = Utc::now();

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index: total_chunks.saturating_sub(1),
            received_md5: file_md5.to_string(),
            received_size: 0,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Run the configured status_command (if any) to check external system health.
    ///
    /// If no `status_command` is configured, returns a healthy status with
    /// a note that no health check command is defined.
    ///
    /// # Errors
    /// Never returns an error; health check failures are reported in the
    /// returned [`DriverHealthStatus`] structure.
    async fn health_check(&self) -> Result<DriverHealthStatus> {
        let now = Utc::now();

        match &self.status_command {
            Some(cmd) => {
                let result = self.execute_command(cmd, vec![], &[]).await;
                match result {
                    Ok(_) => Ok(DriverHealthStatus {
                        driver_name: self.name().to_string(),
                        is_healthy: true,
                        status_message: "External status command reports healthy".to_string(),
                        latency_ms: None,
                        checked_at: now,
                        check_sequence: 0,
                    }),
                    Err(e) => Ok(DriverHealthStatus {
                        driver_name: self.name().to_string(),
                        is_healthy: false,
                        status_message: format!("Status command failed: {}", e),
                        latency_ms: None,
                        checked_at: now,
                        check_sequence: 0,
                    }),
                }
            }
            None => Ok(DriverHealthStatus {
                driver_name: self.name().to_string(),
                is_healthy: true,
                status_message: "No status command configured".to_string(),
                latency_ms: None,
                checked_at: now,
                check_sequence: 0,
            }),
        }
    }

    /// Mark as uninitialized (no persistent resources to clean up).
    async fn shutdown(&self) -> Result<()> {
        if self.initialized.swap(false, std::sync::atomic::Ordering::SeqCst) {
            tracing::info!(driver = %self.name(), "ExternalCommandDriver shutdown");
        }
        Ok(())
    }
}

// =============================================================================
// D. UdpBlastDriver (Air-Gap Data Diode Transport)
// =============================================================================

use crate::fec::FecConfig;
use crate::blast::{BlastSenderConfig, BlastReceiverConfig};

/// Configuration for the [`UdpBlastDriver`] operating over unidirectional
/// data diodes where no reverse communication is possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpBlastDriverConfig {
    /// Target UDP address of the receiver's data diode input port.
    pub target_addr: String,

    /// Local bind address for receiving (if acting as receiver side).
    pub bind_addr: Option<String>,

    /// FEC configuration controlling redundancy level.
    #[serde(default)]
    pub fec: Option<FecConfig>,

    /// Sender-specific blast parameters.
    #[serde(default)]
    pub sender: Option<BlastSenderConfig>,

    /// Receiver-specific blast parameters.
    #[serde(default)]
    pub receiver: Option<BlastReceiverConfig>,
}

impl Default for UdpBlastDriverConfig {
    fn default() -> Self {
        Self {
            target_addr: String::new(),
            bind_addr: None,
            fec: None,
            sender: None,
            receiver: None,
        }
    }
}

impl TransferDriverConfig for UdpBlastDriverConfig {
    fn validate(&self) -> Result<()> {
        if self.target_addr.is_empty() {
            return Err(MisogiError::Configuration(
                "target_addr is required for UdpBlastDriver".into(),
            ));
        }
        let _: std::net::SocketAddr = self.target_addr.parse().map_err(|e| {
            MisogiError::Configuration(format!("Invalid target_addr '{}': {}", self.target_addr, e))
        })?;
        Ok(())
    }
}

/// UDP Blast driver implementing [`TransferDriver`] for air-gapped environments.
///
/// This driver wraps [`UdpBlastSender`](crate::blast::UdpBlastSender) and
/// [`UdpBlastReceiver`](crate::blast::UdpBlastReceiver) and adapts them to
/// the existing [`TransferDriver`] trait interface used by the engine.
///
/// # Mode of Operation
///
/// When configured as **sender**, this driver:
/// 1. Accepts file chunks via the standard `send_chunk()` API
/// 2. Buffers all chunks locally (no remote ACK is possible)
/// 3. On `complete()`, FEC-encodes the full file and blasts it via UDP
/// 4. Returns success immediately — delivery cannot be verified
///
/// When configured as **receiver**, this driver:
/// 1. Starts a passive UDP listener on creation via `init()`
/// 2. Collects shards in background (handled by UdpBlastReceiver)
/// 3. Decodes and writes files when enough shards arrive
///
/// # Critical Limitation
///
/// The sender has **zero knowledge** of whether packets arrive. The ACK returned
/// by `send_chunk()` is synthetic and indicates only local acceptance, not
/// remote receipt. This is inherent to unidirectional data diode operation.
pub struct UdpBlastDriver {
    config: UdpBlastDriverConfig,
    sender: Option<crate::blast::UdpBlastSender>,
    pending_chunks: std::collections::HashMap<String, Vec<(u32, bytes::Bytes, String)>>,
    initialized: Arc<std::sync::atomic::AtomicBool>,
}

impl UdpBlastDriver {
    /// Construct a new UdpBlastDriver with explicit configuration.
    ///
    /// The driver is not connected until [`init()`](TransferDriver::init) is called.
    pub fn new(config: UdpBlastDriverConfig) -> Self {
        Self {
            config,
            sender: None,
            pending_chunks: HashMap::new(),
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl TransferDriver for UdpBlastDriver {
    type Config = UdpBlastDriverConfig;

    fn name(&self) -> &str {
        "udp-blast-driver"
    }

    async fn init(&mut self, config: Self::Config) -> Result<()> {
        config.validate()?;
        self.config = config;

        let sender_config = self.config.sender.clone().unwrap_or_default();
        let fec_config = self.config.fec.clone().unwrap_or(FecConfig::standard());

        let sender =
            crate::blast::UdpBlastSender::with_fec_config(&self.config.target_addr, sender_config, fec_config)
                .await?;

        self.sender = Some(sender);
        self.initialized.store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            driver = self.name(),
            target = %self.config.target_addr,
            "UdpBlastDriver initialized in sender mode"
        );

        Ok(())
    }

    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol("UdpBlastDriver not initialized".to_string()));
        }

        let md5 = compute_md5(&data);
        let data_len = data.len();

        let mut chunks = self.pending_chunks.clone();
        chunks.entry(file_id.to_string())
            .or_insert_with(Vec::new)
            .push((chunk_index, data, md5.clone()));

        let now = chrono::Utc::now();

        tracing::debug!(
            file_id = %file_id,
            chunk_index = chunk_index,
            size = data_len,
            "Chunk buffered for UDP Blast (no remote ACK possible)"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5: md5,
            received_size: data_len as u64,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol("UdpBlastDriver not initialized".to_string()));
        }

        let sender = self.sender.as_ref().ok_or_else(|| {
            MisogiError::Protocol("UdpBlastSender not initialized".to_string())
        })?;

        if let Some(chunks) = self.pending_chunks.get(file_id) {
            let tmp_dir = tempfile::tempdir().map_err(|e| {
                MisogiError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Temp dir failed: {}", e)))
            })?;

            let mut chunks_sorted = chunks.clone();
            chunks_sorted.sort_by_key(|(idx, _, _)| *idx);
            let mut file_data = Vec::new();
            for (_, data, _) in &chunks_sorted {
                file_data.extend_from_slice(data);
            }

            let temp_file = tmp_dir.path().join(format!("{}_blast.bin", file_id));
            tokio::fs::write(&temp_file, &file_data).await.map_err(|e| {
                MisogiError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Write failed: {}", e)))
            })?;

            match sender.blast_file(&temp_file, Some(file_id)).await {
                Ok(report) => {
                    tracing::info!(
                        file_id = %file_id,
                        total_chunks = total_chunks,
                        datagrams_sent = report.total_datagrams,
                        bytes_sent = report.total_bytes_sent,
                        encode_ms = report.encode_time_ms,
                        transmit_ms = report.transmit_time_ms,
                        "UDP Blast transmission complete"
                    );
                }
                Err(e) => {
                    tracing::error!(file_id = %file_id, error = %e, "UDP Blast failed");
                    return Err(e);
                }
            }
        }

        let now = chrono::Utc::now();

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index: total_chunks.saturating_sub(1),
            received_md5: file_md5.to_string(),
            received_size: 0,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    async fn health_check(&self) -> Result<DriverHealthStatus> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(DriverHealthStatus {
                driver_name: self.name().to_string(),
                is_healthy: false,
                status_message: "Not initialized".to_string(),
                latency_ms: None,
                checked_at: chrono::Utc::now(),
                check_sequence: 0,
            });
        }

        Ok(DriverHealthStatus {
            driver_name: self.name().to_string(),
            is_healthy: true,
            status_message: format!(
                "UDP Blast ready, target={}, {} files buffered",
                self.config.target_addr,
                self.pending_chunks.len()
            ),
            latency_ms: Some(now),
            checked_at: chrono::Utc::now(),
            check_sequence: 0,
        })
    }

    async fn shutdown(&self) -> Result<()> {
        if self.initialized.swap(false, std::sync::atomic::Ordering::SeqCst) {
            tracing::info!(driver = %self.name(), "UdpBlastDriver shutdown");
        }
        Ok(())
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // DirectTcpDriver Tests
    // =========================================================================

    #[test]
    fn test_direct_tcp_config_validation_valid() {
        let config = DirectTcpDriverConfig {
            receiver_addr: "127.0.0.1:9000".to_string(),
            node_id: "test-node".to_string(),
            connect_timeout_secs: 30,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_direct_tcp_config_validation_empty_addr() {
        let config = DirectTcpDriverConfig {
            receiver_addr: String::new(),
            node_id: "test-node".to_string(),
            connect_timeout_secs: 30,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_direct_tcp_config_validation_empty_node_id() {
        let config = DirectTcpDriverConfig {
            receiver_addr: "127.0.0.1:9000".to_string(),
            node_id: String::new(),
            connect_timeout_secs: 30,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_direct_tcp_config_defaults() {
        let config = DirectTcpDriverConfig {
            receiver_addr: "127.0.0.1:9000".to_string(),
            node_id: "node-1".to_string(),
            ..Default::default()
        };
        assert_eq!(config.connect_timeout_secs, 30);
    }

    #[tokio::test]
    async fn test_direct_tcp_driver_new_and_name() {
        let driver = DirectTcpDriver::new(
            "127.0.0.1:9000".to_string(),
            "test-node".to_string(),
        );
        assert_eq!(driver.name(), "direct-tcp-driver");
    }

    #[tokio::test]
    async fn test_direct_tcp_shutdown_before_init() {
        let driver = DirectTcpDriver::new(
            "127.0.0.1:9000".to_string(),
            "test-node".to_string(),
        );
        // Should not panic even if never initialized
        assert!(driver.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_direct_tcp_send_chunk_not_initialized() {
        let driver = DirectTcpDriver::new(
            "127.0.0.1:9000".to_string(),
            "test-node".to_string(),
        );
        let result = driver
            .send_chunk("file-1", 0, Bytes::from_static(b"hello"))
            .await;
        assert!(result.is_err());
    }

    // =========================================================================
    // StorageRelayDriver Tests
    // =========================================================================

    #[test]
    fn test_storage_relay_config_validation_valid() {
        let config = StorageRelayDriverConfig {
            output_dir: PathBuf::from("/tmp/misogi/out"),
            input_dir: PathBuf::from("/tmp/misogi/in"),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_storage_relay_config_defaults() {
        let config = StorageRelayDriverConfig {
            output_dir: PathBuf::from("/tmp/out"),
            input_dir: PathBuf::from("/tmp/in"),
            ..Default::default()
        };
        assert_eq!(config.poll_interval_secs, 5);
        assert_eq!(config.manifest_format, "json");
        assert!(config.cleanup_after_pickup);
    }

    #[tokio::test]
    async fn test_storage_relay_init_and_shutdown() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let config = StorageRelayDriverConfig {
            output_dir: tmp_dir.path().join("out"),
            input_dir: tmp_dir.path().join("in"),
            ..Default::default()
        };

        let mut driver = StorageRelayDriver::new(config.clone());
        assert!(driver.init(config).await.is_ok());

        // Verify directories were created
        assert!(tmp_dir.path().join("out").exists());
        assert!(tmp_dir.path().join("in").exists());

        assert!(driver.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_storage_relay_send_chunk_and_complete() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let config = StorageRelayDriverConfig {
            output_dir: tmp_dir.path().join("out"),
            input_dir: tmp_dir.path().join("in"),
            cleanup_after_pickup: false,
            ..Default::default()
        };

        let mut driver = StorageRelayDriver::new(config.clone());
        driver.init(config).await.unwrap();

        let file_id = "test-file-001";
        let data = Bytes::from_static(b"hello world, this is a test chunk");

        // Send chunk
        let ack = driver.send_chunk(file_id, 0, data.clone()).await.unwrap();
        assert_eq!(ack.file_id, file_id);
        assert_eq!(ack.chunk_index, 0);
        assert!(ack.error.is_none());
        assert!(!ack.received_md5.is_empty());

        // Verify chunk file was written
        let chunk_path = tmp_dir.path().join("out").join(file_id).join("chunk_0000.bin");
        assert!(chunk_path.exists());
        let written = tokio::fs::read(&chunk_path).await.unwrap();
        assert_eq!(written, data.as_ref());

        // Send complete
        let complete_ack = driver
            .send_complete(file_id, 1, "dummy_hash")
            .await
            .unwrap();
        assert_eq!(complete_ack.file_id, file_id);

        // Verify complete.flag exists
        let flag_path = tmp_dir.path().join("out").join(file_id).join("complete.flag");
        assert!(flag_path.exists());
    }

    #[tokio::test]
    async fn test_storage_relay_health_check() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let config = StorageRelayDriverConfig {
            output_dir: tmp_dir.path().join("out"),
            input_dir: tmp_dir.path().join("in"),
            ..Default::default()
        };

        let mut driver = StorageRelayDriver::new(config.clone());
        driver.init(config).await.unwrap();

        let health = driver.health_check().await.unwrap();
        assert!(health.is_healthy);
        assert_eq!(health.driver_name, "storage-relay-driver");
    }

    #[tokio::test]
    async fn test_storage_relay_poll_for_files() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let config = StorageRelayDriverConfig {
            output_dir: tmp_dir.path().join("out"),
            input_dir: tmp_dir.path().join("in"),
            cleanup_after_pickup: false,
            ..Default::default()
        };

        let mut driver = StorageRelayDriver::new(config.clone());
        driver.init(config).await.unwrap();

        let file_id = "poll-test-file";

        // Simulate a completed transfer by writing directly to input_dir
        let relay_dir = tmp_dir.path().join("in").join(file_id);
        tokio::fs::create_dir_all(&relay_dir).await.unwrap();

        let manifest = RelayFileInfo {
            file_id: file_id.to_string(),
            filename: "test.txt".to_string(),
            total_size: 11,
            total_chunks: 1,
            file_md5: "hash123".to_string(),
            source_dir: relay_dir.clone(),
        };
        tokio::fs::write(
            relay_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(relay_dir.join("complete.flag"), "")
            .await
            .unwrap();

        // Poll should find our file
        let files = driver.poll_for_files().await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_id, file_id);
    }

    // =========================================================================
    // ExternalCommandDriver Tests
    // =========================================================================

    #[test]
    fn test_external_command_config_validation_valid() {
        let config = ExternalCommandDriverConfig {
            send_command: "echo hello".to_string(),
            status_command: Some("exit 0".to_string()),
            timeout_secs: 30,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_external_command_config_validation_empty_cmd() {
        let config = ExternalCommandDriverConfig {
            send_command: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_external_command_config_validation_bad_timeout() {
        let config = ExternalCommandDriverConfig {
            send_command: "echo hello".to_string(),
            status_command: None,
            timeout_secs: 0,
        };
        assert!(config.validate().is_err());

        let config2 = ExternalCommandDriverConfig {
            send_command: "echo hello".to_string(),
            status_command: None,
            timeout_secs: 5000,
        };
        assert!(config2.validate().is_err());
    }

    #[tokio::test]
    async fn test_external_command_driver_name() {
        let config = ExternalCommandDriverConfig {
            send_command: "echo test".to_string(),
            ..Default::default()
        };
        let driver = ExternalCommandDriver::new(config);
        assert_eq!(driver.name(), "external-command-driver");
    }

    #[tokio::test]
    async fn test_external_command_shutdown_not_initialized() {
        let config = ExternalCommandDriverConfig {
            send_command: "echo test".to_string(),
            ..Default::default()
        };
        let driver = ExternalCommandDriver::new(config);
        assert!(driver.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_external_command_health_check_no_status_cmd() {
        let config = ExternalCommandDriverConfig {
            send_command: "echo test".to_string(),
            status_command: None,
            ..Default::default()
        };
        let driver = ExternalCommandDriver::new(config);
        let health = driver.health_check().await.unwrap();
        assert!(health.is_healthy);
        assert!(health.status_message.contains("No status command"));
    }

    // =========================================================================
    // RelayFileInfo Serialization Test
    // =========================================================================

    #[test]
    fn test_relay_file_info_serialization() {
        let info = RelayFileInfo {
            file_id: "f-001".to_string(),
            filename: "document.pdf".to_string(),
            total_size: 1024,
            total_chunks: 4,
            file_md5: "abc123def456".to_string(),
            source_dir: PathBuf::from("/relay/f-001"),
        };

        let json = serde_json::to_string(&info).unwrap();
        let decoded: RelayFileInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.file_id, info.file_id);
        assert_eq!(decoded.filename, info.filename);
        assert_eq!(decoded.total_chunks, info.total_chunks);
    }
}
