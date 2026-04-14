//! Pluggable Transfer Driver Instance — Enum Dispatch Layer.
//!
//! Wraps all concrete [`TransferDriver`] implementations into a single enum
//! enabling runtime configuration-driven selection without dynamic dispatch
//! (`dyn Trait`) overhead or object-safety constraints from associated types.
//!
//! # Architecture
//!
//! ```text
//! SenderConfig.transfer_driver_type
//!       │
//!       ▼
//! ┌─────────────────────────────────────┐
//! │  TransferDriverInstance (enum)      │
//! ├─────────────────────────────────────┤
//! │  DirectTcp(DirectTcpDriver)        │ ← default, TCP tunnel
//! │  StorageRelay(StorageRelayDriver)   │ ← air-gap / NFS relay
//! │  ExternalCommand(ExternalCommand)  │ ← scp / rsync bridge
//! │  UdpBlast(UdpBlastDriver)          │ ← UDP data diode
//! └─────────────────────────────────────┘
//!       │
//!       ▼  match self { ... } → static dispatch
//! ```
//!
//! # Why Enum Instead of `dyn TransferDriver`?
//!
//! The [`TransferDriver`] trait uses an associated type (`Config`) and generic
//! method signatures that prevent it from being object-safe. This enum provides:
//!
//! - **Zero runtime cost**: `match` is statically dispatched (no vtable lookup).
//! - **Full type safety**: Each variant's `Config` type is known at compile time.
//! - **Extensibility**: Add new drivers by appending variants (no ABI break).

use bytes::Bytes;
use misogi_core::error::Result;
use misogi_core::traits::{
    ChunkAck, DriverHealthStatus,
    TransferDriver,
};

use misogi_core::drivers::{
    DirectTcpDriver,
    DirectTcpDriverConfig,
    StorageRelayDriver,
    StorageRelayDriverConfig,
    ExternalCommandDriver,
    ExternalCommandDriverConfig,
    UdpBlastDriver,
    UdpBlastDriverConfig,
};

// =============================================================================
// TransferDriverInstance Enum
// =============================================================================

/// Enum dispatch wrapper for all pluggable transfer driver implementations.
///
/// Each variant holds a fully-constructed driver instance. Methods on this enum
/// forward calls to the inner driver via `match` expressions.
///
/// # Thread Safety
///
/// All inner driver types implement `Send + Sync`. This enum inherits those
/// bounds automatically when wrapped in `Arc<>`.
///
/// # Clone
///
/// This enum does **not** implement `Clone` because inner driver types hold
/// non-cloneable resources (TCP sockets, file handles). Use `Arc<>` for sharing.
pub enum TransferDriverInstance {
    /// Direct TCP connection through [`TunnelClient`].
    ///
    /// Standard Misogi mode: sender opens TCP socket to receiver.
    DirectTcp(DirectTcpDriver),

    /// File-system based relay for air-gapped networks.
    ///
    /// Both nodes poll shared storage (NFS, SMB, USB shuttle).
    StorageRelay(StorageRelayDriver),

    /// Subprocess bridge for third-party transfer tools.
    ///
    /// Delegates to external commands like `scp`, `rsync`, or proprietary gateways.
    ExternalCommand(ExternalCommandDriver),

    /// UDP broadcast with FEC for unidirectional data diodes.
    ///
    /// One-way physical data diode: no reverse communication possible.
    UdpBlast(UdpBlastDriver),
}

impl TransferDriverInstance {
    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Returns the human-readable name of the active driver.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::DirectTcp(d) => d.name(),
            Self::StorageRelay(d) => d.name(),
            Self::ExternalCommand(d) => d.name(),
            Self::UdpBlast(d) => d.name(),
        }
    }

    /// Returns the driver type identifier used in configuration files.
    #[must_use]
    #[allow(dead_code)]
    pub fn type_id(&self) -> &'static str {
        match self {
            Self::DirectTcp(_) => "direct_tcp",
            Self::StorageRelay(_) => "storage_relay",
            Self::ExternalCommand(_) => "external_command",
            Self::UdpBlast(_) => "udp_blast",
        }
    }

    // -----------------------------------------------------------------
    // TransferDriver Trait Forwarding
    // -----------------------------------------------------------------

    /// Initialize the underlying driver connection.
    ///
    /// For `DirectTcp`: opens TCP socket and performs handshake.
    /// For `StorageRelay`: validates directories exist.
    /// For `ExternalCommand`: verifies command template is executable.
    /// For `UdpBlast`: binds local UDP socket.
    #[allow(dead_code)]
    pub async fn init(&mut self) -> Result<()> {
        match self {
            Self::DirectTcp(driver) => {
                let config = DirectTcpDriverConfig {
                    receiver_addr: String::new(), // Filled by caller via re-construction
                    node_id: String::new(),
                    connect_timeout_secs: 30,
                };
                driver.init(config).await
            }
            Self::StorageRelay(driver) => {
                let config = StorageRelayDriverConfig::default();
                driver.init(config).await
            }
            Self::ExternalCommand(driver) => {
                let config = ExternalCommandDriverConfig::default();
                driver.init(config).await
            }
            Self::UdpBlast(driver) => {
                let config = UdpBlastDriverConfig::default();
                driver.init(config).await
            }
        }
    }

    /// Transmit a single file chunk to the receiver.
    ///
    /// Returns a [`ChunkAck`] containing acknowledgment metadata from the receiver.
    pub async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        match self {
            Self::DirectTcp(driver) => driver.send_chunk(file_id, chunk_index, data).await,
            Self::StorageRelay(driver) => driver.send_chunk(file_id, chunk_index, data).await,
            Self::ExternalCommand(driver) => driver.send_chunk(file_id, chunk_index, data).await,
            Self::UdpBlast(driver) => driver.send_chunk(file_id, chunk_index, data).await,
        }
    }

    /// Signal that all chunks for a file have been transmitted.
    ///
    /// Returns the final [`ChunkAck`] from the receiver containing
    /// end-to-end integrity verification results.
    pub async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        match self {
            Self::DirectTcp(driver) => driver.send_complete(file_id, total_chunks, file_md5).await,
            Self::StorageRelay(driver) => driver.send_complete(file_id, total_chunks, file_md5).await,
            Self::ExternalCommand(driver) => driver.send_complete(file_id, total_chunks, file_md5).await,
            Self::UdpBlast(driver) => driver.send_complete(file_id, total_chunks, file_md5).await,
        }
    }

    /// Perform a health check against the transport backend.
    ///
    /// Returns [`DriverHealthStatus`] indicating connectivity and latency.
    #[allow(dead_code)]
    pub async fn health_check(&self) -> Result<DriverHealthStatus> {
        match self {
            Self::DirectTcp(driver) => driver.health_check().await,
            Self::StorageRelay(driver) => driver.health_check().await,
            Self::ExternalCommand(driver) => driver.health_check().await,
            Self::UdpBlast(driver) => driver.health_check().await,
        }
    }

    /// Gracefully shut down the transport connection.
    ///
    /// Flushes pending buffers and releases network resources.
    #[allow(dead_code)]
    pub async fn shutdown(&self) -> Result<()> {
        match self {
            Self::DirectTcp(driver) => driver.shutdown().await,
            Self::StorageRelay(driver) => driver.shutdown().await,
            Self::ExternalCommand(driver) => driver.shutdown().await,
            Self::UdpBlast(driver) => driver.shutdown().await,
        }
    }

    // -----------------------------------------------------------------
    // Factory Methods (preferred over direct enum construction)
    // -----------------------------------------------------------------

    /// Construct a `DirectTcp` variant from address and node ID.
    #[must_use]
    pub fn direct_tcp(receiver_addr: String, node_id: String) -> Self {
        Self::DirectTcp(DirectTcpDriver::new(receiver_addr, node_id))
    }

    /// Construct a `StorageRelay` variant from directory paths.
    #[must_use]
    pub fn storage_relay(output_dir: String, input_dir: String, poll_interval_secs: u64) -> Self {
        let config = StorageRelayDriverConfig {
            output_dir: std::path::PathBuf::from(&output_dir),
            input_dir: std::path::PathBuf::from(&input_dir),
            poll_interval_secs,
            manifest_format: "json".to_string(),
            cleanup_after_pickup: true,
        };
        Self::StorageRelay(StorageRelayDriver::new(config))
    }

    /// Construct an `ExternalCommand` variant from command templates.
    #[must_use]
    pub fn external_command(send_command: String, status_command: String, timeout_secs: u64) -> Self {
        let config = ExternalCommandDriverConfig {
            send_command,
            status_command: Some(status_command),
            timeout_secs,
        };
        Self::ExternalCommand(ExternalCommandDriver::new(config))
    }

    /// Construct a `UdpBlast` variant from target address.
    #[must_use]
    pub fn udp_blast(target_addr: String) -> Self {
        let config = UdpBlastDriverConfig {
            target_addr,
            bind_addr: None,
            fec: Some(misogi_core::fec::FecConfig {
                data_shards: 16,
                parity_shards: 4,
                shard_size: 1400,
            }),
            sender: Some(misogi_core::blast::sender::BlastSenderConfig {
                repeat_count: 3,
                repeat_interval_us: 1000,
                manifest_repeats: 5,
                max_datagram_size: 1400,
                adaptive_rate: false,
                eof_repeats: 3,
            }),
            receiver: None,
        };
        Self::UdpBlast(UdpBlastDriver::new(config))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_direct_tcp_name() {
        let instance = TransferDriverInstance::direct_tcp(
            "127.0.0.1:9000".to_string(),
            "test-node".to_string(),
        );
        assert_eq!(instance.name(), "direct-tcp-driver");
        assert_eq!(instance.type_id(), "direct_tcp");
    }

    #[test]
    fn test_storage_relay_name() {
        let instance = TransferDriverInstance::storage_relay(
            "/tmp/relay/out".to_string(),
            "/tmp/relay/in".to_string(),
            10,
        );
        assert_eq!(instance.type_id(), "storage_relay");
    }

    #[test]
    fn test_external_command_name() {
        let instance = TransferDriverInstance::external_command(
            "scp %s remote:/".to_string(),
            "echo done".to_string(),
            60,
        );
        assert_eq!(instance.type_id(), "external_command");
    }

    #[test]
    fn test_udp_blast_name() {
        let instance = TransferDriverInstance::udp_blast("192.168.254.2:9002".to_string());
        assert_eq!(instance.type_id(), "udp_blast");
    }

    #[test]
    fn test_arc_wrap() {
        let instance = TransferDriverInstance::direct_tcp(
            "10.0.0.1:9000".to_string(),
            "arc-test".to_string(),
        );
        let _wrapped = Arc::new(instance); // Arc wrapping should compile
    }
}
