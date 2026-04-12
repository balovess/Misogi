//! Application state for the Misogi Receiver (受信側) component.
//!
//! This module defines [`AppState`], the shared state container for the receiver
//! that holds configuration, file registry, storage backend, and optionally
//! a pluggable [`TransferDriver`] for receiving files via different transports.
//!
//! # Pluggable Trait Layer (Task 5.14)
//!
//! Starting from Task 5.14, `AppState` supports an optional `transfer_driver`
//! field enabling runtime-swappable transport backends:
//!
//! | Mode                  | Driver                    | Use Case                     |
//! |-----------------------|---------------------------|------------------------------|
//! | TCP Server (default)  | `None` (uses built-in)   | Standard direct TCP receive  |
//! | Storage Relay Polling | `StorageRelayDriver`     | Diode/NFS shared folder      |
//!
//! When `transfer_driver` is `Some(...)`, the receiver can poll for incoming
//! files instead of (or in addition to) listening for TCP connections.

#[allow(dead_code)]

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::ReceiverConfig;
use crate::storage::ChunkStorage;
use misogi_core::FileInfo;

/// Central application state for the Misogi Receiver component.
///
/// Holds all dependencies required by the receiver's HTTP/gRPC API handlers,
/// TCP listener, and optional storage relay polling task.
pub struct AppState {
    /// Parsed receiver configuration (immutable after startup).
    pub config: ReceiverConfig,

    /// Registry of received files awaiting download or already completed.
    ///
    /// Protected by `RwLock` for concurrent read/write access.
    #[allow(dead_code)]
    pub files: RwLock<Vec<FileInfo>>,

    /// Chunk storage backend managing file assembly and persistence.
    pub storage: ChunkStorage,

    // =======================================================================
    // Pluggable Trait Layer (Task 5.14)
    // =======================================================================

    /// Optional transfer driver for receiving files via non-TCP transports.
    ///
    /// When `Some(driver)`, the receiver can use this driver to poll for
    /// incoming files (e.g., from a shared folder in diode/NFS scenarios).
    /// When `None` (default), the receiver relies solely on its built-in
    /// TCP server for incoming transfers.
    ///
    /// **Note**: This field is reserved for future StorageRelayDriver integration.
    /// Currently always `None` as receiver polling mode is not yet implemented.
    /// The field type uses a concrete placeholder to avoid associated type
    /// specification issues with `dyn TransferDriver` (which requires `Config`).
    ///
    /// **Typical Configuration**:
    /// - TCP mode: `None` (default, backward compatible)
    /// - Storage relay mode: Future enhancement via `StorageRelayDriver`
    #[allow(dead_code)]
    pub transfer_driver: Option<String>,
}

/// Shared reference to application state, suitable for Axum's `.with_state()`.
pub type SharedState = Arc<AppState>;

impl AppState {
    /// Build receiver AppState from configuration.
    ///
    /// Constructs storage backend and optionally initializes a TransferDriver
    /// based on `config.transfer_mode`. For Task 5.14+ deployments, prefer
    /// this constructor over manual field initialization.
    ///
    /// # Arguments
    /// * `config` — Parsed receiver configuration
    ///
    /// # Returns
    /// Fully initialized `AppState` ready for use.
    pub fn new(config: ReceiverConfig) -> Self {
        let storage = ChunkStorage::new(&config.storage_dir, &config.download_dir.to_string_lossy());

        // Initialize transfer driver if configured for non-TCP mode (Task 5.14)
        // For now, default to None (TCP mode); StorageRelayDriver integration
        // will be added when receiver polling mode is fully implemented.
        let transfer_driver = None;

        Self {
            config,
            files: RwLock::new(Vec::new()),
            storage,
            transfer_driver,
        }
    }
}
