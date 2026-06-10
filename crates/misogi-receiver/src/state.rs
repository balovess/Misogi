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
//!
//! # Self-Healing Transport Integrity (Task 6.27)
//!
//! When `integrity_config` is `Some(...)`, the receiver performs per-chunk
//! integrity verification on all incoming chunks:
//!
//! - **Data hash verification** — Recomputes chunk hash and compares with envelope.
//! - **Envelope authenticity** — Verifies envelope self-hash (tamper-proof seal).
//! - **Chain validation** — Checks previous_chunk_hash linkage when enabled.
//! - **Automatic repair request** — Sends NACK for corrupted chunks to trigger retransmission.
//!
//! The `session_manager` tracks transfer progress for checkpoint-based resume
//! when the sender reconnects after interruption.

use crate::config::ReceiverConfig;
use crate::storage::ChunkStorage;
use misogi_core::FileInfo;
// Self-healing transport integrity imports (Task 6.27)
use misogi_core::integrity::{IntegrityConfig, IntegrityVerifier, SessionManager};
// Multi-tier relay imports (Task 6.25)
use misogi_core::relay::RelayMesh;
#[allow(dead_code)]
use std::sync::Arc;
use tokio::sync::RwLock;

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

    // =======================================================================
    // Self-Healing Transport Integrity Layer (Task 6.27)
    // =======================================================================
    /// Optional integrity configuration for self-healing transport.
    ///
    /// When `Some(config)`, incoming chunks are verified against their
    /// [`IntegrityEnvelope`] before being written to storage. Corrupted
    /// chunks trigger NACK responses to request retransmission.
    ///
    /// # Security Implications
    /// - Enabled: Detects bit-flip corruption, tampering, replay attacks.
    /// - Disabled: Relies solely on TCP checksums (weak protection).
    ///
    /// # Backward Compatibility
    /// This field is optional to maintain compatibility with existing
    /// deployments that do not require integrity verification.
    pub integrity_config: Option<IntegrityConfig>,

    /// Integrity verifier for per-chunk hash verification.
    ///
    /// Initialized when `integrity_config` is `Some(...)`.
    /// Used by [`tunnel_handler`](crate::tunnel_handler) to verify each
    /// incoming chunk against its envelope before storage.
    ///
    /// # Thread Safety
    /// This type is `Clone + Send + Sync` and can be freely shared
    /// across async tasks.
    pub integrity_verifier: Option<IntegrityVerifier>,

    /// Session manager for self-healing transport lifecycle tracking.
    ///
    /// Manages session creation, checkpoint persistence, and cleanup.
    /// Initialized when `integrity_config` is `Some(...)`.
    ///
    /// # Thread Safety
    /// Internally uses `parking_lot::RwLock` for high-performance
    /// concurrent access from multiple async tasks.
    pub session_manager: Option<Arc<SessionManager>>,

    // =======================================================================
    // Multi-Tier Relay Integration (Task 6.25)
    // =======================================================================
    /// Integrated multi-tier relay mesh for cross-network file reception.
    ///
    /// When `Some(mesh)`, the receiver can accept files forwarded through
    /// a multi-hop relay topology. The mesh encapsulates:
    /// - [`RelayForwarder`]: Executes chunk-level forwarding through paths.
    /// - [`RelayNodeManager`]: Manages node health and circuit breakers.
    /// - [`RoutePlanner`]: Computes optimal paths through the topology.
    ///
    /// `None` when relay mode is disabled (default for backward compatibility).
    /// When enabled, the receiver acts as a terminal node in a relay mesh,
    /// receiving files forwarded from upstream edge/proxy/hub nodes.
    ///
    /// # Configuration
    ///
    /// Enable via `[relay]` TOML section with `enabled = true` and
    /// topology definition (nodes and edges).
    ///
    /// # Security Implications
    ///
    /// - Each hop can enforce encryption and approval requirements.
    /// - Circuit breakers prevent cascading failures across the mesh.
    /// - Health tracking enables dynamic rerouting around degraded nodes.
    ///
    /// # Note
    ///
    /// RelayMesh is not yet available; this field uses a placeholder type
    /// until the relay module is enabled in misogi-core.
    #[allow(dead_code)]
    pub relay_mesh: Option<String>, // Placeholder: will be Option<Arc<RelayMesh>> when relay module is enabled
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
        let storage =
            ChunkStorage::new(&config.storage_dir, &config.download_dir.to_string_lossy());

        // Initialize transfer driver if configured for non-TCP mode (Task 5.14)
        // For now, default to None (TCP mode); StorageRelayDriver integration
        // will be added when receiver polling mode is fully implemented.
        let transfer_driver = None;

        // Initialize integrity subsystem when enabled (Task 6.27)
        // When enabled, creates IntegrityVerifier and SessionManager for
        // per-chunk verification and checkpoint-based resume.
        // Falls back to None when disabled (backward compatible).
        let (integrity_config, integrity_verifier, session_manager) = if config.integrity_enabled {
            let cfg = IntegrityConfig::sha256_default();
            let verifier = IntegrityVerifier::new(
                misogi_core::integrity::HashAlgorithm::Sha256,
                cfg.verification.zero_tolerance,
            );
            let session_mgr = SessionManager::with_persistence(
                &std::path::PathBuf::from(&config.storage_dir).join("sessions"),
            );
            (Some(cfg), Some(verifier), Some(Arc::new(session_mgr)))
        } else {
            (None, None, None)
        };

        // Initialize relay mesh if configured (Task 6.25)
        // For now, default to None; full relay configuration loading
        // will be added when the [relay] TOML section schema is defined.
        // Note: RelayMesh is not yet available; using placeholder type.
        let relay_mesh: Option<String> = None;

        Self {
            config,
            files: RwLock::new(Vec::new()),
            storage,
            transfer_driver,
            integrity_config,
            integrity_verifier,
            session_manager,
            // Multi-Tier Relay Integration (Task 6.25)
            relay_mesh,
        }
    }
}
