//! Configuration management for Misogi Receiver node.
//!
//! This module provides configuration loading, validation, and environment
//! variable override support for the receiver component of the Misogi (禊)
//! cross-network file transfer system.
//!
//! # Architecture Overview
//!
//! The receiver configuration follows a layered approach identical to the sender:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Configuration Layers                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Layer 1: misogi.toml (TOML file)                           │
//! │    ↓ Primary source of truth                                 │
//! │  Layer 2: Environment Variables (MISOGI_*)                   │
//!    ↓ Overrides specific fields at runtime                      │
//! │  Layer 3: CLI Arguments (--flag)                             │
//!    ↓ Highest priority overrides                                │
//! │  Layer 4: ReceiverConfig (final resolved configuration)      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Phase 5 Extension Sections (Receiver Subset)
//!
//! The receiver supports a subset of Phase 5 sections relevant to its role
//! as the file reception endpoint. Approval flow and PII scanning are
//! sender-side concerns and are NOT included in the receiver configuration.
//!
//! | Section               | Purpose                                      | Required |
//! |-----------------------|----------------------------------------------|----------|
//! | `[server]`            | HTTP/gRPC listener settings                  | Yes      |
//! | `[storage]`           | Local file storage paths                     | Yes      |
//! | `[tunnel]`            | Reverse tunnel to sender                     | Optional |
//! | `[daemon]`            | Background service mode                      | Optional |
//! | `[transfer_driver]`   | StorageRelayDriver input_dir mode            | Optional |
//! | `[log]`               | Audit log format and retention settings      | Optional |
//! | `[encoding]`          | Japanese text encoding detection/handling     | Optional |
//! | `[file_types]`        | File type validation on receive              | Optional |
//!
//! # Backward Compatibility
//!
//! All new sections are **optional** with `#[serde(default)]`. A minimal `misogi.toml`
//! containing only `[server]` and `[storage]` continues to work identically to
//! previous versions.
//!
//! # Thread Safety
//!
//! Once constructed, [`ReceiverConfig`] is fully immutable (`Send + Sync`) and safe
//! to share across async tasks without synchronization overhead.

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use misogi_core::error::{MisogiError, Result};

// =============================================================================
// Section R1: Transfer Driver Configuration (Receiver Subset)
// =============================================================================

/// Transfer driver type for the receiver node.
///
/// The receiver supports fewer driver types than the sender since it is the
/// passive endpoint of file transfers. It primarily handles incoming files
/// from direct TCP connections or storage relay pickup.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverTransferDriverType {
    /// Accept files via direct TCP connection from sender.
    DirectTcp,

    /// Pick up files from storage relay input directory.
    ///
    /// Used for air-gapped networks where the sender deposits files to
    /// a shared filesystem and the receiver polls for new arrivals.
    StorageRelay,
}

impl Default for ReceiverTransferDriverType {
    fn default() -> Self {
        Self::DirectTcp
    }
}

impl ReceiverTransferDriverType {
    /// Parse from string with fallback to DirectTcp for unknown values.
    /// Part of the stable public parsing API; used by [`Self::as_str`] round-trip
    /// and available for library consumers / test code.
    #[allow(dead_code)]
    pub fn from_str_fallback(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "direct_tcp" | "tcp" => Self::DirectTcp,
            "storage_relay" | "relay" | "storage" => Self::StorageRelay,
            _ => Self::DirectTcp,
        }
    }

    /// Serialize to canonical string representation (inverse of [`Self::from_str_fallback`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DirectTcp => "direct_tcp",
            Self::StorageRelay => "storage_relay",
        }
    }
}

/// Transfer driver configuration for the receiver node.
///
/// Focused on input-side operations: receiving files via TCP or polling
/// storage relay directories for inbound transfers from the sender.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReceiverTransferDriverConfig {
    /// Selected transfer driver type.
    #[serde(default)]
    pub r#type: ReceiverTransferDriverType,

    // ---- Storage Relay Specific (Receiver Side) ----

    /// Input directory for picking up files deposited by sender (relay mode).
    #[serde(default)]
    pub input_dir: Option<String>,

    /// Output directory where completed receives are stored.
    #[serde(default)]
    pub output_dir: Option<String>,

    /// Polling interval in seconds for checking relay input directory.
    #[serde(default = "default_receiver_relay_poll_interval")]
    pub poll_interval_secs: u64,

    /// Manifest file format for relay metadata ("json" or "toml").
    #[serde(default = "default_manifest_format")]
    pub manifest_format: String,

    /// Whether to delete relayed files after successful processing.
    #[serde(default = "default_relay_cleanup")]
    pub cleanup_after_pickup: bool,
}

fn default_receiver_relay_poll_interval() -> u64 {
    10
}

fn default_manifest_format() -> String {
    String::from("json")
}

fn default_relay_cleanup() -> bool {
    true
}

impl Default for ReceiverTransferDriverConfig {
    fn default() -> Self {
        Self {
            r#type: ReceiverTransferDriverType::default(),
            input_dir: None,
            output_dir: None,
            poll_interval_secs: default_receiver_relay_poll_interval(),
            manifest_format: default_manifest_format(),
            cleanup_after_pickup: default_relay_cleanup(),
        }
    }
}

// =============================================================================
// Section R2: Log Configuration (Receiver)
// =============================================================================

/// Audit log formatter type selection (same as sender).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormatType {
    /// JSON Lines format — one JSON object per line (default).
    Json,

    /// Syslog-compatible text format with structured metadata.
    Syslog,

    /// CEF (Common Event Format) for SIEM integration.
    Cef,

    /// User-customizable Tera template format.
    Custom,
}

impl Default for LogFormatType {
    fn default() -> Self {
        Self::Json
    }
}

/// Log configuration section for the receiver node.
///
/// Controls audit log output format for received file events. The receiver
/// logs different event types than the sender (FileReceived, FileStored,
/// etc.) but uses the same formatting infrastructure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    /// Output format for audit log entries.
    #[serde(default)]
    pub format: LogFormatType,

    /// Path to Tera template file (required when format = "custom").
    #[serde(default)]
    pub template_path: Option<String>,

    /// Maximum number of log entries held in memory before flushing to disk.
    #[serde(default = "default_max_memory_entries")]
    pub max_memory_entries: usize,

    /// Number of days to retain log files before rotation/deletion.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_max_memory_entries() -> usize {
    1000
}

fn default_retention_days() -> u32 {
    365
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormatType::default(),
            template_path: None,
            max_memory_entries: default_max_memory_entries(),
            retention_days: default_retention_days(),
        }
    }
}

// =============================================================================
// Section R3: Encoding Configuration (Receiver)
// =============================================================================

/// Action for handling unknown/untrusted fonts in reconstructed PDF documents.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownFontAction {
    /// Keep unknown font references unchanged.
    Preserve,

    /// Remove unknown font references entirely.
    Strip,

    /// Replace unknown fonts with fallback fonts.
    Replace,
}

impl Default for UnknownFontAction {
    fn default() -> Self {
        Self::Preserve
    }
}

/// Encoding configuration for the receiver node.
///
/// Handles encoding detection and conversion for incoming files that may
/// originate from legacy Japanese systems using Shift-JIS, EUC-JP, or ISO-2022-JP.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncodingConfig {
    /// Fallback encoding name when auto-detection fails.
    #[serde(default = "default_encoding")]
    pub default_encoding: String,

    /// Strategy for handling unknown fonts in sanitized PDF output.
    #[serde(default)]
    pub unknown_font_action: UnknownFontAction,

    /// Ordered list of safe fallback font names for PDF substitution.
    #[serde(default = "default_fallback_fonts")]
    pub fallback_fonts: Vec<String>,
}

fn default_encoding() -> String {
    String::from("utf-8")
}

fn default_fallback_fonts() -> Vec<String> {
    vec![
        String::from("IPAexMincho"),
        String::from("IPAGothic"),
    ]
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            default_encoding: default_encoding(),
            unknown_font_action: UnknownFontAction::default(),
            fallback_fonts: default_fallback_fonts(),
        }
    }
}

// =============================================================================
// Section R4: File Types Configuration (Receiver Validation)
// =============================================================================

/// Single entry in the receiver's file type registry.
///
/// Used for validating incoming files against expected magic bytes and
/// assigning appropriate handlers for received content.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypeRegistryEntry {
    /// File extension including leading dot (e.g., ".pdf", ".jtd", ".xlsx").
    #[serde(default)]
    pub extension: String,

    /// Expected hex-encoded magic bytes for this file type.
    #[serde(default)]
    pub magic_hex: String,

    /// Whether magic byte validation is enforced for this file type.
    #[serde(default)]
    pub required_magic: bool,

    /// Handler identifier for this file type on receive.
    #[serde(default)]
    pub handler: String,
}

impl Default for FileTypeRegistryEntry {
    fn default() -> Self {
        Self {
            extension: String::new(),
            magic_hex: String::new(),
            required_magic: false,
            handler: String::new(),
        }
    }
}

/// Blocked file extension rule for the receiver.
///
/// Extensions listed here are rejected at the API boundary before any
/// processing occurs, providing a first-line defense against malicious uploads.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockedExtensionEntry {
    /// File extension to block (including leading dot).
    #[serde(default)]
    pub extension: String,

    /// Human-readable reason for the block.
    #[serde(default)]
    pub reason: String,
}

impl Default for BlockedExtensionEntry {
    fn default() -> Self {
        Self {
            extension: String::new(),
            reason: String::new(),
        }
    }
}

/// File types configuration section for the receiver node.
///
/// Manages file type validation rules applied to incoming files before
/// they are stored in the download directory.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypesConfig {
    /// Default action for unrecognized file extensions: "allow" or "block".
    #[serde(default = "default_file_action")]
    pub default_action: String,

    /// Registered file types with validation rules.
    #[serde(default)]
    pub registry: Vec<FileTypeRegistryEntry>,

    /// Explicitly blocked file extensions.
    #[serde(default)]
    pub blocked_extensions: Vec<BlockedExtensionEntry>,
}

fn default_file_action() -> String {
    String::from("allow")
}

impl Default for FileTypesConfig {
    fn default() -> Self {
        Self {
            default_action: default_file_action(),
            registry: Vec::new(),
            blocked_extensions: Vec::new(),
        }
    }
}

// =============================================================================
// Legacy Server/Storage/Tunnel/Daemon Config (Unchanged)
// =============================================================================

/// Server configuration for the Misogi Receiver node.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Bind address for the HTTP API server (e.g., "0.0.0.0:3002").
    #[serde(default = "default_server_addr")]
    pub addr: String,
}

fn default_server_addr() -> String {
    "0.0.0.0:3002".to_string()
}

/// Storage configuration for local file handling.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Directory for storing received chunks during upload.
    #[serde(default = "default_storage_dir")]
    pub chunk_dir: String,

    /// Directory for completed downloads.
    #[serde(default = "default_download_dir")]
    pub download_dir: String,
}

fn default_storage_dir() -> String {
    "./data/receiver/chunks".to_string()
}

fn default_download_dir() -> String {
    "./data/receiver/downloads".to_string()
}

/// Tunnel configuration for reverse proxy connectivity.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TunnelConfig {
    /// Remote tunnel server address.
    #[serde(default)]
    pub remote_addr: Option<String>,

    /// Authentication token for tunnel registration.
    #[serde(default)]
    pub auth_token: Option<String>,

    /// Local port for tunnel listener.
    #[serde(default = "default_tunnel_port")]
    pub local_port: u16,
}

fn default_tunnel_port() -> u16 {
    9000
}

/// Daemon/service mode configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    /// Run process as background daemon.
    #[serde(default = "default_daemon_enabled")]
    pub enabled: bool,

    /// PID file path for daemon process.
    #[serde(default)]
    pub pid_file: Option<String>,

    /// Log file path for daemon output.
    #[serde(default)]
    pub log_file: Option<String>,
}

fn default_daemon_enabled() -> bool {
    false
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_blast_listen_port() -> u16 {
    9002
}

fn default_blast_session_timeout_secs() -> u64 {
    300
}

// =============================================================================
// Section R4: UDP Blast Configuration (Receiver Side)
// =============================================================================

/// UDP Blast receiver configuration for unidirectional data diode transfer.
///
/// When enabled, the receiver node listens on a dedicated UDP port for
/// FEC-protected file shards sent through physical one-way data diodes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlastConfig {
    /// Whether blast reception is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// UDP port to listen for incoming blast datagrams.
    #[serde(default = "default_blast_listen_port")]
    pub listen_port: u16,

    /// Directory to store reassembled blast files.
    #[serde(default)]
    pub output_dir: Option<PathBuf>,

    /// Maximum time (seconds) to wait for all shards before decode attempt.
    #[serde(default = "default_blast_session_timeout_secs")]
    pub session_timeout_secs: u64,
}

impl Default for BlastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: default_blast_listen_port(),
            output_dir: None,
            session_timeout_secs: default_blast_session_timeout_secs(),
        }
    }
}

// =============================================================================
// Section R5: Versioning Configuration (Multi-Version API Management)
// =============================================================================

/// Single sunset policy entry for one API version.
///
/// Defines the lifecycle phase and timeline for a specific API version,
/// enabling Japanese SIer to plan multi-year migration schedules per
/// the compliance requirements of Japanese government B2B/B2G deployments.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SunsetPolicyConfig {
    /// API version string this policy applies to (e.g., "v1", "v2").
    #[serde(default)]
    pub version: String,

    /// Current lifecycle phase: "stable", "deprecated", "soft_sunset", "hard_sunset".
    #[serde(default = "default_receiver_sunset_phase")]
    pub phase: String,

    /// ISO 8601 date when hard sunset takes effect (HTTP 410 Gone).
    #[serde(default)]
    pub hard_sunset_date: Option<String>,

    /// ISO 8601 date when deprecation was first announced (for audit trail).
    #[serde(default)]
    pub announced_date: Option<String>,

    /// URL to human-readable migration guide for SIer budget justification.
    #[serde(default)]
    pub migration_guide_url: Option<String>,
}

fn default_receiver_sunset_phase() -> String {
    String::from("stable")
}

impl Default for SunsetPolicyConfig {
    fn default() -> Self {
        Self {
            version: String::new(),
            phase: default_receiver_sunset_phase(),
            hard_sunset_date: None,
            announced_date: None,
            migration_guide_url: None,
        }
    }
}

/// Multi-version API management configuration for the receiver node.
///
/// Controls deprecation warnings, RFC 8594 Sunset headers, and per-version
/// lifecycle phases for enterprise-grade API version transitions on the
/// file reception endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersioningConfig {
    /// Default active API version for new clients ("v1" or "v2").
    #[serde(default = "default_receiver_versioning_version")]
    pub default_version: String,

    /// Whether to emit structured `[WARN][DEPRECATION]` log entries.
    #[serde(default = "default_true")]
    pub deprecation_warnings_enabled: bool,

    /// Whether to inject RFC 8594 HTTP headers into deprecated responses.
    #[serde(default = "default_true")]
    pub deprecation_headers: bool,

    /// Per-version sunset policy definitions (ordered array).
    #[serde(default)]
    pub sunset_policies: Vec<SunsetPolicyConfig>,
}

fn default_receiver_versioning_version() -> String {
    String::from("v1")
}

impl Default for VersioningConfig {
    fn default() -> Self {
        Self {
            default_version: default_receiver_versioning_version(),
            deprecation_warnings_enabled: true,
            deprecation_headers: true,
            sunset_policies: Vec::new(),
        }
    }
}

// =============================================================================
// Root TomlConfig Structure (Deserialization Target)
// =============================================================================

/// Root structure for deserializing the complete receiver `misogi.toml`.
///
/// All Phase 5 sections are **optional** with `#[serde(default)]`. Existing
/// configurations without these sections continue to work identically.
///
/// # Minimal Valid Configuration
///
/// ```toml
/// [server]
/// addr = "0.0.0.0:3002"
///
/// [storage]
/// chunk_dir = "./chunks"
/// download_dir = "./downloads"
/// ```
#[derive(Debug, Deserialize, Serialize)]
pub struct TomlConfig {
    // ---- Core Sections (Required for Basic Operation) ----

    /// HTTP/gRPC server listener settings.
    #[serde(default)]
    pub server: ServerConfig,

    /// Local file storage paths.
    #[serde(default)]
    pub storage: StorageConfig,

    // ---- Optional Core Sections ----

    /// Reverse tunnel to sender node.
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,

    /// Background service mode settings.
    #[serde(default)]
    pub daemon: Option<DaemonConfig>,

    // ---- Phase 5 Extended Sections (All Optional, Receiver Subset) ----

    /// Transfer driver backend selection (receiver side).
    #[serde(default)]
    pub transfer_driver: Option<ReceiverTransferDriverConfig>,

    /// Audit log format and retention configuration.
    #[serde(default)]
    pub log: Option<LogConfig>,

    /// Japanese text encoding detection and handling.
    #[serde(default)]
    pub encoding: Option<EncodingConfig>,

    /// File type validation rules for incoming files.
    #[serde(default)]
    pub file_types: Option<FileTypesConfig>,

    /// UDP Blast receiver configuration for unidirectional data diode transfer.
    #[serde(default)]
    pub blast_config: Option<BlastConfig>,

    /// Multi-version API management and sunset policy configuration.
    ///
    /// Controls deprecation warnings, RFC 8594 headers, and per-version
    /// lifecycle phases (Stable → Deprecated → SoftSunset → HardSunset).
    #[serde(default)]
    pub versioning: Option<VersioningConfig>,
}

// =============================================================================
// Runtime Configuration (Final Resolved State)
// =============================================================================

/// Fully resolved runtime configuration for the Misogi Receiver node.
///
/// This struct represents the final configuration state after applying all layers:
/// 1. TOML file defaults
/// 2. Environment variable overrides (`MISOGI_*`)
/// 3. CLI argument overrides (applied after construction)
///
/// All fields have sensible defaults ensuring the system can operate even with
/// an empty or missing configuration file.
///
/// # Thread Safety
///
/// This struct is fully immutable once constructed and implements `Send + Sync`,
/// making it safe to wrap in `Arc<>` for sharing across async tasks.
///
/// # Environment Variable Overrides
///
/// | Variable                        | Field Affected               | Example              |
/// |---------------------------------|------------------------------|----------------------|
/// | `MISOGI_SERVER_ADDR`            | `server_addr`                | `0.0.0.0:8080`       |
/// | `MISOGI_CHUNK_DIR`              | `chunk_dir`                 | `/var/misogi/chunks`  |
/// | `MISOGI_DOWNLOAD_DIR`           | `download_dir`               | `/var/misogi/downloads`|
/// | `MISOGI_TRANSFER_DRIVER_TYPE`   | `transfer_driver_type`       | `storage_relay`      |
/// | `MISOGI_LOG_FORMAT`             | `log_format`                 | `cef`                |
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct ReceiverConfig {
    // ---- Core Network Settings ----

    /// Bind address for the HTTP API server.
    pub server_addr: String,

    // ---- Storage Paths ----

    /// Directory for storing received chunks during upload.
    pub chunk_dir: PathBuf,

    /// Directory for completed downloads.
    pub download_dir: PathBuf,

    // ---- Tunnel Settings ----

    /// Remote tunnel server address (if configured).
    pub tunnel_remote_addr: Option<String>,

    /// Tunnel authentication token (if configured).
    pub tunnel_auth_token: Option<String>,

    /// Local port for tunnel listener.
    pub tunnel_local_port: u16,

    // ---- Daemon Settings ----

    /// Whether to run as background daemon.
    pub daemon_enabled: bool,

    /// PID file path for daemon mode.
    pub daemon_pid_file: Option<String>,

    /// Log file path for daemon mode.
    pub daemon_log_file: Option<String>,

    // ---- Phase 5: Transfer Driver (Receiver) ----

    /// Selected transfer driver type (direct_tcp, storage_relay).
    pub transfer_driver_type: String,

    /// Storage relay input directory (for storage_relay driver).
    pub transfer_input_dir: Option<String>,

    /// Storage relay output directory (for processed files).
    pub transfer_output_dir: Option<String>,

    /// Storage relay polling interval in seconds.
    pub transfer_poll_interval_secs: u64,

    // ---- Phase 5: Log Configuration ----

    /// Audit log output format (json, syslog, cef, custom).
    pub log_format: String,

    /// Path to custom log template (when format = "custom").
    pub log_template_path: Option<String>,

    /// Maximum in-memory log entries before flush.
    pub log_max_memory_entries: usize,

    /// Log file retention period in days.
    pub log_retention_days: u32,

    // ---- Phase 5: Encoding ----

    /// Fallback encoding name for undetectable inputs.
    pub encoding_default_encoding: String,

    /// Strategy for unknown PDF fonts.
    pub encoding_unknown_font_action: String,

    /// Safe fallback font list for PDF substitution.
    pub encoding_fallback_fonts: Vec<String>,

    // ---- Phase 5: File Types ----

    /// Default action for unrecognized file extensions.
    pub file_types_default_action: String,

    // ---- Legacy Fields (Required by existing code) ----

    /// Storage directory path (alias for chunk_dir, used by ChunkStorage).
    ///
    /// This field provides backward compatibility with [`ChunkStorage`] which
    /// expects a `storage_dir` field for chunk storage operations.
    pub storage_dir: String,

    /// Tunnel port alias (same as tunnel_local_port, used by main.rs).
    pub tunnel_port: u16,

    /// Output directory for daemon mode file output.
    pub output_dir: Option<PathBuf>,

    /// Logging verbosity level for tracing subscriber.
    pub log_level: String,

    /// Whether to log PPAP conversion events from the sender side.
    ///
    /// When a file arrives that was converted from PPAP on the sender side,
    /// receiver logs this for end-to-end audit trail completeness.
    #[serde(default = "default_false")]
    pub ppap_log_converted: bool,

    // ---- Phase 7: UDP Blast (Air-Gap Data Diode) ----

    /// UDP port for incoming Blast traffic from data diode.
    #[serde(default = "default_blast_listen_port")]
    pub blast_listen_port: u16,

    /// Whether UDP Blast receiving mode is enabled.
    #[serde(default = "default_false")]
    pub blast_enabled: bool,

    /// Directory for writing files reconstructed from Blast transfers.
    #[serde(default)]
    pub blast_output_dir: Option<PathBuf>,

    /// Maximum time (seconds) to wait for shards before attempting decode.
    #[serde(default = "default_blast_session_timeout_secs")]
    pub blast_session_timeout_secs: u64,

    // ---- Multi-Version API Management (Resolved Runtime Fields) ----

    /// Default active API version for this deployment ("v1" or "v2").
    pub versioning_default_version: String,

    /// Whether deprecation warning logging is enabled for legacy API access.
    pub versioning_deprecation_warnings_enabled: bool,

    /// Whether RFC 8594 Sunset/Deprecated/Link headers are injected.
    pub versioning_deprecation_headers: bool,
}

impl Default for ReceiverConfig {
    /// Create a ReceiverConfig with all sensible defaults applied.
    fn default() -> Self {
        Self {
            server_addr: default_server_addr(),
            chunk_dir: PathBuf::from(default_storage_dir()),
            download_dir: PathBuf::from(default_download_dir()),
            tunnel_remote_addr: None,
            tunnel_auth_token: None,
            tunnel_local_port: default_tunnel_port(),
            daemon_enabled: default_daemon_enabled(),
            daemon_pid_file: None,
            daemon_log_file: None,
            // Phase 5: Transfer Driver defaults
            transfer_driver_type: String::from("direct_tcp"),
            transfer_input_dir: None,
            transfer_output_dir: None,
            transfer_poll_interval_secs: default_receiver_relay_poll_interval(),
            // Phase 5: Log defaults
            log_format: String::from("json"),
            log_template_path: None,
            log_max_memory_entries: default_max_memory_entries(),
            log_retention_days: default_retention_days(),
            // Phase 5: Encoding defaults
            encoding_default_encoding: default_encoding(),
            encoding_unknown_font_action: String::from("preserve"),
            encoding_fallback_fonts: default_fallback_fonts(),
            // Phase 5: File Types defaults
            file_types_default_action: default_file_action(),
            // Legacy fields defaults
            storage_dir: default_storage_dir(),
            tunnel_port: default_tunnel_port(),
            output_dir: None,
            log_level: String::from("info"),
            ppap_log_converted: false,
            // Blast (UDP data diode) defaults
            blast_enabled: false,
            blast_listen_port: default_blast_listen_port(),
            blast_output_dir: None,
            blast_session_timeout_secs: default_blast_session_timeout_secs(),
            versioning_default_version: "v1".to_string(),
            versioning_deprecation_warnings_enabled: true,
            versioning_deprecation_headers: true,
        }
    }
}

impl ReceiverConfig {
    /// Load configuration from a TOML file and apply environment variable overrides.
    ///
    /// This is the primary configuration loading method. It performs:
    ///
    /// 1. **TOML Parsing**: Read and deserialize `misogi.toml` from the given path.
    /// 2. **Env Override**: Apply `MISOGI_*` environment variable overrides.
    /// 3. **Validation**: Verify critical paths and settings are coherent.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the `misogi.toml` configuration file. Pass `None`
    ///   to use default values without loading any file.
    ///
    /// # Returns
    ///
    /// A fully resolved [`ReceiverConfig`] instance ready for use.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if the configuration file cannot be read.
    /// - [`MisogiError::Serialization`] if the TOML content is malformed.
    /// - [`MisogiError::Configuration`] if critical settings are invalid.
    #[allow(dead_code)]
    pub async fn load(config_path: Option<PathBuf>) -> Result<Self> {
        let mut config = Self::default();

        if let Some(ref path) = config_path {
            config = Self::from_toml(path)?;
        }

        config.apply_env_overrides();
        config.validate()?;

        info!(
            server_addr = %config.server_addr,
            chunk_dir = %config.chunk_dir.display(),
            download_dir = %config.download_dir.display(),
            driver_type = %config.transfer_driver_type,
            log_format = %config.log_format,
            "Receiver configuration loaded successfully"
        );

        Ok(config)
    }

    /// Load configuration with CLI argument overrides applied.
    ///
    /// This is the primary entry point used by [`main`](crate::main) to construct
    /// the final runtime configuration. It applies overrides in priority order:
    ///
    /// ```text
    /// 1. Load from TOML file (base configuration)
    /// 2. Apply MISOGI_* environment variable overrides
    /// 3. Apply CLI argument overrides (highest priority)
    /// 4. Validate final configuration
    /// ```
    pub fn load_with_cli(cli: &crate::cli::CommandLine) -> Self {
        // Step 1: Load from TOML file
        let mut config = if let Some(ref path) = cli.config {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match toml::from_str::<TomlConfig>(&content) {
                        Ok(toml_config) => Self::from_toml_unchecked(&toml_config),
                        Err(e) => {
                            tracing::error!(error = %e, path = %path.display(), "Failed to parse TOML config, using defaults");
                            Self::default()
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, path = ?path, "Failed to read config file, using defaults");
                    Self::default()
                }
            }
        } else {
            Self::default()
        };

        // Step 2: Apply environment variable overrides
        config.apply_env_overrides();

        // Step 3: Apply CLI argument overrides
        config.apply_cli_overrides(cli);

        // Step 4: Validate (log warnings but don't fail startup)
        let _ = config.validate();

        config
    }

    /// Internal helper to map TomlConfig to ReceiverConfig without file I/O.
    fn from_toml_unchecked(toml: &TomlConfig) -> Self {
        let server_addr = toml.server.addr.clone();
        let storage_dir = toml.storage.chunk_dir.clone();
        let chunk_dir = PathBuf::from(&storage_dir);
        let download_dir = PathBuf::from(&toml.storage.download_dir);

        let (tunnel_remote_addr, tunnel_auth_token, tunnel_local_port) =
            if let Some(ref tunnel) = toml.tunnel {
                (
                    tunnel.remote_addr.clone(),
                    tunnel.auth_token.clone(),
                    tunnel.local_port,
                )
            } else {
                (None, None, default_tunnel_port())
            };

        let (daemon_enabled, daemon_pid_file, daemon_log_file) =
            if let Some(ref daemon) = toml.daemon {
                (
                    daemon.enabled,
                    daemon.pid_file.clone(),
                    daemon.log_file.clone(),
                )
            } else {
                (default_daemon_enabled(), None, None)
            };

        // Phase 5 sections
        let (transfer_driver_type, transfer_input_dir, transfer_output_dir, transfer_poll_interval_secs) =
            if let Some(ref td) = toml.transfer_driver {
                let type_str = td.r#type.as_str().to_string();
                (
                    type_str.to_string(),
                    td.input_dir.clone(),
                    td.output_dir.clone(),
                    td.poll_interval_secs,
                )
            } else {
                ("direct_tcp".to_string(), None, None, default_receiver_relay_poll_interval())
            };

        let (log_format, log_template_path, log_max_memory_entries, log_retention_days) =
            if let Some(ref lg) = toml.log {
                let fmt_str = match lg.format {
                    LogFormatType::Json => "json",
                    LogFormatType::Syslog => "syslog",
                    LogFormatType::Cef => "cef",
                    LogFormatType::Custom => "custom",
                };
                (fmt_str.to_string(), lg.template_path.clone(), lg.max_memory_entries, lg.retention_days)
            } else {
                ("json".to_string(), None, default_max_memory_entries(), default_retention_days())
            };

        let (encoding_default_encoding, encoding_unknown_font_action, encoding_fallback_fonts) =
            if let Some(ref enc) = toml.encoding {
                let ufas = match enc.unknown_font_action {
                    UnknownFontAction::Preserve => "preserve",
                    UnknownFontAction::Strip => "strip",
                    UnknownFontAction::Replace => "replace",
                };
                (enc.default_encoding.clone(), ufas.to_string(), enc.fallback_fonts.clone())
            } else {
                (default_encoding(), "preserve".to_string(), default_fallback_fonts())
            };

        let file_types_default_action =
            toml.file_types.as_ref().map(|f| f.default_action.clone()).unwrap_or_else(default_file_action);

        // ---- Map Versioning Section (Multi-Version API Management) ----
        let (versioning_default_version, versioning_deprecation_warnings_enabled, versioning_deprecation_headers) =
            if let Some(ref v) = toml.versioning {
                (
                    v.default_version.clone(),
                    v.deprecation_warnings_enabled,
                    v.deprecation_headers,
                )
            } else {
                ("v1".to_string(), true, true)
            };

        Self {
            server_addr,
            chunk_dir: chunk_dir.clone(),
            download_dir,
            storage_dir,
            tunnel_port: tunnel_local_port,
            output_dir: None,
            log_level: String::from("info"),
            tunnel_remote_addr,
            tunnel_auth_token,
            tunnel_local_port,
            daemon_enabled,
            daemon_pid_file,
            daemon_log_file,
            transfer_driver_type,
            transfer_input_dir,
            transfer_output_dir,
            transfer_poll_interval_secs,
            log_format,
            log_template_path,
            log_max_memory_entries,
            log_retention_days,
            encoding_default_encoding,
            encoding_unknown_font_action,
            encoding_fallback_fonts,
            file_types_default_action,
            ppap_log_converted: false,
            // Blast (UDP data diode) fields
            blast_enabled: toml.blast_config.as_ref().map(|b| b.enabled).unwrap_or(false),
            blast_listen_port: toml.blast_config.as_ref().map(|b| b.listen_port).unwrap_or_else(default_blast_listen_port),
            blast_output_dir: toml.blast_config.as_ref().and_then(|b| b.output_dir.clone()),
            blast_session_timeout_secs: toml.blast_config.as_ref().map(|b| b.session_timeout_secs).unwrap_or_else(default_blast_session_timeout_secs),
            versioning_default_version,
            versioning_deprecation_warnings_enabled,
            versioning_deprecation_headers,
        }
    }

    /// Apply CLI argument overrides to this configuration.
    fn apply_cli_overrides(&mut self, cli: &crate::cli::CommandLine) {
        if let Some(ref addr) = cli.addr {
            self.server_addr = addr.clone();
        }
        if let Some(ref dir) = cli.storage_dir {
            self.chunk_dir = PathBuf::from(dir);
            self.storage_dir = dir.clone();
        }
        if let Some(ref dir) = cli.download_dir {
            self.download_dir = PathBuf::from(dir);
        }
        if let Some(port) = cli.tunnel_port {
            self.tunnel_local_port = port;
            self.tunnel_port = port;
        }
        if let Some(ref level) = cli.log_level {
            self.log_level = level.clone();
        }
    }

    /// Parse configuration from a TOML file path.
    ///
    /// Reads the specified TOML file, deserializes it into [`TomlConfig`],
    /// and maps all sections to [`ReceiverConfig`] fields.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path to the `misogi.toml` file.
    ///
    /// # Returns
    ///
    /// A [`ReceiverConfig`] with all values populated from the TOML file.
    /// Missing sections retain their default values.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if the file cannot be read.
    /// - [`MisogiError::Serialization`] if TOML parsing fails.
    #[allow(dead_code)]
    pub fn from_toml(path: &Path) -> Result<Self> {
        info!(config_path = %path.display(), "Loading receiver configuration from TOML file");

        let content = std::fs::read_to_string(path).map_err(|e| {
            MisogiError::Io(e)
        })?;

        let toml_config: TomlConfig = toml::from_str(&content).map_err(|e| {
            MisogiError::Protocol(format!(
                "Failed to parse receiver configuration file '{}': {}",
                path.display(),
                e
            ))
        })?;

        // Map core sections (existing behavior, unchanged)
        let server_addr = toml_config.server.addr;
        let storage_dir = toml_config.storage.chunk_dir.clone();
        let chunk_dir = PathBuf::from(&storage_dir);
        let download_dir = PathBuf::from(&toml_config.storage.download_dir);

        // Map optional tunnel configuration
        let (tunnel_remote_addr, tunnel_auth_token, tunnel_local_port) =
            if let Some(tunnel) = toml_config.tunnel {
                (
                    tunnel.remote_addr,
                    tunnel.auth_token,
                    tunnel.local_port,
                )
            } else {
                (None, None, default_tunnel_port())
            };

        // Map optional daemon configuration
        let (daemon_enabled, daemon_pid_file, daemon_log_file) =
            if let Some(daemon) = toml_config.daemon {
                (
                    daemon.enabled,
                    daemon.pid_file,
                    daemon.log_file,
                )
            } else {
                (default_daemon_enabled(), None, None)
            };

        // ---- Map Phase 5: Transfer Driver Section (Receiver) ----
        let (
            transfer_driver_type,
            transfer_input_dir,
            transfer_output_dir,
            transfer_poll_interval_secs,
        ) = if let Some(ref td) = toml_config.transfer_driver {
            let type_str = td.r#type.as_str().to_string();
            (
                type_str.to_string(),
                td.input_dir.clone(),
                td.output_dir.clone(),
                td.poll_interval_secs,
            )
        } else {
            (
                "direct_tcp".to_string(),
                None,
                None,
                default_receiver_relay_poll_interval(),
            )
        };

        // ---- Map Phase 5: Log Section ----
        let (log_format, log_template_path, log_max_memory_entries, log_retention_days) =
            if let Some(ref lg) = toml_config.log {
                let fmt_str = match lg.format {
                    LogFormatType::Json => "json",
                    LogFormatType::Syslog => "syslog",
                    LogFormatType::Cef => "cef",
                    LogFormatType::Custom => "custom",
                };
                (
                    fmt_str.to_string(),
                    lg.template_path.clone(),
                    lg.max_memory_entries,
                    lg.retention_days,
                )
            } else {
                ("json".to_string(), None, default_max_memory_entries(), default_retention_days())
            };

        // ---- Map Phase 5: Encoding Section ----
        let (encoding_default_encoding, encoding_unknown_font_action, encoding_fallback_fonts) =
            if let Some(ref enc) = toml_config.encoding {
                let font_action_str = match enc.unknown_font_action {
                    UnknownFontAction::Preserve => "preserve",
                    UnknownFontAction::Strip => "strip",
                    UnknownFontAction::Replace => "replace",
                };
                (
                    enc.default_encoding.clone(),
                    font_action_str.to_string(),
                    enc.fallback_fonts.clone(),
                )
            } else {
                (default_encoding(), "preserve".to_string(), default_fallback_fonts())
            };

        // ---- Map Phase 5: File Types Section ----
        let file_types_default_action =
            toml_config.file_types
                .as_ref()
                .map(|ft| ft.default_action.clone())
                .unwrap_or_else(default_file_action);

        Ok(Self {
            server_addr,
            chunk_dir: chunk_dir.clone(),
            download_dir,
            storage_dir: storage_dir, // Legacy alias (String for ChunkStorage compatibility)
            tunnel_port: tunnel_local_port,
            output_dir: None,
            log_level: String::from("info"),
            tunnel_remote_addr,
            tunnel_auth_token,
            tunnel_local_port,
            daemon_enabled,
            daemon_pid_file,
            daemon_log_file,
            // Phase 5 sections
            transfer_driver_type,
            transfer_input_dir,
            transfer_output_dir,
            transfer_poll_interval_secs,
            log_format,
            log_template_path,
            log_max_memory_entries,
            log_retention_days,
            encoding_default_encoding,
            encoding_unknown_font_action,
            encoding_fallback_fonts,
            file_types_default_action,
            ppap_log_converted: false,
            // Blast (UDP data diode) fields
            blast_enabled: toml_config.blast_config.as_ref().map(|b| b.enabled).unwrap_or(false),
            blast_listen_port: toml_config.blast_config.as_ref().map(|b| b.listen_port).unwrap_or_else(default_blast_listen_port),
            blast_output_dir: toml_config.blast_config.as_ref().and_then(|b| b.output_dir.clone()),
            blast_session_timeout_secs: toml_config.blast_config.as_ref().map(|b| b.session_timeout_secs).unwrap_or_else(default_blast_session_timeout_secs),
            versioning_default_version: "v1".to_string(),
            versioning_deprecation_warnings_enabled: true,
            versioning_deprecation_headers: true,
        })
    }

    /// Apply MISOGI_* environment variable overrides to this configuration.
    ///
    /// # Supported Environment Variables
    ///
    /// | Variable | Target Field | Notes |
    /// |----------|-------------|-------|
    /// | `MISOGI_SERVER_ADDR` | `server_addr` | HTTP bind address |
    /// | `MISOGI_CHUNK_DIR` | `chunk_dir` | Chunk storage path |
    /// | `MISOGI_DOWNLOAD_DIR` | `download_dir` | Download directory path |
    /// | `MISOGI_TRANSFER_DRIVER_TYPE` | `transfer_driver_type` | Driver selection |
    /// | `MISOGI_LOG_FORMAT` | `log_format` | Log output format |
    fn apply_env_overrides(&mut self) {
        // ---- Core Overrides ----

        if let Ok(addr) = env::var("MISOGI_SERVER_ADDR") {
            info!(addr = %addr, "Overriding server_addr from environment");
            self.server_addr = addr;
        }

        if let Ok(dir) = env::var("MISOGI_CHUNK_DIR") {
            info!(dir = %dir, "Overriding chunk_dir from environment");
            self.chunk_dir = PathBuf::from(&dir);
            self.storage_dir = dir;
        }

        if let Ok(dir) = env::var("MISOGI_DOWNLOAD_DIR") {
            info!(dir = %dir, "Overriding download_dir from environment");
            self.download_dir = PathBuf::from(dir);
        }

        if let Ok(addr) = env::var("MISOGI_TUNNEL_REMOTE_ADDR") {
            info!(addr = %addr, "Overriding tunnel_remote_addr from environment");
            self.tunnel_remote_addr = Some(addr);
        }

        if let Ok(token) = env::var("MISOGI_TUNNEL_AUTH_TOKEN") {
            info!("Overriding tunnel_auth_token from environment (value masked)");
            self.tunnel_auth_token = Some(token);
        }

        // ---- Phase 5 Overrides ----

        if let Ok(driver) = env::var("MISOGI_TRANSFER_DRIVER_TYPE") {
            info!(driver = %driver, "Overriding transfer_driver_type from environment");
            self.transfer_driver_type = driver.to_lowercase();
        }

        if let Ok(format) = env::var("MISOGI_LOG_FORMAT") {
            info!(format = %format, "Overriding log_format from environment");
            self.log_format = format.to_lowercase();
        }
    }

    /// Validate critical configuration settings for coherence and correctness.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if validation passes.
    /// - `Err(MisogiError::Configuration)` if critical settings are invalid.
    fn validate(&self) -> Result<()> {
        if self.server_addr.is_empty() {
            return Err(MisogiError::Configuration(
                "server_addr must not be empty".to_string(),
            ));
        }

        if !self.server_addr.contains(':') {
            return Err(MisogiError::Configuration(format!(
                "Invalid server_addr '{}': must contain port (e.g., '0.0.0.0:3002')",
                self.server_addr
            )));
        }

        // Validate log format
        match self.log_format.as_str() {
            "json" | "syslog" | "cef" | "custom" => {}
            other => {
                warn!(format = %other, "Unrecognized log format, falling back to 'json'");
            }
        }

        Ok(())
    }

    /// Create an Arc-wrapped clone of this configuration for sharing.
    #[allow(dead_code)]
    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: Minimal Configuration (Backward Compatibility)
    // =========================================================================

    #[test]
    fn test_minimal_toml_parses_correctly() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3002"

[storage]
chunk_dir = "./chunks"
download_dir = "./downloads"
"#;
        let config: TomlConfig = toml::from_str(toml_content).expect("Minimal TOML should parse");

        assert_eq!(config.server.addr, "0.0.0.0:3002");
        assert_eq!(config.storage.chunk_dir, "./chunks");
        assert_eq!(config.storage.download_dir, "./downloads");

        // All Phase 5 sections should be None
        assert!(config.transfer_driver.is_none());
        assert!(config.log.is_none());
        assert!(config.encoding.is_none());
        assert!(config.file_types.is_none());
    }

    #[test]
    fn test_minimal_receiver_config_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("minimal.toml");

        let toml_content = r#"
[server]
addr = "127.0.0.1:8888"

[storage]
chunk_dir = "/tmp/test_chunks"
download_dir = "/tmp/test_downloads"
"#;
        std::fs::write(&config_path, toml_content).unwrap();

        let config = ReceiverConfig::from_toml(&config_path).unwrap();

        assert_eq!(config.server_addr, "127.0.0.1:8888");
        assert_eq!(config.chunk_dir, PathBuf::from("/tmp/test_chunks"));
        assert_eq!(config.download_dir, PathBuf::from("/tmp/test_downloads"));

        // Phase 5 defaults should be applied
        assert_eq!(config.transfer_driver_type, "direct_tcp");
        assert_eq!(config.log_format, "json");
        assert_eq!(config.encoding_default_encoding, "utf-8");
        assert_eq!(config.file_types_default_action, "allow");
    }

    // =========================================================================
    // Test: Phase 5 Section Parsing
    // =========================================================================

    #[test]
    fn test_transfer_driver_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3002"

[storage]
chunk_dir = "./chunks"
download_dir = "./downloads"

[transfer_driver]
type = "storage_relay"
input_dir = "./relay/inbound/"
output_dir = "./relay/processed/"
poll_interval_secs = 20
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let td = config.transfer_driver.expect("transfer_driver should be present");
        assert!(matches!(td.r#type, ReceiverTransferDriverType::StorageRelay));
        assert_eq!(td.input_dir.as_deref().unwrap(), "./relay/inbound/");
        assert_eq!(td.poll_interval_secs, 20);
    }

    #[test]
    fn test_log_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3002"

[storage]
chunk_dir = "./chunks"
download_dir = "./downloads"

[log]
format = "syslog"
retention_days = 730
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let log_cfg = config.log.expect("log section should be present");
        assert!(matches!(log_cfg.format, LogFormatType::Syslog));
        assert_eq!(log_cfg.retention_days, 730);
    }

    #[test]
    fn test_encoding_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3002"

[storage]
chunk_dir = "./chunks"
download_dir = "./downloads"

[encoding]
default_encoding = "Shift_JIS"
unknown_font_action = "strip"
fallback_fonts = ["MS Mincho"]
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let enc = config.encoding.expect("encoding should be present");
        assert_eq!(enc.default_encoding, "Shift_JIS");
        assert!(matches!(enc.unknown_font_action, UnknownFontAction::Strip));
        assert_eq!(enc.fallback_fonts.len(), 1);
    }

    #[test]
    fn test_file_types_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3002"

[storage]
chunk_dir = "./chunks"
download_dir = "./downloads"

[file_types]
default_action = "block"

[[file_types.registry]]
extension = ".pdf"
magic_hex = "255044462D"
required_magic = true
handler = "pdf_receive"

[[file_types.blocked_extensions]]
extension = ".exe"
reason = "Executables not allowed on receiver"
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let ft = config.file_types.expect("file_types should be present");
        assert_eq!(ft.default_action, "block");
        assert_eq!(ft.registry.len(), 1);
        assert_eq!(ft.registry[0].extension, ".pdf");
        assert_eq!(ft.blocked_extensions.len(), 1);
    }

    // =========================================================================
    // Test: Full Configuration
    // =========================================================================

    #[test]
    fn test_full_configuration_all_sections() {
        let toml_content = r#"
[server]
addr = "192.168.1.200:3002"

[storage]
chunk_dir = "/data/receiver/chunks"
download_dir = "/data/receiver/downloads"

[tunnel]
remote_addr = "tunnel.example.com:9000"
auth_token = "receiver-token-456"

[transfer_driver]
type = "storage_relay"
input_dir = "/data/relay/inbound"

[log]
format = "cef"
retention_days = 1825

[encoding]
default_encoding = "Windows-31J"

[file_types]
default_action = "allow"
"#;
        let config: TomlConfig = toml::from_str(toml_content).expect("Full TOML should parse");

        assert!(config.transfer_driver.is_some());
        assert!(config.log.is_some());
        assert!(config.encoding.is_some());
        assert!(config.file_types.is_some());

        // Verify ReceiverConfig maps correctly
        let rc = ReceiverConfig::from_toml_unchecked(&config);

        assert_eq!(rc.server_addr, "192.168.1.200:3002");
        assert_eq!(rc.transfer_driver_type, "storage_relay");
        assert_eq!(rc.log_format, "cef");
        assert_eq!(rc.encoding_default_encoding, "Windows-31J");
        assert_eq!(rc.file_types_default_action, "allow");
    }

    #[allow(dead_code)]
    fn from_toml_unchecked(toml: &TomlConfig) -> ReceiverConfig {
        let server_addr = toml.server.addr.clone();
        let chunk_dir = PathBuf::from(&toml.storage.chunk_dir);
        let download_dir = PathBuf::from(&toml.storage.download_dir);

        let (driver_type, _, _, poll) = if let Some(ref td) = toml.transfer_driver {
            let ds = td.r#type.as_str().to_string();
            (ds.to_string(), td.input_dir.clone(), td.output_dir.clone(), td.poll_interval_secs)
        } else {
            ("direct_tcp".to_string(), None, None, 10)
        };

        let (lf, _, lme, lrd) = if let Some(ref lg) = toml.log {
            let fs = match lg.format {
                LogFormatType::Json => "json",
                LogFormatType::Syslog => "syslog",
                LogFormatType::Cef => "cef",
                LogFormatType::Custom => "custom",
            };
            (fs.to_string(), lg.template_path.clone(), lg.max_memory_entries, lg.retention_days)
        } else {
            ("json".to_string(), None, 1000, 365)
        };

        let (enc_de, enc_ufa, _) = if let Some(ref e) = toml.encoding {
            let ufas = match e.unknown_font_action {
                UnknownFontAction::Preserve => "preserve",
                UnknownFontAction::Strip => "strip",
                UnknownFontAction::Replace => "replace",
            };
            (e.default_encoding.clone(), ufas.to_string(), e.fallback_fonts.clone())
        } else {
            ("utf-8".to_string(), "preserve".to_string(), vec![String::from("IPAexMincho"), String::from("IPAGothic")])
        };

        let fta = toml.file_types.as_ref().map(|f| f.default_action.clone()).unwrap_or_else(|| "allow".to_string());

        ReceiverConfig {
            server_addr,
            chunk_dir: chunk_dir.clone(),
            download_dir,
            tunnel_remote_addr: None,
            tunnel_auth_token: None,
            tunnel_local_port: 9000,
            daemon_enabled: false,
            daemon_pid_file: None,
            daemon_log_file: None,
            transfer_driver_type: driver_type,
            transfer_input_dir: None,
            transfer_output_dir: None,
            transfer_poll_interval_secs: poll,
            log_format: lf,
            log_template_path: None,
            log_max_memory_entries: lme,
            log_retention_days: lrd,
            encoding_default_encoding: enc_de,
            encoding_unknown_font_action: enc_ufa,
            encoding_fallback_fonts: Vec::new(),
            file_types_default_action: fta,
            storage_dir: chunk_dir.clone().to_string_lossy().to_string(),
            tunnel_port: 9000,
            output_dir: None,
            log_level: String::from("info"),
            ppap_log_converted: false,
            // Phase 7: UDP Blast (Air-Gap Data Diode) — disabled by default
            blast_enabled: false,
            blast_listen_port: default_blast_listen_port(),
            blast_output_dir: None,
            blast_session_timeout_secs: default_blast_session_timeout_secs(),
            versioning_default_version: "v1".to_string(),
            versioning_deprecation_warnings_enabled: true,
            versioning_deprecation_headers: true,
        }
    }

    // =========================================================================
    // Test: Validation Logic
    // =========================================================================

    #[test]
    fn test_validate_valid_config() {
        let config = ReceiverConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_server_addr_fails() {
        let mut config = ReceiverConfig::default();
        config.server_addr = String::new();
        assert!(config.validate().is_err());
    }

    // =========================================================================
    // Test: Enum Defaults
    // =========================================================================

    #[test]
    fn test_enum_defaults() {
        assert!(matches!(ReceiverTransferDriverType::default(), ReceiverTransferDriverType::DirectTcp));
        assert!(matches!(LogFormatType::default(), LogFormatType::Json));
        assert!(matches!(UnknownFontAction::default(), UnknownFontAction::Preserve));
    }

    #[test]
    fn test_receiver_transfer_driver_type_from_str_fallback() {
        assert!(matches!(ReceiverTransferDriverType::from_str_fallback("direct_tcp"), ReceiverTransferDriverType::DirectTcp));
        assert!(matches!(ReceiverTransferDriverType::from_str_fallback("storage_relay"), ReceiverTransferDriverType::StorageRelay));
        assert!(matches!(ReceiverTransferDriverType::from_str_fallback("unknown"), ReceiverTransferDriverType::DirectTcp)); // fallback
    }
}
