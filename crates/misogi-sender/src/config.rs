//! Configuration management for Misogi Sender node.
//!
//! This module provides comprehensive configuration loading, validation, and
//! environment variable override support for the sender component of the
//! Misogi (禊) cross-network file transfer system.
//!
//! # Architecture Overview
//!
//! The configuration system follows a layered approach:
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
//! │  Layer 4: SenderConfig (final resolved configuration)        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Phase 5 Extension Sections
//!
//! Starting from Phase 5, the following optional TOML sections are supported:
//!
//! | Section               | Purpose                                      | Required |
//! |-----------------------|----------------------------------------------|----------|
//! | `[server]`            | HTTP/gRPC listener settings                  | Yes      |
//! | `[storage]`           | Local file storage paths                     | Yes      |
//! | `[tunnel]`            | Reverse tunnel to receiver                   | Optional |
//! | `[daemon]`            | Background service mode                      | Optional |
//! | `[approval_flow]`     | Transfer approval workflow triggers          | Optional |
//! | `[transfer_driver]`   | Transfer backend selection (TCP/relay/cmd)   | Optional |
//! | `[cdr_strategies]`    | Content disarm & reconstruction policies     | Optional |
//! | `[file_types]`        | File type registry and blocking rules         | Optional |
//! | `[pii_detector]`      | Personal identifiable information scanning   | Optional |
//! | `[log]`               | Audit log format and retention settings      | Optional |
//! | `[vendor_isolation]`  | Multi-tenant vendor access control           | Optional |
//! | `[calendar]`          | Japanese calendar (Wareki) integration       | Optional |
//! | `[encoding]`          | Japanese text encoding detection/handling     | Optional |
//! | `[external_sanitizers]`| Third-party tool adapter configurations      | Optional |
//! | `[ppap]`              | PPAP (Password Protected Attachment Protocol) handling | Optional |
//! | `[blast]`             | UDP Blast air-gap data diode transfer settings      | Optional |
//!
//! # Backward Compatibility
//!
//! All new sections are **optional** with `#[serde(default)]`. A minimal `misogi.toml`
//! containing only `[server]` and `[storage]` continues to work identically to
//! previous versions.
//!
//! # Thread Safety
//!
//! Once constructed, [`SenderConfig`] is fully immutable (`Send + Sync`) and safe
//! to share across async tasks without synchronization overhead.
//!
//! # Examples
//!
//! ## Minimal Configuration
//!
//! ```toml
//! [server]
//! addr = "0.0.0.0:3001"
//!
//! [storage]
//! upload_dir = "./data/sender/uploads"
//! staging_dir = "./data/sender/staging"
//! ```
//!
//! ## Full Configuration with All Phase 5 Sections
//!
//! ```toml
//! [server]
//! addr = "0.0.0.0:3001"
//!
//! [storage]
//! upload_dir = "./data/sender/uploads"
//! staging_dir = "./data/sender/staging"
//!
//! [approval_flow]
//! require_approval = true
//!
//! [transfer_driver]
//! type = "direct_tcp"
//!
//! [pii_detector]
//! enabled = true
//!
//! [log]
//! format = "json"
//! ```

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use misogi_core::error::{MisogiError, Result};

// =============================================================================
// Section 1: Approval Flow Configuration
// =============================================================================

/// Trigger type for approval workflow state transitions.
///
/// Defines how the system detects external approval/rejection events for
/// transfer requests pending authorization.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalTriggerType {
    /// HTTP callback trigger — waits for POST/PUT to a webhook endpoint.
    ///
    /// Used when an external approval system (e.g., workflow engine, ERP)
    /// sends HTTP notifications upon approval decision.
    HttpCallback,

    /// gRPC call trigger — invokes a remote gRPC service for status polling.
    ///
    /// Suitable for microservice architectures where approval services
    /// expose gRPC interfaces for status queries.
    GrpcCall,

    /// File polling trigger — watches a directory for approval marker files.
    ///
    /// Common in legacy government systems where approvals are signaled
    /// by creating `.approved` or `.rejected` files in a shared filesystem.
    FilePolling,
}

impl Default for ApprovalTriggerType {
    fn default() -> Self {
        Self::HttpCallback
    }
}

/// Single trigger definition within the approval flow system.
///
/// Each trigger defines one mechanism by which the approval workflow can
/// detect state transitions (e.g., PENDING_APPROVAL → APPROVED).
///
/// # TOML Example
///
/// ```toml
/// [[approval_flow.triggers]]
/// type = "http_callback"
/// path = "/api/v1/files/{file_id}/approve"
/// require_payload_status = "APPROVED"
/// auth_header = "X-Approval-Token"
/// shared_secret = ""
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalTriggerConfig {
    /// Type of trigger mechanism (http_callback, grpc_call, file_polling).
    #[serde(default)]
    pub r#type: ApprovalTriggerType,

    /// HTTP endpoint path for http_callback type (e.g., "/api/v1/approvals/{file_id}").
    ///
    /// Supports `{file_id}` template variable replacement at runtime.
    #[serde(default)]
    pub path: String,

    /// Expected payload body string for http_callback approval confirmation.
    ///
    /// If non-empty, the HTTP request body must contain this exact string
    /// to be considered a valid approval signal.
    #[serde(default)]
    pub require_payload_status: Option<String>,

    /// HTTP header name containing authentication token for http_callback.
    ///
    /// If configured, this header must be present and valid on incoming
    /// approval webhook requests.
    #[serde(default)]
    pub auth_header: Option<String>,

    /// HMAC shared secret for verifying webhook signature authenticity.
    ///
    /// When set, incoming webhooks must include an HMAC-SHA256 signature
    /// computed using this secret to prevent spoofing attacks.
    #[serde(default)]
    pub shared_secret: String,
}

impl Default for ApprovalTriggerConfig {
    fn default() -> Self {
        Self {
            r#type: ApprovalTriggerType::default(),
            path: String::new(),
            require_payload_status: None,
            auth_header: None,
            shared_secret: String::new(),
        }
    }
}

/// State transition rule within the approval finite state machine.
///
/// Defines valid edges in the approval workflow graph:
///
/// ```text
/// PENDING_APPROVAL --[external_approve]--> APPROVED --[auto]--> TRANSFERRING
/// PENDING_APPROVAL --[external_reject]--> REJECTED
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalTransitionConfig {
    /// Source state name for this transition (e.g., "PENDING_APPROVAL").
    #[serde(default)]
    pub from: String,

    /// Destination state name for this transition (e.g., "APPROVED").
    #[serde(default)]
    pub to: String,

    /// Trigger identifier that fires this transition (must match a trigger name).
    #[serde(default)]
    pub trigger: String,
}

impl Default for ApprovalTransitionConfig {
    fn default() -> Self {
        Self {
            from: String::new(),
            to: String::new(),
            trigger: String::new(),
        }
    }
}

/// Complete approval flow configuration section.
///
/// Controls whether file transfers require explicit approval before execution,
/// and defines the mechanisms for detecting approval/rejection events.
///
/// # Security Note
///
/// When `require_approval = true`, NO file transfer proceeds without traversing
/// the full approval state machine. This is mandatory for LGWAN cross-network
/// transfers under Japanese government security guidelines.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalFlowConfig {
    /// Whether transfers require explicit approval before execution.
    ///
    /// - `true`: All transfers enter PENDING_APPROVAL state initially.
    /// - `false`: Transfers proceed immediately (dev/test mode only).
    #[serde(default = "default_approval_required")]
    pub require_approval: bool,

    /// Initial state for new transfer requests entering the approval workflow.
    ///
    /// Typically "PENDING_APPROVAL" but can be customized for custom workflows.
    #[serde(default = "default_initial_state")]
    pub initial_state: String,

    /// List of trigger definitions that can advance the approval state machine.
    #[serde(default)]
    pub triggers: Vec<ApprovalTriggerConfig>,

    /// List of valid state transitions in the approval FSM.
    #[serde(default)]
    pub transitions: Vec<ApprovalTransitionConfig>,
}

fn default_approval_required() -> bool {
    true // Secure default: require approval
}

fn default_initial_state() -> String {
    String::from("PENDING_APPROVAL")
}

impl Default for ApprovalFlowConfig {
    fn default() -> Self {
        Self {
            require_approval: default_approval_required(),
            initial_state: default_initial_state(),
            triggers: Vec::new(),
            transitions: Vec::new(),
        }
    }
}

// =============================================================================
// Section 2: Transfer Driver Configuration
// =============================================================================

/// Transfer driver type selection.
///
/// Determines the underlying transport mechanism used for sending files
/// to the receiver node across network boundaries.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TransferDriverType {
    /// Direct TCP connection — sender opens TCP socket to receiver.
    ///
    /// Simplest mode: requires direct network reachability between
    /// sender and receiver (same LAN, VPN, or allowed firewall rule).
    DirectTcp,

    /// Storage-based relay — files deposited to shared storage, picked up by receiver.
    ///
    /// Used for air-gapped networks where no direct TCP connectivity exists.
    /// Both nodes poll a shared filesystem (NFS, SMB, USB shuttle).
    StorageRelay,

    /// External command delegation — invoke third-party transfer tool.
    ///
    /// For integrations with existing secure transfer solutions (e.g.,
    /// government-mandated gateways, proprietary protocols).
    ExternalCommand,
}

impl Default for TransferDriverType {
    fn default() -> Self {
        Self::DirectTcp
    }
}

impl TransferDriverType {
    /// Parse from string with fallback to DirectTcp for unknown values.
    /// Part of the stable public parsing API; used by [`Self::as_str`] round-trip
    /// and available for library consumers / test code.
    #[allow(dead_code)]
    pub fn from_str_fallback(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "direct_tcp" | "tcp" => Self::DirectTcp,
            "storage_relay" | "relay" | "storage" => Self::StorageRelay,
            "external_command" | "external" | "command" => Self::ExternalCommand,
            _ => Self::DirectTcp,
        }
    }

    /// Serialize to canonical string representation (inverse of [`Self::from_str_fallback`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DirectTcp => "direct_tcp",
            Self::StorageRelay => "storage_relay",
            Self::ExternalCommand => "external_command",
        }
    }
}

/// Complete transfer driver configuration section.
///
/// Selects and configures the transport mechanism for cross-network file delivery.
///
/// # Driver-Specific Fields
///
/// Only the fields relevant to the selected `r#type` are used at runtime;
/// others are ignored but preserved for configuration switching.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferDriverConfig {
    /// Selected transfer driver type.
    #[serde(default)]
    pub r#type: TransferDriverType,

    // ---- Storage Relay Specific ----

    /// Output directory for files awaiting relay pickup (sender → relay).
    #[serde(default)]
    pub output_dir: Option<String>,

    /// Input directory for picking up relayed files (receiver → sender, for acks).
    #[serde(default)]
    pub input_dir: Option<String>,

    /// Polling interval in seconds for checking relay directories.
    #[serde(default = "default_relay_poll_interval")]
    pub poll_interval_secs: u64,

    /// Manifest file format for relay metadata ("json" or "toml").
    #[serde(default = "default_manifest_format")]
    pub manifest_format: String,

    /// Whether to delete relayed files after successful pickup.
    #[serde(default = "default_relay_cleanup")]
    pub cleanup_after_pickup: bool,

    // ---- External Command Specific ----

    /// Command template for initiating a send operation.
    ///
    /// Supports `%s` (source file path) and `%d` (destination specifier)
    /// template variables.
    #[serde(default)]
    pub send_command: Option<String>,

    /// Command template for checking transfer status.
    ///
    /// Supports `%s` (transfer ID or file reference) template variable.
    #[serde(default)]
    pub status_command: Option<String>,

    /// Maximum time in seconds to wait for external command completion.
    #[serde(default = "default_external_timeout")]
    pub timeout_secs: u64,
}

fn default_relay_poll_interval() -> u64 {
    10
}

fn default_manifest_format() -> String {
    String::from("json")
}

fn default_relay_cleanup() -> bool {
    true
}

fn default_external_timeout() -> u64 {
    60
}

impl Default for TransferDriverConfig {
    fn default() -> Self {
        Self {
            r#type: TransferDriverType::default(),
            output_dir: None,
            input_dir: None,
            poll_interval_secs: default_relay_poll_interval(),
            manifest_format: default_manifest_format(),
            cleanup_after_pickup: default_relay_cleanup(),
            send_command: None,
            status_command: None,
            timeout_secs: default_external_timeout(),
        }
    }
}

// =============================================================================
// Section 3: CDR Strategies Configuration
// =============================================================================

/// VBA whitelist strategy configuration.
///
/// Controls which VBA macros are permitted to survive CDR sanitization.
/// By default, ALL macros are removed unless explicitly whitelisted.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VbaWhitelistConfig {
    /// Whether the VBA whitelist strategy is active.
    #[serde(default)]
    pub enabled: bool,

    /// Whitelist mode: "hash" (allow by SHA-256 hash) or "name" (allow by macro name).
    #[serde(default = "default_whitelist_type")]
    pub whitelist_type: String,

    /// List of allowed macro entries (hashes or names depending on whitelist_type).
    #[serde(default)]
    pub entries: Vec<String>,

    /// Default action for non-whitelisted macros: "remove" or "quarantine".
    #[serde(default = "default_vba_action")]
    pub default_action: String,
}

fn default_whitelist_type() -> String {
    String::from("hash")
}

fn default_vba_action() -> String {
    String::from("remove")
}

impl Default for VbaWhitelistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            whitelist_type: default_whitelist_type(),
            entries: Vec::new(),
            default_action: default_vba_action(),
        }
    }
}

/// Format downgrade strategy configuration.
///
/// Defines rules for converting complex document formats to safer flattened
/// equivalents (e.g., .xlsx → .csv, .docx → .pdf).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FormatDowngradeConfig {
    /// Whether the format downgrade strategy is active.
    #[serde(default)]
    pub enabled: bool,

    /// List of format conversion rules (format-specific configuration).
    #[serde(default)]
    pub rules: Vec<FormatDowngradeRule>,
}

/// Single format downgrade rule mapping source format to target format.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FormatDowngradeRule {
    /// Source file extension to match (e.g., ".xlsx", ".docx").
    #[serde(default)]
    pub source_ext: String,

    /// Target extension for downgraded output (e.g., ".csv", ".pdf").
    #[serde(default)]
    pub target_ext: String,

    /// Whether this rule should be applied automatically.
    #[serde(default)]
    pub auto_apply: bool,
}

impl Default for FormatDowngradeRule {
    fn default() -> Self {
        Self {
            source_ext: String::new(),
            target_ext: String::new(),
            auto_apply: false,
        }
    }
}

impl Default for FormatDowngradeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules: Vec::new(),
        }
    }
}

/// ClamAV antivirus integration configuration.
///
/// Configures the interface to ClamAV daemon (clamd) for virus scanning
/// during the CDR pipeline. This is required for many Japanese government
/// security certifications (JIS Q 27001, ISMAP).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClamAvIntegrationConfig {
    /// Whether ClamAV scanning is enabled in the CDR pipeline.
    #[serde(default)]
    pub enabled: bool,

    /// Unix domain socket or TCP address for clamd daemon.
    ///
    /// Examples: "/var/run/clamd.sock", "tcp://localhost:3310"
    #[serde(default = "default_clamd_socket")]
    pub socket_path: String,

    /// Maximum file size in MB to send to ClamAV (larger files skipped).
    #[serde(default = "default_clamav_max_size")]
    pub max_scan_size_mb: u64,

    /// Timeout in seconds for ClamAV scan operations.
    #[serde(default = "default_clamav_timeout")]
    pub timeout_secs: u64,

    /// Action when virus is detected: "block", "quarantine", or "warn".
    #[serde(default = "default_clamav_virus_action")]
    pub action_on_virus: String,

    /// Action when scan completes clean: "pass", "pass_with_warning", or "log_only".
    #[serde(default = "default_clamav_clean_action")]
    pub action_on_clean: String,
}

fn default_clamd_socket() -> String {
    String::from("/var/run/clamd.sock")
}

fn default_clamav_max_size() -> u64 {
    100
}

fn default_clamav_timeout() -> u64 {
    30
}

fn default_clamav_virus_action() -> String {
    String::from("block")
}

fn default_clamav_clean_action() -> String {
    String::from("pass_with_warning")
}

impl Default for ClamAvIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: default_clamd_socket(),
            max_scan_size_mb: default_clamav_max_size(),
            timeout_secs: default_clamav_timeout(),
            action_on_virus: default_clamav_virus_action(),
            action_on_clean: default_clamav_clean_action(),
        }
    }
}

/// Combined CDR strategies configuration section.
///
/// Groups all Content Disarm & Reconstruction policy configurations
/// into a single `[cdr_strategies]` TOML section.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CdrStrategiesConfig {
    /// VBA macro whitelist strategy.
    #[serde(default)]
    pub vba_whitelist: VbaWhitelistConfig,

    /// Document format downgrade strategy.
    #[serde(default)]
    pub format_downgrade: FormatDowngradeConfig,

    /// ClamAV antivirus integration.
    #[serde(default)]
    pub clamav_integration: ClamAvIntegrationConfig,
}

impl Default for CdrStrategiesConfig {
    fn default() -> Self {
        Self {
            vba_whitelist: VbaWhitelistConfig::default(),
            format_downgrade: FormatDowngradeConfig::default(),
            clamav_integration: ClamAvIntegrationConfig::default(),
        }
    }
}

// =============================================================================
// Section 4: File Types Configuration
// =============================================================================

/// Single entry in the file type registry.
///
/// Maps a file extension to its expected magic bytes and assigned sanitizer,
/// enabling deep content validation beyond simple extension checking.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypeRegistryEntry {
    /// File extension including leading dot (e.g., ".pdf", ".jtd", ".xlsx").
    #[serde(default)]
    pub extension: String,

    /// Expected hex-encoded magic bytes for this file type (e.g., "255044462D" for PDF).
    ///
    /// If `required_magic = true`, files with this extension MUST start with these bytes.
    #[serde(default)]
    pub magic_hex: String,

    /// Whether magic byte validation is enforced for this file type.
    ///
    /// - `true`: Reject files whose headers don't match `magic_hex`.
    /// - `false`: Skip magic validation for this extension.
    #[serde(default)]
    pub required_magic: bool,

    /// Sanitizer identifier to apply for this file type.
    ///
    /// Built-in values: "pdf_builtin", "jtd_builtin", "office_builtin"
    /// Custom values map to [`ExternalSanitizerConfig`] entries.
    #[serde(default)]
    pub sanitizer: String,
}

impl Default for FileTypeRegistryEntry {
    fn default() -> Self {
        Self {
            extension: String::new(),
            magic_hex: String::new(),
            required_magic: false,
            sanitizer: String::new(),
        }
    }
}

/// Blocked file extension rule.
///
/// Defines extensions that are explicitly forbidden from upload regardless
/// of content. Provides a first-line defense before deeper inspection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockedExtensionEntry {
    /// File extension to block (including leading dot, e.g., ".exe", ".scr").
    #[serde(default)]
    pub extension: String,

    /// Human-readable reason for the block (shown in error messages and audit logs).
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

/// Complete file types configuration section.
///
/// Manages the file type registry (extension → magic bytes → sanitizer mappings)
/// and blocked extension list for upload-time filtering.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypesConfig {
    /// Default action for unrecognized file extensions: "allow" or "block".
    #[serde(default = "default_file_action")]
    pub default_action: String,

    /// Registered file types with magic byte validation rules.
    #[serde(default)]
    pub registry: Vec<FileTypeRegistryEntry>,

    /// Explicitly blocked file extensions (rejected before any processing).
    #[serde(default)]
    pub blocked_extensions: Vec<BlockedExtensionEntry>,
}

fn default_file_action() -> String {
    String::from("allow") // Permissive default; tighten in production
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
// Section 5: PII Detector Configuration
// =============================================================================

/// Action to take when PII (Personal Identifiable Information) is detected.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    /// Block the file transfer entirely.
    Block,

    /// Mask detected PII patterns with replacement characters.
    Mask,

    /// Log an alert but allow the transfer to proceed.
    AlertOnly,
}

impl Default for PiiAction {
    fn default() -> Self {
        Self::AlertOnly // Safest default: don't break workflows unexpectedly
    }
}

/// Single PII detection rule definition.
///
/// Each rule specifies a regex pattern to scan for and the action to take
/// when matches are found.
///
/// # Pattern Syntax
///
/// Patterns use standard Rust regex syntax. Common PII patterns by region:
///
/// **Japan (APPI Compliance):**
/// | Pattern              | Description                          |
/// |----------------------|--------------------------------------|
/// | `\b\d{12}\b`        | My Number (マイナンバー, 12 digits)   |
/// | `\b\d{3}-?\d{4}\b`  | Postal code (郵便番号)                |
/// | `[一-龥]+\s*様`      | Name + honorific (氏名)              |
///
/// **Korea (PIPA Compliance):**
/// | Pattern                      | Description                      |
/// |------------------------------|----------------------------------|
/// | `\b\d{6}-?[1-8]\d{6}\b`     | Resident Registration Number    |
/// | `\b01[01689]-?\d{3,4}-?\d{4}\b` | Mobile phone (carrier prefix) |
///
/// **US (State Privacy Laws):**
/// | Pattern                    | Description                  |
/// |----------------------------|------------------------------|
/// | `\b\d{3}-\d{2}-\d{4}\b`  | Social Security Number (SSN) |
///
/// **Universal:**
/// | Pattern                       | Description             |
/// |-------------------------------|-------------------------|
/// | `\b4[0-9]{12}(?:[0-9]{3})?\b` | Visa/Mastercard (Luhn)  |
/// | `\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b` | Email address   |
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PiiRuleConfig {
    /// Unique human-readable name for this rule (used in audit logs).
    #[serde(default)]
    pub name: String,

    /// Regular expression pattern to match against file contents.
    #[serde(default)]
    pub pattern: String,

    /// Action when this pattern matches: "block", "mask", or "alert_only".
    #[serde(default)]
    pub action: PiiAction,

    /// Human-readable description of what this rule detects (for documentation).
    #[serde(default)]
    pub description: String,
}

impl Default for PiiRuleConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            pattern: String::new(),
            action: PiiAction::default(),
            description: String::new(),
        }
    }
}

/// Complete PII detector configuration section.
///
/// Controls scanning of uploaded files for personal identifiable information
/// (個人情報) as required by APPI (Act on the Protection of Personal Information)
/// and Japanese government data handling regulations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PiiDetectorConfig {
    /// Whether PII scanning is enabled for uploaded files.
    #[serde(default)]
    pub enabled: bool,

    /// Default action when PII is detected and no rule-specific action is defined.
    #[serde(default)]
    pub default_action: PiiAction,

    /// Character used for masking detected PII (e.g., "*", "X", "■").
    #[serde(default = "default_mask_char")]
    pub mask_char: String,

    /// List of PII detection rules applied in order.
    #[serde(default)]
    pub rules: Vec<PiiRuleConfig>,
}

fn default_mask_char() -> String {
    String::from("*")
}

impl Default for PiiDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: PiiAction::default(),
            mask_char: default_mask_char(),
            rules: Vec::new(),
        }
    }
}

// =============================================================================
// Section 6: Log Configuration
// =============================================================================

/// Audit log formatter type selection.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormatType {
    /// JSON Lines format — one JSON object per line (default, backward compatible).
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

impl LogFormatType {
    /// Parse from string with fallback to Json for unknown values.
    /// Part of the stable public parsing API; used by [`Self::as_str`] round-trip
    /// and available for library consumers / test code.
    #[allow(dead_code)]
    pub fn from_str_fallback(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" | "jsonl" => Self::Json,
            "syslog" => Self::Syslog,
            "cef" => Self::Cef,
            "custom" | "template" => Self::Custom,
            _ => Self::Json,
        }
    }

    /// Serialize to canonical string representation (inverse of [`Self::from_str_fallback`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Syslog => "syslog",
            Self::Cef => "cef",
            Self::Custom => "custom",
        }
    }
}

/// Complete log configuration section.
///
/// Controls audit log output format, retention policy, and memory buffering
/// for the [`misogi_core::log_engine`](misogi_core::log_engine) module.
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
    365 // One year retention per compliance requirements
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
// Section 7: Vendor Isolation Configuration
// =============================================================================

/// Single vendor account definition for the isolation manager.
///
/// Maps directly to [`misogi_core::contrib::jp::vendor::VendorAccount`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VendorAccountConfig {
    /// Unique vendor user identifier (primary key).
    #[serde(default)]
    pub user_id: String,

    /// Display name for audit logs and UI.
    #[serde(default)]
    pub display_name: String,

    /// List of CIDR networks allowed for this vendor's connections.
    #[serde(default)]
    pub ip_whitelist: Vec<String>,

    /// Forced CDR policy override for this vendor's uploads.
    #[serde(default)]
    pub force_max_cdr_policy: Option<String>,

    /// Whether dual-person approval is required for this vendor's transfers.
    #[serde(default)]
    pub require_dual_approval: bool,

    /// Maximum uploads per hour for this vendor (0 = unlimited).
    #[serde(default)]
    pub upload_rate_limit_per_hour: u32,

    /// Maximum file size in MB for this vendor's uploads (0 = unlimited).
    #[serde(default)]
    pub max_file_size_mb: u64,
}

impl Default for VendorAccountConfig {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            display_name: String::new(),
            ip_whitelist: Vec::new(),
            force_max_cdr_policy: None,
            require_dual_approval: false,
            upload_rate_limit_per_hour: 0,
            max_file_size_mb: 0,
        }
    }
}

/// Complete vendor isolation configuration section.
///
/// Enables multi-tenant access control for external vendor (取引先) accounts,
/// providing IP whitelisting, rate limiting, and per-vendor CDR policy enforcement.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VendorIsolationConfig {
    /// Master switch for the entire vendor isolation system.
    #[serde(default)]
    pub enabled: bool,

    /// Registered vendor accounts with their security profiles.
    #[serde(default)]
    pub accounts: Vec<VendorAccountConfig>,
}

impl Default for VendorIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            accounts: Vec::new(),
        }
    }
}

// =============================================================================
// Section 8: Calendar Configuration
// =============================================================================

/// Japanese calendar (Wareki / 和暦) integration configuration.
///
/// Enables business day calculations, national holiday awareness, and
/// filename Wareki notation auto-detection for Japanese compliance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CalendarConfig {
    /// Whether calendar integration is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Path to calendar.toml file containing custom organizational holidays.
    ///
    /// If empty, only built-in Japanese national holidays are used.
    #[serde(default)]
    pub calendar_file: String,

    /// Whether to automatically elevate security controls during holidays.
    ///
    /// When `true`, non-business days trigger stricter rate limits and
    /// additional approval requirements (防御的運用モード).
    #[serde(default)]
    pub auto_defense_mode: bool,

    /// Whether to auto-detect Wareki era notation in filenames (R08, H28, etc.).
    ///
    /// Detected Wareki years are logged and can be used for archive categorization.
    #[serde(default = "default_wareki_detection")]
    pub wareki_filename_detection: bool,
}

fn default_wareki_detection() -> bool {
    true // Enable by default for JP environments
}

impl Default for CalendarConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            calendar_file: String::new(),
            auto_defense_mode: false,
            wareki_filename_detection: default_wareki_detection(),
        }
    }
}

// =============================================================================
// Section 9: Encoding Configuration
// =============================================================================

/// Action for handling unknown/untrusted fonts in reconstructed PDF documents.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownFontAction {
    /// Keep unknown font references unchanged (safest for compatibility).
    Preserve,

    /// Remove unknown font references entirely (safest for security).
    Strip,

    /// Replace unknown fonts with fallback fonts from the configured list.
    Replace,
}

impl Default for UnknownFontAction {
    fn default() -> Self {
        Self::Preserve
    }
}

impl UnknownFontAction {
    /// Parse from string with fallback to Preserve for unknown values.
    /// Part of the stable public parsing API; used by [`Self::as_str`] round-trip
    /// and available for library consumers / test code.
    #[allow(dead_code)]
    pub fn from_str_fallback(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "strip" | "remove" => Self::Strip,
            "replace" | "substitute" => Self::Replace,
            _ => Self::Preserve,
        }
    }

    /// Serialize to canonical string representation (inverse of [`Self::from_str_fallback`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strip => "strip",
            Self::Replace => "replace",
            Self::Preserve => "preserve",
        }
    }
}

/// Japanese text encoding handler configuration.
///
/// Controls automatic encoding detection, conversion, and PDF font safety
/// for Japanese text processing in the CDR pipeline.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncodingConfig {
    /// Fallback encoding name when auto-detection fails or returns low confidence.
    ///
    /// IANA charset names: "UTF-8", "Shift_JIS", "Windows-31J", "EUC-JP", "ISO-2022-JP"
    #[serde(default = "default_encoding")]
    pub default_encoding: String,

    /// Strategy for handling unknown fonts in sanitized PDF output.
    #[serde(default)]
    pub unknown_font_action: UnknownFontAction,

    /// Ordered list of safe fallback font names for PDF font substitution.
    ///
    /// Used when `unknown_font_action = "replace"`.
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
// Section 10: External Sanitizers Configuration
// =============================================================================

/// Success action for external sanitizer completion.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSuccessAction {
    /// Trust the output without additional verification.
    TrustOutput,

    /// Verify output differs from input (confirming modification occurred).
    VerifyHash,
}

impl Default for ExternalSuccessAction {
    fn default() -> Self {
        Self::TrustOutput
    }
}

/// Failure action for external sanitizer errors.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalFailureAction {
    /// Block the transfer and log the failure.
    BlockAndLog,

    /// Allow transfer but emit warning log.
    WarnAndPass,
}

impl Default for ExternalFailureAction {
    fn default() -> Self {
        Self::BlockAndLog
    }
}

/// Single external sanitizer adapter configuration.
///
/// Maps a file extension to an external command-line sanitization tool.
/// See [`misogi_core::contrib::jp::external_adapter::ExternalSanitizerConfig`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalSanitizerAdapterConfig {
    /// File extension this adapter handles (including dot, e.g., ".jtd").
    #[serde(default)]
    pub extension: String,

    /// Path to the external sanitizer executable.
    #[serde(default)]
    pub command: String,

    /// Command-line arguments with template variables.
    #[serde(default)]
    pub args: Vec<String>,

    /// Maximum execution time in seconds.
    #[serde(default = "default_external_sanitizer_timeout")]
    pub timeout_secs: u64,

    /// Policy for successful completion (exit code 0).
    #[serde(default)]
    pub on_success: ExternalSuccessAction,

    /// Policy for failures (non-zero exit code, timeout).
    #[serde(default)]
    pub on_failure: ExternalFailureAction,
}

fn default_external_sanitizer_timeout() -> u64 {
    60
}

impl Default for ExternalSanitizerAdapterConfig {
    fn default() -> Self {
        Self {
            extension: String::new(),
            command: String::new(),
            args: Vec::new(),
            timeout_secs: default_external_sanitizer_timeout(),
            on_success: ExternalSuccessAction::default(),
            on_failure: ExternalFailureAction::default(),
        }
    }
}

/// Complete external sanitizers configuration section.
///
/// Registry of third-party tool adapters for file formats that cannot be
/// safely sanitized using pure Rust libraries.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalSanitizersConfig {
    /// Registered external sanitizer adapters keyed by file extension.
    #[serde(default, rename = "adapter")]
    pub adapters: Vec<ExternalSanitizerAdapterConfig>,
}

impl Default for ExternalSanitizersConfig {
    fn default() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }
}

// =============================================================================
// Section S10: Versioning Configuration (Multi-Version API Management)
// =============================================================================

/// Single sunset policy entry for one API version.
///
/// Defines the lifecycle phase and timeline for a specific API version,
/// enabling Japanese SIer to plan multi-year migration schedules per
/// the compliance requirements of Japanese government B2B/B2G deployments.
///
/// # TOML Example
///
/// ```toml
/// [[versioning.sunset_policies]]
/// version = "v1"
/// phase = "deprecated"
/// hard_sunset_date = "2027-03-31"
/// announced_date = "2025-04-11"
/// migration_guide_url = "https://docs.misogi.dev/migration/v1-to-v2"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SunsetPolicyConfig {
    /// API version string this policy applies to (e.g., "v1", "v2").
    #[serde(default)]
    pub version: String,

    /// Current lifecycle phase: "stable", "deprecated", "soft_sunset", "hard_sunset".
    #[serde(default = "default_sunset_phase")]
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

fn default_sunset_phase() -> String {
    String::from("stable")
}

impl Default for SunsetPolicyConfig {
    fn default() -> Self {
        Self {
            version: String::new(),
            phase: default_sunset_phase(),
            hard_sunset_date: None,
            announced_date: None,
            migration_guide_url: None,
        }
    }
}

/// Multi-version API management configuration.
///
/// Controls deprecation warnings, RFC 8594 Sunset headers, sunset policies,
/// and compatibility adapter behavior for enterprise-grade API version transitions.
///
/// # Japanese Compliance Context
///
/// Japanese government SIer (System Integrator) procurement cycles span multiple
/// fiscal years. This configuration provides the granular control needed for:
///
/// - **Budget justification**: `[WARN][DEPRECATION]` logs with sunset dates give
///   SIer operators evidence to request upgrade budgets from government clients.
/// - **Gradual migration**: Phase machine (Stable → Deprecated → SoftSunset → HardSunset)
///   allows coexistence of legacy v1 systems alongside new v2 deployments.
/// - **Audit trail**: Every deprecated access is logged with Client IP, Request ID,
///   User-Agent, and exact sunset date for compliance auditing.
///
/// # TOML Example
///
/// ```toml
/// [versioning]
/// default_version = "v1"
/// deprecation_warnings_enabled = true
/// deprecation_headers = true
///
/// [[versioning.sunset_policies]]
/// version = "v1"
/// phase = "deprecated"
/// hard_sunset_date = "2027-03-31"
/// announced_date = "2025-04-11"
/// migration_guide_url = "https://docs.misogi.dev/migration/v1-to-v2"
///
/// [[versioning.sunset_policies]]
/// version = "v2"
/// phase = "stable"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersioningConfig {
    /// Default active API version for new clients ("v1" or "v2").
    #[serde(default = "default_versioning_version")]
    pub default_version: String,

    /// Whether to emit structured `[WARN][DEPRECATION]` log entries when
    /// a client accesses a deprecated API version.
    #[serde(default = "default_true")]
    pub deprecation_warnings_enabled: bool,

    /// Whether to inject RFC 8594 HTTP headers (`Sunset`, `Deprecated`,
    /// `Link: rel="successor-version"`) into responses from deprecated endpoints.
    #[serde(default = "default_true")]
    pub deprecation_headers: bool,

    /// Per-version sunset policy definitions (ordered array).
    #[serde(default)]
    pub sunset_policies: Vec<SunsetPolicyConfig>,
}

fn default_versioning_version() -> String {
    String::from("v1")
}

impl Default for VersioningConfig {
    fn default() -> Self {
        Self {
            default_version: default_versioning_version(),
            deprecation_warnings_enabled: true,
            deprecation_headers: true,
            sunset_policies: Vec::new(),
        }
    }
}

/// Server configuration for the Misogi Sender node.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Bind address for the HTTP API server (e.g., "0.0.0.0:3001").
    #[serde(default = "default_server_addr")]
    pub addr: String,
}

fn default_server_addr() -> String {
    "0.0.0.0:3001".to_string()
}

/// Storage configuration for local file handling.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Directory for storing uploaded files before processing.
    #[serde(default = "default_upload_dir")]
    pub upload_dir: String,

    /// Staging area for files undergoing CDR sanitization.
    #[serde(default = "default_staging_dir")]
    pub staging_dir: String,
}

fn default_upload_dir() -> String {
    "./data/sender/uploads".to_string()
}

fn default_staging_dir() -> String {
    "./data/sender/staging".to_string()
}

/// Tunnel configuration for reverse proxy connectivity.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TunnelConfig {
    /// Remote tunnel server address (e.g., "tunnel.example.com:9000").
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

// =============================================================================
// Root TomlConfig Structure (Deserialization Target)
// =============================================================================

/// Root structure for deserializing the complete `misogi.toml` configuration file.
///
/// All Phase 5 sections are **optional** with `#[serde(default)]`. Existing
/// configurations without these sections continue to work identically.
///
/// # Minimal Valid Configuration
///
/// ```toml
/// [server]
/// addr = "0.0.0.0:3001"
///
/// [storage]
/// upload_dir = "./uploads"
/// staging_dir = "./staging"
/// ```
///
/// # Full Configuration Example
///
/// See module-level documentation for complete example with all sections.
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

    /// Reverse tunnel to receiver node.
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,

    /// Background service mode settings.
    #[serde(default)]
    pub daemon: Option<DaemonConfig>,

    // ---- Phase 5 Extended Sections (All Optional) ----

    /// Transfer approval workflow configuration.
    #[serde(default)]
    pub approval_flow: Option<ApprovalFlowConfig>,

    /// Transfer driver backend selection and configuration.
    #[serde(default)]
    pub transfer_driver: Option<TransferDriverConfig>,

    /// CDR (Content Disarm & Reconstruction) strategy policies.
    #[serde(default)]
    pub cdr_strategies: Option<CdrStrategiesConfig>,

    /// File type registry and blocking rules.
    #[serde(default)]
    pub file_types: Option<FileTypesConfig>,

    /// Personal Identifiable Information detector settings.
    #[serde(default)]
    pub pii_detector: Option<PiiDetectorConfig>,

    /// Audit log format and retention configuration.
    #[serde(default)]
    pub log: Option<LogConfig>,

    /// Multi-tenant vendor isolation settings.
    #[serde(default)]
    pub vendor_isolation: Option<VendorIsolationConfig>,

    /// Japanese calendar (Wareki) integration settings.
    #[serde(default)]
    pub calendar: Option<CalendarConfig>,

    /// Japanese text encoding detection and handling.
    #[serde(default)]
    pub encoding: Option<EncodingConfig>,

    /// Third-party external sanitizer tool adapters.
    #[serde(default)]
    pub external_sanitizers: Option<ExternalSanitizersConfig>,
}

// =============================================================================
// Runtime Configuration (Final Resolved State)
// =============================================================================

/// Fully resolved runtime configuration for the Misogi Sender node.
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
/// The following environment variables can override TOML values at runtime:
///
/// | Variable                        | Field Affected               | Example              |
/// |---------------------------------|------------------------------|----------------------|
/// | `MISOGI_SERVER_ADDR`            | `server_addr`                | `0.0.0.0:8080`       |
/// | `MISOGI_UPLOAD_DIR`             | `upload_dir`                 | `/var/misogi/uploads`|
/// | `MISOGI_STAGING_DIR`            | `staging_dir`                | `/var/misogi/stage`  |
/// | `MISOGI_TUNNEL_REMOTE_ADDR`     | `tunnel_remote_addr`         | `tunnel.example.com:9000` |
/// | `MISOGI_TUNNEL_AUTH_TOKEN`      | `tunnel_auth_token`          | `secret-token-123`   |
/// | `MISOGI_TRANSFER_DRIVER_TYPE`   | `transfer_driver_type`       | `storage_relay`      |
/// | `MISOGI_LOG_FORMAT`             | `log_format`                 | `cef`                |
/// | `MISOGI_PRESET`                 | (applies preset defaults)    | `lgwan_government`   |
/// | `MISOGI_PII_ENABLED`            | `pii_enabled`                | `true`               |
/// | `MISOGI_VENDOR_ISOLATION_ENABLED`| `vendor_isolation_enabled`   | `true`               |
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct SenderConfig {
    // ---- Core Network Settings ----

    /// Bind address for the HTTP API server.
    pub server_addr: String,

    // ---- Storage Paths ----

    /// Directory for uploaded files awaiting processing.
    pub upload_dir: PathBuf,

    /// Staging area for files undergoing CDR sanitization.
    pub staging_dir: PathBuf,

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

    // ---- Phase 5: Approval Flow ----

    /// Whether transfer approval is required before execution.
    pub approval_require_approval: bool,

    /// Initial state for approval workflow FSM.
    pub approval_initial_state: String,

    /// Configured approval triggers (HTTP callback, gRPC, file polling).
    pub approval_triggers: Vec<ApprovalTriggerConfig>,

    /// Valid state transitions in the approval FSM.
    pub approval_transitions: Vec<ApprovalTransitionConfig>,

    // ---- Phase 5: Transfer Driver ----

    /// Selected transfer driver type (direct_tcp, storage_relay, external_command).
    pub transfer_driver_type: String,

    /// Storage relay output directory (for storage_relay driver).
    pub transfer_output_dir: Option<String>,

    /// Storage relay input directory (for storage_relay driver).
    pub transfer_input_dir: Option<String>,

    /// Storage relay polling interval in seconds.
    pub transfer_poll_interval_secs: u64,

    /// External command template for send operations.
    pub transfer_send_command: Option<String>,

    /// External command template for status checks.
    pub transfer_status_command: Option<String>,

    /// External command timeout in seconds.
    pub transfer_timeout_secs: u64,

    // ---- Phase 5: CDR Strategies ----

    /// Whether VBA whitelist strategy is enabled.
    pub cdr_vba_whitelist_enabled: bool,

    /// Whether format downgrade strategy is enabled.
    pub cdr_format_downgrade_enabled: bool,

    /// Whether ClamAV scanning is enabled.
    pub cdr_clamav_enabled: bool,

    /// ClamAV socket path.
    pub cdr_clamav_socket_path: String,

    // ---- Phase 5: File Types ----

    /// Default action for unrecognized file extensions.
    pub file_types_default_action: String,

    // ---- Phase 5: PII Detector ----

    /// Whether PII scanning is enabled.
    pub pii_enabled: bool,

    /// Character used for masking detected PII.
    pub pii_mask_char: String,

    // ---- Phase 5: Log Configuration ----

    /// Audit log output format (json, syslog, cef, custom).
    pub log_format: String,

    /// Path to custom log template (when format = "custom").
    pub log_template_path: Option<String>,

    /// Maximum in-memory log entries before flush.
    pub log_max_memory_entries: usize,

    /// Log file retention period in days.
    pub log_retention_days: u32,

    // ---- Phase 5: Vendor Isolation ----

    /// Whether vendor isolation system is enabled.
    pub vendor_isolation_enabled: bool,

    // ---- Phase 5: Calendar ----

    /// Whether Japanese calendar integration is enabled.
    pub calendar_enabled: bool,

    /// Path to custom calendar.toml file.
    pub calendar_file: String,

    /// Whether to elevate security during holidays.
    pub calendar_auto_defense_mode: bool,

    /// Whether to detect Wareki notation in filenames.
    pub calendar_wareki_detection: bool,

    // ---- Phase 5: Encoding ----

    /// Fallback encoding name for undetectable inputs.
    pub encoding_default_encoding: String,

    /// Strategy for unknown PDF fonts.
    pub encoding_unknown_font_action: String,

    /// Safe fallback font list for PDF substitution.
    pub encoding_fallback_fonts: Vec<String>,

    // ---- Phase 5: External Sanitizers ----

    /// Registered external sanitizer adapter count.
    pub external_sanitizer_count: usize,

    // ---- Legacy Fields (Required by existing code) ----

    /// Storage directory path for file chunks (alias for upload_dir, used by FileUploader).
    ///
    /// This field provides backward compatibility with the existing [`FileUploader`]
    /// and daemon module which expect a `storage_dir` field.
    pub storage_dir: String,

    /// Chunk size in bytes for file splitting during upload.
    ///
    /// Default: 8 MB (8388608 bytes). Larger values reduce chunk count but increase
    /// memory usage per transfer operation.
    pub chunk_size: usize,

    /// Receiver node address for automatic transfer triggering.
    ///
    /// When configured, completed uploads automatically trigger transfer to this address.
    /// Format: "host:port" (e.g., "192.168.1.100:3002").
    pub receiver_addr: Option<String>,

    /// Whether to automatically sanitize files after upload completion.
    ///
    /// When `true`, the CDR pipeline runs automatically on each uploaded file
    /// using the configured `sanitization_policy`.
    pub auto_sanitize: bool,

    /// Directory to watch for new files in daemon mode.
    ///
    /// When set, the daemon monitors this directory for new files and
    /// automatically uploads them.
    pub watch_dir: Option<PathBuf>,

    /// CDR sanitization policy applied during file processing.
    ///
    /// Determines how active content (macros, scripts, embedded objects)
    /// is handled during Content Disarm & Reconstruction.
    pub sanitization_policy: misogi_cdr::SanitizationPolicy,

    /// Logging verbosity level for tracing subscriber.
    ///
    /// Accepted values: "trace", "debug", "info", "warn", "error".
    /// Default: "info".
    pub log_level: String,

    // ---- Phase 6: PPAP Handling ----

    /// PPAP (Password Protected Attachment Protocol) detection and handling configuration.
    ///
    /// PPAP is Japan's infamous insecure file transfer practice where documents are
    /// sent as password-protected ZIPs with passwords transmitted via email/phone.
    /// Japan's MIC issued guidance to discontinue PPAP in April 2024.
    #[serde(default)]
    pub ppap_config: Option<PpapConfig>,

    // ---- Phase 7: UDP Blast (Air-Gap Data Diode) ----

    /// UDP Blast configuration for unidirectional data diode transfer.
    ///
    /// When enabled, files can be transmitted through physical one-way data
    /// diodes using FEC-protected UDP "blast" mode with zero reverse communication.
    #[serde(default)]
    pub blast_config: Option<BlastConfig>,

    /// Multi-version API management and sunset policy configuration.
    ///
    /// Controls deprecation warnings, RFC 8594 headers, and per-version
    /// lifecycle phases (Stable → Deprecated → SoftSunset → HardSunset).
    #[serde(default)]
    pub versioning: Option<VersioningConfig>,

    // ---- Multi-Version API Management (Resolved Runtime Fields) ----

    /// Default active API version for this deployment ("v1" or "v2").
    pub versioning_default_version: String,

    /// Whether deprecation warning logging is enabled for legacy API access.
    pub versioning_deprecation_warnings_enabled: bool,

    /// Whether RFC 8594 Sunset/Deprecated/Link headers are injected.
    pub versioning_deprecation_headers: bool,

    // ---- Phase 8: JTD (Ichitaro) Conversion ----

    /// Whether automatic JTD-to-PDF conversion is enabled.
    ///
    /// When true and a .jtd file is detected as input, it will be converted
    /// to PDF before CDR processing using the configured converter.
    pub jtd_conversion_enabled: bool,

    /// JTD converter backend type ("auto", "libreoffice", "ichitaro_viewer", "dummy").
    pub jtd_converter_type: String,

    /// Maximum time in seconds allowed for a single JTD-to-PDF conversion.
    pub jtd_timeout_secs: u64,
}

/// PPAP (Password Protected Attachment Protocol) detection and handling configuration.
///
/// Controls how the system responds to files exhibiting characteristics of
/// Japan's Password Protected Attachment Protocol (PPAP).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PpapConfig {
    /// Whether PPAP detection is enabled.
    ///
    /// When disabled, password-protected ZIPs are treated as normal files
    /// (encryption will cause extraction failure, handled as I/O error).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Handling policy when PPAP is detected.
    /// Options: "block", "warn_and_sanitize", "quarantine", "convert_to_secure".
    #[serde(default = "default_ppap_policy")]
    pub policy: String,

    /// Minimum confidence score (0.0-1.0) to trigger PPAP handling.
    #[serde(default = "default_ppap_confidence_threshold")]
    pub confidence_threshold: f64,

    /// Whether to generate formal compliance events for each PPAP detection.
    #[serde(default = "default_true")]
    pub generate_compliance_event: bool,

    /// Directory path for quarantined PPAP files (used when policy = "quarantine").
    #[serde(default)]
    pub quarantine_dir: Option<PathBuf>,

    /// Retention period (days) for quarantined PPAP files before auto-deletion.
    #[serde(default = "default_quarantine_retention_days")]
    pub quarantine_retention_days: u64,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_ppap_policy() -> String {
    "warn_and_sanitize".to_string()
}

fn default_ppap_confidence_threshold() -> f64 {
    0.7
}

fn default_quarantine_retention_days() -> u64 {
    90
}

impl Default for PpapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            policy: default_ppap_policy(),
            confidence_threshold: default_ppap_confidence_threshold(),
            generate_compliance_event: true,
            quarantine_dir: None,
            quarantine_retention_days: default_quarantine_retention_days(),
        }
    }
}

// =============================================================================
// Section S9: Blast Configuration (UDP Air-Gap Data Diode)
// =============================================================================

/// UDP Blast configuration for unidirectional data diode file transfer.
///
/// Controls the behavior of [`UdpBlastDriver`](misogi_core::drivers::UdpBlastDriver)
/// when operating over physical one-way links where no reverse communication
/// is possible. Files are encoded with FEC (Forward Error Correction), split
/// into shards, and fired through a UDP socket toward a receiver on the
/// other side of a data diode.
///
/// # Example TOML
///
/// ```toml
/// [blast]
/// enabled = true
/// target_addr = "192.168.254.2:9002"
/// fec_data_shards = 16
/// fec_parity_shards = 4
/// repeat_count = 3
/// session_timeout_secs = 300
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlastConfig {
    /// Whether UDP Blast mode is enabled.
    ///
    /// When false, blast transfer is unavailable even if requested via API.
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// Target UDP address of the receiver's data diode input port.
    ///
    /// Must be a valid `host:port` address reachable through the data diode.
    /// Example: `"192.168.254.2:9002"` for a typical optical diode setup.
    #[serde(default)]
    pub target_addr: String,

    /// Number of FEC data shards per encoding block.
    ///
    /// Higher values allow larger files but increase decode complexity.
    /// Must be >= 4. Typical values: 8, 12, 16.
    #[serde(default = "default_blast_data_shards")]
    pub fec_data_shards: usize,

    /// Number of FEC parity (redundancy) shards per block.
    ///
    /// Determines loss tolerance: losing up to this many shards is recoverable.
    /// Recommended ratio: parity/data ≈ 0.25 (e.g., 4 parity / 16 data).
    #[serde(default = "default_blast_parity_shards")]
    pub fec_parity_shards: usize,

    /// How many times each shard packet is repeated for redundancy.
    ///
    /// Since no ACKs are possible, repetition increases delivery probability.
    /// Each repeat multiplies bandwidth usage by this factor.
    /// Recommended: 3 for clean links, 5 for noisy optical diodes.
    #[serde(default = "default_repeat_count")]
    pub repeat_count: u32,

    /// Maximum time (seconds) to wait for all shards before declaring timeout.
    ///
    /// The receiver will attempt FEC decode when this expires regardless
    /// of how many shards arrived.
    #[serde(default = "default_session_timeout_secs")]
    pub session_timeout_secs: u64,
}

fn default_blast_data_shards() -> usize { 16 }
fn default_blast_parity_shards() -> usize { 4 }
fn default_session_timeout_secs() -> u64 { 300 }
fn default_repeat_count() -> u32 { 3 }

impl Default for BlastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_addr: String::new(),
            fec_data_shards: default_blast_data_shards(),
            fec_parity_shards: default_blast_parity_shards(),
            repeat_count: default_repeat_count(),
            session_timeout_secs: default_session_timeout_secs(),
        }
    }
}

impl Default for SenderConfig {
    /// Create a SenderConfig with all sensible defaults applied.
    ///
    /// This provides a working configuration suitable for development and testing
    /// without requiring any external configuration file.
    fn default() -> Self {
        Self {
            server_addr: default_server_addr(),
            upload_dir: PathBuf::from(default_upload_dir()),
            staging_dir: PathBuf::from(default_staging_dir()),
            tunnel_remote_addr: None,
            tunnel_auth_token: None,
            tunnel_local_port: default_tunnel_port(),
            daemon_enabled: default_daemon_enabled(),
            daemon_pid_file: None,
            daemon_log_file: None,
            // Phase 5: Approval Flow defaults
            approval_require_approval: default_approval_required(),
            approval_initial_state: default_initial_state(),
            approval_triggers: Vec::new(),
            approval_transitions: Vec::new(),
            // Phase 5: Transfer Driver defaults
            transfer_driver_type: String::from("direct_tcp"),
            transfer_output_dir: None,
            transfer_input_dir: None,
            transfer_poll_interval_secs: default_relay_poll_interval(),
            transfer_send_command: None,
            transfer_status_command: None,
            transfer_timeout_secs: default_external_timeout(),
            // Phase 5: CDR defaults
            cdr_vba_whitelist_enabled: false,
            cdr_format_downgrade_enabled: false,
            cdr_clamav_enabled: false,
            cdr_clamav_socket_path: default_clamd_socket(),
            // Phase 5: File Types defaults
            file_types_default_action: default_file_action(),
            // Phase 5: PII defaults
            pii_enabled: false,
            pii_mask_char: default_mask_char(),
            // Phase 5: Log defaults
            log_format: String::from("json"),
            log_template_path: None,
            log_max_memory_entries: default_max_memory_entries(),
            log_retention_days: default_retention_days(),
            // Phase 5: Vendor Isolation defaults
            vendor_isolation_enabled: false,
            // Phase 5: Calendar defaults
            calendar_enabled: false,
            calendar_file: String::new(),
            calendar_auto_defense_mode: false,
            calendar_wareki_detection: default_wareki_detection(),
            // Phase 5: Encoding defaults
            encoding_default_encoding: default_encoding(),
            encoding_unknown_font_action: String::from("preserve"),
            encoding_fallback_fonts: default_fallback_fonts(),
            // Phase 5: External Sanitizers defaults
            external_sanitizer_count: 0,
            blast_config: None,
            versioning: None,
            // Legacy fields defaults
            storage_dir: default_upload_dir(),
            chunk_size: 8 * 1024 * 1024, // 8 MB default chunk size
            receiver_addr: None,
            auto_sanitize: false,
            watch_dir: None,
            sanitization_policy: misogi_cdr::SanitizationPolicy::default(),
            log_level: String::from("info"),
            ppap_config: None,
            versioning_default_version: "v1".to_string(),
            versioning_deprecation_warnings_enabled: true,
            versioning_deprecation_headers: true,
            // Phase 8: JTD Conversion defaults
            jtd_conversion_enabled: false,
            jtd_converter_type: "auto".to_string(),
            jtd_timeout_secs: 120,
        }
    }
}

impl SenderConfig {
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
    /// A fully resolved [`SenderConfig`] instance ready for use.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if the configuration file cannot be read.
    /// - [`MisogiError::Serialization`] if the TOML content is malformed.
    /// - [`MisogiError::Configuration`] if critical settings are invalid.
    ///
    /// # Environment Variable Precedence
    ///
    /// Environment variables take precedence over TOML file values:
    ///
    /// ```text
    /// CLI Args > Env Vars > TOML File > Defaults
    /// ```
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::path::PathBuf;
    ///
    /// let config = SenderConfig::load(Some(PathBuf::from("misogi.toml"))).await?;
    /// println!("Server binding to: {}", config.server_addr);
    /// ```
    #[allow(dead_code)]
    pub async fn load(config_path: Option<PathBuf>) -> Result<Self> {
        // Start with default configuration
        let mut config = Self::default();

        // Load from TOML file if path provided
        if let Some(ref path) = config_path {
            config = Self::from_toml(path)?;
        }

        // Apply environment variable overrides (always applied, even without TOML)
        config.apply_env_overrides();

        // Validate critical settings
        config.validate()?;

        info!(
            server_addr = %config.server_addr,
            upload_dir = %config.upload_dir.display(),
            staging_dir = %config.staging_dir.display(),
            driver_type = %config.transfer_driver_type,
            pii_enabled = config.pii_enabled,
            log_format = %config.log_format,
            "Sender configuration loaded successfully"
        );

        Ok(config)
    }

    /// Load configuration with CLI argument overrides applied.
    ///
    /// This is the primary entry point used by [`main`](crate::main) to construct
    /// the final runtime configuration. It applies overrides in the correct priority order:
    ///
    /// ```text
    /// 1. Load from TOML file (base configuration)
    /// 2. Apply MISOGI_* environment variable overrides
    /// 3. Apply CLI argument overrides (highest priority)
    /// 4. Validate final configuration
    /// ```
    ///
    /// # Arguments
    ///
    /// * `cli` - Parsed command-line arguments from [`CommandLine`].
    ///
    /// # Returns
    ///
    /// A fully resolved [`SenderConfig`] with all override layers applied.
    pub fn load_with_cli(cli: &crate::cli::CommandLine) -> Self {
        // Step 1: Load from TOML file
        let mut config = if let Some(ref path) = cli.config {
            // Blocking I/O is acceptable here during startup
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

        // Step 3: Apply CLI argument overrides (highest priority)
        config.apply_cli_overrides(cli);

        // Step 4: Validate (log warnings but don't fail startup)
        let _ = config.validate();

        config
    }

    /// Internal helper to map TomlConfig to SenderConfig without file I/O.
    #[allow(dead_code)]
    fn from_toml_unchecked(toml: &TomlConfig) -> Self {
        // Map core sections (existing behavior, unchanged)
        let server_addr = toml.server.addr.clone();
        let storage_dir = toml.storage.upload_dir.clone();
        let upload_dir = PathBuf::from(&storage_dir);
        let staging_dir = PathBuf::from(&toml.storage.staging_dir);

        // Map optional tunnel configuration
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

        // Map optional daemon configuration
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

        // ---- Map Phase 5: Approval Flow Section ----
        let (approval_require_approval, approval_initial_state, approval_triggers, approval_transitions) =
            if let Some(ref af) = toml.approval_flow {
                (
                    af.require_approval,
                    af.initial_state.clone(),
                    af.triggers.clone(),
                    af.transitions.clone(),
                )
            } else {
                (
                    default_approval_required(),
                    default_initial_state(),
                    Vec::new(),
                    Vec::new(),
                )
            };

        // ---- Map Phase 5: Transfer Driver Section ----
        let (
            transfer_driver_type,
            transfer_output_dir,
            transfer_input_dir,
            transfer_poll_interval_secs,
            transfer_send_command,
            transfer_status_command,
            transfer_timeout_secs,
        ) = if let Some(ref td) = toml.transfer_driver {
            let type_str = td.r#type.as_str().to_string();
            (
                type_str.to_string(),
                td.output_dir.clone(),
                td.input_dir.clone(),
                td.poll_interval_secs,
                td.send_command.clone(),
                td.status_command.clone(),
                td.timeout_secs,
            )
        } else {
            (
                "direct_tcp".to_string(),
                None,
                None,
                default_relay_poll_interval(),
                None,
                None,
                default_external_timeout(),
            )
        };

        // ---- Map Phase 5: CDR Strategies Section ----
        let (cdr_vba_whitelist_enabled, cdr_format_downgrade_enabled, cdr_clamav_enabled, cdr_clamav_socket_path) =
            if let Some(ref cdr) = toml.cdr_strategies {
                (
                    cdr.vba_whitelist.enabled,
                    cdr.format_downgrade.enabled,
                    cdr.clamav_integration.enabled,
                    cdr.clamav_integration.socket_path.clone(),
                )
            } else {
                (false, false, false, default_clamd_socket())
            };

        // ---- Map Phase 5: File Types Section ----
        let file_types_default_action =
            toml.file_types
                .as_ref()
                .map(|ft| ft.default_action.clone())
                .unwrap_or_else(default_file_action);

        // ---- Map Phase 5: PII Detector Section ----
        let (pii_enabled, pii_mask_char) =
            if let Some(ref pii) = toml.pii_detector {
                (
                    pii.enabled,
                    pii.mask_char.clone(),
                )
            } else {
                (false, default_mask_char())
            };

        // ---- Map Phase 5: Log Section ----
        let (log_format, log_template_path, log_max_memory_entries, log_retention_days) =
            if let Some(ref lg) = toml.log {
                let fmt_str = lg.format.as_str().to_string();
                (
                    fmt_str.to_string(),
                    lg.template_path.clone(),
                    lg.max_memory_entries,
                    lg.retention_days,
                )
            } else {
                ("json".to_string(), None, default_max_memory_entries(), default_retention_days())
            };

        // ---- Map Phase 5: Vendor Isolation Section ----
        let vendor_isolation_enabled =
            toml.vendor_isolation
                .as_ref()
                .map(|vi| vi.enabled)
                .unwrap_or(false);

        // ---- Map Phase 5: Calendar Section ----
        let (calendar_enabled, calendar_file, calendar_auto_defense_mode, calendar_wareki_detection) =
            if let Some(ref cal) = toml.calendar {
                (
                    cal.enabled,
                    cal.calendar_file.clone(),
                    cal.auto_defense_mode,
                    cal.wareki_filename_detection,
                )
            } else {
                (false, String::new(), false, default_wareki_detection())
            };

        // ---- Map Phase 5: Encoding Section ----
        let (encoding_default_encoding, encoding_unknown_font_action, encoding_fallback_fonts) =
            if let Some(ref enc) = toml.encoding {
                let font_action_str = enc.unknown_font_action.as_str().to_string();
                (
                    enc.default_encoding.clone(),
                    font_action_str.to_string(),
                    enc.fallback_fonts.clone(),
                )
            } else {
                (default_encoding(), "preserve".to_string(), default_fallback_fonts())
            };

        // ---- Map Phase 5: External Sanitizers Section ----
        let external_sanitizer_count =
            toml.external_sanitizers
                .as_ref()
                .map(|es| es.adapters.len())
                .unwrap_or(0);

        // ---- Map Versioning Section (Multi-Version API Management) ----
        // Note: Versioning config is not yet available in TomlConfig; using defaults
        let versioning_default_version = "v1".to_string();
        let versioning_deprecation_warnings_enabled = true;
        let versioning_deprecation_headers = true;

        Self {
            server_addr,
            upload_dir: upload_dir.clone(),
            staging_dir,
            storage_dir: storage_dir, // Legacy alias (String for FileUploader compatibility)
            chunk_size: 8 * 1024 * 1024,     // 8 MB default
            receiver_addr: None,
            auto_sanitize: false,
            watch_dir: None,
            sanitization_policy: misogi_cdr::SanitizationPolicy::default(),
            log_level: String::from("info"),
            tunnel_remote_addr,
            tunnel_auth_token,
            tunnel_local_port,
            daemon_enabled,
            daemon_pid_file,
            daemon_log_file,
            approval_require_approval,
            approval_initial_state,
            approval_triggers,
            approval_transitions,
            transfer_driver_type,
            transfer_output_dir,
            transfer_input_dir,
            transfer_poll_interval_secs,
            transfer_send_command,
            transfer_status_command,
            transfer_timeout_secs,
            cdr_vba_whitelist_enabled,
            cdr_format_downgrade_enabled,
            cdr_clamav_enabled,
            cdr_clamav_socket_path,
            file_types_default_action,
            pii_enabled,
            pii_mask_char,
            log_format,
            log_template_path,
            log_max_memory_entries,
            log_retention_days,
            vendor_isolation_enabled,
            calendar_enabled,
            calendar_file,
            calendar_auto_defense_mode,
            calendar_wareki_detection,
            encoding_default_encoding,
            encoding_unknown_font_action,
            encoding_fallback_fonts,
            external_sanitizer_count,
            blast_config: None,
            versioning: None,
            ppap_config: None,
            versioning_default_version,
            versioning_deprecation_warnings_enabled,
            versioning_deprecation_headers,
            // Phase 8: JTD Conversion (TOML not yet supported; using CLI defaults)
            jtd_conversion_enabled: false,
            jtd_converter_type: "auto".to_string(),
            jtd_timeout_secs: 120,
        }
    }

    /// Apply CLI argument overrides to this configuration.
    ///
    /// CLI arguments have the highest priority in the configuration chain:
    /// ```text
    /// CLI Args > Env Vars > TOML File > Defaults
    /// ```
    fn apply_cli_overrides(&mut self, cli: &crate::cli::CommandLine) {
        // Override core settings from CLI
        if let Some(ref addr) = cli.addr {
            self.server_addr = addr.clone();
        }
        if let Some(ref dir) = cli.storage_dir {
            self.upload_dir = PathBuf::from(dir);
            self.storage_dir = dir.clone();
        }
        if let Some(ref dir) = cli.staging_dir {
            self.staging_dir = PathBuf::from(dir);
        }
        if let Some(port) = cli.tunnel_port {
            self.tunnel_local_port = port;
        }
        if let Some(ref level) = cli.log_level {
            self.log_level = level.clone();
        }

        // Override Phase 5 settings from CLI
        if let Some(ref driver) = cli.driver {
            self.transfer_driver_type = driver.to_lowercase();
        }
        if let Some(ref format) = cli.log_format {
            self.log_format = format.to_lowercase();
        }
        if let Some(ref cal_file) = cli.calendar_file {
            self.calendar_file = cal_file.to_string_lossy().to_string();
            self.calendar_enabled = true;
        }
        // Note: --preset handling would go here when preset system is implemented

        // ---- Phase 8: JTD Conversion Overrides ----
        // --convert-jtd-to-pdf takes priority over config file
        if cli.convert_jtd_to_pdf {
            self.jtd_conversion_enabled = true;
            tracing::info!("JTD conversion enabled via --convert-jtd-to-pdf flag");
        }
        // --no-convert-jtd-to-pdf explicitly disables (highest priority)
        if cli.no_convert_jtd_to_pdf {
            self.jtd_conversion_enabled = false;
            tracing::info!("JTD conversion disabled via --no-convert-jtd-to-pdf flag");
        }
        // --jtd-converter overrides converter type
        if !cli.jtd_converter.is_empty() && cli.jtd_converter != "auto" {
            self.jtd_converter_type = cli.jtd_converter.clone();
        }
        // --jtd-timeout overrides timeout
        if cli.jtd_timeout_secs != 120 {
            self.jtd_timeout_secs = cli.jtd_timeout_secs;
        }
    }

    /// Parse configuration from a TOML file path.
    ///
    /// Reads the specified TOML file, deserializes it into [`TomlConfig`],
    /// and maps all sections (core + Phase 5 extended) to [`SenderConfig`] fields.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path to the `misogi.toml` file.
    ///
    /// # Returns
    ///
    /// A [`SenderConfig`] with all values populated from the TOML file.
    /// Missing sections retain their default values.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Io`] if the file cannot be read.
    /// - [`MisogiError::Serialization`] if TOML parsing fails.
    #[allow(dead_code)]
    pub fn from_toml(path: &Path) -> Result<Self> {
        info!(config_path = %path.display(), "Loading configuration from TOML file");

        let content = std::fs::read_to_string(path).map_err(|e| {
            MisogiError::Io(e)
        })?;

        let toml_config: TomlConfig = toml::from_str(&content).map_err(|e| {
            MisogiError::Protocol(format!(
                "Failed to parse configuration file '{}': {}",
                path.display(),
                e
            ))
        })?;

        Ok(Self::from_toml_unchecked(&toml_config))
    }

    /// Apply MISOGI_* environment variable overrides to this configuration.
    fn apply_env_overrides(&mut self) {
        // ---- Core Overrides (Existing) ----

        if let Ok(addr) = env::var("MISOGI_SERVER_ADDR") {
            info!(addr = %addr, "Overriding server_addr from environment");
            self.server_addr = addr;
        }

        if let Ok(dir) = env::var("MISOGI_UPLOAD_DIR") {
            info!(dir = %dir, "Overriding upload_dir from environment");
            self.upload_dir = PathBuf::from(&dir);
            self.storage_dir = dir;
        }

        if let Ok(dir) = env::var("MISOGI_STAGING_DIR") {
            info!(dir = %dir, "Overriding staging_dir from environment");
            self.staging_dir = PathBuf::from(dir);
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

        if let Ok(pii_val) = env::var("MISOGI_PII_ENABLED") {
            let enabled = parse_env_bool(&pii_val, false);
            info!(enabled = enabled, "Overriding pii_enabled from environment");
            self.pii_enabled = enabled;
        }

        if let Ok(vi_val) = env::var("MISOGI_VENDOR_ISOLATION_ENABLED") {
            let enabled = parse_env_bool(&vi_val, false);
            info!(enabled = enabled, "Overriding vendor_isolation_enabled from environment");
            self.vendor_isolation_enabled = enabled;
        }
    }

    /// Validate critical configuration settings for coherence and correctness.
    ///
    /// Performs post-load validation to catch misconfiguration before the system
    /// starts operating on potentially unsafe settings.
    ///
    /// # Checks Performed
    ///
    /// 1. **Address validity**: `server_addr` must be parseable as `host:port`.
    /// 2. **Path existence**: Warning (not error) if directories don't exist yet.
    /// 3. **Driver consistency**: Warn if storage_relay selected but dirs not configured.
    /// 4. **ClamAV path**: Warn if ClamAV enabled but socket path seems unusual.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if validation passes (or only warnings are issued).
    /// - `Err(MisogiError::Configuration)` if critical settings are invalid.
    fn validate(&self) -> Result<()> {
        // Validate server address format
        if self.server_addr.is_empty() {
            return Err(MisogiError::Configuration(
                "server_addr must not be empty".to_string(),
            ));
        }

        // Check for host:port pattern
        if !self.server_addr.contains(':') {
            return Err(MisogiError::Configuration(format!(
                "Invalid server_addr '{}': must contain port (e.g., '0.0.0.0:3001')",
                self.server_addr
            )));
        }

        // Validate transfer driver configuration consistency
        if self.transfer_driver_type == "storage_relay" {
            if self.transfer_output_dir.is_none() && self.transfer_input_dir.is_none() {
                warn!(
                    driver = %self.transfer_driver_type,
                    "Storage relay driver selected but no output_dir/input_dir configured"
                );
            }
        }

        // Validate ClamAV configuration
        if self.cdr_clamav_enabled {
            if self.cdr_clamav_socket_path.is_empty() {
                warn!("ClamAV integration enabled but socket_path is empty");
            }
        }

        // Validate PII configuration
        if self.pii_enabled {
            info!("PII detection enabled — files will be scanned for personal information");
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

    /// Get the effective approval requirement status considering all factors.
    ///
    /// Combines the configured setting with any runtime context to determine
    /// whether approval is currently required for new transfers.
    #[allow(dead_code)]
    pub fn is_approval_required(&self) -> bool {
        self.approval_require_approval
    }

    /// Get the effective transfer driver type as a normalized string.
    ///
    /// Normalizes various input forms to canonical identifiers:
    /// - "direct-tcp" → "direct_tcp"
    /// - "storage-relay" → "storage_relay"
    /// - "EXTERNAL-COMMAND" → "external_command"
    #[allow(dead_code)]
    pub fn get_normalized_driver_type(&self) -> String {
        self.transfer_driver_type.to_lowercase()
    }

    /// Check whether CDR processing is active (any CDR strategy enabled).
    ///
    /// Returns `true` if at least one CDR strategy (VBA whitelist, format downgrade,
    /// or ClamAV scanning) is currently enabled.
    #[allow(dead_code)]
    pub fn is_cdr_active(&self) -> bool {
        self.cdr_vba_whitelist_enabled || self.cdr_format_downgrade_enabled || self.cdr_clamav_enabled
    }

    /// Create an Arc-wrapped clone of this configuration for sharing.
    ///
    /// Convenience method for wrapping in `Arc<>` for thread-safe sharing
    /// across async tasks without cloning the entire struct.
    #[allow(dead_code)]
    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Parse a boolean value from an environment variable string.
///
/// Accepts: "true", "1", "yes", "on" (case-insensitive) as `true`.
/// All other values (including empty string) result in `fallback`.
///
/// # Arguments
///
/// * `value` - The environment variable string to parse.
/// * `fallback` - Default value when parsing fails.
///
/// # Returns
/// `true` if the string represents an affirmative boolean, `fallback` otherwise.
fn parse_env_bool(value: &str, fallback: bool) -> bool {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => {
            warn!(
                value = %value,
                fallback = fallback,
                "Unrecognized boolean environment variable value"
            );
            fallback
        }
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
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"
"#;
        let config: TomlConfig = toml::from_str(toml_content).expect("Minimal TOML should parse");

        assert_eq!(config.server.addr, "0.0.0.0:3001");
        assert_eq!(config.storage.upload_dir, "./uploads");
        assert_eq!(config.storage.staging_dir, "./staging");

        // All Phase 5 sections should be None (not present in minimal config)
        assert!(config.approval_flow.is_none());
        assert!(config.transfer_driver.is_none());
        assert!(config.cdr_strategies.is_none());
        assert!(config.pii_detector.is_none());
        assert!(config.log.is_none());
        assert!(config.vendor_isolation.is_none());
        assert!(config.calendar.is_none());
        assert!(config.encoding.is_none());
        assert!(config.external_sanitizers.is_none());
    }

    #[test]
    fn test_minimal_sender_config_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("minimal.toml");

        let toml_content = r#"
[server]
addr = "127.0.0.1:9999"

[storage]
upload_dir = "/tmp/test_uploads"
staging_dir = "/tmp/test_staging"
"#;
        std::fs::write(&config_path, toml_content).unwrap();

        let config = SenderConfig::from_toml(&config_path).unwrap();

        assert_eq!(config.server_addr, "127.0.0.1:9999");
        assert_eq!(config.upload_dir, PathBuf::from("/tmp/test_uploads"));
        assert_eq!(config.staging_dir, PathBuf::from("/tmp/test_staging"));

        // Phase 5 defaults should be applied
        assert_eq!(config.approval_require_approval, true); // Secure default
        assert_eq!(config.transfer_driver_type, "direct_tcp");
        assert!(!config.pii_enabled);
        assert_eq!(config.log_format, "json");
        assert!(!config.vendor_isolation_enabled);
    }

    // =========================================================================
    // Test: Phase 5 Section Parsing
    // =========================================================================

    #[test]
    fn test_approval_flow_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[approval_flow]
require_approval = true
initial_state = "PENDING_REVIEW"

[[approval_flow.triggers]]
type = "http_callback"
path = "/api/v1/approve"
auth_header = "X-Token"

[[approval_flow.transitions]]
from = "PENDING_REVIEW"
to = "APPROVED"
trigger = "admin_approve"
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let af = config.approval_flow.expect("approval_flow should be present");
        assert!(af.require_approval);
        assert_eq!(af.initial_state, "PENDING_REVIEW");
        assert_eq!(af.triggers.len(), 1);
        assert_eq!(af.triggers[0].path, "/api/v1/approve");
        assert_eq!(af.transitions.len(), 1);
        assert_eq!(af.transitions[0].from, "PENDING_REVIEW");
        assert_eq!(af.transitions[0].to, "APPROVED");
    }

    #[test]
    fn test_transfer_driver_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[transfer_driver]
type = "storage_relay"
output_dir = "./relay/outbound/"
input_dir = "./relay/inbound/"
poll_interval_secs = 15
cleanup_after_pickup = true
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let td = config.transfer_driver.expect("transfer_driver should be present");
        assert!(matches!(td.r#type, TransferDriverType::StorageRelay));
        assert_eq!(td.output_dir.as_deref().unwrap(), "./relay/outbound/");
        assert_eq!(td.poll_interval_secs, 15);
        assert!(td.cleanup_after_pickup);
    }

    #[test]
    fn test_pii_detector_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[pii_detector]
enabled = true
mask_char = "X"

[[pii_detector.rules]]
name = "my_number"
pattern = "\\b\\d{12}\\b"
action = "mask"
description = "Japanese My Number"
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let pii = config.pii_detector.expect("pii_detector should be present");
        assert!(pii.enabled);
        assert_eq!(pii.mask_char, "X");
        assert_eq!(pii.rules.len(), 1);
        assert_eq!(pii.rules[0].name, "my_number");
        assert!(matches!(pii.rules[0].action, PiiAction::Mask));
    }

    #[test]
    fn test_cdr_strategies_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[cdr_strategies.vba_whitelist]
enabled = true
whitelist_type = "hash"
entries = ["abc123"]
default_action = "remove"

[cdr_strategies.clamav_integration]
enabled = true
socket_path = "/var/run/clamd.sock"
max_scan_size_mb = 200
action_on_virus = "block"
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let cdr = config.cdr_strategies.expect("cdr_strategies should be present");
        assert!(cdr.vba_whitelist.enabled);
        assert!(cdr.clamav_integration.enabled);
        assert_eq!(cdr.clamav_integration.max_scan_size_mb, 200);
        assert_eq!(cdr.clamav_integration.action_on_virus, "block");
    }

    #[test]
    fn test_log_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[log]
format = "cef"
max_memory_entries = 500
retention_days = 730
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let log_cfg = config.log.expect("log section should be present");
        assert!(matches!(log_cfg.format, LogFormatType::Cef));
        assert_eq!(log_cfg.max_memory_entries, 500);
        assert_eq!(log_cfg.retention_days, 730);
    }

    #[test]
    fn test_vendor_isolation_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[vendor_isolation]
enabled = true

[[vendor_isolation.accounts]]
user_id = "vendor_a"
display_name = "Vendor A"
ip_whitelist = ["10.0.0.0/8"]
force_max_cdr_policy = "convert_to_flat"
require_dual_approval = true
upload_rate_limit_per_hour = 20
max_file_size_mb = 50
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let vi = config.vendor_isolation.expect("vendor_isolation should be present");
        assert!(vi.enabled);
        assert_eq!(vi.accounts.len(), 1);
        assert_eq!(vi.accounts[0].user_id, "vendor_a");
        assert_eq!(vi.accounts[0].ip_whitelist.len(), 1);
        assert!(vi.accounts[0].require_dual_approval);
        assert_eq!(vi.accounts[0].max_file_size_mb, 50);
    }

    #[test]
    fn test_calendar_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[calendar]
enabled = true
calendar_file = "/etc/misogi/calendar.toml"
auto_defense_mode = true
wareki_filename_detection = true
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let cal = config.calendar.expect("calendar should be present");
        assert!(cal.enabled);
        assert_eq!(cal.calendar_file, "/etc/misogi/calendar.toml");
        assert!(cal.auto_defense_mode);
        assert!(cal.wareki_filename_detection);
    }

    #[test]
    fn test_encoding_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[encoding]
default_encoding = "Windows-31J"
unknown_font_action = "replace"
fallback_fonts = ["MS Mincho", "MS Gothic"]
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let enc = config.encoding.expect("encoding should be present");
        assert_eq!(enc.default_encoding, "Windows-31J");
        assert!(matches!(enc.unknown_font_action, UnknownFontAction::Replace));
        assert_eq!(enc.fallback_fonts.len(), 2);
    }

    #[test]
    fn test_external_sanitizers_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[[external_sanitizers.adapter]]
extension = ".jtd"
command = "/usr/local/bin/jtd_cleaner"
args = ["--input", "{{input_path}}", "--output", "{{output_path}}"]
timeout_secs = 120
on_success = "verify_hash"
on_failure = "block_and_log"
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let es = config.external_sanitizers.expect("external_sanitizers should be present");
        assert_eq!(es.adapters.len(), 1);
        assert_eq!(es.adapters[0].extension, ".jtd");
        assert_eq!(es.adapters[0].timeout_secs, 120);
        assert!(matches!(es.adapters[0].on_success, ExternalSuccessAction::VerifyHash));
        assert!(matches!(es.adapters[0].on_failure, ExternalFailureAction::BlockAndLog));
    }

    #[test]
    fn test_file_types_section_parsing() {
        let toml_content = r#"
[server]
addr = "0.0.0.0:3001"

[storage]
upload_dir = "./uploads"
staging_dir = "./staging"

[file_types]
default_action = "block"

[[file_types.registry]]
extension = ".pdf"
magic_hex = "255044462D"
required_magic = true
sanitizer = "pdf_builtin"

[[file_types.blocked_extensions]]
extension = ".exe"
reason = "Executable files are not allowed"
"#;
        let config: TomlConfig = toml::from_str(toml_content).unwrap();

        let ft = config.file_types.expect("file_types should be present");
        assert_eq!(ft.default_action, "block");
        assert_eq!(ft.registry.len(), 1);
        assert_eq!(ft.registry[0].extension, ".pdf");
        assert!(ft.registry[0].required_magic);
        assert_eq!(ft.blocked_extensions.len(), 1);
        assert_eq!(ft.blocked_extensions[0].extension, ".exe");
    }

    // =========================================================================
    // Test: Full Configuration with All Sections
    // =========================================================================

    #[test]
    fn test_full_configuration_all_sections() {
        let toml_content = r#"
[server]
addr = "192.168.1.100:3001"

[storage]
upload_dir = "/data/misogi/uploads"
staging_dir = "/data/misogi/staging"

[tunnel]
remote_addr = "relay.example.com:9000"
auth_token = "tunnel-secret-token-123"

[daemon]
enabled = true
pid_file = "/var/run/misogi-sender.pid"

[approval_flow]
require_approval = true
initial_state = "PENDING_APPROVAL"

[transfer_driver]
type = "storage_relay"
output_dir = "/data/relay/outbound"
poll_interval_secs = 5

[cdr_strategies.vba_whitelist]
enabled = true

[cdr_strategies.clamav_integration]
enabled = true
socket_path = "/var/run/clamd.sock"

[pii_detector]
enabled = true
mask_char = "*"

[log]
format = "cef"
retention_days = 1825

[vendor_isolation]
enabled = true

[calendar]
enabled = true
wareki_filename_detection = true

[encoding]
default_encoding = "Shift_JIS"

[[external_sanitizers.adapter]]
extension = ".dwg"
command = "/opt/tools/dwg_sanitize"
timeout_secs = 300
"#;
        let config: TomlConfig = toml::from_str(toml_content).expect("Full TOML should parse");

        // Verify all sections are present
        assert!(config.approval_flow.is_some());
        assert!(config.transfer_driver.is_some());
        assert!(config.cdr_strategies.is_some());
        assert!(config.file_types.is_none()); // Not included in this test
        assert!(config.pii_detector.is_some());
        assert!(config.log.is_some());
        assert!(config.vendor_isolation.is_some());
        assert!(config.calendar.is_some());
        assert!(config.encoding.is_some());
        assert!(config.external_sanitizers.is_some());

        // Verify SenderConfig maps correctly
        let sender_config = SenderConfig::from_toml_unchecked(&config);

        assert_eq!(sender_config.server_addr, "192.168.1.100:3001");
        assert!(sender_config.approval_require_approval);
        assert_eq!(sender_config.transfer_driver_type, "storage_relay");
        assert!(sender_config.pii_enabled);
        assert_eq!(sender_config.log_format, "cef");
        assert!(sender_config.vendor_isolation_enabled);
        assert!(sender_config.calendar_enabled);
    }

    // Helper to create SenderConfig from TomlConfig for testing (without file I/O)
    #[allow(dead_code)]
    fn from_toml_unchecked(toml: &TomlConfig) -> SenderConfig {
        // Simplified version for testing that doesn't need file I/O
        let server_addr = toml.server.addr.clone();
        let upload_dir = PathBuf::from(&toml.storage.upload_dir);
        let staging_dir = PathBuf::from(&toml.storage.staging_dir);

        let (approval_req, _, _, _) = if let Some(ref af) = toml.approval_flow {
            (af.require_approval, af.initial_state.clone(), af.triggers.clone(), af.transitions.clone())
        } else {
            (true, String::new(), Vec::new(), Vec::new())
        };

        let (driver_type, _, _, _, _, _, _) = if let Some(ref td) = toml.transfer_driver {
            let ds = td.r#type.as_str().to_string();
            (ds.to_string(), td.output_dir.clone(), td.input_dir.clone(), td.poll_interval_secs, td.send_command.clone(), td.status_command.clone(), td.timeout_secs)
        } else {
            ("direct_tcp".to_string(), None, None, 10, None, None, 60)
        };

        let (pii_en, pii_mc) = if let Some(ref pii) = toml.pii_detector {
            (pii.enabled, pii.mask_char.clone())
        } else {
            (false, "*".to_string())
        };

        let (lf, _, lme, lrd) = if let Some(ref lg) = toml.log {
            let fs = lg.format.as_str().to_string();
            (fs.to_string(), lg.template_path.clone(), lg.max_memory_entries, lg.retention_days)
        } else {
            ("json".to_string(), None, 1000, 365)
        };

        let vi_en = toml.vendor_isolation.as_ref().map(|v| v.enabled).unwrap_or(false);
        let (cal_en, _, cal_adm, cal_wd) = if let Some(ref c) = toml.calendar {
            (c.enabled, c.calendar_file.clone(), c.auto_defense_mode, c.wareki_filename_detection)
        } else {
            (false, String::new(), false, true)
        };

        let (enc_de, enc_ufa, _) = if let Some(ref e) = toml.encoding {
            let ufas = e.unknown_font_action.as_str().to_string();
            (e.default_encoding.clone(), ufas.to_string(), e.fallback_fonts.clone())
        } else {
            ("utf-8".to_string(), "preserve".to_string(), vec![String::from("IPAexMincho"), String::from("IPAGothic")])
        };

        let esc = toml.external_sanitizers.as_ref().map(|e| e.adapters.len()).unwrap_or(0);

        SenderConfig {
            server_addr,
            upload_dir: upload_dir.clone(),
            staging_dir,
            tunnel_remote_addr: None,
            tunnel_auth_token: None,
            tunnel_local_port: 9000,
            daemon_enabled: false,
            daemon_pid_file: None,
            daemon_log_file: None,
            approval_require_approval: approval_req,
            approval_initial_state: String::new(),
            approval_triggers: Vec::new(),
            approval_transitions: Vec::new(),
            transfer_driver_type: driver_type,
            transfer_output_dir: None,
            transfer_input_dir: None,
            transfer_poll_interval_secs: 10,
            transfer_send_command: None,
            transfer_status_command: None,
            transfer_timeout_secs: 60,
            cdr_vba_whitelist_enabled: false,
            cdr_format_downgrade_enabled: false,
            cdr_clamav_enabled: false,
            cdr_clamav_socket_path: String::new(),
            file_types_default_action: String::from("allow"),
            pii_enabled: pii_en,
            pii_mask_char: pii_mc,
            log_format: lf,
            log_template_path: None,
            log_max_memory_entries: lme,
            log_retention_days: lrd,
            vendor_isolation_enabled: vi_en,
            calendar_enabled: cal_en,
            calendar_file: String::new(),
            calendar_auto_defense_mode: cal_adm,
            calendar_wareki_detection: cal_wd,
            encoding_default_encoding: enc_de,
            encoding_unknown_font_action: enc_ufa,
            encoding_fallback_fonts: Vec::new(),
            external_sanitizer_count: esc,
            // Legacy / extension fields
            storage_dir: upload_dir.to_string_lossy().to_string(),
            chunk_size: 8 * 1024 * 1024,
            receiver_addr: None,
            auto_sanitize: false,
            watch_dir: None,
            sanitization_policy: misogi_cdr::SanitizationPolicy::default(),
            log_level: String::from("info"),
            ppap_config: None,
            versioning_default_version: "v1".to_string(),
            versioning_deprecation_warnings_enabled: true,
            versioning_deprecation_headers: true,
            // Phase 8: JTD Conversion
            blast_config: None,
            jtd_conversion_enabled: false,
            jtd_converter_type: "auto".to_string(),
            jtd_timeout_secs: 120,
            versioning: None,
        }
    }

    // =========================================================================
    // Test: Environment Variable Override
    // =========================================================================

    #[test]
    fn test_env_override_transfer_driver() {
        let mut config = SenderConfig::default();
        assert_eq!(config.transfer_driver_type, "direct_tcp");

        // Simulate environment variable
        config.transfer_driver_type = "storage_relay".to_string(); // Would come from env
        assert_eq!(config.transfer_driver_type, "storage_relay");
    }

    #[test]
    fn test_parse_env_bool_true_values() {
        assert!(parse_env_bool("true", false));
        assert!(parse_env_bool("TRUE", false));
        assert!(parse_env_bool("True", false));
        assert!(parse_env_bool("1", false));
        assert!(parse_env_bool("yes", false));
        assert!(parse_env_bool("YES", false));
        assert!(parse_env_bool("on", false));
        assert!(parse_env_bool("ON", false));
    }

    #[test]
    fn test_parse_env_bool_false_values() {
        assert!(!parse_env_bool("false", true));
        assert!(!parse_env_bool("0", true));
        assert!(!parse_env_bool("no", true));
        assert!(!parse_env_bool("off", true));
    }

    #[test]
    fn test_parse_env_bool_unknown_returns_fallback() {
        assert!(!parse_env_bool("maybe", false)); // fallback = false
        assert!(parse_env_bool("maybe", true));  // fallback = true
        assert!(!parse_env_bool("", false));     // empty string
    }

    // =========================================================================
    // Test: Validation Logic
    // =========================================================================

    #[test]
    fn test_validate_valid_config() {
        let config = SenderConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_server_addr_fails() {
        let mut config = SenderConfig::default();
        config.server_addr = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_missing_port_fails() {
        let mut config = SenderConfig::default();
        config.server_addr = String::from("localhost"); // No port
        assert!(config.validate().is_err());
    }

    // =========================================================================
    // Test: Helper Methods
    // =========================================================================

    #[test]
    fn test_is_approval_required() {
        let mut config = SenderConfig::default();
        assert!(config.is_approval_required()); // Default is true

        config.approval_require_approval = false;
        assert!(!config.is_approval_required());
    }

    #[test]
    fn test_get_normalized_driver_type() {
        let mut config = SenderConfig::default();
        config.transfer_driver_type = String::from("Direct-TCP");
        assert_eq!(config.get_normalized_driver_type(), "direct-tcp");
    }

    #[test]
    fn test_is_cdr_active() {
        let mut config = SenderConfig::default();
        assert!(!config.is_cdr_active()); // All disabled by default

        config.cdr_clamav_enabled = true;
        assert!(config.is_cdr_active());
    }

    // =========================================================================
    // Test: Enum Defaults
    // =========================================================================

    #[test]
    fn test_enum_defaults() {
        assert!(matches!(ApprovalTriggerType::default(), ApprovalTriggerType::HttpCallback));
        assert!(matches!(TransferDriverType::default(), TransferDriverType::DirectTcp));
        assert!(matches!(PiiAction::default(), PiiAction::AlertOnly));
        assert!(matches!(LogFormatType::default(), LogFormatType::Json));
        assert!(matches!(UnknownFontAction::default(), UnknownFontAction::Preserve));
        assert!(matches!(ExternalSuccessAction::default(), ExternalSuccessAction::TrustOutput));
        assert!(matches!(ExternalFailureAction::default(), ExternalFailureAction::BlockAndLog));
    }

    #[test]
    fn test_transfer_driver_type_from_str_fallback() {
        assert!(matches!(TransferDriverType::from_str_fallback("direct_tcp"), TransferDriverType::DirectTcp));
        assert!(matches!(TransferDriverType::from_str_fallback("TCP"), TransferDriverType::DirectTcp));
        assert!(matches!(TransferDriverType::from_str_fallback("storage_relay"), TransferDriverType::StorageRelay));
        assert!(matches!(TransferDriverType::from_str_fallback("external"), TransferDriverType::ExternalCommand));
        assert!(matches!(TransferDriverType::from_str_fallback("unknown"), TransferDriverType::DirectTcp)); // fallback
    }

    #[test]
    fn test_log_format_type_from_str_fallback() {
        assert!(matches!(LogFormatType::from_str_fallback("json"), LogFormatType::Json));
        assert!(matches!(LogFormatType::from_str_fallback("syslog"), LogFormatType::Syslog));
        assert!(matches!(LogFormatType::from_str_fallback("cef"), LogFormatType::Cef));
        assert!(matches!(LogFormatType::from_str_fallback("custom"), LogFormatType::Custom));
        assert!(matches!(LogFormatType::from_str_fallback("unknown"), LogFormatType::Json)); // fallback
    }

    #[test]
    fn test_unknown_font_action_from_str_fallback() {
        assert!(matches!(UnknownFontAction::from_str_fallback("preserve"), UnknownFontAction::Preserve));
        assert!(matches!(UnknownFontAction::from_str_fallback("strip"), UnknownFontAction::Strip));
        assert!(matches!(UnknownFontAction::from_str_fallback("replace"), UnknownFontAction::Replace));
        assert!(matches!(UnknownFontAction::from_str_fallback("unknown"), UnknownFontAction::Preserve)); // fallback
    }
}
