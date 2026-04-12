//! Error types for the Misogi SMTP Gateway.
//!
//! All errors in this crate are categorized into domains:
//! - **Protocol**: SMTP protocol-level errors (malformed commands, unexpected state)
//! - **MIME**: Email parsing and MIME structure errors
//! - **Sanitization**: CDR pipeline integration errors
//! - **Delivery**: SMTP relay / delivery failures
//! - **Configuration**: Invalid configuration values
//! - **Io**: File system and network I/O errors

use std::path::PathBuf;

/// Unified error type for the entire `misogi-smtp` crate.
///
/// Every variant carries sufficient context for operator diagnostics
/// and audit log correlation. Error messages are intentionally written
/// to avoid leaking sensitive email content (addresses, subjects, etc.)
/// while preserving enough information for troubleshooting.
#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    // ── Protocol Errors ──────────────────────────────────────────────

    /// SMTP command was malformed or unrecognized.
    #[error("SMTP protocol error: {message}")]
    SmtpProtocol { message: String },

    /// SMTP session exceeded maximum allowed message size.
    #[error("Message size limit exceeded: {actual} bytes (limit: {limit})")]
    MessageSizeExceeded { actual: usize, limit: usize },

    /// SMTP connection was closed by peer before session completed.
    #[error("SMTP connection aborted by peer: {peer_addr}")]
    ConnectionAborted { peer_addr: String },

    // ── MIME Parsing Errors ──────────────────────────────────────────

    /// Raw email data could not be parsed as valid RFC 5322/MIME format.
    #[error("MIME parse error: {reason}")]
    MimeParseError { reason: String },

    /// Required email header is missing or empty.
    #[error("Missing required header: {header}")]
    MissingHeader { header: String },

    /// Transfer encoding (base64, quoted-printable) decoding failed.
    #[error("Transfer encoding decode failed: {encoding}")]
    TransferEncodingFailed { encoding: String },

    /// MIME part nesting depth exceeded safety limit (prevents bomb attacks).
    #[error("MIME nesting depth exceeded: {depth} (max: {max_depth})")]
    NestingDepthExceeded { depth: usize, max_depth: usize },

    /// Attachment extraction encountered an unrecoverable structural issue.
    #[error("Attachment extraction error for part index {part_index}: {reason}")]
    AttachmentExtractError { part_index: usize, reason: String },

    // ── Sanitization Errors ──────────────────────────────────────────

    /// CDR pipeline returned a failure for a specific attachment.
    #[error("Sanitization failed for attachment '{filename}': {reason}")]
    SanitizationFailed { filename: String, reason: String },

    /// Email reassembly after sanitization produced invalid output.
    #[error("Email reassembly failed: {reason}")]
    ReassemblyFailed { reason: String },

    /// Attachment exceeds configured maximum allowed size.
    #[error("Attachment too large: {filename} ({size} bytes, limit: {limit})")]
    AttachmentTooLarge {
        filename: String,
        size: usize,
        limit: usize,
    },

    /// Attachment blocked by policy (executable, password-protected archive, etc.).
    #[error("Attachment blocked by policy: {filename} — {reason}")]
    AttachmentBlocked { filename: String, reason: String },

    // ── Delivery Errors ──────────────────────────────────────────────

    /// SMTP relay connection or authentication failure.
    #[error("SMTP relay error: {reason}")]
    RelayError { reason: String },

    /// Permanent delivery failure (recipient does not exist, domain invalid, etc.).
    #[error("Permanent delivery failure for recipient '{recipient}': {reason}")]
    DeliveryPermanentFailure { recipient: String, reason: String },

    /// Transient delivery failure (temporary DNS issue, greylisting, etc.).
    #[error("Transient delivery failure for recipient '{recipient}': {reason}")]
    DeliveryTransientFailure { recipient: String, reason: String },

    /// All retry attempts exhausted without successful delivery.
    #[error("Delivery retries exhausted for recipient '{recipient}' after {attempts} attempts")]
    RetriesExhausted { recipient: String, attempts: u32 },

    // ── Configuration Errors ────────────────────────────────────────

    /// A required configuration value is missing or invalid.
    #[error("Configuration error: {field} — {reason}")]
    Configuration { field: String, reason: String },

    /// Pickup directory does not exist or is not accessible.
    #[error("Pickup directory not accessible: {path}")]
    PickupDirInvalid { path: PathBuf },

    /// Zone policy configuration contains invalid entries.
    #[error("Invalid zone policy: {reason}")]
    InvalidZonePolicy { reason: String },

    // ── I/O Errors ───────────────────────────────────────────────────

    /// File system or network I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization error (e.g., config file parsing).
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // ── Shutdown Errors ──────────────────────────────────────────────

    /// Server shutdown signal handling error.
    #[error("Shutdown error: {0}")]
    Shutdown(String),
}

/// Type alias for `Result<T, SmtpError>` used throughout this crate.
pub type Result<T> = std::result::Result<T, SmtpError>;
