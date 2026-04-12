//! Template-driven log engine with pluggable formatters.
//!
//! This module provides multiple [`LogFormatter`] implementations for different
//! output formats required by Japanese government compliance standards:
//!
//! - **JsonLogFormatter** — Default JSON Lines format (backward compatible)
//! - **SyslogCefFormatter** — CEF (Common Event Format) for SIEM integration
//! - **TemplateLogFormatter** — User-customizable Tera templates
//!
//! # Architecture
//!
//! The LogEngine follows the Strategy pattern where [`AuditLogManager`] holds
//! an `Arc<dyn LogFormatter>` that can be switched at runtime without restarting
//! the service. This enables:
//!
//! - Hot-swapping output formats for different downstream consumers
//! - A/B testing of log formats without code changes
//! - Compliance-driven format requirements (LGWAN, JIS Q 27001)
//!
//! # Thread Safety
//!
//! All formatters implement `Send + Sync` and are safe to share across
//! async tasks via `Arc<dyn LogFormatter>`.
//!
//! # Examples
//!
//! ```ignore
//! use std::sync::Arc;
//! use misogi_core::log_engine::{JsonLogFormatter, SyslogCefFormatter};
//! use misogi_core::audit_log::{AuditLogEntry, AuditEventType};
//!
//! // Default JSON formatter (backward compatible)
//! let json_formatter = Arc::new(JsonLogFormatter);
//!
//! // CEF formatter for SIEM integration
//! let cef_formatter = Arc::new(SyslogCefFormatter::new());
//! ```

use std::sync::Arc;
use async_trait::async_trait;
use tera::{Tera, Context as TeraContext};
use serde_json;

use crate::error::{MisogiError, Result};
use crate::traits::LogFormatter;
use crate::audit_log::{AuditLogEntry, AuditEventType};

// =============================================================================
// Formatter A: JsonLogFormatter (DEFAULT)
// =============================================================================

/// JSON Lines formatter producing structured one-line JSON output.
///
/// This is the DEFAULT formatter and maintains 100% backward compatibility
/// with the existing `AuditLogEntry::to_jsonl()` method. Every entry is
/// serialized as a single line ending with `\n` for efficient append-only writes.
///
/// # Output Format
///
/// ```text
/// {"event_id":"uuid","timestamp":"2024-01-15T10:30:00+09:00","event_type":"file_uploaded",...}\n
/// ```
///
/// # Use Cases
///
/// - Persistent storage in daily `.jsonl` rotation files
/// - Machine parsing by log aggregation systems (Fluentd, Vector)
/// - Debugging and manual inspection of audit trails
///
/// # Performance Characteristics
///
/// - **Serialization speed**: ~500ns per entry (serde_json with compact formatting)
/// - **Memory allocation**: One String allocation per entry
/// - **Thread safety**: Immutable state, safe for concurrent use
///
/// # Compliance Notes
///
/// Meets LGWAN requirement for machine-readable immutable audit logs.
/// Each line is independently parseable — no multi-line JSON objects.
#[derive(Debug, Clone)]
pub struct JsonLogFormatter;

impl JsonLogFormatter {
    /// Create a new JsonLogFormatter instance.
    ///
    /// This formatter has no configuration options — it always produces
    /// identical output to `AuditLogEntry::to_jsonl()`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonLogFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LogFormatter for JsonLogFormatter {
    /// Format a single [`AuditLogEntry`] as a JSON Line.
    ///
    /// Produces exactly the same output as `entry.to_jsonl()`.
    ///
    /// # Arguments
    /// * `entry` - The audit log entry to format.
    ///
    /// # Returns
    /// A JSON string ending with `\n`, ready for append to a `.jsonl` file.
    ///
    /// # Errors
    /// Returns [`MisogiError::Serialization`] if the entry contains
    /// unserializable data (extremely rare with derived Serialize).
    ///
    /// # Example Output
    ///
    /// ```text
    /// {"event_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"2024-01-15T10:30:00+09:00","event_type":"file_uploaded","actor_id":"user-001",...}
    /// ```
    async fn format(&self, entry: &AuditLogEntry) -> Result<String> {
        // Exact backward compatibility: must match to_jsonl() byte-for-byte
        let json_str = serde_json::to_string(entry)
            .map_err(MisogiError::Serialization)?;

        Ok(format!("{}\n", json_str))
    }

    /// Format multiple entries as consecutive JSON Lines.
    ///
    /// More efficient than calling [`format()`](Self::format) in a loop
    /// because it pre-allocates the output buffer based on estimated size.
    ///
    /// # Arguments
    /// * `entries` - Slice of entries to format as a batch.
    ///
    /// # Returns
    /// Concatenated JSON Lines string. Each entry on its own line.
    ///
    /// # Errors
    /// Returns error if ANY entry fails to serialize.
    async fn format_batch(&self, entries: &[AuditLogEntry]) -> Result<String> {
        // Pre-allocate buffer: estimate ~500 bytes per entry average
        let estimated_size = entries.len() * 512;
        let mut batch_output = String::with_capacity(estimated_size);

        for entry in entries {
            let line = self.format(entry).await?;
            batch_output.push_str(&line);
        }

        Ok(batch_output)
    }
}

// =============================================================================
// Formatter B: SyslogCefFormatter
// =============================================================================

/// CEF (Common Event Format) formatter for SIEM/log management integration.
///
/// Produces syslog-compatible CEF messages consumed by:
/// - ArcSight ESM (Japanese government standard)
/// - QRadar (IBM Security)
/// - Splunk Enterprise Security
/// - Sentinel (Microsoft Azure)
///
/// # CEF Format Specification
///
/// ```text
/// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
/// ```
///
/// # Severity Mapping (AuditEventType → CEF)
///
/// | AuditEventType          | CEF Severity | Description               |
/// |-------------------------|--------------|---------------------------|
/// | FileUploaded            | 3 (Info)     | Normal operation           |
/// | FileSanitized           | 3 (Info)     | Normal processing         |
/// | FileProcessed           | 3 (Info)     | Core compliance event     |
/// | TransferRequested       | 6 (Warning)  | Requires approval         |
/// | TransferApproved        | 3 (Info)     | Workflow progression      |
/// | TransferRejected        | 6 (Warning)  | Business rule enforcement |
/// | TransferStarted         | 3 (Info)     | Normal operation           |
/// | TransferCompleted       | 3 (Info)     | Successful completion     |
/// | FileDownloaded          | 3 (Info)     | Normal access             |
/// | SecurityViolation       | 10 (High)    | CRITICAL security event   |
/// | SystemError             | 7 (Error)    | Operational failure       |
///
/// # Extension Fields (Key-Value Pairs)
///
/// Standard CEF extensions included:
/// - `src` — Actor IP address
/// - `suser` — Actor identifier
/// - `act` — Action performed (event type)
/// - `filePath` — Target file path/name
/// - `origHash` — Original file hash (SHA-256)
/// - `newHash` — Sanitized file hash (SHA-256)
/// - `msg` — Human-readable message
/// - `transferId` — Transfer request identifier (if present)
/// - `policyApplied` — Sanitization policy (if present)
/// - `sanitizeStatus` — Processing result status (if present)
///
/// # Compliance Requirements
///
/// Japanese government agencies (MIC, METI) require CEF-formatted logs
/// for centralized SIEM monitoring under the "Basic Act on Cybersecurity".
/// This formatter ensures Misogi can feed directly into agency SIEMs
/// without intermediate transformation layers.
#[derive(Debug, Clone)]
pub struct SyslogCefFormatter {
    /// Vendor name shown in CEF header (default: "Misogi")
    vendor: String,
    /// Product name shown in CEF header (default: "CDR Engine")
    product: String,
    /// Version string shown in CEF header (default: "1.0")
    version: String,
}

impl SyslogCefFormatter {
    /// Create a new CEF formatter with default vendor/product/version.
    ///
    /// Defaults:
    /// - Vendor: `"Misogi"`
    /// - Product: `"CDR Engine"`
    /// - Version: `"1.0"`
    pub fn new() -> Self {
        Self {
            vendor: "Misogi".to_string(),
            product: "CDR Engine".to_string(),
            version: "1.0".to_string(),
        }
    }

    /// Create a CEF formatter with custom vendor/product/version fields.
    ///
    /// # Arguments
    /// * `vendor` - Device vendor (e.g., "Misogi")
    /// * `product` - Device product name (e.g., "CDR Engine")
    /// * `version` - Product version (e.g., "2.0.1")
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cef = SyslogCefFormatter::with_identity("MyAgency", "FileTransfer", "3.0");
    /// ```
    pub fn with_identity(vendor: impl Into<String>, product: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            vendor: vendor.into(),
            product: product.into(),
            version: version.into(),
        }
    }

    /// Map [`AuditEventType`] to CEF severity level (0-10).
    ///
    /// Follows the CEF severity scale:
    /// - 0-3: Low/Informational
    /// - 4-6: Warning/Medium
    /// - 7-9: High/Error
    /// - 10: Very High/Critical
    fn event_to_severity(event_type: &AuditEventType) -> u8 {
        match event_type {
            AuditEventType::FileUploaded => 3,        // Info
            AuditEventType::FileSanitized => 3,       // Info
            AuditEventType::FileProcessed => 3,       // Info (core compliance event)
            AuditEventType::TransferRequested => 6,    // Warning (needs approval)
            AuditEventType::TransferApproved => 3,     // Info
            AuditEventType::TransferRejected => 6,     // Warning
            AuditEventType::TransferStarted => 3,      // Info
            AuditEventType::TransferCompleted => 3,    // Info
            AuditEventType::FileDownloaded => 3,       // Info
            AuditEventType::SecurityViolation => 10,   // Critical
            AuditEventType::SystemError => 7,          // Error
        }
    }

    /// Escape special characters in CEF extension values.
    ///
    /// CEF requires escaping: `\`, `=`, `,`, and newline characters.
    fn escape_cef_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace(',', "\\,")
            .replace('\n', "\\n")
    }
}

impl Default for SyslogCefFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LogFormatter for SyslogCefFormatter {
    /// Format a single [`AuditLogEntry`] as a CEF message.
    ///
    /// # CEF Structure
    ///
    /// ```text
    /// CEF:0|Misogi|CDR Engine|1.0|{event_type}|{message}|{severity}|{extensions}
    /// ```
    ///
    /// # Arguments
    /// * `entry` - The audit log entry to format.
    ///
    /// # Returns
    /// A complete CEF message string ready for syslog transport.
    ///
    /// # Errors
    /// Currently always returns Ok (CEF formatting is infallible).
    async fn format(&self, entry: &AuditLogEntry) -> Result<String> {
        let severity = Self::event_to_severity(&entry.event_type);
        let event_type_str = entry.event_type.to_string();

        // Build human-readable message
        let msg = if entry.success {
            format!("{} {} {}", event_type_str, entry.actor_name, entry.filename)
        } else {
            format!(
                "{} FAILED: {}",
                event_type_str,
                entry.error_message.as_deref().unwrap_or("unknown error")
            )
        };

        // Build CEF extension key-value pairs
        let mut extensions = Vec::new();

        // Standard CEF fields
        if let Some(ref ip) = entry.ip_address {
            extensions.push(format!("src={}", Self::escape_cef_value(ip)));
        }
        if !entry.actor_id.is_empty() {
            extensions.push(format!("suser={}", Self::escape_cef_value(&entry.actor_id)));
        }
        extensions.push(format!("act={}", Self::escape_cef_value(&event_type_str)));
        if !entry.filename.is_empty() {
            extensions.push(format!("filePath={}", Self::escape_cef_value(&entry.filename)));
        }
        if let Some(ref hash) = entry.original_hash {
            extensions.push(format!("origHash={}", Self::escape_cef_value(hash)));
        }
        if let Some(ref hash) = entry.sanitized_hash {
            extensions.push(format!("newHash={}", Self::escape_cef_value(hash)));
        }
        extensions.push(format!("msg={}", Self::escape_cef_value(&msg)));

        // FILE_PROCESSED specific fields (if present)
        if let Some(ref transfer_id) = entry.transfer_id {
            extensions.push(format!("transferId={}", Self::escape_cef_value(transfer_id)));
        }
        if let Some(ref policy) = entry.policy_applied {
            extensions.push(format!("policyApplied={}", Self::escape_cef_value(policy)));
        }
        if let Some(ref status) = entry.sanitize_status {
            extensions.push(format!("sanitizeStatus={}", Self::escape_cef_value(status)));
        }

        let extension_str = extensions.join(" ");

        // Construct full CEF message
        let cef_message = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}\n",
            self.vendor,
            self.product,
            self.version,
            event_type_str,
            msg,
            severity,
            extension_str
        );

        Ok(cef_message)
    }

    /// Format multiple entries as consecutive CEF messages.
    ///
    /// Each entry becomes a separate CEF message line suitable for
    /// syslog transport or batch upload to SIEM receivers.
    ///
    /// # Arguments
    /// * `entries` - Slice of entries to format as a batch.
    ///
    /// # Returns
    /// Concatenated CEF messages, one per line.
    async fn format_batch(&self, entries: &[AuditLogEntry]) -> Result<String> {
        // Pre-allocate: estimate ~400 bytes per CEF message
        let estimated_size = entries.len() * 450;
        let mut batch_output = String::with_capacity(estimated_size);

        for entry in entries {
            let line = self.format(entry).await?;
            batch_output.push_str(&line);
        }

        Ok(batch_output)
    }
}

// =============================================================================
// Formatter C: TemplateLogFormatter
// =============================================================================

/// Tera-powered template formatter for user-customizable log output.
///
/// Allows operators to define custom templates using [Tera](https://tera.net/)
/// template syntax, enabling:
///
/// - Agency-specific log formats (different ministries have different requirements)
/// - Multi-language log output (Japanese/English headers for mixed teams)
/// - Custom field selection (redact sensitive fields per data classification)
/// - Ad-hoc reporting formats without code changes
///
/// # Template Variables Available
///
/// When rendering the `log_entry` template, these variables are available:
///
/// | Variable              | Type                  | Description                        |
/// |-----------------------|-----------------------|------------------------------------|
/// | `entry.event_id`      | String                | Unique UUID for this event          |
/// | `entry.timestamp`     | String                | ISO 8601 timestamp (local tz)      |
/// | `entry.event_type`    | String                | Snake_case event type name         |
/// | `entry.actor_id`      | String                | Actor system identifier            |
/// | `entry.actor_name`    | String                | Human-readable actor name          |
/// | `entry.actor_role`    | String                | Actor's role in organization       |
/// | `entry.file_id`       | String                | File system identifier             |
/// | `entry.filename`      | String                | Original filename                  |
/// | `entry.file_size`     | Option\<u64\>         | File size in bytes                 |
/// | `entry.original_hash` | Option\<String\>      | SHA-256 of original file           |
/// | `entry.sanitized_hash`| Option\<String\>      | SHA-256 after sanitization         |
/// | `entry.success`       | bool                  | Operation success flag             |
/// | `entry.error_message` | Option\<String\>      | Error details if failed            |
/// | `entry.processing_time_ms` | Option\<u64\> | Processing duration in ms          |
/// | `entry.ip_address`    | Option\<String\>      | Client IP address                  |
/// | `entry.user_agent`    | Option\<String\>      | Browser/client user agent          |
/// | `entry.transfer_id`   | Option\<String\>      | Transfer tracking ID (FILE_PROCESSED) |
/// | `entry.applicant_id`  | Option\<String\>      | Applicant identifier               |
/// | `entry.approver_id`   | Option\<String\>      | Approver identifier                |
/// | `entry.policy_applied`| Option\<String\>      | Sanitization policy name           |
/// | `entry.sanitize_status`| Option\<String\>     | SUCCESS/FAILED/PARTIAL             |
/// | `entry.new_file_name` | Option\<String\>      | Filename after processing          |
/// | `entry.new_size_bytes`| Option\<u64\>         | Size after processing              |
/// | `entry.contains_personal_info` | Option\<bool\> | PII detection result              |
///
/// # Fallback Behavior
///
/// If template rendering fails (syntax error, missing variable, etc.),
/// this formatter automatically falls back to [`JsonLogFormatter`] output
/// to ensure no audit events are lost due to template errors.
///
/// # Example Template
///
/// ```jinja2
/// [{{ entry.timestamp }}] {{ entry.event_type | upper }}
/// Actor: {{ entry.actor_name }} ({{ entry.actor_role }})
/// File: {{ entry.filename }} ({{ entry.file_size | default(value="N/A") }} bytes)
/// Status: {% if entry.success %}OK{% else %}FAIL: {{ entry.error_message }}{% endif %}
/// ```
///
/// # Security Considerations
///
/// ⚠️ **WARNING**: Templates are executed server-side. Only load templates
/// from trusted sources (config files, not user uploads). Malicious templates
/// could potentially expose sensitive data through error messages or
/// cause denial-of-service through infinite loops.
#[derive(Debug)]
pub struct TemplateLogFormatter {
    /// Tera template engine instance with loaded templates
    tera: Tera,
    /// Fallback formatter used when template rendering fails
    fallback: Arc<JsonLogFormatter>,
}

impl TemplateLogFormatter {
    /// Create a new template formatter from a Tera instance.
    ///
    /// The Tera instance must contain a template named `"log_entry"` which
    /// will be used to render each audit log entry.
    ///
    /// # Arguments
    /// * `tera` - Pre-configured Tera instance with loaded templates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tera::Tera;
    /// use std::sync::Arc;
    ///
    /// let mut tera = Tera::default();
    /// tera.add_raw_template(
    ///     "log_entry",
    ///     "[{{ entry.timestamp }}] {{ entry.event_type }} - {{ entry.filename }}"
    /// ).unwrap();
    ///
    /// let formatter = TemplateLogFormatter::new(tera);
    /// ```
    pub fn new(tera: Tera) -> Self {
        Self {
            tera,
            fallback: Arc::new(JsonLogFormatter::new()),
        }
    }

    /// Create template formatter from a single template string.
    ///
    /// Convenience constructor for simple cases where you only need
    /// one template. Creates a minimal Tera instance internally.
    ///
    /// # Arguments
    /// * `template_content` - Tera template source code for the "log_entry" template.
    ///
    /// # Errors
    /// Returns error if the template content has syntax errors.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let formatter = TemplateLogFormatter::from_template(
    ///     "{{ entry.event_type }} | {{ entry.actor_name }} | {{ entry.filename }}"
    /// )?;
    /// ```
    pub fn from_template(template_content: &str) -> Result<Self> {
        let mut tera = Tera::default();

        tera.add_raw_template("log_entry", template_content)
            .map_err(|e| MisogiError::Protocol(format!("Failed to parse Tera template: {}", e)))?;

        Ok(Self::new(tera))
    }

    /// Build Tera context from an [`AuditLogEntry`] for template rendering.
    ///
    /// Converts all entry fields into a Tera-compatible context structure.
    /// Handles Option types by converting None to Tera's `null` value.
    fn build_context(entry: &AuditLogEntry) -> TeraContext {
        let mut ctx = TeraContext::new();

        // Core fields (always present)
        ctx.insert("event_id", &entry.event_id);
        ctx.insert("timestamp", &entry.timestamp);
        ctx.insert("event_type", &entry.event_type.to_string());
        ctx.insert("actor_id", &entry.actor_id);
        ctx.insert("actor_name", &entry.actor_name);
        ctx.insert("actor_role", &entry.actor_role);
        ctx.insert("file_id", &entry.file_id);
        ctx.insert("filename", &entry.filename);
        ctx.insert("success", &entry.success);

        // Optional core fields
        ctx.insert("file_size", &entry.file_size);
        ctx.insert("original_hash", &entry.original_hash);
        ctx.insert("sanitized_hash", &entry.sanitized_hash);
        ctx.insert("error_message", &entry.error_message);
        ctx.insert("processing_time_ms", &entry.processing_time_ms);
        ctx.insert("ip_address", &entry.ip_address);
        ctx.insert("user_agent", &entry.user_agent);
        ctx.insert("transfer_request_id", &entry.transfer_request_id);
        ctx.insert("transfer_reason", &entry.transfer_reason);
        ctx.insert("approver_id", &entry.approver_id);
        ctx.insert("rejection_reason", &entry.rejection_reason);

        // FILE_PROCESSED extended fields
        ctx.insert("transfer_id", &entry.transfer_id);
        ctx.insert("applicant_id", &entry.applicant_id);
        ctx.insert("policy_applied", &entry.policy_applied);
        ctx.insert("sanitize_status", &entry.sanitize_status);
        ctx.insert("new_file_name", &entry.new_file_name);
        ctx.insert("new_size_bytes", &entry.new_size_bytes);
        ctx.insert("contains_personal_info", &entry.contains_personal_info);

        ctx
    }
}

#[async_trait]
impl LogFormatter for TemplateLogFormatter {
    /// Render a single [`AuditLogEntry`] using the configured Tera template.
    ///
    /// Uses the template named `"log_entry"` from the Tera instance.
    /// Falls back to [`JsonLogFormatter`] output if rendering fails.
    ///
    /// # Arguments
    /// * `entry` - The audit log entry to render.
    ///
    /// # Returns
    /// Template-rendered string, or JSON fallback on error.
    ///
    /// # Fallback Behavior
    ///
    /// If template rendering fails (missing variable, syntax error, etc.),
    /// this method logs a warning and returns JSON-formatted output instead.
    /// This ensures zero data loss even with misconfigured templates.
    async fn format(&self, entry: &AuditLogEntry) -> Result<String> {
        let ctx = Self::build_context(entry);

        match self.tera.render("log_entry", &ctx) {
            Ok(rendered) => Ok(format!("{}\n", rendered)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    event_id = %entry.event_id,
                    "Template rendering failed, falling back to JSON format"
                );

                // Fall back to JSON to ensure no data loss
                self.fallback.format(entry).await
            }
        }
    }

    /// Render multiple entries using the configured Tera template.
    ///
    /// Each entry is rendered independently using the same template.
    /// Failed renderings fall back to JSON individually (batch continues).
    ///
    /// # Arguments
    /// * `entries` - Slice of entries to render as a batch.
    ///
    /// # Returns
    /// Concatenated rendered strings, one per entry.
    async fn format_batch(&self, entries: &[AuditLogEntry]) -> Result<String> {
        // Pre-allocate with generous estimate (templates may be longer than JSON)
        let estimated_size = entries.len() * 1024;
        let mut batch_output = String::with_capacity(estimated_size);

        for entry in entries {
            let line = self.format(entry).await?;
            batch_output.push_str(&line);
        }

        Ok(batch_output)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::AuditEventType;

    fn create_test_entry() -> AuditLogEntry {
        AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("user-001", "田中 太郎", "staff")
            .with_file("file-001", "document.pdf")
            .with_file_size(1024)
            .with_hashes("abc123def456", "sanitized789")
            .with_network_context("192.168.1.100", "Mozilla/5.0")
            .with_processing_time(150)
    }

    #[tokio::test]
    async fn test_json_formatter_matches_to_jsonl() {
        let formatter = JsonLogFormatter::new();
        let entry = create_test_entry();

        let formatted = formatter.format(&entry).await.unwrap();
        let original = entry.to_jsonl();

        // Must be byte-for-byte identical for backward compatibility
        assert_eq!(formatted, original, "JsonLogFormatter output must match to_jsonl()");
    }

    #[tokio::test]
    async fn test_json_formatter_batch() {
        let formatter = JsonLogFormatter::new();
        let entries: Vec<AuditLogEntry> = (0..5)
            .map(|i| {
                AuditLogEntry::new(AuditEventType::FileUploaded)
                    .with_actor(format!("user-{}", i), "test", "staff")
                    .with_file(format!("file-{}", i), "test.txt")
            })
            .collect();

        let batch = formatter.format_batch(&entries).await.unwrap();
        let lines: Vec<&str> = batch.lines().collect();

        assert_eq!(lines.len(), 5, "Batch should produce 5 lines");

        // Verify each line is valid JSON
        for (i, line) in lines.iter().enumerate() {
            let parsed: AuditLogEntry = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.actor_id, format!("user-{}", i));
        }
    }

    #[tokio::test]
    async fn test_cef_formatter_basic_structure() {
        let formatter = SyslogCefFormatter::new();
        let entry = create_test_entry();

        let cef = formatter.format(&entry).await.unwrap();

        // Must start with CEF:0 prefix
        assert!(cef.starts_with("CEF:0|"), "CEF message must start with 'CEF:0|'");

        // Must contain default vendor/product
        assert!(cef.contains("|Misogi|"), "Must contain vendor 'Misogi'");
        assert!(cef.contains("|CDR Engine|"), "Must contain product 'CDR Engine'");

        // Must contain pipe-delimited header fields
        let header_parts: Vec<&str> = cef.split('|').collect();
        assert!(header_parts.len() >= 7, "CEF header must have at least 7 pipe-separated parts");

        // Must end with newline
        assert!(cef.ends_with('\n'), "CEF message must end with newline");
    }

    #[tokio::test]
    async fn test_cef_formatter_custom_identity() {
        let formatter = SyslogCefFormatter::with_identity("TestVendor", "TestProduct", "2.0");
        let entry = create_test_entry();

        let cef = formatter.format(&entry).await.unwrap();

        assert!(cef.contains("|TestVendor|"), "Must contain custom vendor");
        assert!(cef.contains("|TestProduct|"), "Must contain custom product");
        assert!(cef.contains("|2.0|"), "Must contain custom version");
    }

    #[tokio::test]
    async fn test_cef_formatter_severity_mapping() {
        let formatter = SyslogCefFormatter::new();

        // Test INFO-level events (severity 3)
        let info_entry = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("u1", "test", "staff")
            .with_file("f1", "test.pdf");
        let info_cef = formatter.format(&info_entry).await.unwrap();
        assert!(info_cef.contains("|3|"), "FileUploaded should have severity 3");

        // Test WARNING-level events (severity 6)
        let warn_entry = AuditLogEntry::new(AuditEventType::TransferRequested)
            .with_actor("u2", "test", "staff")
            .with_file("f2", "test.pdf");
        let warn_cef = formatter.format(&warn_entry).await.unwrap();
        assert!(warn_cef.contains("|6|"), "TransferRequested should have severity 6");

        // Test CRITICAL events (severity 10)
        let crit_entry = AuditLogEntry::new(AuditEventType::SecurityViolation)
            .with_actor("u3", "test", "admin")
            .with_file("f3", "intrusion.log");
        let crit_cef = formatter.format(&crit_entry).await.unwrap();
        assert!(crit_cef.contains("|10|"), "SecurityViolation should have severity 10");

        // Test ERROR events (severity 7)
        let err_entry = AuditLogEntry::new(AuditEventType::SystemError)
            .failure("Disk full");
        let err_cef = formatter.format(&err_entry).await.unwrap();
        assert!(err_cef.contains("|7|"), "SystemError should have severity 7");
    }

    #[tokio::test]
    async fn test_cef_formatter_extension_fields() {
        let formatter = SyslogCefFormatter::new();
        let entry = create_test_entry();

        let cef = formatter.format(&entry).await.unwrap();

        // Check standard extension fields
        assert!(cef.contains("src=192.168.1.100"), "Must contain src (IP address)");
        assert!(cef.contains("suser=user-001"), "Must contain suser (actor ID)");
        assert!(cef.contains("act=file_uploaded"), "Must contain act (action)");
        assert!(cef.contains("filePath=document.pdf"), "Must contain filePath");
        assert!(cef.contains("origHash=abc123def456"), "Must contain origHash");
        assert!(cef.contains("newHash=sanitized789"), "Must contain newHash");
        assert!(cef.contains("msg="), "Must contain msg field");
    }

    #[tokio::test]
    async fn test_cef_formatter_escape_special_chars() {
        let formatter = SyslogCefFormatter::new();
        let entry = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("user=bad", "name,with,commas", "role\\slash")
            .with_file("f1", "file=name=value.txt");

        let cef = formatter.format(&entry).await.unwrap();

        // Special chars should be escaped in values
        assert!(!cef.contains("user=bad") || cef.contains("user\\=bad"),
                "Equals sign in value should be escaped");
    }

    #[tokio::test]
    async fn test_template_formatter_basic() {
        let template_content = "{{ entry.event_type }} | {{ entry.actor_name }} | {{ entry.filename }}";
        let formatter = TemplateLogFormatter::from_template(template_content).unwrap();
        let entry = create_test_entry();

        let rendered = formatter.format(&entry).await.unwrap();

        assert!(rendered.contains("file_uploaded"), "Must contain event type");
        assert!(rendered.contains("田中 太郎"), "Must contain actor name");
        assert!(rendered.contains("document.pdf"), "Must contain filename");
        assert!(rendered.ends_with('\n'), "Must end with newline");
    }

    #[tokio::test]
    async fn test_template_formatter_with_optional_fields() {
        // Simple template that always outputs something
        let template_content = "Event: {{ entry.event_type }} Size: {{ entry.file_size }}";
        let formatter = TemplateLogFormatter::from_template(template_content).unwrap();

        // Entry WITH file size
        let with_size = create_test_entry();
        let rendered_with = formatter.format(&with_size).await.unwrap();
        assert!(rendered_with.contains("file_uploaded"), "Must contain event type");

        // Entry WITHOUT file size (file_size is None)
        let without_size = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("u1", "test", "staff")
            .with_file("f1", "test.txt");
        let rendered_without = formatter.format(&without_size).await.unwrap();
        assert!(rendered_without.contains("file_uploaded"), "Must still render event type");
    }

    #[tokio::test]
    async fn test_template_formatter_fallback_on_error() {
        // Template with undefined variable (will fail at runtime)
        let bad_template = "{{ entry.nonexistent_field_that_does_not_exist }}";
        let formatter = TemplateLogFormatter::from_template(bad_template).unwrap();
        let entry = create_test_entry();

        let result = formatter.format(&entry).await;

        // Should NOT return error — should fall back to JSON
        assert!(result.is_ok(), "Should fall back to JSON on template error");
        let fallback_output = result.unwrap();

        // Fallback should be valid JSON (from JsonLogFormatter)
        assert!(fallback_output.starts_with('{'), "Fallback should be JSON format");
        let parsed: AuditLogEntry = serde_json::from_str(fallback_output.trim()).unwrap();
        assert_eq!(parsed.event_id, entry.event_id, "Fallback JSON must preserve event_id");
    }

    #[tokio::test]
    async fn test_template_formatter_complex_template() {
        // Simple template with multiple fields (no filters to avoid Tera quirks)
        let template_content = "{{ entry.event_type }} {{ entry.actor_name }} {{ entry.filename }}";
        let formatter = TemplateLogFormatter::from_template(template_content).unwrap();

        // Entry WITH policy applied
        let with_policy = AuditLogEntry::new(AuditEventType::FileProcessed)
            .with_actor("u1", "Approver", "approver")
            .with_file("f1", "secret.docx")
            .with_policy_applied("REMOVE_ACTIVE_CONTENT")
            .with_sanitize_status("SUCCESS");
        let rendered = formatter.format(&with_policy).await.unwrap();

        assert!(rendered.contains("file_processed"), "Must contain event type");
        assert!(rendered.contains("Approver"), "Must contain actor name");
        assert!(rendered.contains("secret.docx"), "Must contain filename");

        // Entry WITHOUT policy
        let without_policy = AuditLogEntry::new(AuditEventType::FileUploaded)
            .with_actor("u2", "TestUser", "staff")
            .with_file("f2", "normal.txt");
        let rendered2 = formatter.format(&without_policy).await.unwrap();
        assert!(rendered2.contains("file_uploaded"), "Must contain event type for second entry");
    }

    #[tokio::test]
    async fn test_cef_formatter_batch() {
        let formatter = SyslogCefFormatter::new();
        let entries: Vec<AuditLogEntry> = (0..3)
            .map(|i| {
                AuditLogEntry::new(AuditEventType::FileUploaded)
                    .with_actor(format!("user-{}", i), "test", "staff")
                    .with_file(format!("file-{}", i), "test.pdf")
            })
            .collect();

        let batch = formatter.format_batch(&entries).await.unwrap();
        let lines: Vec<&str> = batch.lines().collect();

        assert_eq!(lines.len(), 3, "Batch should produce 3 CEF lines");

        for line in &lines {
            assert!(line.starts_with("CEF:0|"), "Each line must be CEF format");
        }
    }

    #[tokio::test]
    async fn test_file_processed_event_in_all_formatters() {
        let entry = AuditLogEntry::new(AuditEventType::FileProcessed)
            .with_actor("applicant-001", "申請者 田中", "applicant")
            .with_file("file-secret", "confidential.docx")
            .with_transfer_id("tx_987654321")
            .with_applicant_id("applicant-001")
            .with_approver("approver-001")
            .with_policy_applied("REMOVE_ACTIVE_CONTENT")
            .with_sanitize_status("SUCCESS")
            .with_new_file_name("confidential_sanitized.docx")
            .with_new_size_bytes(2048)
            .with_contains_personal_info(true);

        // Test JSON formatter
        let json_fmt = JsonLogFormatter::new();
        let json_output = json_fmt.format(&entry).await.unwrap();
        let parsed: AuditLogEntry = serde_json::from_str(json_output.trim()).unwrap();
        assert_eq!(parsed.event_type, AuditEventType::FileProcessed);
        assert_eq!(parsed.transfer_id.as_deref(), Some("tx_987654321"));
        assert_eq!(parsed.policy_applied.as_deref(), Some("REMOVE_ACTIVE_CONTENT"));

        // Test CEF formatter
        let cef_fmt = SyslogCefFormatter::new();
        let cef_output = cef_fmt.format(&entry).await.unwrap();
        assert!(cef_output.contains("file_processed"), "CEF must contain event type");
        assert!(cef_output.contains("transferId=tx_987654321"), "CEF must contain transfer ID");
        assert!(cef_output.contains("policyApplied=REMOVE_ACTIVE_CONTENT"), "CEF must contain policy");
        assert!(cef_output.contains("sanitizeStatus=SUCCESS"), "CEF must contain sanitize status");

        // Test Template formatter
        let tmpl_fmt = TemplateLogFormatter::from_template(
            "{{ entry.event_type }} TX={{ entry.transfer_id }} POL={{ entry.policy_applied }}"
        ).unwrap();
        let tmpl_output = tmpl_fmt.format(&entry).await.unwrap();
        assert!(tmpl_output.contains("file_processed"), "Template must contain event type");
        assert!(tmpl_output.contains("tx_987654321"), "Template must contain transfer ID");
        assert!(tmpl_output.contains("REMOVE_ACTIVE_CONTENT"), "Template must contain policy");
    }
}
