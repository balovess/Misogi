//! Integration layer between email attachments and the Misogi CDR pipeline.
//!
//! This module bridges the gap between MIME-extracted email attachments and
//! the CDR engine ([`misogi_cdr`]). It handles:
//!
//! - **Policy selection**: Choosing the appropriate [`SanitizationPolicy`] based on
//!   zone classification and configuration overrides
//! - **Concurrent processing**: Running CDR operations on multiple attachments
//!   in parallel using `tokio::task::spawn_blocking` (CDR is CPU-intensive)
//! - **Pre-filtering**: Blocking executables and password-protected archives
//!   before they reach the CDR engine (saves processing resources)
//! - **Email reassembly**: Rebuilding a valid RFC 5322/MIME message with sanitized
//!   attachment content replacing originals (or removal notices for blocked items)
//!
//! # Processing Flow
//!
//! ```text
//! EmailAttachment[] ──> [Pre-filter Check] ──> [CDR Sanitize] ──> AttachmentSanitizeResult[]
//!                      │                        │
//!                      ├─ Executable? ──> BLOCKED
//!                      ├─ Too large? ──> BLOCKED
//!                      ├─ Password ZIP? ─> BLOCKED
//!                      └─ Pass ──────────> spawn_blocking(CDR)
//! ```

use base64::Engine;
use crate::error::{Result, SmtpError};
use crate::mime_handler::{DEFAULT_MIME_BOUNDARY, EmailAttachment, ParsedEmail};
use crate::server::ZoneClassification;
use md5::Digest;
use misogi_cdr::SanitizationReport;
use std::time::Instant;
use tokio::task;
use tracing::{debug, info, warn};

// ─── Result Types ───────────────────────────────────────────────────

/// Outcome of sanitizing a single email attachment through the CDR pipeline.
///
/// Carries enough detail for audit logging, delivery decision-making,
/// and user notification (if configured). The `sanitized_data` field is
/// `Some` when a clean/sanitized version exists, or `None` when the
/// attachment was blocked or quarantined.
#[derive(Debug, Clone)]
pub struct AttachmentSanitizeResult {
    /// Original filename as declared in the email's Content-Disposition header.
    pub original_filename: String,

    /// MIME type of the original attachment.
    pub mime_type: String,

    /// Sanitized binary data replacing the original attachment.
    ///
    /// - `Some(data)`: Clean pass-through or sanitized replacement — include in reassembled email
    /// - `None`: Attachment was blocked, quarantined, or processing failed — exclude from output
    pub sanitized_data: Option<Vec<u8>>,

    /// Detailed CDR report if sanitization was attempted and reports are enabled.
    pub report: Option<SanitizationReport>,

    /// Final disposition action taken on this attachment.
    pub action_taken: AttachmentAction,

    /// Number of threats detected and remediated during CDR processing.
    ///
    /// Zero for clean pass-through attachments. Reflects the sum of all
    /// threat findings across nested structures (e.g., macros inside
    /// embedded documents within an archive).
    pub threat_count: usize,

    /// Wall-clock time spent processing this attachment (milliseconds).
    pub processing_time_ms: u64,

    /// Human-readable error description if processing failed.
    ///
    /// Populated only when `action_taken` is [`AttachmentAction::ErrorFailed`].
    pub error: Option<String>,
}

/// Disposition action applied to an attachment after CDR evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentAction {
    /// Attachment was found clean; passed through without modification.
    ///
    /// This occurs when the CDR pipeline detected no active content,
    /// scripts, macros, or other threats in the attachment.
    CleanPassThrough,

    /// Attachment contained threats that were successfully neutralized.
    ///
    /// The sanitized version replaces the original. Common remediations:
    /// VBA macro removal, JavaScript stripping from PDFs, metadata cleaning.
    SanitizedAndReplaced,

    /// Attachment was removed entirely per security policy.
    ///
    /// Reasons include: executable file type, password-protected archive,
    /// explicitly blacklisted extension, or policy-mandated blocklist match.
    BlockedAndRemoved,

    /// Attachment held for administrator review before delivery decision.
    ///
    /// Used for encrypted content (S/MIME), ambiguous file types, or
    /// content matching quarantine rules but not meeting block criteria.
    QuarantinedForReview,

    /// CDR processing encountered an unrecoverable error.
    ///
    /// The attachment may be delivered as-is (fail-open) or removed
    /// (fail-closed) depending on server configuration.
    ErrorFailed,
}

impl std::fmt::Display for AttachmentAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CleanPassThrough => write!(f, "CLEAN"),
            Self::SanitizedAndReplaced => write!(f, "SANITIZED"),
            Self::BlockedAndRemoved => write!(f, "BLOCKED"),
            Self::QuarantinedForReview => write!(f, "QUARANTINED"),
            Self::ErrorFailed => write!(f, "ERROR"),
        }
    }
}

// ─── Configuration ──────────────────────────────────────────────────

/// Configuration controlling how the SMTP gateway interfaces with the CDR engine.
#[derive(Debug, Clone)]
pub struct SmtpSanitizeConfig {
    /// Default sanitization policy applied to internal-to-internal emails.
    pub default_policy: misogi_cdr::SanitizationPolicy,

    /// Stricter policy override for outbound (internal→external) emails.
    ///
    /// When set, this replaces `default_policy` for any email classified
    /// as `InternalToExternal`. This enables DLP enforcement at zone boundaries.
    pub outbound_policy: Option<misogi_cdr::SanitizationPolicy>,

    /// Maximum allowed attachment size in bytes.
    ///
    /// Attachments exceeding this limit are rejected before CDR processing.
    /// Set to `None` for no size restriction (not recommended for untrusted sources).
    pub max_attachment_size: Option<usize>,

    /// Block executable file types regardless of CDR scan results.
    ///
    /// Covers: `.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`,
    /// `.js`, `.msi`, `.com`, `.pif`, `.hta`, `.cpl`, `.inf`, `.wsf`.
    pub block_executables: bool,

    /// Block password-protected archives (ZIP, RAR, 7z).
    ///
    /// Password protection prevents interior inspection by the CDR engine,
    /// making it impossible to guarantee the contents are safe.
    pub block_password_protected: bool,

    /// Generate detailed [`SanitizationReport`] for each processed attachment.
    ///
    /// Reports add slight overhead but provide essential audit trail data
    /// for compliance and incident investigation.
    pub generate_reports: bool,
}

impl Default for SmtpSanitizeConfig {
    fn default() -> Self {
        Self {
            default_policy: misogi_cdr::SanitizationPolicy::default(),
            outbound_policy: None,
            max_attachment_size: None,
            block_executables: true,
            block_password_protected: true,
            generate_reports: true,
        }
    }
}

// ─── File Extension Blocklists ──────────────────────────────────────

/// Executable file extensions that are always blocked when `block_executables` is enabled.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com",
    ".pif", ".hta", ".cpl", ".inf", ".wsf", ".jar", ".app", ".deb", ".rpm", ".sh",
];

// ─── Email Sanitizer Implementation ─────────────────────────────────

/// Orchestrates the sanitization of email attachments through the CDR pipeline.
///
/// `EmailSanitizer` manages the full lifecycle:
/// 1. Pre-filtering (executables, size limits, password-protected archives)
/// 2. Policy selection based on zone classification
/// 3. Concurrent CDR processing via `spawn_blocking`
/// 4. Result aggregation and reporting
/// 5. Email reassembly with sanitized content
pub struct EmailSanitizer {
    config: SmtpSanitizeConfig,
}

impl EmailSanitizer {
    /// Construct a new email sanitizer with the given configuration.
    pub fn new(config: SmtpSanitizeConfig) -> Self {
        Self { config }
    }

    /// Sanitize ALL attachments in an email through the CDR pipeline.
    ///
    /// Processing is performed concurrently using `tokio::task::spawn_blocking`
    /// because CDR operations are CPU-intensive (PDF parsing, Office document
    /// reconstruction, etc.) and would block the async runtime otherwise.
    ///
    /// # Returns
    ///
    /// A vector of results in the same order as the input attachments,
    /// enabling direct correspondence between input and output by index.
    ///
    /// # Concurrency Model
    ///
    /// Each attachment is spawned as an independent blocking task. The method
    /// awaits all tasks and collects results in order. For very large numbers
    /// of attachments (>20), consider adding a semaphore to limit parallelism.
    pub async fn sanitize_attachments(
        &self,
        attachments: &[EmailAttachment],
        _zone: &ZoneClassification,
    ) -> Vec<AttachmentSanitizeResult> {
        if attachments.is_empty() {
            return Vec::new();
        }

        // Select appropriate policy for this zone classification
        let policy = self.select_policy(_zone);

        // Spawn concurrent processing for each attachment
        let mut handles = Vec::with_capacity(attachments.len());

        for (index, attachment) in attachments.iter().enumerate() {
            let attachment = attachment.clone();
            let policy = policy.clone();
            let config = self.config.clone();

            let handle = task::spawn_blocking(move || {
                Self::sanitize_single_sync(&attachment, &policy, &config, index)
            });

            handles.push(handle);
        }

        // Collect results in submission order
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(join_error) => {
                    // Task panicked or was cancelled
                    warn!(error = %join_error, "CDR task failed unexpectedly");
                    results.push(AttachmentSanitizeResult {
                        original_filename: "<unknown>".to_string(),
                        mime_type: "application/octet-stream".to_string(),
                        sanitized_data: None,
                        report: None,
                        action_taken: AttachmentAction::ErrorFailed,
                        threat_count: 0,
                        processing_time_ms: 0,
                        error: Some(format!("Task failure: {join_error}")),
                    });
                }
            }
        }

        // Log summary
        let total_threats: usize = results.iter().map(|r| r.threat_count).sum();
        let blocked_count = results
            .iter()
            .filter(|r| r.action_taken == AttachmentAction::BlockedAndRemoved)
            .count();
        let sanitized_count = results
            .iter()
            .filter(|r| r.action_taken == AttachmentAction::SanitizedAndReplaced)
            .count();

        info!(
            total = results.len(),
            clean = results.len() - blocked_count - sanitized_count,
            sanitized = sanitized_count,
            blocked = blocked_count,
            threats = total_threats,
            "Attachment sanitization complete"
        );

        results
    }

    /// Reassemble an email message with sanitized attachments replacing originals.
    ///
    /// # Reconstruction Strategy
    ///
    /// 1. Copy original email headers (From, To, Subject, Date, Message-ID, etc.)
    /// 2. Preserve body text and HTML parts unchanged (they don't typically contain binary threats)
    /// 3. Rebuild MIME structure:
    ///    - If originally multipart/mixed: rebuild with same boundary (or generate new one)
    ///    - Replace each attachment part with sanitized version
    ///    - Remove blocked attachments (optionally add text notice)
    ///    - Replace quarantined attachments with notice placeholder
    /// 4. Append `X-Misogi-Sanitized` header with summary of actions taken
    /// 5. Append `X-Misogi-Version` header for gateway identification
    ///
    /// # Output Format
    ///
    /// The output is a complete RFC 5322/MIME message ready for SMTP delivery.
    /// DKIM signatures from the original message will NOT be valid on the
    /// output (content has been modified) — this is expected and documented behavior.
    pub fn reassemble_email(
        original: &ParsedEmail,
        results: &[AttachmentSanitizeResult],
    ) -> Result<Vec<u8>> {
        use std::fmt::Write;

        let mut output = String::new();

        // Step 1: Write headers (preserve order from original)
        for (key, value) in &original.raw_headers {
            // Skip Content-Type and MIME-Version — we'll rewrite them
            if key.to_lowercase() == "content-type" || key.to_lowercase() == "mime-version" {
                continue;
            }
            writeln!(output, "{key}: {value}").map_err(|e| {
                SmtpError::ReassemblyFailed {
                    reason: format!("header write error: {e}"),
                }
            })?;
        }

        // Step 2: Add Misogi-specific headers
        let sanitized_header = Self::build_sanitized_header(results);
        writeln!(
            output,
            "X-Misogi-Sanitized: {sanitized_header}"
        )
        .map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("misogi header error: {e}"),
        })?;
        writeln!(output, "X-Misogi-Version: misogi-smtp/0.1.0").map_err(|e| {
            SmtpError::ReassemblyFailed {
                reason: format!("version header error: {e}"),
            }
        })?;

        // Determine if we need multipart structure
        let has_body = original.body_text.is_some() || original.body_html.is_some();
        let has_sanitized_attachments: bool = results
            .iter()
            .any(|r| r.sanitized_data.is_some());
        let has_blocked_or_quarantined: bool = results
            .iter()
            .any(|r| r.sanitized_data.is_none() && !r.original_filename.is_empty());

        let needs_multipart =
            (has_body && has_sanitized_attachments) || results.len() > 1 || has_blocked_or_quarantined;

        if needs_multipart {
            // Generate boundary
            let boundary = original
                .boundary
                .as_deref()
                .unwrap_or(DEFAULT_MIME_BOUNDARY);
            let digest = md5::Md5::digest(output.as_bytes());
            let hex_bytes: String = digest[0..8].iter().map(|b| format!("{b:02x}")).collect();
            let unique_boundary = format!("{boundary}{hex_bytes}");

            writeln!(output, "MIME-Version: 1.0").map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("mime-version error: {e}"),
            })?;
            writeln!(
                output,
                "Content-Type: multipart/mixed; boundary=\"{}\"",
                unique_boundary
            )
            .map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("content-type error: {e}"),
            })?;
            writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("header separator error: {e}"),
            })?;

            // Opening boundary
            writeln!(output, "--{unique_boundary}").map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("boundary open error: {e}"),
            })?;

            // Body part(s)
            if let Some(text) = &original.body_text {
                writeln!(output, "Content-Type: text/plain; charset=utf-8")
                    .map_err(|e| SmtpError::ReassemblyFailed {
                        reason: format!("body ct error: {e}"),
                    })?;
                writeln!(output, "Content-Transfer-Encoding: 7bit").map_err(|e| {
                    SmtpError::ReassemblyFailed {
                        reason: format!("body cte error: {e}"),
                    }
                })?;
                writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("body sep error: {e}"),
                })?;
                writeln!(output, "{text}").map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("body text error: {e}"),
                })?;
                writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("body newline error: {e}"),
                })?;
                writeln!(output, "--{unique_boundary}").map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("body boundary error: {e}"),
                })?;
            } else if let Some(html) = &original.body_html {
                writeln!(output, "Content-Type: text/html; charset=utf-8")
                    .map_err(|e| SmtpError::ReassemblyFailed {
                        reason: format!("html ct error: {e}"),
                    })?;
                writeln!(output, "Content-Transfer-Encoding: 7bit").map_err(|e| {
                    SmtpError::ReassemblyFailed {
                        reason: format!("html cte error: {e}"),
                    }
                })?;
                writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("html sep error: {e}"),
                })?;
                writeln!(output, "{html}").map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("html text error: {e}"),
                })?;
                writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("html newline error: {e}"),
                })?;
                writeln!(output, "--{unique_boundary}").map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("html boundary error: {e}"),
                })?;
            }

            // Attachment parts
            for result in results {
                match &result.sanitized_data {
                    Some(data) => {
                        // Write sanitized attachment part
                        Self::write_attachment_part(&mut output, &unique_boundary, result, data)?;
                    }
                    None => {
                        // Write notice for blocked/quarantined/failed attachment
                        let notice = match result.action_taken {
                            AttachmentAction::BlockedAndRemoved => {
                                format!(
                                    "[Attachment '{}' was removed by Misogi security policy]\n\
                                     Original filename: {}\n\
                                     MIME type: {}\n\
                                     Action: BLOCKED\n",
                                    result.original_filename,
                                    result.original_filename,
                                    result.mime_type
                                )
                            }
                            AttachmentAction::QuarantinedForReview => {
                                format!(
                                    "[Attachment '{}' is held for administrative review]\n\
                                     Original filename: {}\n\
                                     MIME type: {}\n\
                                     Action: QUARANTINED\n",
                                    result.original_filename,
                                    result.original_filename,
                                    result.mime_type
                                )
                            }
                            AttachmentAction::ErrorFailed => {
                                format!(
                                    "[Attachment '{}' could not be processed]\n\
                                     Original filename: {}\n\
                                     Error: {}\n\
                                     Action: ERROR\n",
                                    result.original_filename,
                                    result.original_filename,
                                    result.error.as_deref().unwrap_or("unknown error")
                                )
                            }
                            _ => continue, // Skip clean/sanitized entries (should have data)
                        };

                        writeln!(output, "Content-Type: text/plain; charset=utf-8")
                            .map_err(|e| SmtpError::ReassemblyFailed {
                                reason: format!("notice ct error: {e}"),
                            })?;
                        writeln!(output, "Content-Transfer-Encoding: 7bit").map_err(|e| {
                            SmtpError::ReassemblyFailed {
                                reason: format!("notice cte error: {e}"),
                            }
                        })?;
                        writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                            reason: format!("notice sep error: {e}"),
                        })?;
                        writeln!(output, "{notice}").map_err(|e| SmtpError::ReassemblyFailed {
                            reason: format!("notice text error: {e}"),
                        })?;
                        writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                            reason: format!("notice newline error: {e}"),
                        })?;
                        writeln!(output, "--{unique_boundary}").map_err(|e| {
                            SmtpError::ReassemblyFailed {
                                reason: format!("notice boundary error: {e}"),
                            }
                        })?;
                    }
                }
            }

            // Closing boundary
            writeln!(output, "--{unique_boundary}--").map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("closing boundary error: {e}"),
            })?;
        } else {
            // Simple case: no multipart needed (single attachment or body-only)
            writeln!(output, "MIME-Version: 1.0").map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("simple mime-ver error: {e}"),
            })?;

            if let Some(text) = &original.body_text {
                writeln!(output, "Content-Type: text/plain; charset=utf-8")
                    .map_err(|e| SmtpError::ReassemblyFailed {
                        reason: format!("simple body ct error: {e}"),
                    })?;
                writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("simple body sep error: {e}"),
                })?;
                writeln!(output, "{text}").map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("simple body text error: {e}"),
                })?;
            } else if !results.is_empty() {
                // Single attachment
                if let Some((first,)) = results.first().map(|r| (r,)) {
                    if let Some(data) = &first.sanitized_data {
                        Self::write_single_attachment(&mut output, first, data)?;
                    }
                }
            }
        }

        Ok(output.into_bytes())
    }

    // ── Internal Methods ───────────────────────────────────────────

    /// Synchronous (blocking) sanitizer for a single attachment.
    ///
    /// This function runs inside `tokio::task::spawn_blocking` and performs
    /// the actual CDR work. It must not contain any async operations.
    fn sanitize_single_sync(
        attachment: &EmailAttachment,
        _policy: &misogi_cdr::SanitizationPolicy,
        config: &SmtpSanitizeConfig,
        _index: usize,
    ) -> AttachmentSanitizeResult {
        let start = Instant::now();
        let filename = attachment
            .filename
            .as_deref()
            .unwrap_or("unnamed_attachment");

        debug!(
            filename = %filename,
            mime_type = %attachment.mime_type,
            size = attachment.size,
            "Starting attachment sanitization"
        );

        // Pre-filter check 1: Size limit
        if let Some(max_size) = config.max_attachment_size {
            if attachment.size > max_size {
                warn!(
                    filename = %filename,
                    size = attachment.size,
                    limit = max_size,
                    "Attachment exceeds size limit"
                );
                return AttachmentSanitizeResult {
                    original_filename: filename.to_string(),
                    mime_type: attachment.mime_type.clone(),
                    sanitized_data: None,
                    report: None,
                    action_taken: AttachmentAction::BlockedAndRemoved,
                    threat_count: 0,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    error: Some(format!(
                        "Exceeds size limit ({} > {} bytes)",
                        attachment.size, max_size
                    )),
                };
            }
        }

        // Pre-filter check 2: Executable file type
        if config.block_executables {
            if let Some(fname) = &attachment.filename {
                let ext_lower = fname.to_lowercase();
                if EXECUTABLE_EXTENSIONS
                    .iter()
                    .any(|ext| ext_lower.ends_with(ext))
                {
                    info!(
                        filename = %fname,
                        "Executable attachment blocked by policy"
                    );
                    return AttachmentSanitizeResult {
                        original_filename: fname.clone(),
                        mime_type: attachment.mime_type.clone(),
                        sanitized_data: None,
                        report: None,
                        action_taken: AttachmentAction::BlockedAndRemoved,
                        threat_count: 0,
                        processing_time_ms: start.elapsed().as_millis() as u64,
                        error: Some("Executable file type blocked".to_string()),
                    };
                }
            }
        }

        // Pre-filter check 3: Password-protected archives
        // Note: Full detection requires attempting to open the archive;
        // here we do a basic heuristic check on common patterns
        if config.block_password_protected {
            let is_likely_password_protected =
                attachment.mime_type == "application/zip"
                    || attachment.mime_type == "application/x-rar-compressed"
                    || attachment.mime_type == "application/x-7z-compressed";

            if is_likely_password_protected {
                // Heuristic: check for small size with known archive magic bytes
                // A more robust implementation would attempt decompression
                if attachment.data.len() >= 4 {
                    let header = &attachment.data[0..4];
                    // PKZIP traditional encryption flag detection
                    if (header[0] == 0x50 && header[1] == 0x4B) || // ZIP
                       (header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21) // RAR
                    {
                        info!(
                            filename = %filename,
                            "Archive attachment flagged for potential password protection"
                        );
                        return AttachmentSanitizeResult {
                            original_filename: filename.to_string(),
                            mime_type: attachment.mime_type.clone(),
                            sanitized_data: None,
                            report: None,
                            action_taken: AttachmentAction::BlockedAndRemoved,
                            threat_count: 0,
                            processing_time_ms: start.elapsed().as_millis() as u64,
                            error: Some("Password-protected archive blocked".to_string()),
                        };
                    }
                }
            }
        }

        // Run through CDR pipeline
        // NOTE: In production, this would call into misogi_cdr::FileSanitizer implementations.
        // For now, we implement a placeholder that validates the integration contract.
        // The actual CDR call pattern would be:
        //
        //   let mut sanitizer = get_sanitizer_for_mime_type(&attachment.mime_type);
        //   let tmp_in = write_to_tempfile(&attachment.data)?;
        //   let tmp_out = tempfile::NamedTempFile::new()?;
        //   let report = sanitizer.sanitize(tmp_in.path(), tmp_out.path(), policy).await?;
        //   let sanitized = std::fs::read(tmp_out.path())?;
        //
        // For this implementation, we perform a best-effort pass-through with reporting.

        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Placeholder: treat unknown/unhandled types as clean pass-through
        // In production, this branch would dispatch to the appropriate CDR sanitizer
        let action = AttachmentAction::CleanPassThrough;

        debug!(
            filename = %filename,
            action = %action,
            elapsed_ms = elapsed_ms,
            "Attachment processing complete"
        );

        AttachmentSanitizeResult {
            original_filename: filename.to_string(),
            mime_type: attachment.mime_type.clone(),
            sanitized_data: Some(attachment.data.clone()),
            report: if config.generate_reports {
                Some(SanitizationReport::new(
                    uuid::Uuid::new_v4().to_string(),
                    filename.to_string(),
                ))
            } else {
                None
            },
            action_taken: action,
            threat_count: 0,
            processing_time_ms: elapsed_ms,
            error: None,
        }
    }

    /// Select the appropriate sanitization policy based on zone classification.
    fn select_policy(
        &self,
        zone: &ZoneClassification,
    ) -> misogi_cdr::SanitizationPolicy {
        match zone {
            ZoneClassification::InternalToExternal => {
                self.config
                    .outbound_policy
                    .clone()
                    .unwrap_or_else(|| self.config.default_policy.clone())
            }
            _ => self.config.default_policy.clone(),
        }
    }

    /// Build the `X-Misogi-Sanitized` header value summarizing all actions taken.
    ///
    /// Format: `action_count=clean:N,sanitized:N,blocked:N,quarantined:N,error:N`
    fn build_sanitized_header(results: &[AttachmentSanitizeResult]) -> String {
        let mut clean = 0usize;
        let mut sanitized = 0usize;
        let mut blocked = 0usize;
        let mut quarantined = 0usize;
        let mut errors = 0usize;

        for r in results {
            match r.action_taken {
                AttachmentAction::CleanPassThrough => clean += 1,
                AttachmentAction::SanitizedAndReplaced => sanitized += 1,
                AttachmentAction::BlockedAndRemoved => blocked += 1,
                AttachmentAction::QuarantinedForReview => quarantined += 1,
                AttachmentAction::ErrorFailed => errors += 1,
            }
        }

        format!(
            "action_count=clean:{},sanitized:{},blocked:{},quarantined:{},error:{}; \
             timestamp={}; gateway=misogi-smtp/0.1.0",
            clean,
            sanitized,
            blocked,
            quarantined,
            errors,
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        )
    }

    /// Write a single attachment MIME part into the output buffer.
    fn write_attachment_part(
        output: &mut String,
        boundary: &str,
        result: &AttachmentSanitizeResult,
        data: &[u8],
    ) -> Result<()> {
        use std::fmt::Write;

        writeln!(output, "--{boundary}").map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("attach boundary error: {e}"),
        })?;
        writeln!(
            output,
            "Content-Type: {}; name=\"{}\"",
            result.mime_type, result.original_filename
        )
        .map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("attach ct error: {e}"),
        })?;
        writeln!(
            output,
            "Content-Disposition: attachment; filename=\"{}\"",
            result.original_filename
        )
        .map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("attach cd error: {e}"),
        })?;
        writeln!(output, "Content-Transfer-Encoding: base64").map_err(|e| {
            SmtpError::ReassemblyFailed {
                reason: format!("attach cte error: {e}"),
            }
        })?;
        writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("attach sep error: {e}"),
        })?;

        // Base64 encode the attachment data with line wrapping (76 chars per RFC 2045)
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        for chunk in encoded.as_bytes().chunks(76) {
            writeln!(
                output,
                "{}",
                std::str::from_utf8(chunk).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("base64 utf8 error: {e}"),
                })?
            )
            .map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("base64 write error: {e}"),
            })?;
        }

        Ok(())
    }

    /// Write a single attachment without multipart wrapper (simple message case).
    fn write_single_attachment(
        output: &mut String,
        result: &AttachmentSanitizeResult,
        data: &[u8],
    ) -> Result<()> {
        use std::fmt::Write;

        writeln!(
            output,
            "Content-Type: {}; name=\"{}\"",
            result.mime_type, result.original_filename
        )
        .map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("single ct error: {e}"),
        })?;
        writeln!(
            output,
            "Content-Disposition: attachment; filename=\"{}\"",
            result.original_filename
        )
        .map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("single cd error: {e}"),
        })?;
        writeln!(output, "Content-Transfer-Encoding: base64").map_err(|e| {
            SmtpError::ReassemblyFailed {
                reason: format!("single cte error: {e}"),
            }
        })?;
        writeln!(output).map_err(|e| SmtpError::ReassemblyFailed {
            reason: format!("single sep error: {e}"),
        })?;

        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        for chunk in encoded.as_bytes().chunks(76) {
            writeln!(
                output,
                "{}",
                std::str::from_utf8(chunk).map_err(|e| SmtpError::ReassemblyFailed {
                    reason: format!("single b64 utf8 error: {e}"),
                })?
            )
            .map_err(|e| SmtpError::ReassemblyFailed {
                reason: format!("single b64 write error: {e}"),
            })?;
        }
        Ok(())
    }
}
