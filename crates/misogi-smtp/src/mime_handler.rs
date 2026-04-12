//! MIME message parser and attachment extractor.
//!
//! This module provides robust parsing of RFC 5322 Internet Message Format
//! emails with full MIME (RFC 2045-2049) support, including:
//!
//! - **Simple messages**: `text/plain` or `text/html` without multipart structure
//! - **Multipart/alternative**: Paired text and HTML body representations
//! - **Multipart/mixed**: Body parts combined with file attachments
//! - **Nested multipart**: Recursive structures (e.g., `multipart/alternative` inside `multipart/mixed`)
//! - **Transfer encodings**: Base64, quoted-printable, 7bit, 8bit, binary
//! - **Internationalized headers**: RFC 2047 encoded words (`=?charset?encoding?text?=`)
//! - **S/MIME detection**: `application/pkcs7-mime` encrypted content identification
//!
//! # Security Considerations
//!
//! - MIME nesting depth is capped at [`MAX_NESTING_DEPTH`] to prevent
//!   multipart bomb attacks (exponential memory consumption via deeply nested parts)
//! - Attachment size is tracked but not limited here (limiting is the responsibility
//!   of the caller / CDR pipeline configuration)
//! - Malformed MIME boundaries are handled with best-effort recovery rather than panic

use crate::error::{Result, SmtpError};
use crate::server::ZoneClassification;
use crate::server::ZonePolicy;
use base64::Engine;
use chrono::{DateTime, Utc};
use mailparse::ParsedMail;
use tracing::debug;

/// Maximum recursion depth for nested MIME parts.
///
/// Prevents multipart bomb attacks where a malicious email contains
/// thousands of nested multipart containers to cause stack overflow
/// or excessive memory allocation.
const MAX_NESTING_DEPTH: usize = 20;

/// Default MIME boundary string used when rebuilding sanitized emails.
pub const DEFAULT_MIME_BOUNDARY: &str = "=_MisogiSanitized-";

// ─── Parsed Email Structures ────────────────────────────────────────

/// Fully parsed and structured representation of an email message.
///
/// All text fields are decoded from their transfer encoding (base64,
/// quoted-printable) and character set. Binary attachment data is kept
/// in its raw decoded form for direct feeding into the CDR pipeline.
#[derive(Debug, Clone)]
pub struct ParsedEmail {
    /// Raw header key-value pairs in original order.
    ///
    /// Each tuple is `(name, value)` with name already lowercased.
    pub raw_headers: Vec<(String, String)>,

    /// Structured header fields extracted from raw headers.
    pub headers: EmailHeaders,

    /// Decoded plain-text body content (`None` if no text/plain part found).
    pub body_text: Option<String>,

    /// Decoded HTML body content (`None` if no text/html part found).
    pub body_html: Option<String>,

    /// All non-body attachments extracted from the message.
    ///
    /// Order matches appearance order in the original MIME structure.
    pub attachments: Vec<EmailAttachment>,

    /// Whether S/MIME encrypted content was detected.
    ///
    /// Encrypted attachments cannot be inspected by the CDR pipeline
    /// and should be quarantined for manual review.
    pub is_encrypted: bool,

    /// Whether a digital signature (DKIM or S/MIME) was detected.
    ///
    /// Signatures will be invalidated after sanitization because the
    /// content has been modified. This is expected behavior — the gateway
    /// adds its own `X-Misogi-Sanitized` header as replacement attestation.
    pub is_signed: bool,

    /// MIME boundary string from the outermost Content-Type header.
    ///
    /// Used when reconstructing the sanitized email to preserve boundary
    /// compatibility with clients that rely on specific boundary values.
    pub boundary: Option<String>,

    /// Total size of raw input bytes (for logging and size-limit checks).
    pub raw_size: usize,
}

/// Extracted and normalized email headers.
///
/// Addresses are stored both as full header values (preserving display names)
/// and as bare email addresses (for zone classification matching).
#[derive(Debug, Clone)]
pub struct EmailHeaders {
    /// Full `From:` header value (e.g., `"Display Name" <user@example.com>`).
    pub from: String,

    /// Bare sender email address extracted from `From:` header.
    pub from_address: String,

    /// All recipient addresses from `To:` header(s).
    pub to: Vec<String>,

    /// Carbon-copy addresses from `Cc:` header(s).
    pub cc: Vec<String>,

    /// Blind carbon-copy addresses from `Bcc:` header.
    ///
    /// Note: Bcc is typically stripped by the sending MTA before the
    /// message reaches this gateway. This field exists for completeness
    /// but will usually be empty.
    pub bcc: Vec<String>,

    /// Subject line (RFC 2047 decoded if encoded).
    pub subject: String,

    /// Unique message identifier (e.g., `<uuid@domain>`).
    pub message_id: Option<String>,

    /// Date/time the message was sent (parsed from `Date:` header).
    pub date: Option<DateTime<Utc>>,

    /// Received header chain in reverse order (oldest first).
    ///
    /// Useful for tracing the message's path through MTAs before reaching
    /// this gateway. Each entry is the raw `Received:` header value.
    pub received: Vec<String>,

    /// MIME Content-Type of the message body (e.g., `"text/plain"`).
    pub content_type: Option<String>,

    /// MIME version declared by the sender (typically `"1.0"`).
    pub mime_version: Option<String>,
}

/// A single extracted attachment ready for CDR processing.
///
/// Contains all metadata needed to route the attachment through the
/// appropriate sanitizer based on MIME type and filename extension.
#[derive(Debug, Clone)]
pub struct EmailAttachment {
    /// Content-ID for inline/MHTML references (e.g., `<part1@example.com>`).
    pub content_id: Option<String>,

    /// Original filename from `Content-Disposition` or `Content-Type` `name` parameter.
    ///
    /// May be `None` for inline parts without explicit naming.
    pub filename: Option<String>,

    /// Full MIME type string (e.g., `"application/vnd.openxmlformats-officedocument.wordprocessingml.document"`).
    ///
    /// Determined from `Content-Type` header; falls back to `"application/octet-stream"`
    /// if unspecified.
    pub mime_type: String,

    /// Content disposition: `"inline"` or `"attachment"` (per RFC 2183).
    pub content_disposition: String,

    /// Transfer encoding used for this part (e.g., `"base64"`, `"quoted-printable"`).
    ///
    /// `None` implies `"7bit"` (the default per RFC 2045 §6.1).
    pub transfer_encoding: Option<String>,

    /// Fully decoded binary content of this attachment.
    ///
    /// Transfer encoding (base64/QP) has already been reversed.
    /// This data is ready for direct input to the CDR pipeline.
    pub data: Vec<u8>,

    /// Size of decoded data in bytes.
    pub size: usize,

    /// Content-Location URL (used in MHTML / related messages).
    pub content_location: Option<String>,
}

// ─── MIME Handler Implementation ────────────────────────────────────

/// Parser and extractor for MIME-structured email messages.
///
/// `MimeHandler` is stateless and cheaply cloneable. All parsing state
/// is contained within method call stacks, making it safe for concurrent
/// use across multiple async tasks.
#[derive(Debug, Clone)]
pub struct MimeHandler;

impl MimeHandler {
    /// Construct a new MIME handler instance.
    #[inline]
    pub fn new() -> Self {
        Self
    }

    /// Parse raw email bytes (`.eml` format) into structured representation.
    ///
    /// # Supported Formats
    ///
    /// | Structure | Description |
    /// |-----------|-------------|
    /// | Simple | Single `text/plain` or `text/html` body |
    /// | Multipart/alternative | Text + HTML variants of same content |
    /// | Multipart/mixed | Body + one or more file attachments |
    /// | Nested | `multipart/alternative` within `multipart/mixed` |
    /// | Signed | S/MIME or DKIM signature wrapper |
    /// | Encrypted | S/MIME `application/pkcs7-mime` envelope |
    ///
    /// # RFC Compliance
    ///
    /// - RFC 5322 — Internet Message Format (header syntax, folding)
    /// - RFC 2045 — MIME Part One: Format of Internet Message Bodies
    /// - RFC 2046 — MIME Part Two: Media Types
    /// - RFC 2047 — MIME (Non-ASCII) Header Field Extensions
    /// - RFC 2183 — Content-Disposition header field
    /// - RFC 3156 — S/MIME (Multipart/Signed and Application/PKCS7-Mime)
    /// - RFC 6532 — Internationalized Email Headers (UTF-8 support)
    ///
    /// # Errors
    ///
    /// Returns [`SmtpError::MimeParseError`] if the input cannot be parsed
    /// as valid email format (completely malformed, not even recognizable
    /// as an email message).
    ///
    /// Returns [`SmtpError::NestingDepthExceeded`] if MIME part nesting
    /// exceeds [`MAX_NESTING_DEPTH`] (potential bomb attack).
    pub fn parse_email(&self, raw: &[u8]) -> Result<ParsedEmail> {
        let raw_size = raw.len();

        // Parse using mailparse library (handles RFC compliance)
        let parsed = mailparse::parse_mail(raw).map_err(|e| SmtpError::MimeParseError {
            reason: e.to_string(),
        })?;

        // Extract raw headers
        let raw_headers: Vec<(String, String)> = parsed
            .headers
            .iter()
            .map(|h| (h.get_key().to_lowercase(), h.get_value()))
            .collect();

        // Extract structured headers
        let headers = self.extract_email_headers(&raw_headers)?;

        // Detect encryption/signature
        let is_encrypted = self.detect_encryption(&parsed);
        let is_signed = self.detect_signature(&parsed);

        // Extract MIME boundary
        let boundary = self.extract_boundary(&parsed);

        // Walk MIME tree to extract bodies and attachments
        let mut body_text: Option<String> = None;
        let mut body_html: Option<String> = None;
        let mut attachments: Vec<EmailAttachment> = Vec::new();

        self.extract_parts_recursive(
            &parsed,
            &mut body_text,
            &mut body_html,
            &mut attachments,
            0,
        )?;

        debug!(
            body_text = body_text.is_some(),
            body_html = body_html.is_some(),
            attachments = attachments.len(),
            encrypted = is_encrypted,
            signed = is_signed,
            "Email parsed successfully"
        );

        Ok(ParsedEmail {
            raw_headers,
            headers,
            body_text,
            body_html,
            attachments,
            is_encrypted,
            is_signed,
            boundary,
            raw_size,
        })
    }

    /// Classify email zone based on From/To domains vs internal domain list.
    ///
    /// Zone classification determines which sanitization policy applies:
    /// outbound (internal→external) emails receive stricter treatment.
    ///
    /// # Classification Rules
    ///
    /// | Sender Domain | Recipient Domains | Classification |
    /// |--------------|-------------------|----------------|
    /// | Internal     | All internal      | `InternalToInternal` |
    /// | Internal     | Any external      | `InternalToExternal` |
    /// | External     | Any internal      | `ExternalToInternal` |
    /// | External     | All external      | `ExternalToExternal` |
    ///
    /// If no internal domains are configured, all traffic is classified
    /// as `ExternalToExternal`.
    pub fn classify_zone(
        &self,
        email: &ParsedEmail,
        zone_config: &ZonePolicy,
    ) -> ZoneClassification {
        if zone_config.internal_domains.is_empty() {
            return ZoneClassification::ExternalToExternal;
        }

        let sender_internal = Self::is_internal_domain(&email.headers.from_address, &zone_config.internal_domains);

        // Collect all recipient addresses
        let all_recipients: Vec<&String> = email
            .headers
            .to
            .iter()
            .chain(email.headers.cc.iter())
            .chain(email.headers.bcc.iter())
            .collect();

        let has_external_recipient = all_recipients
            .iter()
            .any(|r| !Self::is_internal_domain(r, &zone_config.internal_domains));

        let has_internal_recipient = all_recipients
            .iter()
            .any(|r| Self::is_internal_domain(r, &zone_config.internal_domains));

        match (sender_internal, has_external_recipient, has_internal_recipient) {
            (true, false, _) => ZoneClassification::InternalToInternal,
            (true, true, _) => ZoneClassification::InternalToExternal,
            (false, _, true) => ZoneClassification::ExternalToInternal,
            (false, _, false) => ZoneClassification::ExternalToExternal,
        }
    }

    // ── Internal Methods ───────────────────────────────────────────

    /// Extract structured header fields from raw header list.
    fn extract_email_headers(&self, raw_headers: &[(String, String)]) -> Result<EmailHeaders> {
        let get_header = |name: &str| -> String {
            raw_headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };

        let get_header_multi = |name: &str| -> Vec<String> {
            raw_headers
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .collect()
        };

        let from_raw = get_header("from");
        let from_address = Self::extract_address_only(&from_raw);

        // Parse To/Cc/Bcc addresses (may contain multiple comma-separated addresses)
        let to_raw = get_header("to");
        let to: Vec<String> = Self::split_addresses(&to_raw);

        let cc_raw = get_header("cc");
        let cc: Vec<String> = Self::split_addresses(&cc_raw);

        let bcc_raw = get_header("bcc");
        let bcc: Vec<String> = Self::split_addresses(&bcc_raw);

        let subject = get_header("subject");

        let message_id = {
            let mid = get_header("message-id");
            if mid.is_empty() {
                None
            } else {
                Some(mid)
            }
        };

        let date = {
            let date_str = get_header("date");
            if date_str.is_empty() {
                None
            } else {
                // Try multiple date formats commonly found in emails
                chrono::DateTime::parse_from_rfc2822(&date_str)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|| {
                        chrono::DateTime::parse_from_rfc3339(&date_str)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    })
            }
        };

        let received = get_header_multi("received");
        // Reverse so oldest is first
        let received: Vec<String> = received.into_iter().rev().collect();

        let content_type = {
            let ct = get_header("content-type");
            // Strip parameters, keep only media type
            ct.split(';')
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        let mime_version = {
            let mv = get_header("mime-version");
            if mv.is_empty() {
                None
            } else {
                Some(mv)
            }
        };

        Ok(EmailHeaders {
            from: from_raw,
            from_address,
            to,
            cc,
            bcc,
            subject,
            message_id,
            date,
            received,
            content_type,
            mime_version,
        })
    }

    /// Recursively walk the MIME tree to extract body text, HTML, and attachments.
    ///
    /// # Depth Limiting
    ///
    /// Recursion is capped at [`MAX_NESTING_DEPTH`] levels. Beyond this limit,
    /// the method returns [`SmtpError::NestingDepthExceeded`] to prevent
    /// memory exhaustion from maliciously crafted deeply-nested MIME structures.
    fn extract_parts_recursive(
        &self,
        part: &ParsedMail,
        body_text: &mut Option<String>,
        body_html: &mut Option<String>,
        attachments: &mut Vec<EmailAttachment>,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_NESTING_DEPTH {
            return Err(SmtpError::NestingDepthExceeded {
                depth,
                max_depth: MAX_NESTING_DEPTH,
            });
        }

        let ctype = part.ctype.mimetype.to_string();

        match part.subparts.as_slice() {
            // Leaf node: single content part
            [] => {
                // Get decoded body content
                let data = part.get_body().unwrap_or_default();

                // Determine content disposition
                let content_disposition = part
                    .headers
                    .iter()
                    .find(|h| h.get_key().to_lowercase() == "content-disposition")
                    .map(|h| {
                        h.get_value()
                            .split(';')
                            .next()
                            .unwrap_or("attachment")
                            .trim()
                            .to_lowercase()
                    })
                    .unwrap_or_else(|| "inline".to_string());

                // Determine if this is an attachment or body part
                let is_attachment =
                    content_disposition == "attachment"
                        || (content_disposition == "inline"
                            && !ctype.starts_with("text/")
                            && !data.is_empty());

                // Check for explicit filename from Content-Disposition or Content-Type header
                let filename = part
                    .headers
                    .iter()
                    .find(|h| {
                        let key = h.get_key().to_lowercase();
                        key == "content-disposition" || key == "content-type"
                    })
                    .and_then(|h| {
                        // Parse filename parameter from header value
                        h.get_value()
                            .split(';')
                            .find(|s| s.trim().starts_with("filename="))
                            .and_then(|s| {
                                s.trim()
                                    .strip_prefix("filename=")
                                    .map(|f| f.trim_matches('"').trim().to_string())
                            })
                    });

                // Get Content-ID
                let content_id = part
                    .headers
                    .iter()
                    .find(|h| h.get_key().to_lowercase() == "content-id")
                    .map(|h| h.get_value())
                    .filter(|s| !s.is_empty());

                // Get Content-Location
                let content_location = part
                    .headers
                    .iter()
                    .find(|h| h.get_key().to_lowercase() == "content-location")
                    .map(|h| h.get_value())
                    .filter(|s| !s.is_empty());

                // Get transfer encoding from Content-Transfer-Encoding header
                let transfer_encoding = part
                    .headers
                    .iter()
                    .find(|h| h.get_key().to_lowercase() == "content-transfer-encoding")
                    .map(|h| h.get_value())
                    .filter(|s| !s.is_empty());

                // Get raw bytes for binary attachments (get_body does charset decoding which corrupts binary)
                let (raw_data, data_for_body) = if is_attachment || (!ctype.starts_with("text/") && !data.is_empty()) {
                    let raw = part.get_body_raw().unwrap_or_else(|_| data.clone().into_bytes());
                    (raw, None)
                } else {
                    // Keep a copy for body assignment since into_bytes consumes
                    let data_copy = data.clone();
                    (data_copy.into_bytes(), Some(data))
                };

                if is_attachment {
                    // Determine effective MIME type
                    let effective_mime_type = if ctype.is_empty() {
                        "application/octet-stream".to_string()
                    } else {
                        ctype.clone()
                    };

                    let attachment_size = raw_data.len();
                    attachments.push(EmailAttachment {
                        content_id,
                        filename,
                        mime_type: effective_mime_type,
                        content_disposition,
                        transfer_encoding,
                        data: raw_data,
                        size: attachment_size,
                        content_location,
                    });
                } else if let Some(body_data) = data_for_body {
                    if ctype.starts_with("text/plain") && body_text.is_none() {
                        *body_text = Some(body_data);
                    } else if ctype.starts_with("text/html") && body_html.is_none() {
                        *body_html = Some(body_data);
                    }
                }
            }

            // Container node: multipart structure
            subparts => {
                // For multipart/alternative: prefer text/plain over text/html for body extraction
                // Order matters: mailparse returns alternatives in preference order
                for subpart in subparts {
                    self.extract_parts_recursive(subpart, body_text, body_html, attachments, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Detect S/MIME encrypted content (`application/pkcs7-mime` with `smime-type=enveloped-data`).
    fn detect_encryption(&self, parsed: &ParsedMail) -> bool {
        self.check_content_type_recursive(parsed, |ctype| {
            ctype == "application/pkcs7-mime"
                && parsed
                    .headers
                    .iter()
                    .any(|h| {
                        h.get_key().to_lowercase() == "content-type"
                            && h.get_value().contains("enveloped-data")
                    })
        })
    }

    /// Detect digital signature presence (DKIM or S/MIME).
    fn detect_signature(&self, parsed: &ParsedMail) -> bool {
        // Check for DKIM-Signature header
        let has_dkim = parsed.headers.iter().any(|h| {
            h.get_key().to_lowercase() == "dkim-signature"
        });

        // Check for multipart/signed
        let has_smime_sig = self.check_content_type_recursive(parsed, |ctype| {
            ctype == "multipart/signed"
        });

        has_dkim || has_smime_sig
    }

    /// Extract MIME boundary string from the top-level Content-Type header.
    fn extract_boundary(&self, parsed: &ParsedMail) -> Option<String> {
        parsed
            .ctype
            .params
            .get("boundary")
            .cloned()
    }

    /// Recursively check if any MIME part matches the given content type predicate.
    fn check_content_type_recursive<F>(&self, part: &ParsedMail, predicate: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        let ctype = part.ctype.mimetype.as_str();

        if predicate(ctype) {
            return true;
        }

        part.subparts
            .iter()
            .any(|sp| self.check_content_type_recursive(sp, &predicate))
    }

    /// Extract domain portion from an email address string.
    ///
    /// Handles formats:
    /// - `user@domain.com` → `domain.com`
    /// - `Display Name <user@domain.com>` → `domain.com`
    /// - `<user@domain.com>` → `domain.com`
    /// - Empty or malformed → `None`
    #[allow(dead_code)]
    #[inline]
    fn extract_domain(email_addr: &str) -> Option<String> {
        let addr = Self::extract_address_only(email_addr);
        addr.split('@').nth(1).map(|d| d.to_lowercase())
    }

    /// Extract bare email address from a potentially formatted header value.
    ///
    /// Handles RFC 5322 display-name syntax: `"Display Name" <user@domain>`
    fn extract_address_only(header_value: &str) -> String {
        let trimmed = header_value.trim();

        // Try angle-bracket extraction first
        if let Some(start) = trimmed.find('<') {
            if let Some(end) = trimmed.find('>') {
                return trimmed[start + 1..end].trim().to_string();
            }
        }

        // Fallback: use as-is if it looks like an email
        if trimmed.contains('@') {
            trimmed.to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// Split a header value containing possibly multiple addresses into individual addresses.
    ///
    /// Handles comma separation within To/Cc/Bcc headers while respecting
    /// angle-bracket grouping and quoted strings.
    fn split_addresses(header_value: &str) -> Vec<String> {
        if header_value.trim().is_empty() {
            return Vec::new();
        }

        // Simple comma-aware splitting (full RFC 5322 address-list parsing
        // would require a proper parser; this handles common cases)
        header_value
            .split(',')
            .map(|s| Self::extract_address_only(s))
            .filter(|s| !s.is_empty() && s.contains('@'))
            .collect()
    }

    /// Check whether an email address belongs to an internal domain.
    ///
    /// Matches case-insensitively against each configured internal domain suffix.
    fn is_internal_domain(addr: &str, internal_domains: &[String]) -> bool {
        let addr_lower = addr.to_lowercase();
        for domain in internal_domains {
            let domain_lower = domain.to_lowercase();
            if addr_lower.ends_with(&domain_lower) {
                return true;
            }
        }
        false
    }

    /// Decode transfer-encoded data.
    ///
    /// Supports base64, quoted-printable, and passthrough (7bit/8bit/binary).
    #[allow(dead_code)]
    fn decode_transfer_encoding(data: &[u8], encoding: Option<&str>) -> Result<Vec<u8>> {
        match encoding {
            Some("base64") | Some("Base64") | Some("BASE64") => {
                // Use standard base64 decoder with padding tolerance
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| SmtpError::TransferEncodingFailed {
                        encoding: "base64".to_string(),
                    })
            }
            Some("quoted-printable") | Some("Quoted-Printable") => {
                // Convert &[u8] to &str for the QP decoder
                let data_str = std::str::from_utf8(data).map_err(|_| SmtpError::TransferEncodingFailed {
                    encoding: "quoted-printable".to_string(),
                })?;
                let decoded = quoted_printable::decode(data_str, quoted_printable::ParseMode::Robust)
                    .map_err(|_| SmtpError::TransferEncodingFailed {
                        encoding: "quoted-printable".to_string(),
                    })?;
                Ok(decoded)
            }
            // 7bit, 8bit, binary, or unknown: pass through unchanged
            _ => Ok(data.to_vec()),
        }
    }
}

impl Default for MimeHandler {
    fn default() -> Self {
        Self::new()
    }
}
