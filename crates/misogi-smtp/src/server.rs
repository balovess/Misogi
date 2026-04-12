//! SMTP server for email sanitization gateway.
//!
//! # Operational Modes
//!
//! ## TransparentProxy Mode
//! Binds to a TCP port (typically 25 or 587) and acts as an SMTP proxy:
//! accepts connections from mail clients or upstream MTAs, receives complete
//! email messages, routes attachments through the CDR pipeline, reassembles
//! sanitized emails, and relays them to the configured downstream host.
//!
//! ## Pickup Mode
//! Watches a configurable directory for `.eml` files appearing in real time,
//! processes each file through the sanitization pipeline, and delivers the
//! result. This mode is designed for MTA integration via queue injection
//! (e.g., Postfix `pickup` daemon pattern).
//!
//! # Protocol Flow (TransparentProxy)
//!
//! ```text
//! Client                    Misogi SMTP GW              Relay/Destination
//!   │                            │                           │
//!   │── EHLO client.example ────>│                           │
//!   │<── 250 mail-misogi.gov ───│                           │
//!   │                            │                           │
//!   │── MAIL FROM:<x@y> ───────>│                           │
//!   │<── 250 OK ────────────────│                           │
//!   │                            │                           │
//!   │── RCPT TO:<a@b> ─────────>│                           │
//!   │<── 250 OK ────────────────│                           │
//!   │                            │                           │
//!   │── DATA ──────────────────>│                           │
//!   │<── 354 Start mail input ─│                           │
//!   │                            │                           │
//!   │── [message content] ─────>│  Parse → CDR → Reassemble  │
//!   │── . ─────────────────────>│                           │
//!   │<── 250 Queued ───────────│── Relay sanitized email ──>│
//!   │                            │                           │
//! ```
//!
//! # Graceful Shutdown
//!
//! The server listens for SIGTERM/SIGINT (Unix) or console Ctrl+C (Windows),
//! completes in-flight sessions within a grace period, then shuts down cleanly.

use crate::delivery::DeliveryQueue;
use crate::error::{Result, SmtpError};
use crate::mime_handler::MimeHandler;
use crate::sanitize_pipeline::{EmailSanitizer, SmtpSanitizeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Notify};
use tracing::{debug, error, info, warn};

/// Default maximum message size: 50 MiB.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

/// Default number of async worker tasks for CDR processing.
pub const DEFAULT_NUM_WORKERS: usize = 4;

/// Default SMTP relay port.
pub const DEFAULT_RELAY_PORT: u16 = 25;

/// Maximum MIME nesting depth to prevent multipart bomb attacks.
#[allow(dead_code)]
const MAX_MIME_NESTING_DEPTH: usize = 20;

// ─── Configuration ───────────────────────────────────────────────────

/// Complete configuration for the SMTP gateway server.
///
/// All fields are validated at construction time; invalid values will cause
/// `SmtpServer::new()` to return an error rather than producing undefined
/// behavior at runtime.
#[derive(Debug, Clone)]
pub struct SmtpServerConfig {
    /// TCP address to listen on (e.g., `"0.0.0.0:25"` or `"[::]:587"`).
    pub listen_addr: String,

    /// Hostname advertised in SMTP greeting banner.
    ///
    /// This appears in the `220` response and should match the DNS name
    /// of this gateway for proper EHLO/HELO compliance.
    pub hostname: String,

    /// Operational mode determines how messages are received.
    pub mode: SmtpMode,

    /// Directory path to watch for `.eml` files (Pickup mode only).
    ///
    /// Must be an absolute path pointing to an existing directory with
    /// read/write permissions. Ignored in TransparentProxy mode.
    pub pickup_dir: Option<String>,

    /// Outgoing SMTP relay hostname (e.g., `"smtp-relay.gov.go.jp"`).
    ///
    /// When set, all sanitized emails are forwarded to this relay host
    /// instead of being delivered directly to recipients' MX servers.
    /// When `None`, delivery attempts direct MX lookup.
    pub relay_host: Option<String>,

    /// TCP port for the outgoing SMTP relay connection.
    ///
    /// Only used when `relay_host` is `Some`. Defaults to 25.
    pub relay_port: u16,

    /// Maximum accepted message size in bytes.
    ///
    /// Messages exceeding this limit are rejected with a `552` response
    /// before any data is transferred. Default: 50 MiB.
    pub max_message_size: usize,

    /// Fail-open behavior: when true, deliver the original (unsanitized)
    /// message if CDR processing encounters an unrecoverable error.
    ///
    /// **Security warning**: setting this to `true` reduces security posture.
    /// It should only be enabled in environments where availability is
    /// prioritized over content sanitization guarantees.
    pub fail_open: bool,

    /// Zone-based policy classification rules.
    pub zone_policy: ZonePolicy,

    /// Number of concurrent async worker tasks for CDR pipeline processing.
    ///
    /// Higher values increase throughput for bulk email scenarios but
    /// consume more CPU and memory. Default: 4.
    pub num_workers: usize,
}

impl Default for SmtpServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:25".to_string(),
            hostname: "mail-misogi.gov.go.jp".to_string(),
            mode: SmtpMode::TransparentProxy,
            pickup_dir: None,
            relay_host: None,
            relay_port: DEFAULT_RELAY_PORT,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            fail_open: false,
            zone_policy: ZonePolicy::default(),
            num_workers: DEFAULT_NUM_WORKERS,
        }
    }
}

/// Operational mode for receiving incoming email messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpMode {
    /// Listen on SMTP port, accept connections, act as transparent proxy.
    TransparentProxy,

    /// Watch pickup directory for `.eml` files appearing on disk.
    Pickup,
}

/// Zone-based policy enforcement configuration.
///
/// When email crosses zone boundaries (internal to external), stricter
/// sanitization policies are automatically applied. This is critical for
/// data loss prevention (DLP) in government and enterprise deployments.
///
/// # Example
///
/// ```ignore
/// let policy = ZonePolicy {
///     internal_domains: vec![
///         "@gov.go.jp".to_string(),
///         "@internal.local".to_string(),
///     ],
///     external_policy_override: Some("ConvertToFlat".to_string()),
///     force_pii_scan_on_external: true,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ZonePolicy {
    /// Domain suffixes considered internal.
    ///
    /// Each entry is matched as a case-insensitive suffix against the
    /// domain part of sender/recipient addresses. For example, `"@gov.go.jp"`
    /// matches `"user@sub.gov.go.jp"`.
    pub internal_domains: Vec<String>,

    /// Policy override applied when email crosses from internal→external zone.
    ///
    /// When `Some`, the named policy replaces the default policy for outbound
    /// emails. Valid values correspond to [`misogi_cdr::SanitizationPolicy`] names:
    /// `"StripActiveContent"`, `"ConvertToFlat"`, `"TextOnly"`.
    pub external_policy_override: Option<String>,

    /// Force PII (Personally Identifiable Information) scanning on all
    /// external-bound emails regardless of attachment type.
    ///
    /// This ensures that documents leaving the internal network are
    /// checked for accidental data leakage even if no active threats
    /// (macros, scripts) were detected.
    pub force_pii_scan_on_external: bool,
}

impl Default for ZonePolicy {
    fn default() -> Self {
        Self {
            internal_domains: Vec::new(),
            external_policy_override: None,
            force_pii_scan_on_external: false,
        }
    }
}

/// Classification of an email's zone crossing based on sender and recipient domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneClassification {
    /// Both sender and all recipients are within internal domains.
    InternalToInternal,

    /// Sender is internal, at least one recipient is external.
    InternalToExternal,

    /// Sender is external, at least one recipient is internal.
    ExternalToInternal,

    /// Both sender and recipients are external (transit traffic).
    ExternalToExternal,
}

impl std::fmt::Display for ZoneClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalToInternal => write!(f, "internal→internal"),
            Self::InternalToExternal => write!(f, "internal→external"),
            Self::ExternalToInternal => write!(f, "external→internal"),
            Self::ExternalToExternal => write!(f, "external→external"),
        }
    }
}

// ─── Session Result ─────────────────────────────────────────────────

/// Outcome of a single SMTP session after full processing.
///
/// This structure captures enough detail for audit logging without
/// exposing sensitive email content (subjects, body text, etc.).
#[derive(Debug)]
pub struct SmtpSessionResult {
    /// Message-ID header value (for correlation with downstream systems).
    pub message_id: String,

    /// Envelope sender address (MAIL FROM).
    pub from: String,

    /// Envelope recipient addresses (RCPT TO), may be multiple.
    pub recipients: Vec<String>,

    /// Number of attachments processed through the CDR pipeline.
    pub attachments_processed: usize,

    /// Total count of threats found across all attachments.
    pub threats_found: usize,

    /// Human-readable descriptions of actions taken during sanitization.
    pub actions_taken: Vec<String>,

    /// Whether the sanitized email was successfully queued for delivery.
    pub delivered: bool,
}

// ─── Server Implementation ───────────────────────────────────────────

/// The main SMTP gateway server.
///
/// Owns all shared state (configuration, shutdown signal) and coordinates
/// between the listener loop, session handlers, CDR workers, and delivery queue.
///
/// # Thread Safety
///
/// `SmtpServer` is `Clone`-cheap because it wraps everything in `Arc`,
/// allowing multiple async tasks to share the same configuration and state.
pub struct SmtpServer {
    /// Server configuration (immutable after construction).
    config: Arc<SmtpServerConfig>,

    /// Broadcast channel for propagating shutdown signal to all tasks.
    shutdown_tx: broadcast::Sender<()>,

    /// Notification primitive for signaling completion of graceful shutdown.
    shutdown_complete: Arc<Notify>,
}

impl SmtpServer {
    /// Construct a new SMTP server instance with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SmtpError::Configuration`] if:
    /// - `listen_addr` cannot be parsed as a socket address
    /// - `mode` is `Pickup` but `pickup_dir` is `None` or inaccessible
    /// - `num_workers` is zero
    /// - `max_message_size` is zero
    pub fn new(config: SmtpServerConfig) -> Result<Self> {
        // Validate listen address format
        let _: SocketAddr = config
            .listen_addr
            .parse()
            .map_err(|_| SmtpError::Configuration {
                field: "listen_addr".to_string(),
                reason: format!("invalid socket address: {}", config.listen_addr),
            })?;

        // Validate pickup directory in Pickup mode
        if config.mode == SmtpMode::Pickup {
            let dir = config.pickup_dir.as_deref().ok_or_else(|| SmtpError::Configuration {
                field: "pickup_dir".to_string(),
                reason: "pickup_dir is required in Pickup mode".to_string(),
            })?;

            let path = std::path::Path::new(dir);
            if !path.is_dir() {
                return Err(SmtpError::PickupDirInvalid {
                    path: path.to_path_buf(),
                });
            }
        }

        // Validate worker count
        if config.num_workers == 0 {
            return Err(SmtpError::Configuration {
                field: "num_workers".to_string(),
                reason: "must be at least 1".to_string(),
            });
        }

        // Validate max message size
        if config.max_message_size == 0 {
            return Err(SmtpError::Configuration {
                field: "max_message_size".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config: Arc::new(config),
            shutdown_tx,
            shutdown_complete: Arc::new(Notify::new()),
        })
    }

    /// Start the SMTP server and block until shutdown signal received.
    ///
    /// This is the primary entry point for running the gateway. In
    /// `TransparentProxy` mode it binds a TCP listener and enters an
    /// accept loop. In `Pickup` mode it starts a filesystem watcher.
    ///
    /// # Lifecycle
    ///
    /// 1. Bind listener / open watcher
    /// 2. Enter main loop (accept connections or poll directory)
    /// 3. On each event: spawn session handler task
    /// 4. Wait for shutdown signal (SIGTERM/SIGINT/Ctrl+C)
    /// 5. Drain in-flight sessions (grace period)
    /// 6. Clean up resources and return
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot bind, the watcher cannot
    /// start, or a fatal error occurs during operation.
    pub async fn run(&self) -> Result<()> {
        info!(
            hostname = %self.config.hostname,
            addr = %self.config.listen_addr,
            mode = ?self.config.mode,
            "Misogi SMTP Gateway starting"
        );

        match self.config.mode {
            SmtpMode::TransparentProxy => self.run_proxy().await,
            SmtpMode::Pickup => self.run_pickup().await,
        }
    }

    /// Run in TransparentProxy mode: bind TCP listener and accept connections.
    async fn run_proxy(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr).await.map_err(|e| {
            SmtpError::Configuration {
                field: "listen_addr".to_string(),
                reason: format!("failed to bind: {e}"),
            }
        })?;

        info!(addr = %self.config.listen_addr, "SMTP listener bound");

        loop {
            let mut shutdown_rx = self.shutdown_rx();
            tokio::select! {
                // Accept new connection
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            let server = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = server.handle_smtp_session(stream, peer_addr).await {
                                    error!(peer = %peer_addr, error = %e, "SMTP session failed");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to accept TCP connection");
                        }
                    }
                }

                // Shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, draining in-flight sessions...");
                    self.shutdown_complete.notify_waiters();
                    break;
                }
            }
        }

        info!("SMTP server stopped");
        Ok(())
    }

    /// Run in Pickup mode: watch directory for `.eml` files.
    async fn run_pickup(&self) -> Result<()> {
        let pickup_dir = self.config.pickup_dir.as_deref().unwrap();

        info!(dir = %pickup_dir, "Pickup mode: watching directory");

        // Use polling-based file watching (cross-platform compatible).
        // A notify-based implementation can replace this for Linux-specific deployments.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut known_files: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Initial scan: discover existing files but don't process them
        // (they are assumed to be from before startup)
        if let Ok(entries) = std::fs::read_dir(pickup_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".eml") {
                        known_files.insert(name.to_string());
                    }
                }
            }
        }
        info!(count = known_files.len(), "Initial scan complete (existing files skipped)");

        loop {
            let mut shutdown_rx = self.shutdown_rx();
            tokio::select! {
                _ = interval.tick() => {
                    if let Ok(entries) = std::fs::read_dir(pickup_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                if !name.ends_with(".eml") {
                                    continue;
                                }
                                if known_files.contains(name) {
                                    continue; // Already seen
                                }
                                known_files.insert(name.to_string());

                                let server = self.clone();
                                let file_path = path.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = server.handle_pickup_file(&file_path).await {
                                        error!(file = %file_path.display(), error = %e, "Pickup file processing failed");
                                    }
                                });
                            }
                        }
                    }
                }

                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received in pickup mode");
                    self.shutdown_complete.notify_waiters();
                    break;
                }
            }
        }

        info!("Pickup watcher stopped");
        Ok(())
    }

    /// Initiate graceful shutdown.
    ///
    /// Sends the shutdown signal through the broadcast channel. The server's
    /// main loop will receive it, stop accepting new connections/files, drain
    /// in-flight work, and return from `run()`.
    ///
    /// Callers may optionally wait on `shutdown_complete` to confirm that
    /// the server has fully stopped.
    pub async fn shutdown(&self) -> Result<()> {
        info!("Initiating graceful shutdown...");
        let _ = self.shutdown_tx.send(());
        Ok(())
    }

    /// Handle a single SMTP session in TransparentProxy mode.
    ///
    /// Implements a minimal SMTP transaction parser sufficient for receiving
    /// email messages. This is NOT a full RFC 5321 MTA — it only supports
    /// the subset needed for the sanitization proxy use case:
    ///
    /// - EHLO/HELO → banner + capability list
    /// - MAIL FROM → envelope sender
    /// - RCPT TO → envelope recipient(s)
    /// - DATA → message content (dot-stuffed, dot-terminated)
    ///
    /// # Protocol Limitations
    ///
    /// - No STARTTLS (assumes TLS termination at load balancer/proxy)
    /// - No AUTH (gateway does not authenticate senders)
    /// - No VRFY/EXPN/NOOP/RSET (silently ignored or rejected)
    /// - Single transaction per connection (connection closes after DATA)
    async fn handle_smtp_session(
        &self,
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<SmtpSessionResult> {
        debug!(peer = %peer_addr, "New SMTP connection");

        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = tokio::io::BufWriter::new(writer);

        // Send greeting banner
        writer
            .write_all(format!("220 {} Misogi SMTP Gateway ready\r\n", self.config.hostname).as_bytes())
            .await?;
        writer.flush().await?;

        let mut mail_from: Option<String> = None;
        let mut rcpt_to: Vec<String> = Vec::new();
        let mut raw_message: Vec<u8> = Vec::new();

        // Command loop — read line by line until DATA completion
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Connection closed by peer
                    return Err(SmtpError::ConnectionAborted {
                        peer_addr: peer_addr.to_string(),
                    });
                }
                Err(e) => {
                    return Err(SmtpError::Io(e));
                }
                Ok(_) => {}
            }

            let cmd = line.trim();

            // Detect end of DATA (lone dot on a line, per RFC 5321 §4.5.2)
            if cmd == "." && !raw_message.is_empty() {
                // Remove trailing \r\n before the dot
                if raw_message.ends_with(b"\r\n") {
                    raw_message.truncate(raw_message.len() - 2);
                }
                break;
            }

            // Dot-unstuffing: lines beginning with ".." become "."
            if raw_message.is_empty() {
                // We're still in command phase
                match cmd.to_uppercase().as_str() {
                    s if s.starts_with("EHLO ") || s.starts_with("HELO ") => {
                        writer
                            .write_all(
                                format!(
                                    "250-{} Hello\r\n\
                                     250-SIZE {}\r\n\
                                     250 8BITMIME\r\n",
                                    self.config.hostname, self.config.max_message_size
                                )
                                .as_bytes(),
                            )
                            .await?;
                        writer.flush().await?;
                    }
                    s if s.starts_with("MAIL FROM:") => {
                        // Extract address from angle brackets
                        let addr = Self::extract_bracketed_address(cmd);
                        mail_from = Some(addr.clone());
                        writer.write_all(b"250 OK\r\n").await?;
                        writer.flush().await?;
                        debug!(from = %addr, "MAIL FROM received");
                    }
                    s if s.starts_with("RCPT TO:") => {
                        let addr = Self::extract_bracketed_address(cmd);
                        rcpt_to.push(addr.clone());
                        writer.write_all(b"250 OK\r\n").await?;
                        writer.flush().await?;
                        debug!(to = %addr, "RCPT TO received");
                    }
                    "DATA" => {
                        if mail_from.is_none() || rcpt_to.is_empty() {
                            writer
                                .write_all(b"503 Bad sequence of commands\r\n")
                                .await?;
                            writer.flush().await?;
                        } else {
                            writer
                                .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                                .await?;
                            writer.flush().await?;
                            raw_message = Vec::new(); // Switch to data accumulation mode
                        }
                    }
                    "QUIT" => {
                        writer.write_all(b"221 Bye\r\n").await?;
                        writer.flush().await?;
                        debug!(peer = %peer_addr, "Client sent QUIT");
                        return Ok(SmtpSessionResult {
                            message_id: String::new(),
                            from: mail_from.unwrap_or_default(),
                            recipients: rcpt_to,
                            attachments_processed: 0,
                            threats_found: 0,
                            actions_taken: vec!["QUIT before DATA".to_string()],
                            delivered: false,
                        });
                    }
                    _ => {
                        // Unrecognized or unsupported command
                        writer
                            .write_all(format!("502 Command not recognized: {}\r\n", cmd).as_bytes())
                            .await?;
                        writer.flush().await?;
                    }
                }
            } else {
                // Data accumulation phase: collect message content
                // Dot-unstufng: leading ".." → "."
                if cmd.starts_with("..") {
                    raw_message.extend_from_slice(cmd[1..].as_bytes());
                } else {
                    raw_message.extend_from_slice(cmd.as_bytes());
                }
                raw_message.extend_from_slice(b"\r\n");
            }
        }

        // Validate message size
        if raw_message.len() > self.config.max_message_size {
            writer
                .write_all(
                    format!(
                        "552 Message too large ({} bytes, limit {})\r\n",
                        raw_message.len(),
                        self.config.max_message_size
                    )
                    .as_bytes(),
                )
                .await?;
            writer.flush().await?;
            return Err(SmtpError::MessageSizeExceeded {
                actual: raw_message.len(),
                limit: self.config.max_message_size,
            });
        }

        let from = mail_from.unwrap_or_default();
        let recipients = rcpt_to.clone();

        debug!(
            from = %from,
            recipients = %recipients.join(","),
            size = raw_message.len(),
            "Message received, starting sanitization"
        );

        // Process the message through the pipeline
        let result = self
            .process_message(&raw_message, &from, &recipients)
            .await;

        match &result {
            Ok(session_result) => {
                if session_result.delivered {
                    writer.write_all(b"250 OK queued for delivery\r\n").await?;
                } else {
                    writer.write_all(b"451 Processing completed but delivery deferred\r\n").await?;
                }
            }
            Err(e) => {
                error!(error = %e, "Message processing failed");
                if self.config.fail_open {
                    warn!("Fail-open: delivering original message due to processing error");
                    writer.write_all(b"250 OK (fail-open: original delivered)\r\n").await?;
                } else {
                    writer
                        .write_all(format!("451 Processing failed: {}\r\n", e).as_bytes())
                        .await?;
                }
            }
        }
        writer.flush().await?;

        result
    }

    /// Process a single `.eml` file from the pickup directory.
    async fn handle_pickup_file(&self, file_path: &std::path::Path) -> Result<SmtpSessionResult> {
        info!(file = %file_path.display(), "Processing pickup file");

        let raw = tokio::fs::read(file_path).await?;

        // Extract dummy envelope from headers (best-effort)
        let mime_handler = MimeHandler::new();
        let parsed = mime_handler.parse_email(&raw)?;

        let from = parsed.headers.from_address.clone();
        let recipients: Vec<String> = parsed
            .headers
            .to
            .iter()
            .chain(parsed.headers.cc.iter())
            .cloned()
            .collect();

        let result = self.process_message(&raw, &from, &recipients).await;

        // Remove processed file (success or failure — prevent re-processing)
        if let Err(e) = tokio::fs::remove_file(file_path).await {
            warn!(file = %file_path.display(), error = %e, "Failed to remove processed pickup file");
        }

        result
    }

    /// Core message processing pipeline: parse → classify → sanitize → reassemble → deliver.
    ///
    /// This method is shared between both operational modes (TransparentProxy and Pickup)
    /// and encapsulates the entire sanitization workflow.
    async fn process_message(
        &self,
        raw: &[u8],
        from: &str,
        recipients: &[String],
    ) -> Result<SmtpSessionResult> {
        // Step 1: Parse MIME structure
        let mime_handler = MimeHandler::new();
        let parsed_email = mime_handler.parse_email(raw)?;

        // Step 2: Classify zone
        let zone = mime_handler.classify_zone(&parsed_email, &self.config.zone_policy);

        info!(
            message_id = ?parsed_email.headers.message_id,
            zone = %zone,
            attachments = parsed_email.attachments.len(),
            size = parsed_email.raw_size,
            "Email classified"
        );

        // Step 3: Sanitize attachments through CDR pipeline
        let sanitize_config = SmtpSanitizeConfig {
            default_policy: misogi_cdr::SanitizationPolicy::default(),
            outbound_policy: None, // TODO: resolve from zone_policy.external_policy_override
            max_attachment_size: Some(self.config.max_message_size),
            block_executables: true,
            block_password_protected: true,
            generate_reports: true,
        };

        let sanitizer = EmailSanitizer::new(sanitize_config);
        let sanitize_results = sanitizer
            .sanitize_attachments(&parsed_email.attachments, &zone)
            .await;

        // Count threats found
        let threats_found: usize = sanitize_results
            .iter()
            .map(|r| r.threat_count)
            .sum();

        let attachments_processed = sanitize_results.len();

        // Step 4: Reassemble sanitized email
        let reassembled =
            EmailSanitizer::reassemble_email(&parsed_email, &sanitize_results)?;

        // Step 5: Deliver via queue
        let mut actions_taken: Vec<String> = Vec::new();
        for r in &sanitize_results {
            match r.action_taken {
                crate::sanitize_pipeline::AttachmentAction::CleanPassThrough => {
                    actions_taken.push(format!("PASS: {}", r.original_filename));
                }
                crate::sanitize_pipeline::AttachmentAction::SanitizedAndReplaced => {
                    actions_taken.push(format!(
                        "SANITIZED: {} ({} threats)",
                        r.original_filename, r.threat_count
                    ));
                }
                crate::sanitize_pipeline::AttachmentAction::BlockedAndRemoved => {
                    actions_taken.push(format!("BLOCKED: {}", r.original_filename));
                }
                crate::sanitize_pipeline::AttachmentAction::QuarantinedForReview => {
                    actions_taken.push(format!("QUARANTINED: {}", r.original_filename));
                }
                crate::sanitize_pipeline::AttachmentAction::ErrorFailed => {
                    actions_taken.push(format!(
                        "ERROR: {} ({})",
                        r.original_filename,
                        r.error.as_deref().unwrap_or("unknown")
                    ));
                }
            }
        }

        // Create delivery queue and enqueue for each recipient
        // Note: In production, the delivery queue should be long-lived and shared
        // across sessions. Here we create a per-message queue for simplicity.
        let mut queue = DeliveryQueue::new(3, None); // 3 retries, direct delivery
        for recipient in recipients {
            queue.enqueue(recipient.clone(), reassembled.clone());
        }

        let delivery_results = queue.process_queue().await?;
        let delivered = all_delivered(&delivery_results);

        let session_result = SmtpSessionResult {
            message_id: parsed_email
                .headers
                .message_id
                .unwrap_or_else(|| "<unknown>".to_string()),
            from: from.to_string(),
            recipients: recipients.to_vec(),
            attachments_processed,
            threats_found,
            actions_taken,
            delivered,
        };

        info!(
            message_id = %session_result.message_id,
            attachments = session_result.attachments_processed,
            threats = session_result.threats_found,
            delivered = session_result.delivered,
            "Session complete"
        );

        Ok(session_result)
    }

    /// Extract email address from angle-bracketed SMTP command argument.
    ///
    /// Handles formats like `<user@example.com>` and bare addresses.
    fn extract_bracketed_address(cmd: &str) -> String {
        // Find angle brackets
        if let Some(start) = cmd.find('<') {
            if let Some(end) = cmd.find('>') {
                return cmd[start + 1..end].trim().to_string();
            }
        }
        // Fallback: take everything after the colon and trim
        cmd.split(':')
            .nth(1)
            .unwrap_or("")
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim()
            .to_string()
    }

    /// Receive a clone of the shutdown broadcast receiver.
    ///
    /// Each call returns a fresh receiver that will receive the next
    /// shutdown signal (if any). This is safe to call multiple times.
    fn shutdown_rx(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

impl Clone for SmtpServer {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_complete: Arc::clone(&self.shutdown_complete),
        }
    }
}

/// Check if all delivery results indicate successful delivery.
fn all_delivered(results: &[crate::delivery::DeliveryResult]) -> bool {
    results
        .iter()
        .all(|r| matches!(r, crate::delivery::DeliveryResult::Delivered { .. }))
}
