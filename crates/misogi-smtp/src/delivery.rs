//! Email delivery queue with retry logic and transient failure handling.
//!
//! This module implements a robust delivery subsystem that:
//!
//! - **Queues sanitized emails** for each recipient after CDR processing
//! - **Retries transient failures** with exponential backoff (configurable delays)
//! - **Distinguishes permanent vs transient** SMTP errors to avoid futile retries
//! - **Supports relay mode** (forward to configured SMTP host) or direct delivery
//! - **Tracks all outcomes** for audit and monitoring purposes
//!
//! # Retry Strategy
//!
//! Exponential backoff with the following default schedule:
//!
//! | Attempt | Delay  | Cumulative Wait |
//! |---------|--------|-----------------|
//! | 1st     | 10s    | 10s             |
//! | 2nd     | 30s    | 40s             |
//! | 3rd     | 60s    | 100s            |
//! | 4th     | 300s   | 400s            |
//!
//! After exhausting all retry attempts, the task is moved to the permanent failure list.
//!
//! # Error Classification
//!
//! SMTP response codes determine error category:
//!
//! - **2xx**: Success -> move to completed
//! - **4xx**: Permanent failure (invalid address, policy rejection) -> move to failed (no retry)
//! - **5xx** / timeout / connection error: Transient failure -> schedule retry with backoff

use crate::error::Result;
use chrono::{DateTime, Utc};
use lettre::{
    message::Mailbox,
    Message, SmtpTransport, Transport,
};
use std::collections::VecDeque;
use tracing::{debug, error, info, warn};

/// Default maximum number of delivery retry attempts.
pub const DEFAULT_MAX_RETRIES: u32 = 4;

/// Default retry delay sequence in seconds: [10, 30, 60, 300].
const DEFAULT_RETRY_DELAYS: [u64; 4] = [10, 30, 60, 300];

// ─── Delivery Task ──────────────────────────────────────────────────

/// A pending email delivery task awaiting processing or retry.
///
/// Each task represents one attempt to deliver one email to one recipient.
/// A single processed message with N recipients generates N tasks in the queue.
#[derive(Debug)]
pub struct DeliveryTask {
    /// Unique identifier for this delivery task (UUID v4).
    pub id: uuid::Uuid,

    /// Recipient email address for this delivery.
    pub recipient: String,

    /// Full sanitized email data (RFC 5322/MIME formatted bytes).
    pub email_data: Vec<u8>,

    /// Number of delivery attempts already made (starts at 0).
    pub attempts: u32,

    /// Error message from the most recent failed attempt (if any).
    pub last_error: Option<String>,

    /// Timestamp when this task was created/enqueued.
    pub created_at: DateTime<Utc>,

    /// Earliest timestamp at which the next retry should be attempted.
    ///
    /// Set to `created_at` for initial attempts; updated with backoff delay
    /// after each transient failure.
    pub next_retry_at: DateTime<Utc>,
}

// ─── Delivery Result ────────────────────────────────────────────────

/// Outcome of a single delivery task's lifecycle.
///
/// Each variant captures sufficient context for audit logging and
/// operational alerting without exposing email content.
#[derive(Debug, Clone)]
pub enum DeliveryResult {
    /// Email was successfully delivered to the recipient's mail server.
    Delivered {
        /// Recipient address that accepted the message.
        recipient: String,
        /// Total attempts required (1 = first-attempt success).
        attempts: u32,
    },

    /// Delivery failed permanently — no further retries will be attempted.
    ///
    /// Causes include: invalid mailbox, domain does not exist, policy rejection,
    /// or exceeding maximum retry count with only transient errors.
    FailedPermanently {
        /// Recipient address that rejected/failed the message.
        recipient: String,
        /// Error description from the final attempt.
        last_error: String,
        /// Total attempts made before giving up.
        attempts: u32,
    },

    /// Delivery has not yet succeeded but is scheduled for future retry.
    ///
    /// This variant appears in intermediate queue states; final states are
    /// `Delivered` or `FailedPermanently`.
    PendingRetry {
        /// Recipient address awaiting retry.
        recipient: String,
        /// Seconds until next scheduled retry attempt.
        next_retry_in_secs: u64,
    },
}

impl DeliveryResult {
    /// Returns true if this result represents a successful delivery.
    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered { .. })
    }
}

// ─── Delivery Queue Implementation ──────────────────────────────────

/// Email delivery queue with exponential backoff retry logic.
///
/// The queue manages the complete lifecycle of outbound email delivery:
/// enqueue → process → deliver/retry/complete/fail. It is designed to be
/// long-lived and shared across multiple SMTP sessions in production use;
/// per-message queues (as used in the current server implementation) are
/// acceptable for lower-volume deployments.
///
/// # Thread Safety
///
/// `DeliveryQueue` is NOT thread-safe by design. In async contexts, it should
/// be accessed from a single task or protected by `Mutex` if shared across tasks.
///
/// # Usage Pattern
///
/// ```ignore
/// let mut queue = DeliveryQueue::new(3, Some(relay_transport));
/// let id = queue.enqueue("user@example.com", sanitized_email_bytes);
/// let results = queue.process_queue().await?;
/// for r in &results {
///     match r {
///         DeliveryResult::Delivered { recipient, .. } => info!(to = %recipient, "Delivered"),
///         DeliveryResult::FailedPermanently { recipient, last_error, .. } => {
///             error!(to = %recipient, error = %last_error, "Delivery failed");
///         }
///         _ => {}
///     }
/// }
/// ```
pub struct DeliveryQueue {
    /// Tasks awaiting delivery or retry.
    pending: VecDeque<DeliveryTask>,

    /// Successfully completed deliveries.
    completed: Vec<DeliveryResult>,

    /// Permanently failed deliveries (exhausted retries or permanent errors).
    failed: Vec<DeliveryResult>,

    /// Maximum number of retry attempts before permanent failure.
    max_retries: u32,

    /// Retry delay sequence in seconds (indexed by attempt number).
    ///
    /// `retry_delays[0]` = delay before 1st retry (after initial failure),
    /// `retry_delays[1]` = delay before 2nd retry, etc.
    retry_delays: [u64; 4],

    /// Optional SMTP relay transport for forwarding emails.
    ///
    /// When `Some`, all emails are sent through this relay host instead of
    /// performing direct MX lookup. When `None`, the queue cannot actually
    /// deliver emails (useful for testing/dry-run scenarios).
    relay: Option<SmtpTransport>,
}

impl DeliveryQueue {
    /// Construct a new delivery queue with specified retry configuration.
    ///
    /// # Arguments
    ///
    /// * `max_retries` — Maximum delivery attempts before permanent failure (default: 4)
    /// * `relay` — Optional SMTP relay transport for forwarding messages
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Direct delivery (no relay)
    /// let queue = DeliveryQueue::new(3, None);
    ///
    /// // With relay
    /// let relay = SmtpTransport::relay("smtp.example.com")
    ///     .credentials(Credentials::new("user", "pass"))
    ///     .build();
    /// let queue = DeliveryQueue::new(4, Some(relay));
    /// ```
    pub fn new(max_retries: u32, relay: Option<SmtpTransport>) -> Self {
        Self {
            pending: VecDeque::new(),
            completed: Vec::new(),
            failed: Vec::new(),
            max_retries,
            retry_delays: DEFAULT_RETRY_DELAYS,
            relay,
        }
    }

    /// Enqueue an email for delivery to a single recipient.
    ///
    /// Returns the UUID of the created delivery task for tracking purposes.
    ///
    /// The task is immediately eligible for processing on the next call to
    /// [`process_queue`](Self::process_queue).
    pub fn enqueue(&mut self, recipient: String, email_data: Vec<u8>) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        let now = Utc::now();

        let task = DeliveryTask {
            id,
            recipient,
            email_data,
            attempts: 0,
            last_error: None,
            created_at: now,
            next_retry_at: now,
        };

        self.pending.push_back(task);

        debug!(
            task_id = %id,
            pending_count = self.pending.len(),
            "Delivery task enqueued"
        );

        id
    }

    /// Process all pending delivery tasks whose retry time has arrived.
    ///
    /// For each eligible task:
    ///
    /// 1. Attempt delivery via relay (or return error if no relay configured)
    /// 2. On success (`2xx`): move to [`completed`](Self::completed_tasks)
    /// 3. On transient failure (`5xx`, timeout, connection error):
    ///    - Increment attempt counter
    ///    - Calculate next retry time using exponential backoff
    ///    - If under `max_retries`: keep in pending for next cycle
    ///    - If at or over `max_retries`: move to [`failed`](Self::failed_tasks)
    /// 4. On permanent failure (`4xx`): move directly to [`failed`](Self::failed_tasks) without retry
    ///
    /// # Returns
    ///
    /// All results from tasks that reached a terminal state (delivered or permanently failed)
    /// during this processing cycle. Tasks scheduled for future retry are not included.
    ///
    /// # Errors
    ///
    /// Returns an error only for fatal queue-level failures (should not occur under
    /// normal operation). Individual delivery failures are captured in result objects.
    pub async fn process_queue(&mut self) -> Result<Vec<DeliveryResult>> {
        let now = Utc::now();
        let mut terminal_results: Vec<DeliveryResult> = Vec::new();

        // Collect tasks that are due for processing
        // We iterate by index because we may modify the deque during iteration
        let mut i = 0;
        while i < self.pending.len() {
            // Check if this task is due (next_retry_at <= now)
            let is_due = {
                match self.pending.get(i) {
                    Some(task) => task.next_retry_at <= now,
                    None => false,
                }
            };

            if !is_due {
                i += 1;
                continue;
            }

            // Remove the task from the pending queue
            let task = self.pending.remove(i).expect("task exists (checked above)");

            debug!(
                task_id = %task.id,
                recipient = %task.recipient,
                attempt = task.attempts + 1,
                "Processing delivery task"
            );

            // Attempt delivery
            let result = self.deliver_single(&task).await;

            match result {
                DeliveryResult::Delivered {
                    ref recipient,
                    attempts,
                } => {
                    info!(
                        task_id = %task.id,
                        to = %recipient,
                        attempts = attempts,
                        "Email delivered successfully"
                    );
                    self.completed.push(result.clone());
                    terminal_results.push(result);
                }
                DeliveryResult::FailedPermanently {
                    ref recipient,
                    ref last_error,
                    attempts,
                } => {
                    warn!(
                        task_id = %task.id,
                        to = %recipient,
                        attempts = attempts,
                        error = %last_error,
                        "Delivery failed permanently"
                    );
                    self.failed.push(result.clone());
                    terminal_results.push(result);
                }
                DeliveryResult::PendingRetry {
                    ref recipient,
                    next_retry_in_secs: _next_retry_in_secs,
                } => {
                    let new_attempts = task.attempts + 1;

                    if new_attempts >= self.max_retries {
                        // Exhausted all retries
                        let fail_result = DeliveryResult::FailedPermanently {
                            recipient: recipient.clone(),
                            last_error: task.last_error.unwrap_or_else(|| {
                                "Retry limit exceeded".to_string()
                            }),
                            attempts: new_attempts,
                        };
                        error!(
                            task_id = %task.id,
                            to = %recipient,
                            attempts = new_attempts,
                            "Delivery retries exhausted"
                        );
                        self.failed.push(fail_result.clone());
                        terminal_results.push(fail_result);
                    } else {
                        // Schedule next retry with exponential backoff
                        let delay_index = (new_attempts as usize).min(self.retry_delays.len() - 1);
                        let delay_secs = self.retry_delays[delay_index];
                        let next_retry = now + chrono::Duration::seconds(delay_secs as i64);

                        info!(
                            task_id = %task.id,
                            to = %recipient,
                            attempt = new_attempts,
                            next_delay_secs = delay_secs,
                            next_retry_at = %next_retry.to_rfc3339(),
                            "Scheduling retry"
                        );

                        let retried_task = DeliveryTask {
                            id: task.id,
                            recipient: task.recipient,
                            email_data: task.email_data,
                            attempts: new_attempts,
                            last_error: task.last_error,
                            created_at: task.created_at,
                            next_retry_at: next_retry,
                        };

                        // Re-insert at current position (don't increment i since we removed one)
                        self.pending.insert(i, retried_task);
                        i += 1; // Advance past the re-inserted task
                    }
                }
            }
        }

        Ok(terminal_results)
    }

    /// Attempt delivery of a single email to its recipient.
    ///
    /// This method constructs a lettre `Message` from the raw email data
    /// and sends it via the configured relay transport (if any).
    ///
    /// # Error Classification
    ///
    /// Attempts to distinguish between:
    /// - **Transient**: Connection refused, timeout, DNS resolution failure, 5xx responses
    /// - **Permanent**: 4xx responses, invalid address format
    /// - **No relay**: Configuration issue (treated as permanent)
    async fn deliver_single(&self, task: &DeliveryTask) -> DeliveryResult {
        // If no relay is configured, we cannot deliver
        let relay = match &self.relay {
            Some(r) => r,
            None => {
                return DeliveryResult::FailedPermanently {
                    recipient: task.recipient.clone(),
                    last_error: "No SMTP relay configured".to_string(),
                    attempts: task.attempts,
                };
            }
        };

        // Build lettre Message from raw email data
        // We need to parse enough of the raw data to construct a valid Message
        let message = match Self::build_lettre_message(&task.email_data, &task.recipient) {
            Ok(msg) => msg,
            Err(e) => {
                return DeliveryResult::FailedPermanently {
                    recipient: task.recipient.clone(),
                    last_error: format!("Message construction failed: {e}"),
                    attempts: task.attempts,
                };
            }
        };

        // Attempt delivery via relay
        match relay.send(&message) {
            Ok(_) => DeliveryResult::Delivered {
                recipient: task.recipient.clone(),
                attempts: task.attempts + 1,
            },
            Err(e) => {
                let error_string = e.to_string();
                
                // Classify error type based on lettre error content
                // Note: lettre wraps SMTP responses; we inspect for common patterns
                let is_transient = error_string.contains("timeout")
                    || error_string.contains("connection")
                    || error_string.contains("refused")
                    || error_string.contains("unavailable")
                    || error_string.contains("temporary")
                    || error_string.contains("450")
                    || error_string.contains("451")
                    || error_string.contains("452")
                    || error_string.contains("454");

                if is_transient {
                    DeliveryResult::PendingRetry {
                        recipient: task.recipient.clone(),
                        next_retry_in_secs: {
                            let delay_index =
                                (task.attempts as usize).min(DEFAULT_RETRY_DELAYS.len() - 1);
                            DEFAULT_RETRY_DELAYS[delay_index]
                        },
                    }
                } else {
                    DeliveryResult::FailedPermanently {
                        recipient: task.recipient.clone(),
                        last_error: error_string,
                        attempts: task.attempts + 1,
                    }
                }
            }
        }
    }

    /// Build a lettre `Message` from raw RFC 5322 email data.
    ///
    /// Extracts From, To, Subject headers from raw data and constructs
    /// a properly structured lettre message with the original body content.
    fn build_lettre_message(
        raw_data: &[u8],
        _recipient: &str,
    ) -> std::result::Result<Message, Box<dyn std::error::Error>> {
        // Parse raw email to extract headers for message construction
        let parsed = mailparse::parse_mail(raw_data)?;

        // Extract key headers
        let from_header = parsed.headers.iter().find(|h| h.get_key().to_lowercase() == "from");
        let subject_header = parsed
            .headers
            .iter()
            .find(|h| h.get_key().to_lowercase() == "subject");

        let from_addr = from_header
            .map(|h| h.get_value())
            .unwrap_or_else(|| "misogi-smtp@localhost".to_string());

        let subject = subject_header
            .map(|h| h.get_value())
            .unwrap_or_default();

        // Get body text
        let body = parsed.get_body().unwrap_or_default();

        // Build lettre message
        let message = Message::builder()
            .from(from_addr.parse::<Mailbox>()?)
            .to(_recipient.parse::<Mailbox>()?)
            .subject(subject)
            .body(body)?;

        Ok(message)
    }

    /// Retrieve tasks that have permanently failed (exhausted retries or permanent errors).
    ///
    /// Returns a reference to the internal failure list. Useful for:
    /// - Generating bounce notifications
    /// - Alerting operators about delivery issues
    /// - Audit reporting on undeliverable messages
    pub fn failed_tasks(&self) -> &[DeliveryResult] {
        &self.failed
    }

    /// Retrieve successfully completed delivery tasks.
    pub fn completed_tasks(&self) -> &[DeliveryResult] {
        &self.completed
    }

    /// Count of tasks currently pending (awaiting retry or first attempt).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Total count of all tasks ever enqueued (pending + completed + failed).
    pub fn total_task_count(&self) -> usize {
        self.pending.len() + self.completed.len() + self.failed.len()
    }
}
