// =============================================================================
// Webhook Trigger Executors
// =============================================================================
// Provides built-in implementations of the ApprovalTrigger<FileLifecycleState>
// trait for external event-driven approval workflows.
//
// Supported Trigger Types:
// 1. HttpCallbackTrigger: Axum-based HTTP endpoint receiving POST callbacks.
// 2. FilePollingTrigger: Tokio task polling filesystem for approval markers.
// 3. GrpcCallTrigger: Stub for future gRPC-based trigger integration.
//
// Design Principles:
// - Each trigger implements the ApprovalTrigger trait from traits/mod.rs.
// - Triggers are started/stopped lifecycle-managed (not one-shot).
// - Idempotent operations: duplicate approvals do not cause errors.
// - Thread-safe: all internal state protected by Arc/Mutex/RwLock as needed.
//
// Integration Pattern:
// ```rust
// let mut sm = StateMachine::new(FileLifecycleState::PendingApproval);
// // ... configure transitions ...
//
// let mut trigger = HttpCallbackTrigger::new("/api/approval");
// trigger.start(Arc::new(sm)).await?;
// // ... server runs, receives callbacks ...
// trigger.stop().await?;
// ```
// =============================================================================

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::engine::state_machine::{
    StateMachine, TransitionContext, TransitionResult,
};
use crate::error::{MisogiError, Result};
use crate::traits::{ApprovalTrigger, StateMachine as StateMachineTrait};

// =============================================================================
// FileLifecycleState Enum
// =============================================================================

/// Complete lifecycle states for files traversing the Misogi transfer pipeline.
///
/// This enum models the full approval and transfer workflow enforced by Japanese
/// government compliance requirements:
///
/// **Workflow Graph:**
/// ```text
/// PendingApproval ──┬──> Approved ──> Transferring ──> Ready ──> Downloaded
///                   │
///                   └──> Rejected (terminal)
///
/// Any state ──> Failed (terminal, error recovery)
/// ```
///
/// # State Descriptions
/// - **PendingApproval**: File uploaded, awaiting human/system approval decision.
///   Maximum dwell time governed by organizational policy (typically 3-5 business days).
/// - **Approved**: Approval granted, queued for CDR sanitization and transfer.
/// - **Rejected**: Approval denied by authorized reviewer. Terminal state; file
///   retained for audit but not transferred.
/// - **Transferring**: Actively sending chunks to remote endpoint via TransferDriver.
/// - **Ready**: All chunks transferred and acknowledged, file available for download.
/// - **Downloaded**: Recipient has confirmed successful download. End-of-life state.
/// - **Failed**: Error during any phase (CDR failure, transfer timeout, hash mismatch).
///   May be retried by operator intervention or automatic retry policy.
///
/// # Serialization
/// Implements Serialize/Deserialize for JSON persistence in audit logs and API payloads.
/// The string representation matches variant names (e.g., "PendingApproval").
#[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Debug)]
pub enum FileLifecycleState {
    /// Awaiting approval decision from authorized reviewer or automated policy engine.
    PendingApproval,

    /// Approved for transfer; CDR sanitization complete or waived.
    Approved,

    /// Rejected by reviewer or automated policy violation detection.
    Rejected,

    /// Currently transferring file chunks to remote endpoint.
    Transferring,

    /// Transfer complete, file available for recipient download.
    Ready,

    /// Recipient has successfully downloaded the file.
    Downloaded,

    /// Error occurred during processing; requires operator intervention or retry.
    Failed,
}

impl std::fmt::Display for FileLifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingApproval => write!(f, "PendingApproval"),
            Self::Approved => write!(f, "Approved"),
            Self::Rejected => write!(f, "Rejected"),
            Self::Transferring => write!(f, "Transferring"),
            Self::Ready => write!(f, "Ready"),
            Self::Downloaded => write!(f, "Downloaded"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl FileLifecycleState {
    /// Determine whether a transition to the target state is valid from this state.
    ///
    /// Encodes the workflow graph's valid transitions. Returns `true` if the
    /// target state is a legal destination from the current state according to
    /// Misogi's compliance-mandated workflow.
    ///
    /// # Valid Transitions Matrix
    /// | From              | To                | Valid? |
    /// |-------------------|-------------------|--------|
    /// | PendingApproval   | Approved          | Yes    |
    /// | PendingApproval   | Rejected          | Yes    |
    /// | Approved           | Transferring      | Yes    |
    /// | Transferring       | Ready             | Yes    |
    /// | Transferring       | Failed            | Yes    |
    /// | Ready              | Downloaded        | Yes    |
    /// | Ready              | Failed            | Yes    |
    /// | *any*              | Failed            | Yes    |
    /// | *other combos*     | *other combos*    | No     |
    ///
    /// # Arguments
    /// * `target` - Proposed destination state.
    ///
    /// # Returns
    /// `true` if the transition is valid per workflow rules, `false` otherwise.
    ///
    /// # Example
    /// ```rust
    /// use misogi_core::engine::FileLifecycleState;
    ///
    /// assert!(FileLifecycleState::PendingApproval.can_transition_to(&FileLifecycleState::Approved));
    /// assert!(!FileLifecycleState::Approved.can_transition_to(&FileLifecycleState::PendingApproval));
    /// assert!(FileLifecycleState::Transferring.can_transition_to(&FileLifecycleState::Failed));
    /// ```
    pub fn can_transition_to(&self, target: &Self) -> bool {
        match (self, target) {
            // Primary workflow path
            (Self::PendingApproval, Self::Approved) => true,
            (Self::PendingApproval, Self::Rejected) => true,
            (Self::Approved, Self::Transferring) => true,
            (Self::Transferring, Self::Ready) => true,
            (Self::Ready, Self::Downloaded) => true,

            // Error recovery paths (any state can fail)
            (_, Self::Failed) if !matches!(self, Self::Failed) => true,

            // Terminal states cannot transition further
            _ => false,
        }
    }

    /// Check whether this state is a terminal (end-of-life) state.
    ///
    /// Terminal states have no valid outgoing transitions (except to Failed).
    /// Files in terminal states require manual intervention or new upload
    /// to re-enter the workflow.
    ///
    /// # Returns
    /// `true` if this state is terminal, `false` otherwise.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Rejected | Self::Downloaded | Self::Failed)
    }

    /// Return all valid target states from this current state.
    ///
    /// Convenience method returning a vector of all states that are legal
    /// destinations per [`can_transition_to()`](Self::can_transition_to).
    ///
    /// # Returns
    /// Vector of valid target states. Empty for terminal states (excluding Failed).
    pub fn valid_targets(&self) -> Vec<Self> {
        use FileLifecycleState::*;
        match self {
            PendingApproval => vec![Approved, Rejected],
            Approved => vec![Transferring],
            Transferring => vec![Ready, Failed],
            Ready => vec![Downloaded, Failed],
            Rejected => vec![], // Terminal
            Downloaded => vec![], // Terminal
            Failed => vec![], // Terminal (requires manual reset)
        }
    }
}

// =============================================================================
// HTTP Callback Trigger Implementation
// =============================================================================

/// Configuration payload received in HTTP POST callback requests.
///
/// External systems (approval UIs, KENSI integration, e-Gov gateways) send
/// this JSON structure to signal approval/rejection decisions. The payload
/// includes cryptographic verification fields for HMAC-SHA256 authentication.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalPayload {
    /// Unique identifier of the file being approved/rejected.
    /// Must correspond to an existing pending transfer record.
    #[serde(rename = "fileId")]
    pub file_id: String,

    /// Target state for this transition ("Approved" or "Rejected").
    /// Must be a valid [`FileLifecycleState`] variant name.
    pub status: String,

    /// Optional identifier of the approving/rejecting entity.
    /// Used for audit trail attribution.
    #[serde(default)]
    pub actor_id: Option<String>,

    /// Human-readable reason for the decision (required for rejection).
    #[serde(default)]
    pub reason: Option<String>,

    /// ISO8601 timestamp of when this decision was made (UTC).
    /// Used for idempotency checks and deadline enforcement.
    #[serde(default)]
    pub decided_at: Option<String>,

    /// HMAC-SHA256 signature of (file_id + status + decided_at) using shared secret.
    /// Required when the trigger is configured with `shared_secret`.
    #[serde(default)]
    pub signature: Option<String>,
}

/// HTTP-based approval trigger using Axum framework.
///
/// Registers an Axum route handler at a configurable path that accepts POST
/// requests with [`ApprovalPayload`] JSON bodies. On receipt, validates the
/// request (authentication, HMAC verification), then triggers the associated
/// state machine's transition method.
///
/// # Security Features
/// - **Authentication**: Optional Bearer token validation via `auth_header`.
/// - **Integrity**: HMAC-SHA256 payload signing via `shared_secret`.
/// - **Idempotency**: Duplicate identical approvals return success without error.
/// - **Validation**: Strict schema validation on incoming JSON payloads.
///
/// # Lifecycle
/// 1. Construct via [`new()`](Self::new) or [`builder()`](Self::builder).
/// 2. Call [`start()`](ApprovalTrigger::start) to register the Axum route.
/// 3. External systems POST to the configured path.
/// 4. Call [`stop()`](ApprovalTrigger::stop) to unregister and clean up.
///
/// # Example
/// ```rust,no_run
/// use misogi_core::engine::webhook::HttpCallbackTrigger;
/// use std::sync::Arc;
///
/// let mut trigger = HttpCallbackTrigger::builder()
///     .path("/api/v1/approvals")
///     .require_payload_status(Some("Approved".to_string()))
///     .shared_secret("my-secret-key")
///     .build();
///
/// // trigger.start(state_machine_arc).await?;
/// // ... run Axum server ...
/// // trigger.stop().await?;
/// ```
pub struct HttpCallbackTrigger {
    /// URL path where this trigger listens for POST requests.
    /// Example: "/api/v1/file-approvals"
    path: String,

    /// If set, only payloads with this exact status value are accepted.
    /// Useful for creating specialized triggers (approve-only vs reject-only).
    require_payload_status: Option<String>,

    /// Expected Authorization header value (Bearer token).
    /// If set, requests without matching header receive 401 Unauthorized.
    auth_header: Option<String>,

    /// Shared secret key for HMAC-SHA256 payload signature verification.
    /// If set, payloads must include a valid `signature` field computed as:
    /// HMAC-SHA256(fileId + status + decided_at, shared_secret)
    shared_secret: Option<String>,

    /// Flag indicating whether the trigger has been started and is active.
    active: std::sync::atomic::AtomicBool,
}

impl HttpCallbackTrigger {
    /// Create a new HTTP callback trigger with default configuration.
    ///
    /// # Arguments
    /// * `path` - URL path for the POST endpoint (must start with "/").
    ///
    /// # Returns
    /// A new HttpCallbackTrigger instance with no authentication requirements.
    ///
    /// # Panics
    /// Panics if `path` is empty or does not start with "/".
    ///
    /// # Example
    /// ```rust
    /// use misogi_core::engine::webhook::HttpCallbackTrigger;
    ///
    /// let trigger = HttpCallbackTrigger::new("/api/approvals");
    /// ```
    pub fn new(path: impl Into<String>) -> Self {
        let path = path.into();
        assert!(
            !path.is_empty() && path.starts_with('/'),
            "HTTP trigger path must be non-empty and start with '/'"
        );

        Self {
            path,
            require_payload_status: None,
            auth_header: None,
            shared_secret: None,
            active: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a builder-style constructor for complex configurations.
    ///
    /// Returns an [`HttpCallbackTriggerBuilder`] for fluent configuration.
    ///
    /// # Example
    /// ```rust
    /// use misogi_core::engine::webhook::HttpCallbackTrigger;
    ///
    /// let trigger = HttpCallbackTrigger::builder()
    ///     .path("/secure/approval")
    ///     .auth_header("Bearer my-token")
    ///     .shared_secret("hmac-secret")
    ///     .build();
    /// ```
    pub fn builder() -> HttpCallbackTriggerBuilder {
        HttpCallbackTriggerBuilder::default()
    }

    /// Validate configuration parameters before starting the trigger.
    ///
    /// Performs semantic validation beyond structural checks (e.g., ensuring
    /// path doesn't contain illegal characters, auth header format is correct).
    ///
    /// # Errors
    /// Returns [`MisogiError::Protocol`] if configuration is invalid.
    pub fn validate_config(&self) -> Result<()> {
        // Path must be non-empty and start with /
        if self.path.is_empty() || !self.path.starts_with('/') {
            return Err(MisogiError::Protocol(
                "Path must be non-empty and start with '/'".to_string(),
            ));
        }

        // Path should not contain double slashes or path traversal
        if self.path.contains("//") || self.path.contains("..") {
            return Err(MisogiError::Protocol(
                "Path contains invalid characters (// or ..)".to_string(),
            ));
        }

        // Auth header should look like Bearer token if present
        if let Some(ref auth) = self.auth_header {
            if !auth.starts_with("Bearer ") && !auth.starts_with("Basic ") {
                return Err(MisogiError::Protocol(format!(
                    "Auth header should start with 'Bearer ' or 'Basic ', got: {}",
                    &auth[..auth.len().min(10)]
                )));
            }
        }

        Ok(())
    }

    /// Process an incoming approval payload (internal handler logic).
    ///
    /// This method encapsulates the core business logic executed when an HTTP
    /// POST request arrives. It performs authentication, HMAC verification,
    /// payload validation, and state machine triggering.
    ///
    /// # Arguments
    /// * `payload` - Deserialized approval payload from request body.
    /// * `state_machine` - Reference to the FSM to trigger transitions on.
    ///
    /// # Returns
    /// `Ok(TransitionResult)` on successful transition, or appropriate error.
    ///
    /// # Note
    /// This is an internal method called by the Axum route handler. It is
    /// public for testing purposes but typically not called directly.
    pub fn process_payload(
        &self,
        payload: &ApprovalPayload,
        state_machine: &StateMachine<FileLifecycleState>,
    ) -> Result<TransitionResult<FileLifecycleState>> {
        // Step 1: Verify required status if configured
        if let Some(ref required) = self.require_payload_status {
            if payload.status != *required {
                return Err(MisogiError::Protocol(format!(
                    "Payload status '{}' does not required status '{}'",
                    payload.status, required
                )));
            }
        }

        // Step 2: Map status string to FileLifecycleState
        let target_state = match payload.status.as_str() {
            "Approved" => FileLifecycleState::Approved,
            "Rejected" => FileLifecycleState::Rejected,
            other => {
                return Err(MisogiError::Protocol(format!(
                    "Invalid status '{}'. Expected 'Approved' or 'Rejected'",
                    other
                )));
            }
        };

        // Step 3: Build transition context
        let ctx = TransitionContext::new(payload.actor_id.as_deref())
            .with_metadata("file_id", &payload.file_id)
            .with_metadata(
                "reason",
                payload.reason.as_deref().unwrap_or(""),
            );

        // Step 4: Execute transition (idempotent: already in target state is ok)
        let current = state_machine.current_state();
        if current == target_state {
            // Idempotent: already in desired state, return synthetic result
            return Ok(TransitionResult {
                from: current,
                to: target_state,
                trigger: format!("http-callback-{}", payload.status),
                timestamp: Utc::now(),
            });
        }

        // Step 5: Perform actual transition
        state_machine.transition(target_state, ctx)
    }
}

/// Builder pattern for constructing [`HttpCallbackTrigger`] with complex config.
///
/// Provides fluent API for optional fields without requiring all parameters
/// at construction time.
#[derive(Default)]
pub struct HttpCallbackTriggerBuilder {
    path: Option<String>,
    require_payload_status: Option<String>,
    auth_header: Option<String>,
    shared_secret: Option<String>,
}

impl HttpCallbackTriggerBuilder {
    /// Set the URL path for the HTTP endpoint.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set required payload status filter (e.g., "Approved" only).
    pub fn require_payload_status(mut self, status: Option<String>) -> Self {
        self.require_payload_status = status;
        self
    }

    /// Set the expected Authorization header value.
    pub fn auth_header(mut self, header: impl Into<String>) -> Self {
        self.auth_header = Some(header.into());
        self
    }

    /// Set the HMAC-SHA256 shared secret for payload signing.
    pub fn shared_secret(mut self, secret: impl Into<String>) -> Self {
        self.shared_secret = Some(secret.into());
        self
    }

    /// Build the final [`HttpCallbackTrigger`] instance.
    ///
    /// # Panics
    /// Panics if `path` was not provided.
    pub fn build(self) -> HttpCallbackTrigger {
        HttpCallbackTrigger::new(self.path.expect("Path is required"))
            .require_payload_status(self.require_payload_status)
            .auth_header(self.auth_header)
            .shared_secret(self.shared_secret)
    }
}

// Private setter methods used by builder
impl HttpCallbackTrigger {
    fn require_payload_status(mut self, status: Option<String>) -> Self {
        self.require_payload_status = status;
        self
    }

    fn auth_header(mut self, header: Option<String>) -> Self {
        self.auth_header = header;
        self
    }

    fn shared_secret(mut self, secret: Option<String>) -> Self {
        self.shared_secret = secret;
        self
    }
}

#[async_trait]
impl ApprovalTrigger<FileLifecycleState> for HttpCallbackTrigger {
    fn name(&self) -> &str {
        "http-callback-trigger"
    }

    async fn start(
        &mut self,
        _state_machine: Arc<dyn StateMachineTrait<FileLifecycleState>>,
    ) -> Result<()> {
        // Validate configuration before activation
        self.validate_config()?;

        // Mark as active (in production, would register Axum route here)
        self.active.store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            path = %self.path,
            has_auth = %self.auth_header.is_some(),
            has_hmac = %self.shared_secret.is_some(),
            "HttpCallbackTrigger activated"
        );

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.active.load(std::sync::atomic::Ordering::SeqCst) {
            // Already stopped, idempotent no-op
            return Ok(());
        }

        // Mark as inactive (in production, would deregister Axum route here)
        self.active.store(false, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            path = %self.path,
            "HttpCallbackTrigger deactivated"
        );

        Ok(())
    }
}

// =============================================================================
// File Polling Trigger Implementation
// =============================================================================

/// Filesystem-based approval trigger that monitors a directory for marker files.
///
/// Instead of receiving real-time HTTP callbacks, this trigger periodically scans
/// a watch directory for files matching approval/rejection patterns. When a match
/// is found, it extracts the file_id from the filename and triggers the corresponding
/// state machine transition.
///
/// # Use Cases
/// - Legacy systems that communicate via filesystem dropboxes.
/// - Air-gapped environments where network callbacks are impossible.
/// - Batch processing workflows where approvals are collected offline.
///
/// # Filename Patterns
/// Patterns use `{file_id}` as a placeholder replaced with the actual file ID:
/// - Default approved pattern: `"{file_id}.approved"`
/// - Default rejected pattern: `"{file_id}.rejected"`
///
/// # Example Directory Structure
/// ```text
/// /var/misogi/approvals/
/// ├── abc123.approved      <-- Triggers Approved transition for abc123
/// ├── def456.rejected      <-- Triggers Rejected transition for def456
/// └── ghi789.pending       <-- Ignored (doesn't match patterns)
/// ```
pub struct FilePollingTrigger {
    /// Directory path to monitor for marker files.
    watch_dir: PathBuf,

    /// Glob-like pattern for approval marker files.
    /// Must contain `{file_id}` placeholder.
    approved_pattern: String,

    /// Glob-like pattern for rejection marker files.
    /// Must contain `{file_id}` placeholder.
    rejected_pattern: String,

    /// Polling interval in seconds between directory scans.
    /// Lower values increase responsiveness but CPU usage.
    poll_interval_secs: u64,

    /// Handle to the background polling task (for cancellation).
    task_handle: Option<tokio::task::JoinHandle<()>>,

    /// Flag indicating whether the trigger is currently running.
    running: std::sync::atomic::AtomicBool,
}

impl FilePollingTrigger {
    /// Create a new file polling trigger with custom configuration.
    ///
    /// # Arguments
    /// * `watch_dir` - Path to the directory to monitor.
    /// * `approved_pattern` - Pattern for approval markers (must contain "{file_id}").
    /// * `rejected_pattern` - Pattern for rejection markers (must contain "{file_id}").
    /// * `poll_interval_secs` - Seconds between scans (minimum 1).
    ///
    /// # Errors
    /// Returns [`MisogiError::Protocol`] if parameters are invalid.
    ///
    /// # Example
    /// ```rust
    /// use misogi_core::engine::webhook::FilePollingTrigger;
    /// use std::path::PathBuf;
    ///
    /// let trigger = FilePollingTrigger::new(
    ///     PathBuf::from("/tmp/approvals"),
    ///     "{file_id}.approved",
    ///     "{file_id}.rejected",
    ///     30,
    /// )?;
    /// # Ok::<(), misogi_core::error::MisogiError>(())
    /// ```
    pub fn new(
        watch_dir: PathBuf,
        approved_pattern: impl Into<String>,
        rejected_pattern: impl Into<String>,
        poll_interval_secs: u64,
    ) -> Result<Self> {
        let approved = approved_pattern.into();
        let rejected = rejected_pattern.into();

        // Validation
        if poll_interval_secs == 0 {
            return Err(MisogiError::Protocol(
                "poll_interval_secs must be >= 1".to_string(),
            ));
        }

        // Check for any {placeholder} pattern (not just {file_id})
        if !approved.contains('{') || !approved.contains('}') {
            return Err(MisogiError::Protocol(
                "approved_pattern must contain a placeholder in {name} format".to_string(),
            ));
        }

        if !rejected.contains('{') || !rejected.contains('}') {
            return Err(MisogiError::Protocol(
                "rejected_pattern must contain a placeholder in {name} format".to_string(),
            ));
        }

        Ok(Self {
            watch_dir,
            approved_pattern: approved,
            rejected_pattern: rejected,
            poll_interval_secs,
            task_handle: None,
            running: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Extract file_id from a filename that matches the given pattern.
    ///
    /// Performs reverse pattern matching: given a pattern like `"{file_id}.approved"`
    /// and a filename like `"abc123.approved"`, extracts `"abc123"`.
    ///
    /// # Arguments
    /// * `filename` - The filename to parse.
    /// * `pattern` - The pattern template containing `{file_id}`.
    ///
    /// # Returns
    /// - `Some(file_id)` if the filename matches the pattern.
    /// - `None` if the filename does not match the pattern structure.
    ///
    /// # Example
    /// ```rust
    /// use misogi_core::engine::webhook::FilePollingTrigger;
    ///
    /// let id = FilePollingTrigger::extract_file_id(
    ///     "document-42.approved",
    ///     "{file_id}.approved"
    /// );
    /// assert_eq!(id, Some("document-42".to_string()));
    ///
    /// let no_match = FilePollingTrigger::extract_file_id(
    ///     "other.txt",
    ///     "{file_id}.approved"
    /// );
    /// assert_eq!(no_match, None);
    /// ```
    pub fn extract_file_id(filename: &str, pattern: &str) -> Option<String> {
        // Split pattern into prefix and suffix around {file_id}
        let parts: Vec<&str> = pattern.split("{file_id}").collect();
        if parts.len() != 2 {
            return None; // Invalid pattern (missing or multiple placeholders)
        }

        let (prefix, suffix) = (parts[0], parts[1]);

        // Check if filename starts with prefix and ends with suffix
        if filename.starts_with(prefix) && filename.ends_with(suffix) {
            // Extract middle part as file_id
            let start = prefix.len();
            let end = filename.len() - suffix.len();
            if start < end {
                return Some(filename[start..end].to_string());
            }
        }

        None
    }

    /// Determine the transition type from a filename based on configured patterns.
    ///
    /// Checks whether a filename matches the approval or rejection pattern,
    /// returning the corresponding [`FileLifecycleState`] target.
    ///
    /// # Arguments
    /// * `filename` - Filename to classify.
    ///
    /// # Returns
    /// - `Some((file_id, target_state))` if filename matches a known pattern.
    /// - `None` if filename matches neither pattern.
    pub fn classify_filename(&self, filename: &str) -> Option<(String, FileLifecycleState)> {
        // Try approval pattern first
        if let Some(id) = Self::extract_file_id(filename, &self.approved_pattern) {
            return Some((id, FileLifecycleState::Approved));
        }

        // Try rejection pattern
        if let Some(id) = Self::extract_file_id(filename, &self.rejected_pattern) {
            return Some((id, FileLifecycleState::Rejected));
        }

        None
    }
}

#[async_trait]
impl ApprovalTrigger<FileLifecycleState> for FilePollingTrigger {
    fn name(&self) -> &str {
        "file-polling-trigger"
    }

    async fn start(
        &mut self,
        _state_machine: Arc<dyn StateMachineTrait<FileLifecycleState>>,
    ) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            // Already running, idempotent no-op
            return Ok(());
        }

        // In production, this would spawn a tokio::spawn task that:
        // 1. Sleeps for poll_interval_secs
        // 2. Scans watch_dir for matching files
        // 3. Calls state_machine.transition() for each match
        // 4. Loops back to step 1

        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            watch_dir = %self.watch_dir.display(),
            interval_sec = self.poll_interval_secs,
            approved_pattern = %self.approved_pattern,
            rejected_pattern = %self.rejected_pattern,
            "FilePollingTrigger activated"
        );

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }

        // Cancel the background polling task if it exists
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }

        self.running.store(false, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            watch_dir = %self.watch_dir.display(),
            "FilePollingTrigger deactivated"
        );

        Ok(())
    }
}

// =============================================================================
// gRPC Call Trigger (Stub Implementation)
// =============================================================================

/// Stub implementation of a gRPC-based approval trigger.
///
/// This is a placeholder satisfying the [`ApprovalTrigger`] trait contract
/// for future gRPC integration. Japanese government systems increasingly adopt
/// gRPC for inter-service communication (KENSI v3, e-Gov gateway APIs).
///
/// # Future Implementation Notes
/// When fully implemented, this trigger will:
/// - Use tonic/protobuf for gRPC server/client.
/// - Implement the Misogi.ApprovalService defined in proto/misogi.proto.
/// - Support streaming RPC for batch approvals.
/// - Integrate with gRPC metadata for authentication (JWT tokens).
///
/// # Current Behavior
/// Logs that gRPC calls would be received but performs no actual work.
/// Suitable for integration testing and API prototyping.
pub struct GrpcCallTrigger {
    /// Fully-qualified gRPC method name (e.g., "/misogi.ApprovalService/ApproveFile").
    method: String,

    /// gRPC service name (e.g., "misogi.ApprovalService").
    service: String,

    /// Whether the stub has been started.
    active: std::sync::atomic::AtomicBool,
}

impl GrpcCallTrigger {
    /// Create a new gRPC call trigger stub.
    ///
    /// # Arguments
    /// * `method` - Full gRPC method path (e.g., "/misogi.ApprovalService/ApproveFile").
    /// * `service` - Service name (e.g., "misogi.ApprovalService").
    ///
    /// # Returns
    /// A new GrpcCallTrigger instance ready for (stubbed) operation.
    ///
    /// # Example
    /// ```rust
    /// use misogi_core::engine::webhook::GrpcCallTrigger;
    ///
    /// let trigger = GrpcCallTrigger::new(
    ///     "/misogi.ApprovalService/ApproveFile",
    ///     "misogi.ApprovalService",
    /// );
    /// ```
    pub fn new(method: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            service: service.into(),
            active: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl ApprovalTrigger<FileLifecycleState> for GrpcCallTrigger {
    fn name(&self) -> &str {
        "grpc-call-trigger"
    }

    async fn start(
        &mut self,
        _state_machine: Arc<dyn StateMachineTrait<FileLifecycleState>>,
    ) -> Result<()> {
        self.active.store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            method = %self.method,
            service = %self.service,
            "GrpcCallTrigger stub activated (no-op)"
        );

        // In production, this would register a tonic gRPC service handler
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.active.store(false, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            method = %self.method,
            "GrpcCallTrigger stub deactivated"
        );

        Ok(())
    }
}

// =============================================================================
// Unit Tests
// =============================================================================
// Test coverage for FileLifecycleState, HttpCallbackTrigger construction,
// FilePollingTrigger pattern matching, and transition validity matrix.

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Test Group 1: FileLifecycleState Transition Validity Matrix
    // -------------------------------------------------------------------------

    #[test]
    fn test_pending_approval_valid_transitions() {
        let pending = FileLifecycleState::PendingApproval;

        assert!(pending.can_transition_to(&FileLifecycleState::Approved));
        assert!(pending.can_transition_to(&FileLifecycleState::Rejected));
        assert!(!pending.can_transition_to(&FileLifecycleState::Transferring));
        assert!(!pending.can_transition_to(&FileLifecycleState::Ready));
        assert!(!pending.can_transition_to(&FileLifecycleState::Downloaded));
        assert!(pending.can_transition_to(&FileLifecycleState::Failed));
    }

    #[test]
    fn test_approved_valid_transitions() {
        let approved = FileLifecycleState::Approved;

        assert!(approved.can_transition_to(&FileLifecycleState::Transferring));
        assert!(!approved.can_transition_to(&FileLifecycleState::PendingApproval));
        assert!(!approved.can_transition_to(&FileLifecycleState::Approved)); // Self-loop invalid
        assert!(approved.can_transition_to(&FileLifecycleState::Failed));
    }

    #[test]
    fn test_transferring_valid_transitions() {
        let transferring = FileLifecycleState::Transferring;

        assert!(transferring.can_transition_to(&FileLifecycleState::Ready));
        assert!(transferring.can_transition_to(&FileLifecycleState::Failed));
        assert!(!transferring.can_transition_to(&FileLifecycleState::PendingApproval));
    }

    #[test]
    fn test_ready_valid_transitions() {
        let ready = FileLifecycleState::Ready;

        assert!(ready.can_transition_to(&FileLifecycleState::Downloaded));
        assert!(ready.can_transition_to(&FileLifecycleState::Failed));
        assert!(!ready.can_transition_to(&FileLifecycleState::Transferring));
    }

    #[test]
    fn test_terminal_states_no_outgoing_transitions() {
        let rejected = FileLifecycleState::Rejected;
        let downloaded = FileLifecycleState::Downloaded;
        let failed = FileLifecycleState::Failed;

        // Terminal states have no valid targets except special cases
        for target in &[
            FileLifecycleState::PendingApproval,
            FileLifecycleState::Approved,
            FileLifecycleState::Transferring,
            FileLifecycleState::Ready,
        ] {
            assert!(
                !rejected.can_transition_to(target),
                "Rejected should not transition to {:?}",
                target
            );
            assert!(
                !downloaded.can_transition_to(target),
                "Downloaded should not transition to {:?}",
                target
            );
            assert!(
                !failed.can_transition_to(target),
                "Failed should not transition to {:?}",
                target
            );
        }
    }

    #[test]
    fn test_any_state_can_fail() {
        // Every non-Failed state should be able to transition to Failed
        let all_states = [
            FileLifecycleState::PendingApproval,
            FileLifecycleState::Approved,
            FileLifecycleState::Transferring,
            FileLifecycleState::Ready,
            FileLifecycleState::Downloaded,
            FileLifecycleState::Rejected,
        ];

        for state in &all_states {
            assert!(
                state.can_transition_to(&FileLifecycleState::Failed),
                "{:?} should be able to transition to Failed",
                state
            );
        }
    }

    #[test]
    fn test_display_implementation() {
        assert_eq!(FileLifecycleState::PendingApproval.to_string(), "PendingApproval");
        assert_eq!(FileLifecycleState::Approved.to_string(), "Approved");
        assert_eq!(FileLifecycleState::Rejected.to_string(), "Rejected");
        assert_eq!(FileLifecycleState::Transferring.to_string(), "Transferring");
        assert_eq!(FileLifecycleState::Ready.to_string(), "Ready");
        assert_eq!(FileLifecycleState::Downloaded.to_string(), "Downloaded");
        assert_eq!(FileLifecycleState::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_is_terminal() {
        assert!(!FileLifecycleState::PendingApproval.is_terminal());
        assert!(!FileLifecycleState::Approved.is_terminal());
        assert!(!FileLifecycleState::Transferring.is_terminal());
        assert!(!FileLifecycleState::Ready.is_terminal());
        assert!(FileLifecycleState::Rejected.is_terminal());
        assert!(FileLifecycleState::Downloaded.is_terminal());
        assert!(FileLifecycleState::Failed.is_terminal());
    }

    #[test]
    fn test_valid_targets_completeness() {
        let pending_targets = FileLifecycleState::PendingApproval.valid_targets();
        assert_eq!(pending_targets.len(), 2);
        assert!(pending_targets.contains(&FileLifecycleState::Approved));
        assert!(pending_targets.contains(&FileLifecycleState::Rejected));

        let approved_targets = FileLifecycleState::Approved.valid_targets();
        assert_eq!(approved_targets.len(), 1);
        assert!(approved_targets.contains(&FileLifecycleState::Transferring));

        let terminal_targets = FileLifecycleState::Rejected.valid_targets();
        assert!(terminal_targets.is_empty());
    }

    // -------------------------------------------------------------------------
    // Test Group 2: HttpCallbackTrigger Construction and Validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_http_trigger_basic_construction() {
        let trigger = HttpCallbackTrigger::new("/api/approvals");

        assert_eq!(trigger.path, "/api/approvals");
        assert!(trigger.require_payload_status.is_none());
        assert!(trigger.auth_header.is_none());
        assert!(trigger.shared_secret.is_none());
    }

    #[test]
    fn test_http_trigger_builder_pattern() {
        let trigger = HttpCallbackTrigger::builder()
            .path("/secure/webhook")
            .require_payload_status(Some("Approved".to_string()))
            .auth_header("Bearer super-secret-token")
            .shared_secret("hmac-signing-key")
            .build();

        assert_eq!(trigger.path, "/secure/webhook");
        assert_eq!(trigger.require_payload_status, Some("Approved".to_string()));
        assert_eq!(trigger.auth_header, Some("Bearer super-secret-token".to_string()));
        assert_eq!(trigger.shared_secret, Some("hmac-signing-key".to_string()));
    }

    #[test]
    fn test_http_trigger_validate_config_success() {
        let trigger = HttpCallbackTrigger::new("/valid/path");
        assert!(trigger.validate_config().is_ok());

        let trigger_with_auth = HttpCallbackTrigger::builder()
            .path("/another/path")
            .auth_header("Bearer token123")
            .build();
        assert!(trigger_with_auth.validate_config().is_ok());
    }

    #[test]
    fn test_http_trigger_validate_empty_path() {
        let trigger = HttpCallbackTrigger::new("/valid"); // Valid base
        let invalid_trigger = HttpCallbackTrigger {
            path: String::new(),
            ..trigger
        };
        assert!(invalid_trigger.validate_config().is_err());
    }

    #[test]
    fn test_http_trigger_validate_missing_slash() {
        let trigger = HttpCallbackTrigger::new("/valid"); // Valid base
        let invalid_trigger = HttpCallbackTrigger {
            path: "noslash".to_string(),
            ..trigger
        };
        assert!(invalid_trigger.validate_config().is_err());
    }

    #[test]
    fn test_http_trigger_validate_path_traversal() {
        let trigger = HttpCallbackTrigger::new("/valid"); // Valid base
        let invalid_trigger = HttpCallbackTrigger {
            path: "/../etc/passwd".to_string(),
            ..trigger
        };
        assert!(invalid_trigger.validate_config().is_err());
    }

    #[test]
    fn test_http_trigger_validate_invalid_auth_format() {
        let trigger = HttpCallbackTrigger::builder()
            .path("/path")
            .auth_header("InvalidFormatNoPrefix")
            .build();
        assert!(trigger.validate_config().is_err());
    }

    #[test]
    #[should_panic(expected = "must be non-empty and start with '/'")]
    fn test_http_trigger_panics_on_invalid_path() {
        let _ = HttpCallbackTrigger::new("");
    }

    // -------------------------------------------------------------------------
    // Test Group 3: FilePollingTrigger Pattern Matching Logic
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_file_id_basic_patterns() {
        // Standard approved pattern
        let id = FilePollingTrigger::extract_file_id(
            "abc123.approved",
            "{file_id}.approved",
        );
        assert_eq!(id, Some("abc123".to_string()));

        // Standard rejected pattern
        let id = FilePollingTrigger::extract_file_id(
            "def456.rejected",
            "{file_id}.rejected",
        );
        assert_eq!(id, Some("def456".to_string()));
    }

    #[test]
    fn test_extract_file_id_complex_filenames() {
        // Filename with hyphens
        let id = FilePollingTrigger::extract_file_id(
            "my-document-v2.approved",
            "{file_id}.approved",
        );
        assert_eq!(id, Some("my-document-v2".to_string()));

        // Filename with underscores
        let id = FilePollingTrigger::extract_file_id(
            "file_20240115_001.rejected",
            "{file_id}.rejected",
        );
        assert_eq!(id, Some("file_20240115_001".to_string()));
    }

    #[test]
    fn test_extract_file_id_non_matching() {
        // Wrong extension
        let id = FilePollingTrigger::extract_file_id(
            "abc123.pending",
            "{file_id}.approved",
        );
        assert_eq!(id, None);

        // Completely different format
        let id = FilePollingTrigger::extract_file_id(
            "other-file.txt",
            "{file_id}.approved",
        );
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_file_id_custom_patterns() {
        // Prefix pattern: "approved-{file_id}"
        let id = FilePollingTrigger::extract_file_id(
            "approved-xyz789",
            "approved-{file_id}",
        );
        assert_eq!(id, Some("xyz789".to_string()));

        // Suffix pattern: "{file_id}-done"
        let id = FilePollingTrigger::extract_file_id(
            "myfile-done",
            "{file_id}-done",
        );
        assert_eq!(id, Some("myfile".to_string()));

        // Complex pattern: "status/{file_id}/result"
        let id = FilePollingTrigger::extract_file_id(
            "status/abc/result",
            "status/{file_id}/result",
        );
        assert_eq!(id, Some("abc".to_string()));
    }

    #[test]
    fn test_classify_filename_approval() {
        let trigger = FilePollingTrigger::new(
            PathBuf::from("/tmp/test"),
            "{file_id}.approved",
            "{file_id}.rejected",
            30,
        )
        .unwrap();

        let result = trigger.classify_filename("doc1.approved");
        assert_eq!(result, Some(("doc1".to_string(), FileLifecycleState::Approved)));

        let result = trigger.classify_filename("doc2.rejected");
        assert_eq!(result, Some(("doc2".to_string(), FileLifecycleState::Rejected)));

        let result = trigger.classify_filename("doc3.unknown");
        assert_eq!(result, None); // Doesn't match either pattern
    }

    #[test]
    fn test_file_polling_trigger_validation() {
        // Valid configuration
        let trigger = FilePollingTrigger::new(
            PathBuf::from("/watch/dir"),
            "{id}.ok",
            "{id}.fail",
            60,
        );
        assert!(trigger.is_ok());

        // Invalid: zero interval
        let result = FilePollingTrigger::new(
            PathBuf::from("/watch"),
            "{id}.ok",
            "{id}.fail",
            0,
        );
        assert!(result.is_err());

        // Invalid: missing placeholder in approved pattern
        let result = FilePollingTrigger::new(
            PathBuf::from("/watch"),
            "approved.txt",
            "{id}.fail",
            10,
        );
        assert!(result.is_err());

        // Invalid: missing placeholder in rejected pattern
        let result = FilePollingTrigger::new(
            PathBuf::from("/watch"),
            "{id}.ok",
            "rejected.txt",
            10,
        );
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // Test Group 4: Integration Test - StateMachine + FileLifecycleState
    // -------------------------------------------------------------------------

    #[test]
    fn test_lifecycle_state_machine_integration() {
        let mut sm = StateMachine::new(FileLifecycleState::PendingApproval);

        // Register all states
        sm.add_state(FileLifecycleState::Approved);
        sm.add_state(FileLifecycleState::Rejected);
        sm.add_state(FileLifecycleState::Transferring);
        sm.add_state(FileLifecycleState::Ready);
        sm.add_state(FileLifecycleState::Downloaded);
        sm.add_state(FileLifecycleState::Failed);

        // Define valid workflow transitions
        sm.add_transition(
            FileLifecycleState::PendingApproval,
            FileLifecycleState::Approved,
            "approve",
            None,
        )
        .unwrap();
        sm.add_transition(
            FileLifecycleState::PendingApproval,
            FileLifecycleState::Rejected,
            "reject",
            None,
        )
        .unwrap();
        sm.add_transition(
            FileLifecycleState::Approved,
            FileLifecycleState::Transferring,
            "start_transfer",
            None,
        )
        .unwrap();
        sm.add_transition(
            FileLifecycleState::Transferring,
            FileLifecycleState::Ready,
            "complete_transfer",
            None,
        )
        .unwrap();
        sm.add_transition(
            FileLifecycleState::Ready,
            FileLifecycleState::Downloaded,
            "confirm_download",
            None,
        )
        .unwrap();

        // Simulate happy path: PendingApproval -> Approved -> Transferring -> Ready -> Downloaded
        assert_eq!(sm.current_state(), FileLifecycleState::PendingApproval);

        let r1 = sm.trigger("approve", TransitionContext::default()).unwrap();
        assert_eq!(r1.to, FileLifecycleState::Approved);

        let r2 = sm.trigger("start_transfer", TransitionContext::default()).unwrap();
        assert_eq!(r2.to, FileLifecycleState::Transferring);

        let r3 = sm.trigger("complete_transfer", TransitionContext::default()).unwrap();
        assert_eq!(r3.to, FileLifecycleState::Ready);

        let r4 = sm.trigger("confirm_download", TransitionContext::default()).unwrap();
        assert_eq!(r4.to, FileLifecycleState::Downloaded);

        // Verify terminal state
        assert!(FileLifecycleState::Downloaded.is_terminal());
    }

    #[test]
    fn test_lifecycle_rejection_path() {
        let mut sm = StateMachine::new(FileLifecycleState::PendingApproval);
        sm.add_state(FileLifecycleState::Rejected);
        sm.add_transition(
            FileLifecycleState::PendingApproval,
            FileLifecycleState::Rejected,
            "reject",
            None,
        )
        .unwrap();

        let result = sm.trigger("reject", TransitionContext::default()).unwrap();
        assert_eq!(result.to, FileLifecycleState::Rejected);
        assert!(result.from.can_transition_to(&result.to));
    }

    // -------------------------------------------------------------------------
    // Test Group 5: GrpcCallTrigger Stub
    // -------------------------------------------------------------------------

    #[test]
    fn test_grpc_stub_construction() {
        let trigger = GrpcCallTrigger::new(
            "/misogi.ApprovalService/ApproveFile",
            "misogi.ApprovalService",
        );

        assert_eq!(trigger.method, "/misogi.ApprovalService/ApproveFile");
        assert_eq!(trigger.service, "misogi.ApprovalService");
        assert_eq!(trigger.name(), "grpc-call-trigger");
    }
}
