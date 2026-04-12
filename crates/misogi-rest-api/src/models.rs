//! Domain Models, Request/Response Types, and Configuration
//!
//! Defines every serializable type used across the Misogi REST API surface.
//! All public types derive `serde::Serialize` and `serde::Deserialize`.
//!
//! # Naming Conventions
//!
//! - **Request** types end in `Request` or `Query`
//! - **Response** domain types are plain nouns (`FileItem`, `PolicyInfo`)
//! - **Envelope** types wrap responses (`ApiResult`, `PaginatedResponse`)
//! - **Configuration** types end in `Config`

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ===========================================================================
// Response Envelopes
// ===========================================================================

/// Standard success envelope wrapping every successful API response.
///
/// Provides a uniform top-level structure that clients can always destructure:
/// ```json
/// { "data": { ... }, "meta": { "page": 1, ... } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResult<T> {
    /// The response payload -- type varies by endpoint.
    pub data: T,

    /// Optional pagination metadata (present only on list endpoints).
    pub meta: Option<PaginationMeta>,
}

/// Machine-readable error detail attached to failed API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Stable error identifier (e.g., `"FILE_NOT_FOUND"`).
    pub code: String,

    /// Human-readable error description safe for display to end users.
    pub message: String,

    /// Optional structured additional context (e.g., field validation errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Pagination metadata returned alongside paginated list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    /// Current page number (1-based).
    pub page: u32,

    /// Number of items per page.
    pub per_page: u32,

    /// Total number of items matching the query (across all pages).
    pub total_count: u64,

    /// Whether a subsequent page of results exists.
    pub has_more: bool,
}

/// Cursor-based paginated response envelope.
///
/// Uses an opaque `next_cursor` string for efficient deep pagination
/// without offset-based performance degradation on large datasets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Opaque cursor for fetching the next page. `None` if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    /// Whether additional results exist beyond this page.
    pub has_more: bool,

    /// Total number of matching records (may be approximate).
    pub total_count: u64,

    /// Items on the current page.
    pub items: Vec<T>,
}

// ===========================================================================
// Domain Models -- Files
// ===========================================================================

/// Lightweight file item representation for list endpoints.
///
/// Omits heavy fields (hash, report, raw metadata) to keep list responses lean.
/// Use [`get_file`](crate::handlers::files::get_file) to retrieve full details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileItem {
    /// Unique file identifier (UUID v4).
    pub id: Uuid,

    /// Original filename as provided by the uploader.
    pub filename: String,

    /// File size in bytes.
    pub size_bytes: u64,

    /// MIME type detected during upload.
    pub mime_type: String,

    /// Current processing status of the file.
    pub status: FileStatus,

    /// Timestamp when the file was first uploaded.
    pub created_at: DateTime<Utc>,

    /// Timestamp of the last status change or metadata update.
    pub updated_at: DateTime<Utc>,
}

/// Detailed file representation including cryptographic hashes and sanitization context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDetail {
    /// Unique file identifier (UUID v4).
    pub id: Uuid,

    /// Original filename as provided by the uploader.
    pub filename: String,

    /// File size in bytes.
    pub size_bytes: u64,

    /// MIME type detected during upload.
    pub mime_type: String,

    /// SHA-256 hex digest of the original file content.
    pub sha256_hash: String,

    /// Current processing status of the file.
    pub status: FileStatus,

    /// Name of the sanitization policy applied (or pending).
    pub sanitization_policy: Option<String>,

    /// Timestamp when the file was first uploaded.
    pub created_at: DateTime<Utc>,

    /// Timestamp of the last status change or metadata update.
    pub updated_at: DateTime<Utc>,

    /// Arbitrary key-value metadata attached to this file.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Processing lifecycle status for a file within the Misogi pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    /// File has been uploaded but not yet queued for scanning.
    Uploaded,
    /// File is currently being analyzed by the scanner engine.
    Scanning,
    /// Sanitization completed successfully; output available.
    Sanitized,
    /// Sanitization found threats; file quarantined.
    Quarantined,
    /// File was explicitly deleted by an administrator or user.
    Deleted,
    /// An internal error prevented processing.
    Error,
}

impl Default for FileStatus {
    fn default() -> Self {
        Self::Uploaded
    }
}

// ===========================================================================
// Domain Models -- Sanitization Report
// ===========================================================================

/// Comprehensive sanitization report generated after a file completes CDR processing.
///
/// Contains threat findings, actions taken, and timing information suitable
/// for both UI display and compliance audit trails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationReport {
    /// Identifier of the file this report describes.
    pub file_id: Uuid,

    /// Name of the policy that was applied during sanitization.
    pub policy_applied: String,

    /// Total number of distinct threats detected.
    pub threats_found: u32,

    /// Individual threat findings with severity and location details.
    pub threat_details: Vec<ThreatDetail>,

    /// List of remediation actions performed on the file.
    pub actions_taken: Vec<String>,

    /// Wall-clock time spent processing this file (milliseconds).
    pub processing_time_ms: u64,
}

/// Describes a single threat finding within a sanitized file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetail {
    /// Severity level of this threat (e.g., `"critical"`, `"high"`, `"medium"`, `"low"`).
    pub severity: String,

    /// Threat category classification (e.g., `"macro"`, `"script"`, `"embedded_object"`).
    pub category: String,

    /// Human-readable description of what was found.
    pub description: String,

    /// Location within the file where the threat was detected
    /// (e.g., sheet name, page number, byte offset).
    pub location: Option<String>,
}

// ===========================================================================
// Domain Models -- Policies
// ===========================================================================

/// Sanitization policy information returned from policy endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// Unique policy identifier (UUID v4).
    pub id: Uuid,

    /// Human-readable policy name.
    pub name: String,

    /// Description of the policy's purpose and scope.
    pub description: Option<String>,

    /// Glob patterns for file types this policy applies to
    /// (e.g., `["*.docx", "*.xlsx", "*.pptx"]`).
    pub file_type_patterns: Vec<String>,

    /// Action to take when a matched file violates this policy.
    pub action: PolicyAction,

    /// Maximum allowed file size in megabytes for this policy.
    pub max_file_size_mb: u32,

    /// Timestamp when this policy was created.
    pub created_at: DateTime<Utc>,

    /// Timestamp when this policy was last modified.
    pub updated_at: DateTime<Utc>,
}

/// Action to perform when a file matches a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Sanitize the file (CDR) and return a clean copy.
    Sanitize,
    /// Block/reject the file entirely.
    Reject,
    /// Quarantine the file for manual review.
    Quarantine,
    /// Allow the file through without modification.
    Allow,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Sanitize
    }
}

// ===========================================================================
// Domain Models -- Jobs (Scan Tasks)
// ===========================================================================

/// Current status of an asynchronous scan job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    /// Unique job identifier (UUID v4).
    pub job_id: Uuid,

    /// Lifecycle state of the job.
    pub status: JobState,

    /// Completion percentage (0--100). Updated periodically during execution.
    pub progress_pct: u8,

    /// URL to download the sanitized result (populated only when `status == Completed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_url: Option<String>,

    /// Error message (populated only when `status == Failed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Timestamp when the job was created.
    pub created_at: DateTime<Utc>,

    /// Timestamp when the job began execution (`None` if still pending).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// Timestamp when the job finished (success or failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Lifecycle states for async scan jobs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Job is queued and waiting for a worker.
    Pending,
    /// Job is actively being processed.
    Running,
    /// Job completed successfully.
    Completed,
    /// Job terminated due to an unrecoverable error.
    Failed,
}

/// Response returned immediately after submitting a new scan job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCreated {
    /// Unique identifier of the newly created job.
    pub job_id: Uuid,

    /// Estimated duration in seconds (best-effort heuristic).
    pub estimated_duration_sec: u32,

    /// URL to poll for job status updates.
    pub status_url: String,
}

// ===========================================================================
// Domain Models -- Audit
// ===========================================================================

/// Single entry in the audit log trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique audit entry identifier.
    pub id: Uuid,

    /// Timestamp when the audited action occurred.
    pub timestamp: DateTime<Utc>,

    /// Identifier of the user (or service account) who performed the action.
    pub user_id: String,

    /// Action verb describing what happened (e.g., `"file_upload"`, `"policy_create"`).
    pub action: String,

    /// Type of resource affected (e.g., `"file"`, `"policy"`, `"job"`).
    pub resource_type: String,

    /// Identifier of the specific resource affected.
    pub resource_id: String,

    /// Structured details about the action (varies by action type).
    pub details: serde_json::Value,

    /// IP address of the client that initiated the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
}

// ===========================================================================
// Domain Models -- Health & Metrics
// ===========================================================================

/// Health check response returned by liveness and readiness probes.
///
/// Follows Kubernetes probe conventions with component-level granularity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall system health status string (`"ok"` or `"degraded"`).
    pub status: String,

    /// Semantic version of the running Misogi REST API service.
    pub version: String,

    /// Number of seconds since the process started.
    pub uptime_secs: u64,

    /// Per-component health breakdown.
    pub components: Vec<ComponentHealth>,
}

/// Health status of an individual dependency or subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Human-readable component name (e.g., `"auth_engine"`, `"scanner"`).
    pub name: String,

    /// Status string: `"healthy"`, `"unhealthy"`, or `"degraded"`.
    pub status: String,

    /// Round-trip latency to this component in milliseconds (when measurable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
}

// ===========================================================================
// Configuration
// ===========================================================================

/// Top-level configuration for the Misogi REST API server.
///
/// Typically loaded from environment variables or a TOML configuration file
/// at application startup, then passed to [`create_app`](crate::router::create_app).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestApiConfig {
    /// TCP bind address for the HTTP listener (e.g., `"0.0.0.0:8080"`).
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// List of allowed CORS origins. Empty means allow-all (development only).
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// Maximum requests per minute per API key (sliding window).
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,

    /// JWT issuer claim value used for token validation.
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,

    /// Name of the default sanitization policy applied when none is specified.
    #[serde(default = "default_policy")]
    pub default_policy: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_rate_limit_rpm() -> u32 {
    60
}

fn default_jwt_issuer() -> String {
    "misogi-auth".to_string()
}

fn default_policy() -> String {
    "default".to_string()
}

impl Default for RestApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            cors_origins: vec![],
            rate_limit_rpm: default_rate_limit_rpm(),
            jwt_issuer: default_jwt_issuer(),
            default_policy: default_policy(),
        }
    }
}

// ===========================================================================
// Request / Query Types
// ===========================================================================

/// Query parameters for listing files with filtering and sorting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFilesQuery {
    /// Page number (1-based). Defaults to 1.
    #[serde(default = "default_page")]
    pub page: u32,

    /// Number of items per page. Defaults to 20, max 100.
    #[serde(default = "default_per_page")]
    pub per_page: u32,

    /// Filter by file status (e.g., `"uploaded"`, `"sanitized"`, `"quarantined"`).
    #[serde(default)]
    pub status: Option<FileStatus>,

    /// Sort field (e.g., `"created_at"`, `"filename"`, "`size_bytes`").
    #[serde(default = "default_sort_by")]
    pub sort_by: String,

    /// Sort order: `"asc"` or `"desc"`. Defaults to `"desc"`.
    #[serde(default = "default_sort_order")]
    pub sort_order: String,

    /// Filter by MIME type pattern (e.g., `"application/pdf"`).
    #[serde(default)]
    pub mime_type_filter: Option<String>,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    20
}

fn default_sort_by() -> String {
    "created_at".to_string()
}

fn default_sort_order() -> String {
    "desc".to_string()
}

/// Request body for submitting a new scan job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Identifier of the file to scan.
    pub file_id: Uuid,

    /// Name of the sanitization policy to apply. If omitted, uses the configured default.
    #[serde(default)]
    pub policy: Option<String>,
}

/// Request body for creating a new sanitization policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    /// Human-readable policy name (required, unique).
    pub name: String,

    /// Optional description of the policy's purpose.
    pub description: Option<String>,

    /// Glob patterns for matching file types (e.g., `["*.pdf", "*.docx"]`).
    pub file_type_patterns: Vec<String>,

    /// Action to take when a matched file triggers this policy.
    pub action: PolicyAction,

    /// Maximum file size in megabytes allowed under this policy.
    pub max_file_size_mb: u32,
}

/// Request body for partially updating an existing policy.
///
/// All fields are optional; omitted fields retain their current values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolicyRequest {
    /// New policy name.
    #[serde(default)]
    pub name: Option<String>,

    /// New description.
    #[serde(default)]
    pub description: Option<String>,

    /// New file type glob patterns.
    #[serde(default)]
    pub file_type_patterns: Option<Vec<String>>,

    /// New action.
    #[serde(default)]
    pub action: Option<PolicyAction>,

    /// New maximum file size in megabytes.
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
}

/// Query parameters for filtering audit log entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start of the time range filter (inclusive). ISO 8601 format.
    #[serde(default)]
    pub start_date: Option<DateTime<Utc>>,

    /// End of the time range filter (exclusive). ISO 8601 format.
    #[serde(default)]
    pub end_date: Option<DateTime<Utc>>,

    /// Filter by user ID who performed the action.
    #[serde(default)]
    pub user_id: Option<String>,

    /// Filter by action type verb (e.g., `"file_upload"`, `"policy_delete"`).
    #[serde(default)]
    pub action_type: Option<String>,

    /// Page number (1-based). Defaults to 1.
    #[serde(default = "default_page")]
    pub page: u32,

    /// Items per page. Defaults to 50.
    #[serde(default = "default_audit_per_page")]
    pub per_page: u32,
}

fn default_audit_per_page() -> u32 {
    50
}
