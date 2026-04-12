// =============================================================================
// Misogi Storage Backend Trait — Pillar 2: Pluggable Storage Architecture
// =============================================================================
// This module defines the core storage abstraction for the Misogi system,
// enabling runtime-swappable backend implementations (local filesystem, S3,
// Azure Blob, GCS, MinIO, etc.) without coupling business logic to any
// specific storage provider.
//
// Design Principles:
// - All async methods use #[async_trait] for ergonomic trait object compatibility.
// - The trait requires Send + Sync + Debug for safe concurrent usage across tokio tasks.
// - Error handling uses a dedicated StorageError enum with comprehensive variants.
// - Data transfer uses bytes::Bytes for zero-copy efficiency where possible.
//
// Thread Safety Guarantee:
// All implementors MUST be Send + Sync. The Misogi runtime holds trait objects
// behind Arc<> and shares them across tokio tasks without additional locking.
// Implementors that hold internal mutable state must use Arc<RwLock<T>> or
// equivalent synchronization primitives internally.
//
// Lifecycle Contract:
// 1. Backend is instantiated with provider-specific configuration.
// 2. Caller invokes put/get/delete/exists operations as needed.
// 3. Periodic health monitoring via health_check().
// 4. Graceful shutdown releases all held resources (implementation-defined).
// =============================================================================

use std::fmt::Debug;
use std::io;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use thiserror::Error;

// =============================================================================
// StorageError — Comprehensive error type for storage operations
// =============================================================================

/// Error type for all storage backend operations.
///
/// This enum covers the full spectrum of failure modes that storage backends
/// may encounter, from simple not-found errors to complex network failures
/// and quota violations. Each variant carries sufficient context for
/// operator diagnostics and automated retry decisions.
///
/// # Error Classification
///
/// | Category          | Variants                          | Retryable? |
/// |-------------------|-----------------------------------|------------|
/// | Client errors     | NotFound, AlreadyExists, PermissionDenied | No    |
/// | Resource limits   | QuotaExceeded                     | No         |
/// | Network errors    | NetworkError                      | Yes*       |
/// | Internal errors   | InternalError, IoError            | Yes*       |
/// | Configuration     | ConfigurationError                | No         |
/// | Capability        | NotSupported                      | No         |
///
/// *Retry only with exponential backoff; caller MUST implement circuit breaker.
#[derive(Error, Debug)]
pub enum StorageError {
    /// The requested key does not exist in the storage backend.
    ///
    /// Returned by [`StorageBackend::get()`] when the key is absent.
    /// Callers SHOULD check existence via [`StorageBackend::exists()`]
    /// before attempting retrieval if 404-like semantics are expected.
    #[error("storage key not found: {0}")]
    NotFound(String),

    /// An object with the same key already exists in the storage backend.
    ///
    /// Returned by [`StorageBackend::put()`] when the backend enforces
    /// uniqueness constraints and the key is already present.
    /// Callers MAY choose to overwrite by deleting first, or abort.
    #[error("storage key already exists: {0}")]
    AlreadyExists(String),

    /// The operation was denied due to insufficient permissions.
    ///
    /// Indicates an authentication or authorization failure at the
    /// storage provider level. The backing service account may lack
    /// the required IAM role / ACL entry / bucket policy permission.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The operation would exceed the configured storage quota.
    ///
    /// Returned when the backend's capacity limit (total bytes, object count,
    /// or per-user allocation) would be violated by this operation.
    /// Quota limits are typically enforced at the bucket/container level.
    #[error("storage quota exceeded: {0}")]
    QuotaExceeded(String),

    /// A network-level error occurred during communication with the backend.
    ///
    /// Wraps transient connectivity issues (DNS resolution failure, TCP reset,
    /// TLS handshake timeout, HTTP 502/503/504 responses). The wrapped string
    /// SHOULD contain the underlying error message for debugging purposes.
    ///
    /// # Retry Guidance
    /// This error is potentially retryable. Implementers of retry logic MUST:
    /// - Use exponential backoff with jitter.
    /// - Set a maximum retry count (recommended: 3-5).
    /// - Implement circuit breaker after consecutive failures.
    #[error("network error: {0}")]
    NetworkError(String),

    /// An internal error occurred within the storage backend implementation.
    ///
    /// This is a catch-all for unexpected errors that don't fit other variants.
    /// Production code SHOULD avoid this variant; specific errors are preferred
    /// for proper error handling by callers. The wrapped string MUST contain
    /// actionable diagnostic information.
    #[error("internal storage error: {0}")]
    InternalError(String),

    /// The requested operation is not supported by this backend implementation.
    ///
    /// Returned when a caller attempts an operation that the concrete backend
    /// does not implement (e.g., listing objects on a key-value-only store,
    /// or setting content-type on a backend that ignores metadata).
    /// The wrapped string identifies the unsupported capability.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// An I/O error occurred during filesystem or stream operations.
    ///
    /// Wraps standard library I/O errors from file read/write operations,
    /// temporary file creation, or stream buffering. This variant preserves
    /// the original [`std::io::Error`] for accurate source-level diagnosis.
    #[error("I/O error: {0}")]
    IoError(#[source] io::Error),

    /// A configuration error prevented the operation from proceeding.
    ///
    /// Indicates invalid or missing configuration parameters (e.g.,
    /// missing endpoint URL, invalid credentials format, unrecognized
    /// region name). Configuration errors are NOT retryable — they
    /// require administrative intervention to fix.
    #[error("configuration error: {0}")]
    ConfigurationError(String),
}

impl From<io::Error> for StorageError {
    /// Convert a [`std::io::Error`] into [`StorageError::IoError`].
    ///
    /// This conversion enables the `?` operator on any function returning
    /// `Result<_, StorageError>` where the fallible operation produces
    /// a standard I/O error (file open, read, write, seek, etc.)
    fn from(err: io::Error) -> Self {
        StorageError::IoError(err)
    }
}

// =============================================================================
// StorageInfo — Metadata returned by successful put operations
// =============================================================================

/// Metadata returned by [`StorageBackend::put()`] after successful storage.
///
/// This structure captures all relevant information about the stored object
/// that may be needed by downstream processing: identity, size, type,
/// timestamping, and integrity verification token.
///
/// # Field Semantics
///
/// | Field         | Source                              | Guarantees               |
/// |---------------|-------------------------------------|--------------------------|
/// | `key`         | Caller-provided (echoed back)       | Exact match to input     |
/// | `size`        | Computed from `data.len()`          | Always present           |
/// | `content_type`| Caller-provided or backend-detected | May be None              |
/// | `created_at`  | Backend-generated timestamp         | May be None (best-effort)|
/// | `etag`        | Backend-computed integrity token    | May be None              |
///
/// # ETag Usage
/// When present, the `etag` field enables conditional operations:
/// - If-Match / If-None-Match headers for optimistic concurrency control.
/// - Change detection for cache invalidation strategies.
/// - Integrity verification against the stored data.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageInfo {
    /// Unique identifier of the stored object (same as the `key` parameter).
    ///
    /// Echoed back from the input to enable chaining patterns where the
    /// caller passes the returned `StorageInfo` directly to notification
    /// or indexing systems without retaining the original key separately.
    pub key: String,

    /// Size of the stored data in bytes.
    ///
    /// Computed as `data.len()` at the time of storage. For backends that
    /// apply compression or encoding, this value represents the logical
    /// (uncompressed) size unless otherwise documented by the implementation.
    pub size: u64,

    /// MIME content type of the stored data.
    ///
    /// Provided by the caller via configuration or inferred by the backend
    /// from file extension / magic bytes. `None` if unknown or not applicable.
    pub content_type: Option<String>,

    /// Timestamp when the object was created (UTC).
    ///
    /// Generated by the storage backend. `None` if the backend does not
    /// support timestamps or the clock is unsynchronized. Consumers SHOULD
    /// treat `None` as "timestamp unavailable" rather than assuming current time.
    pub created_at: Option<DateTime<Utc>>,

    /// Entity tag for change detection and integrity verification.
    ///
    /// Computed by the backend (typically MD5, SHA-256 hash, or opaque revision
    /// identifier). Format is backend-specific but SHOULD be usable in
    /// conditional request headers. `None` if the backend does not support etags.
    pub etag: Option<String>,
}

impl StorageInfo {
    /// Create a new [`StorageInfo`] with required fields only.
    ///
    /// Optional fields (`content_type`, `created_at`, `etag`) default to `None`.
    /// Use the builder pattern or direct field assignment for optional fields.
    ///
    /// # Arguments
    /// * `key` - Object identifier matching the storage key.
    /// * `size` - Size of the stored data in bytes.
    ///
    /// # Example
    /// ```ignore
    /// let info = StorageInfo::new("documents/report.pdf", 1024);
    /// assert_eq!(info.size, 1024);
    /// assert!(info.content_type.is_none());
    /// ```
    pub fn new(key: impl Into<String>, size: u64) -> Self {
        Self {
            key: key.into(),
            size,
            content_type: None,
            created_at: None,
            etag: None,
        }
    }

    /// Check whether this storage info includes an integrity verification token.
    ///
    /// Returns `true` if the `etag` field is `Some(...)` and non-empty.
    /// Used by callers to determine whether conditional operations are safe.
    pub fn has_etag(&self) -> bool {
        self.etag.as_ref().map_or(false, |e| !e.is_empty())
    }

    /// Check whether this storage info includes a creation timestamp.
    ///
    /// Returns `true` if the `created_at` field is `Some(...)`.
    /// Used by callers to determine whether temporal ordering is available.
    pub fn has_timestamp(&self) -> bool {
        self.created_at.is_some()
    }
}

// =============================================================================
// StorageBackend — Core trait for pluggable storage implementations
// =============================================================================

/// Abstracts the storage layer for object/blob storage operations.
///
/// [`StorageBackend`] is the central abstraction enabling Misogi to store and
/// retrieve file data using arbitrary storage providers (local disk, Amazon S3,
/// Azure Blob Storage, Google Cloud Storage, MinIO, etc.) without coupling
/// the business logic to any specific provider's SDK or API surface.
///
/// # Architecture Position
///
/// This trait occupies **Pillar 2** of the Misogi Pluggable Architecture:
///
/// - **Pillar 1**: TransferDriver (network transport layer)
/// - **Pillar 2**: StorageBackend (object/blob storage layer) ← THIS TRAIT
/// - **Pillar 3**: CDRStrategy (content processing layer)
///
/// All three pillars connect through the Plugin Registry for runtime composition.
///
/// # Concurrency Model
///
/// Implementations MUST support concurrent invocation of multiple methods
/// from different tokio tasks. Specifically:
///
/// - **Concurrent reads**: Multiple `get()` calls for different keys MAY execute
///   simultaneously. Same-key concurrent reads are safe (return same data).
/// - **Concurrent writes**: Multiple `put()` calls for different keys MAY execute
///   simultaneously. Same-key concurrent writes have undefined behavior unless
///   documented otherwise by the implementation.
/// - **Read-write overlap**: `get(key)` and `delete(key)` for the same key MAY
///   race. Implementations SHOULD document their consistency guarantees
///   (eventual consistency vs. strong consistency).
///
/// # Key Semantics
///
/// Keys are UTF-8 strings interpreted according to backend-specific rules:
///
/// - **S3-style**: Keys are object identifiers within a bucket. Slash (`/`)
///   characters create a virtual hierarchy but do not imply actual directories.
/// - **Local filesystem**: Keys are relative paths within a base directory.
///   Path traversal sequences (`../`, absolute paths) MUST be rejected.
/// - **Azure Blob**: Keys are blob names within a container.
///
/// Implementations MUST validate keys for safety-relevant constraints
/// (length limits, forbidden characters, path traversal) before forwarding
/// to the underlying provider.
///
/// # Error Handling Strategy
///
/// All methods return [`Result<_, StorageError>`]. Callers SHOULD handle
/// errors based on variant classification:
///
/// - **Immediate failure (no retry)**: [`NotFound`](StorageError::NotFound),
///   [`AlreadyExists`](StorageError::AlreadyExists),
///   [`PermissionDenied`](StorageError::PermissionDenied),
///   [`QuotaExceeded`](StorageError::QuotaExceeded),
///   [`ConfigurationError`](StorageError::ConfigurationError),
///   [`NotSupported`](StorageError::NotSupported).
/// - **Retry with backoff**: [`NetworkError`](StorageError::NetworkError),
///   [`InternalError`](StorageError::InternalError),
///   [`IoError`](StorageError::IoError).
///
/// # Implementation Checklist
///
/// Concrete implementations MUST:
/// 1. Validate all inputs before initiating I/O operations.
/// 2. Enforce key length limits (recommendation: ≤ 1024 UTF-8 bytes).
/// 3. Reject path traversal attempts in filesystem-based backends.
/// 4. Implement connection pooling for remote backends.
/// 5. Provide meaningful error messages with context (key name, operation).
/// 6. Support cancellation via async drop / shutdown signals.
/// 7. Document consistency model (strong vs. eventual).
/// 8. Document size limits (per-object max, total capacity).
/// 9. Implement `health_check()` for monitoring integration.
/// 10. Return accurate `StorageInfo` metadata on successful `put()`.
#[async_trait]
pub trait StorageBackend: Send + Sync + Debug {
    /// Store data under the given key.
    ///
    /// Creates or overwrites an object identified by `key` with the provided
    /// `data`. On success, returns [`StorageInfo`] containing metadata about
    /// the stored object.
    ///
    /// # Arguments
    /// * `key` - Unique identifier for the object. Interpretation depends on
    ///   the backend (object name, relative path, blob name). MUST be valid UTF-8.
    /// * `data` - Binary content to store. Ownership is transferred to allow
    ///   zero-copy optimization in backends that support it (e.g., S3 PutObject
    ///   can take ownership of the Bytes buffer).
    ///
    /// # Returns
    /// [`StorageInfo`] with metadata about the stored object on success.
    ///
    /// # Errors
    /// - [`StorageError::AlreadyExists`] if the backend enforces uniqueness
    ///   and the key already exists (implementation-dependent behavior).
    /// - [`StorageError::QuotaExceeded`] if storing would exceed capacity limits.
    /// - [`StorageError::PermissionDenied`] if the credentials lack write access.
    /// - [`StorageError::NetworkError`] on transient connectivity failures.
    /// - [`StorageError::IoError`] on local filesystem failures.
    /// - [`StorageError::ConfigurationError`] if the backend is misconfigured.
    ///
    /// # Idempotency
    /// Calling `put()` twice with the same key SHOULD result in the second
    /// call either overwriting silently or returning [`AlreadyExists`],
    /// depending on the implementation's conflict resolution policy.
    async fn put(&self, key: &str, data: Bytes) -> Result<StorageInfo, StorageError>;

    /// Retrieve data stored under the given key.
    ///
    /// Reads and returns the complete object content identified by `key`.
    /// For large objects, callers SHOULD consider streaming interfaces
    /// if the backend provides them (not covered by this base trait).
    ///
    /// # Arguments
    /// * `key` - Identifier of the object to retrieve.
    ///
    /// # Returns
    /// The object's binary content as [`Bytes`] on success.
    ///
    /// # Errors
    /// - [`StorageError::NotFound`] if no object exists under this key.
    /// - [`StorageError::PermissionDenied`] if the credentials lack read access.
    /// - [`StorageError::NetworkError`] on transient connectivity failures.
    /// - [`StorageError::IoError`] on local filesystem or buffer errors.
    ///
    /// # Performance Note
    /// This method loads the entire object into memory. For objects larger
    /// than available RAM, consider implementing a streaming extension trait.
    async fn get(&self, key: &str) -> Result<Bytes, StorageError>;

    /// Delete the object stored under the given key.
    ///
    /// Removes the object identified by `key` from the storage backend.
    /// After successful deletion, subsequent `get()` calls SHOULD return
    /// [`StorageError::NotFound`], and `exists()` SHOULD return `false`.
    ///
    /// # Arguments
    /// * `key` - Identifier of the object to delete.
    ///
    /// # Returns
    /// `Ok(())` on successful deletion (including idempotent delete of
    /// a non-existent key, depending on implementation).
    ///
    /// # Errors
    /// - [`StorageError::PermissionDenied`] if the credentials lack delete access.
    /// - [`StorageError::NetworkError`] on transient connectivity failures.
    /// - [`StorageError::IoError`] on local filesystem errors.
    /// - [`StorageError::NotSupported`] if the backend does not support deletion.
    ///
    /// # Idempotency
    /// Deleting a non-existent key SHOULD succeed silently (return `Ok(())`)
    /// rather than returning an error. This matches S3 DeleteObject behavior
    /// and simplifies cleanup logic.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Check whether an object exists under the given key.
    ///
    /// Performs a lightweight existence check without retrieving the full
    /// object content. Implementations SHOULD use HEAD requests or equivalent
    /// metadata-only operations to minimize bandwidth consumption.
    ///
    /// # Arguments
    /// * `key` - Identifier to check for existence.
    ///
    /// # Returns
    /// `true` if an object exists under this key, `false` otherwise.
    ///
    /// # Errors
    /// - [`StorageError::PermissionDenied`] if existence cannot be determined
    ///   due to access restrictions.
    /// - [`StorageError::NetworkError`] on connectivity failures.
    ///
    /// # Consistency Note
    /// In eventually-consistent backends (e.g., S3 standard after write),
    /// `exists()` may return stale results. Strongly consistent backends
    /// (S3 strong consistency, local filesystem) provide immediate visibility.
    async fn exists(&self, key: &str) -> Result<bool, StorageError>;

    /// Perform a lightweight health check against the storage backend.
    ///
    /// Verifies that the backend is reachable and operational without
    /// performing any destructive operations. This method SHOULD be fast
    /// (target <500ms) and suitable for frequent invocation by monitoring
    /// systems (every 10-60 seconds recommended).
    ///
    /// Typical implementation strategies:
    /// - **S3/Azure/GCS**: HeadBucket / GetAccountInfo / minimal API call.
    /// - **Local filesystem**: Check base directory accessibility (stat).
    /// - **Custom**: Ping endpoint, check connection pool status.
    ///
    /// # Returns
    /// `Ok(())` if the backend is healthy and operational.
    ///
    /// # Errors
    /// - [`StorageError::NetworkError`] if the backend is unreachable.
    /// - [`StorageError::PermissionDenied`] if credentials are invalid/expired.
    /// - [`StorageError::ConfigurationError`] if the backend is misconfigured.
    /// - [`StorageError::InternalError`] for unexpected internal failures.
    ///
    /// # Monitoring Integration
    /// This method is designed for integration with:
    /// - Kubernetes liveness/readiness probes.
    /// - Prometheus / Grafana dashboards.
    /// - PagerDuty / OpsGenie alerting pipelines.
    /// - Enterprise monitoring systems (Zabbix, Nagios, Datadog).
    async fn health_check(&self) -> Result<(), StorageError>;

    /// Return the identifier string for this backend implementation type.
    ///
    /// Used for logging, audit trails, dynamic dispatch identification,
    /// and plugin registry lookups. The returned value SHOULD be unique
    /// across all registered storage backends within a single runtime.
    ///
    /// # Examples
    /// - `"local-fs"` — Local filesystem backend.
    /// - `"s3"` — Amazon S3 (or S3-compatible like MinIO).
    /// - `"azure-blob"` — Azure Blob Storage.
    /// - `"gcs"` — Google Cloud Storage.
    /// - `"memory"` — In-memory backend for testing.
    ///
    /// # Implementation Note
    /// This method is synchronous (no async overhead) since it returns
    /// static metadata about the implementation itself, not about its
    /// current state.
    fn backend_type(&self) -> &'static str;
}

#[cfg(test)]
mod tests;
