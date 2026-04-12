//! Configuration types and buffer entry definitions for the pull driver.
//!
//! This module defines all data structures that configure and represent
//! the state of individual entries within the pull buffer, including
//! validation logic and serde serialization support.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{MisogiError, Result};
use crate::traits::TransferDriverConfig;

// =============================================================================
// Default Configuration Constants
// =============================================================================

/// Default interval between receiver poll cycles.
fn default_poll_interval() -> Duration {
    Duration::from_secs(5)
}

/// Default maximum buffer capacity in megabytes before rejecting new entries.
fn default_buffer_max_size_mb() -> u64 {
    512
}

/// Default duration after which unacknowledged buffer entries are evicted.
fn default_retention_duration() -> Duration {
    Duration::from_secs(3600) // 1 hour
}

/// Default filesystem path for optional disk-backed buffer persistence.
fn default_buffer_path() -> PathBuf {
    PathBuf::from("./misogi_pull_buffer")
}

// =============================================================================
// A. PullConfig — Driver Configuration
// =============================================================================

/// Configuration parameters for [`PullDriver`](super::driver::PullDriver) (Mode B: Poll-Based Pull).
///
/// All fields have sensible defaults suitable for typical enterprise deployments.
/// Serializable to/from TOML/JSON for external configuration management.
///
/// # Validation Rules (enforced by [`TransferDriverConfig::validate`])
///
/// | Field                | Minimum   | Maximum     | Default       |
/// |----------------------|-----------|-------------|---------------|
/// | `poll_interval`      | 100 ms    | —           | 5 s           |
/// | `buffer_max_size_mb` | 0         | 1,048,576   | 512 MB        |
/// | `retention_duration` | 1 s       | —           | 3,600 s (1 h) |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullConfig {
    /// Interval between consecutive receiver poll cycles.
    ///
    /// Shorter intervals reduce transfer latency but increase network overhead.
    /// Recommended: 1-10 seconds depending on link characteristics.
    #[serde(
        serialize_with = "serialize_duration_ms",
        deserialize_with = "deserialize_duration_ms"
    )]
    pub poll_interval: Duration,

    /// Maximum total buffer size in megabytes.
    ///
    /// When the aggregate size of unacknowledged entries exceeds this limit,
    /// `send_chunk()` rejects new data with [`MisogiError::Protocol`].
    /// Set to 0 for unlimited (not recommended in production).
    #[serde(default = "default_buffer_max_size_mb")]
    pub buffer_max_size_mb: u64,

    /// Duration after which unacknowledged entries are automatically evicted.
    ///
    /// This prevents stale entries from accumulating when the receiver is offline
    /// or has stopped polling. Evicted entries are logged but not retried.
    #[serde(
        serialize_with = "serialize_duration_ms",
        deserialize_with = "deserialize_duration_ms"
    )]
    pub retention_duration: Duration,

    /// Optional filesystem path for disk-backed buffer persistence.
    ///
    /// When set, buffer entries are also written to this directory as files,
    /// enabling survival across process restarts. When empty (default),
    /// the buffer operates purely in-memory.
    #[serde(default = "default_buffer_path")]
    pub buffer_path: PathBuf,
}

impl Default for PullConfig {
    fn default() -> Self {
        Self {
            poll_interval: default_poll_interval(),
            buffer_max_size_mb: default_buffer_max_size_mb(),
            retention_duration: default_retention_duration(),
            buffer_path: default_buffer_path(),
        }
    }
}

/// Serialize a [`Duration`] as milliseconds (u64) for serde transport.
fn serialize_duration_ms<S>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_u64(d.as_millis() as u64)
}

/// Deserialize a [`Duration`] from milliseconds (u64) via serde transport.
fn deserialize_duration_ms<'de, D>(d: D) -> std::result::Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ms = u64::deserialize(d)?;
    Ok(Duration::from_millis(ms))
}

#[async_trait]
impl TransferDriverConfig for PullConfig {
    /// Validate that configuration values are within acceptable operational bounds.
    ///
    /// # Validation Rules
    /// - `poll_interval` must be >= 100ms (sub-100ms polling is abusive).
    /// - `buffer_max_size_mb` must be <= 1048576 (1 TB upper sanity bound).
    /// - `retention_duration` must be >= 1 second.
    fn validate(&self) -> Result<()> {
        if self.poll_interval < Duration::from_millis(100) {
            return Err(MisogiError::Configuration(format!(
                "poll_interval must be >= 100ms, got {:?}",
                self.poll_interval
            )));
        }
        if self.buffer_max_size_mb > 1024 * 1024 {
            return Err(MisogiError::Configuration(format!(
                "buffer_max_size_mb must be <= 1048576 (1 TB), got {}",
                self.buffer_max_size_mb
            )));
        }
        if self.retention_duration < Duration::from_secs(1) {
            return Err(MisogiError::Configuration(format!(
                "retention_duration must be >= 1s, got {:?}",
                self.retention_duration
            )));
        }
        Ok(())
    }
}

// =============================================================================
// B. PullBufferEntry — Single Buffer Entry
// =============================================================================

/// Lifecycle state of a [`PullBufferEntry`] within the pull buffer.
///
/// Entries progress monotonically through these states:
/// `Pending` → `Pulling` → `Acknowledged`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PullEntryStatus {
    /// Entry has been written by the sender and awaits pickup by the receiver.
    Pending,

    /// Entry is currently being pulled by the receiver (in-flight transfer).
    Pulling,

    /// Entry has been acknowledged by the receiver and is eligible for eviction.
    Acknowledged,
}

impl Default for PullEntryStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// A single entry stored in the pull buffer awaiting receiver pickup.
///
/// Each entry represents one complete file (or chunk) deposited by the sender.
/// Entries transition through states: `Pending` → `Pulling` → `Acknowledged`.
///
/// # Memory Footprint
///
/// Entry payload (`data`) is held as [`Bytes`] (reference-counted bytes).
/// For large files, consider using `buffer_path` disk backing to avoid
/// excessive memory consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullBufferEntry {
    /// Unique identifier for this buffer entry (UUID v4).
    pub entry_id: String,

    /// File identifier this entry belongs to (correlates chunks of the same file).
    pub file_id: String,

    /// Zero-based chunk index within the file (for multi-chunk transfers).
    pub chunk_index: u32,

    /// Raw payload data of this chunk/file.
    ///
    /// Serialized as a byte array for JSON transport; deserialized back into
    /// `Bytes` for zero-copy compatibility with the rest of the pipeline.
    #[serde(with = "bytes_serde")]
    pub data: Bytes,

    /// MD5 hash of `data` computed at insertion time for integrity verification.
    pub data_md5: String,

    /// Current lifecycle status of this entry.
    #[serde(default)]
    pub status: PullEntryStatus,

    /// Wall-clock timestamp when this entry was created (inserted into buffer).
    /// Represented as milliseconds since UNIX epoch for portability.
    pub created_at: u64,

    /// Wall-clock timestamp when this entry was last modified (status change).
    /// Represented as milliseconds since UNIX epoch for portability.
    pub updated_at: u64,

    /// Total size of the original file in bytes (0 if unknown).
    pub total_file_size: u64,
}

// =============================================================================
// C. Custom Serde Module for Bytes Serialization
// =============================================================================

/// Custom serde module for serializing [`bytes::Bytes`] as a byte array.
///
/// The `bytes::Bytes` type does not implement `Serialize`/`Deserialize` by default.
/// This module bridges the gap by converting to/from `Vec<u8>` during (de)serialization,
/// preserving the ergonomic use of `Bytes` throughout the codebase while enabling
/// structured logging and persistence via serde-compatible formats.
mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `Bytes` as a byte vector.
    pub fn serialize<S>(data: &Bytes, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(data.as_ref())
    }

    /// Deserialize `Bytes` from a byte vector.
    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(Bytes::from(vec))
    }
}

impl PullBufferEntry {
    /// Compute the age of this entry since creation, in milliseconds.
    ///
    /// Returns elapsed time from `created_at` to now. Uses saturating arithmetic
    /// so clock skew cannot produce negative values.
    pub fn age_ms(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(self.created_at)
    }

    /// Returns true if this entry has exceeded the given retention duration.
    ///
    /// Used by the cleanup cycle to determine whether an entry should be evicted.
    pub fn is_expired(&self, retention: Duration) -> bool {
        self.age_ms() > retention.as_millis() as u64
    }

    /// Returns the size of this entry's payload in bytes.
    pub fn payload_size(&self) -> usize {
        self.data.len()
    }
}
