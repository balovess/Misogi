//! Core [`PullDriver`] struct definition and inherent methods.
//!
/// This module contains the main driver data structure, constructors,
/// receiver-side poll/pull/ack API, and internal buffer management helpers.
///
/// # Concurrency Model
///
/// ```text
///  Thread A (Sender)          Thread B (Receiver)         Thread C (Receiver)
///  ┌──────────────┐           ┌──────────────┐           ┌──────────────┐
///  │ send_chunk() │           │list_pending()│           │ pull_file()  │
///  │ write lock   │───write──►│ read lock    │───read───►│ write lock   │
///  └──────────────┘           └──────────────┘           └──────────────┘
/// ```
///
/// - **Sender** acquires write lock briefly during `send_chunk()` / `send_complete()`.
/// - **Receiver** holds read lock during `list_pending_files()` (non-blocking for sender).
/// - **Receiver** acquires write lock during `pull_file()` / `ack_file()` (brief).
///
/// The [`TransferDriver`](crate::traits::TransferDriver) trait implementation
/// resides in [`driver_impl`](super::driver_impl) to respect the 500-line limit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::error::{MisogiError, Result};
use super::types::{
    PullConfig, PullBufferEntry, PullEntryStatus,
};

// =============================================================================
// PullDriver — Main Driver Implementation
// =============================================================================

/// Pull-mode transfer driver implementing [`TransferDriver`](crate::traits::TransferDriver) for Mode B operation.
///
/// This driver decouples sender and receiver timing: the sender deposits data
/// into a shared buffer zone, and the receiver pulls data on its own schedule.
/// This pattern is essential for air-gapped, high-latency, or regulated environments
/// where push-based transfers are prohibited by network policy.
///
/// # Buffer Management
///
/// - Capacity enforcement: total buffered bytes <= `buffer_max_size_mb * 1024 * 1024`.
/// - Retention eviction: entries older than `retention_duration` are cleaned on each write.
/// - Disk persistence: optional filesystem backing via `buffer_path` in [`PullConfig`].
#[derive(Debug)]
pub struct PullDriver {
    /// Driver configuration (immutable after init).
    pub(crate) config: PullConfig,

    /// Shared buffer containing all pending/in-flight entries.
    /// Protected by `RwLock` for concurrent read / exclusive write access.
    pub(crate) buffer: Arc<RwLock<HashMap<String, PullBufferEntry>>>,

    /// Monotonically increasing health check sequence counter.
    pub(crate) check_sequence: Arc<std::sync::atomic::AtomicU64>,

    /// Whether the driver has been initialized.
    pub(crate) initialized: Arc<std::sync::atomic::AtomicBool>,

    /// Running tally of total bytes currently held in the buffer.
    /// Maintained alongside the HashMap for O(1) capacity checks.
    pub(crate) buffer_bytes: Arc<std::sync::atomic::AtomicU64>,

    /// Count of entries ever inserted (monotonic, for diagnostics).
    pub(crate) insert_count: Arc<std::sync::atomic::AtomicU64>,

    /// Count of entries ever acknowledged (monotonic, for diagnostics).
    pub(crate) ack_count: Arc<std::sync::atomic::AtomicU64>,
}

impl PullDriver {
    /// Construct a new [`PullDriver`] with default configuration.
    ///
    /// The driver is not operational until [`TransferDriver::init`] is called.
    pub fn new() -> Self {
        Self::with_config(PullConfig::default())
    }

    /// Construct a new [`PullDriver`] with explicit configuration.
    ///
    /// # Arguments
    /// * `config` — Pull-mode operational parameters.
    pub fn with_config(config: PullConfig) -> Self {
        Self {
            config,
            buffer: Arc::new(RwLock::new(HashMap::new())),
            check_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            buffer_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            insert_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ack_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    // ---------------------------------------------------------------------
    // Receiver-Side API (Poll / Pull / Ack Cycle)
    // ---------------------------------------------------------------------

    /// List all buffer entries that are available for pulling.
    ///
    /// Returns entries whose status is [`PullEntryStatus::Pending`]. The receiver
    /// calls this method at each poll cycle to discover new data from the sender.
    ///
    /// # Returns
    /// A vector of [`PullBufferEntry`] clones (metadata + data) ready for retrieval.
    /// Empty vector means no pending work.
    ///
    /// # Errors
    /// Never errors; returns empty vec on uninitialized state.
    pub async fn list_pending_files(&self) -> Result<Vec<PullBufferEntry>> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        let buf = self.buffer.read().await;
        let pending: Vec<PullBufferEntry> = buf
            .values()
            .filter(|e| e.status == PullEntryStatus::Pending)
            .cloned()
            .collect();

        tracing::debug!(
            pending_count = pending.len(),
            "PullDriver: listed pending files"
        );

        Ok(pending)
    }

    /// Pull (retrieve) a specific buffer entry by its ID, marking it in-flight.
    ///
    /// Transitions the entry status from `Pending` to `Pulling`, preventing
    /// concurrent pull attempts for the same entry. The caller receives a clone
    /// of the full entry including payload data.
    ///
    /// # Arguments
    /// * `entry_id` — Unique identifier returned by [`list_pending_files()`](Self::list_pending_files).
    ///
    /// # Returns
    /// The [`PullBufferEntry`] with full payload data.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if entry_id does not exist.
    /// - [`MisogiError::Protocol`] if entry is not in `Pending` state (already pulled).
    pub async fn pull_file(&self, entry_id: &str) -> Result<PullBufferEntry> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "PullDriver not initialized".to_string(),
            ));
        }

        let mut buf = self.buffer.write().await;

        let entry = buf.get_mut(entry_id).ok_or_else(|| {
            MisogiError::NotFound(format!("Entry '{}' not found in pull buffer", entry_id))
        })?;

        if entry.status != PullEntryStatus::Pending {
            return Err(MisogiError::Protocol(format!(
                "Entry '{}' is not Pending (current: {:?})",
                entry_id, entry.status
            )));
        }

        entry.status = PullEntryStatus::Pulling;
        entry.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let cloned = entry.clone();

        tracing::info!(
            entry_id = %entry_id,
            file_id = %cloned.file_id,
            chunk_index = cloned.chunk_index,
            size = cloned.payload_size(),
            "PullDriver: file pulled (marked in-flight)"
        );

        Ok(cloned)
    }

    /// Acknowledge receipt of a pulled file, marking it for eventual eviction.
    ///
    /// Transitions the entry status from `Pulling` to `Acknowledged`. The entry
    /// remains in the buffer until the next retention cleanup cycle removes it.
    ///
    /// # Arguments
    /// * `entry_id` — Unique identifier of the entry being acknowledged.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if entry_id does not exist.
    /// - [`MisogiError::Protocol`] if entry is not in `Pulling` state.
    pub async fn ack_file(&self, entry_id: &str) -> Result<()> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "PullDriver not initialized".to_string(),
            ));
        }

        let mut buf = self.buffer.write().await;

        let entry = buf.get_mut(entry_id).ok_or_else(|| {
            MisogiError::NotFound(format!(
                "Entry '{}' not found in pull buffer",
                entry_id
            ))
        })?;

        if entry.status != PullEntryStatus::Pulling {
            return Err(MisogiError::Protocol(format!(
                "Entry '{}' is not Pulling (current: {:?})",
                entry_id, entry.status
            )));
        }

        let old_status = entry.status.clone();
        entry.status = PullEntryStatus::Acknowledged;
        entry.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Update atomic counters
        self.ack_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.buffer_bytes
            .fetch_sub(entry.payload_size() as u64, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            entry_id = %entry_id,
            file_id = %entry.file_id,
            previous_status = ?old_status,
            "PullDriver: file acknowledged"
        );

        Ok(())
    }

    // ---------------------------------------------------------------------
    // Internal Helpers
    // ---------------------------------------------------------------------

    /// Evict expired and acknowledged entries from the buffer.
    ///
    /// Called internally before each write to prevent unbounded growth.
    /// Removes entries where:
    /// - Status is `Acknowledged` (already confirmed received).
    /// - Age exceeds `retention_duration` (stale/unpicked entries).
    ///
    /// Returns the number of entries evicted.
    pub(crate) async fn cleanup_expired(&self) -> usize {
        let mut buf = self.buffer.write().await;
        let before = buf.len();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let retention_ms = self.config.retention_duration.as_millis() as u64;

        buf.retain(|_id, entry| {
            let should_keep = match entry.status {
                PullEntryStatus::Acknowledged => false,
                _ => now_ms.saturating_sub(entry.created_at) <= retention_ms,
            };
            if !should_keep {
                self.buffer_bytes
                    .fetch_sub(entry.payload_size() as u64, std::sync::atomic::Ordering::SeqCst);
            }
            should_keep
        });

        let evicted = before.saturating_sub(buf.len());
        if evicted > 0 {
            tracing::debug!(evicted, "PullDriver: expired entries cleaned up");
        }
        evicted
    }

    /// Calculate current total buffered bytes across all non-acknowledged entries.
    pub(crate) async fn current_buffer_bytes(&self) -> u64 {
        let buf = self.buffer.read().await;
        buf.values()
            .filter(|e| e.status != PullEntryStatus::Acknowledged)
            .map(|e| e.payload_size() as u64)
            .sum()
    }
}
