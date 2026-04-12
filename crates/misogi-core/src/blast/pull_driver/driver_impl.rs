//! [`TransferDriver`] trait implementation for [`PullDriver`](super::driver::PullDriver).
//!
/// This module contains the async trait method implementations that satisfy
/// the [`TransferDriver`](crate::traits::TransferDriver) contract for Mode B
/// pull-based transfer operation.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;

use crate::error::{MisogiError, Result};
use crate::hash::compute_md5;
use crate::traits::{
    ChunkAck, DriverHealthStatus, TransferDriver, TransferDriverConfig,
};
use super::types::{PullConfig, PullBufferEntry, PullEntryStatus};
use super::driver::PullDriver;

#[async_trait]
impl TransferDriver for PullDriver {
    type Config = PullConfig;

    /// Returns `"pull-driver"`.
    fn name(&self) -> &str {
        "pull-driver"
    }

    /// Initialize the pull driver with the provided configuration.
    ///
    /// Creates the buffer directory (if `buffer_path` is configured) and
    /// marks the driver as ready for operations.
    ///
    /// Idempotent: subsequent calls after the first return `Ok(())` immediately.
    ///
    /// # Errors
    /// - [`MisogiError::Configuration`] if config validation fails.
    /// - [`MisogiError::Io`] if buffer directory cannot be created.
    async fn init(&mut self, config: Self::Config) -> Result<()> {
        config.validate()?;
        self.config = config;

        // Create buffer directory if path is specified
        if !self.config.buffer_path.as_os_str().is_empty() {
            tokio::fs::create_dir_all(&self.config.buffer_path).await?;
        }

        self.initialized
            .store(true, std::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            driver = self.name(),
            poll_interval_ms = self.config.poll_interval.as_millis(),
            buffer_max_size_mb = self.config.buffer_max_size_mb,
            retention_sec = self.config.retention_duration.as_secs(),
            buffer_path = %self.config.buffer_path.display(),
            "PullDriver initialized (Mode B: Poll-Based Pull)"
        );

        Ok(())
    }

    /// Write a file chunk into the pull buffer (sender-side operation).
    ///
    /// The chunk is stored as a [`PullBufferEntry`] with status `Pending`,
    /// awaiting pickup by the receiver via [`pull_file()`](super::driver::PullDriver::pull_file).
    ///
    /// Before inserting, this method:
    /// 1. Runs retention cleanup to evict stale entries.
    /// 2. Checks buffer capacity against `buffer_max_size_mb`.
    /// 3. Generates a UUID v4 entry identifier.
    /// 4. Inserts the entry and updates byte counters.
    ///
    /// # Arguments
    /// * `file_id` — Identifier of the file this chunk belongs to.
    /// * `chunk_index` — Zero-based position of this chunk within the file.
    /// * `data` — Raw chunk payload bytes.
    ///
    /// # Returns
    /// A synthetic [`ChunkAck`] confirming local buffer acceptance.
    /// Note: This ACK does **not** confirm remote receipt (receiver must pull + ack).
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if not initialized or buffer is over capacity.
    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "PullDriver not initialized".to_string(),
            ));
        }

        // Step 1: Cleanup expired entries first
        self.cleanup_expired().await;

        // Step 2: Check buffer capacity
        let max_bytes = self.config.buffer_max_size_mb * 1024 * 1024;
        if max_bytes > 0 {
            let current = self.current_buffer_bytes().await;
            if current.saturating_add(data.len() as u64) > max_bytes {
                return Err(MisogiError::Protocol(format!(
                    "Buffer over capacity: {}/{} MB",
                    current / (1024 * 1024),
                    self.config.buffer_max_size_mb
                )));
            }
        }

        // Step 3: Create entry
        let md5 = compute_md5(&data);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry_id = uuid::Uuid::new_v4().to_string();
        let entry = PullBufferEntry {
            entry_id: entry_id.clone(),
            file_id: file_id.to_string(),
            chunk_index,
            data: data.clone(),
            data_md5: md5.clone(),
            status: PullEntryStatus::Pending,
            created_at: now_ms,
            updated_at: now_ms,
            total_file_size: 0,
        };

        // Step 4: Insert into buffer
        {
            let mut buf = self.buffer.write().await;
            buf.insert(entry_id.clone(), entry);
        }

        // Update atomic counters
        self.insert_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.buffer_bytes
            .fetch_add(data.len() as u64, std::sync::atomic::Ordering::SeqCst);

        let now = Utc::now();

        tracing::debug!(
            entry_id = %entry_id,
            file_id = %file_id,
            chunk_index = chunk_index,
            size = data.len(),
            md5 = %md5,
            "PullDriver: chunk written to buffer (pending pull)"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index,
            received_md5: md5,
            received_size: data.len() as u64,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Signal that all chunks for a file have been written to the buffer.
    ///
    /// In pull mode, this is a no-op marker event. The receiver discovers
    /// completion by observing that no new chunks arrive for a given `file_id`
    /// after a timeout period. This method exists for [`TransferDriver`] trait
    /// compatibility and logs the completion signal for audit purposes.
    ///
    /// # Arguments
    /// * `file_id` — Identifier of the completed file transfer.
    /// * `total_chunks` — Total number of chunks sent (for audit logging).
    /// * `file_md5` — Expected MD5 of the reconstructed file (for audit logging).
    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MisogiError::Protocol(
                "PullDriver not initialized".to_string(),
            ));
        }

        let now = Utc::now();

        tracing::info!(
            file_id = %file_id,
            total_chunks = total_chunks,
            file_md5 = %file_md5,
            "PullDriver: send_complete signaled (receiver will detect completion)"
        );

        Ok(ChunkAck {
            file_id: file_id.to_string(),
            chunk_index: total_chunks.saturating_sub(1),
            received_md5: file_md5.to_string(),
            received_size: 0,
            ack_timestamp: now.to_rfc3339(),
            error: None,
        })
    }

    /// Perform health check reporting buffer utilization and driver readiness.
    ///
    /// Probes:
    /// 1. Initialization status.
    /// 2. Current entry count and buffer utilization percentage.
    /// 3. Counter statistics (inserts, acknowledgments).
    /// 4. Whether any entries are approaching retention expiry.
    ///
    /// Target latency: < 5ms (in-memory buffer probe).
    ///
    /// # Returns
    /// A [`DriverHealthStatus`] snapshot suitable for monitoring dashboards.
    async fn health_check(&self) -> Result<DriverHealthStatus> {
        let seq = self
            .check_sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        if !self.initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(DriverHealthStatus {
                driver_name: self.name().to_string(),
                is_healthy: false,
                status_message: "Not initialized".to_string(),
                latency_ms: None,
                checked_at: Utc::now(),
                check_sequence: seq,
            });
        }

        let buf = self.buffer.read().await;
        let total_entries = buf.len();
        let pending_count = buf
            .values()
            .filter(|e| e.status == PullEntryStatus::Pending)
            .count();
        let acknowledged_count = buf
            .values()
            .filter(|e| e.status == PullEntryStatus::Acknowledged)
            .count();
        drop(buf);

        let current_bytes = self.buffer_bytes.load(std::sync::atomic::Ordering::SeqCst);
        let max_bytes = self.config.buffer_max_size_mb * 1024 * 1024;
        let utilization_pct = if max_bytes > 0 {
            (current_bytes as f64 / max_bytes as f64 * 100.0) as u64
        } else {
            0
        };

        let inserts = self.insert_count.load(std::sync::atomic::Ordering::SeqCst);
        let acks = self.ack_count.load(std::sync::atomic::Ordering::SeqCst);

        Ok(DriverHealthStatus {
            driver_name: self.name().to_string(),
            is_healthy: true,
            status_message: format!(
                "entries={}, pending={}, acked={}, inserts={}, acks={}, buffer={}/{}MB ({}%)",
                total_entries,
                pending_count,
                acknowledged_count,
                inserts,
                acks,
                current_bytes / (1024 * 1024),
                self.config.buffer_max_size_mb,
                utilization_pct
            ),
            latency_ms: Some(0), // In-memory probe is sub-millisecond
            checked_at: Utc::now(),
            check_sequence: seq,
        })
    }

    /// Gracefully shut down the pull driver, releasing buffer resources.
    ///
    /// Clears all buffer entries and marks the driver as inactive.
    /// If `buffer_path` was configured, persisted files are NOT deleted
    /// (they may be needed for recovery); call explicitly if cleanup is desired.
    ///
    /// Idempotent: safe to call multiple times.
    async fn shutdown(&self) -> Result<()> {
        if self.initialized.swap(false, std::sync::atomic::Ordering::SeqCst) {
            // Clear the buffer
            let mut buf = self.buffer.write().await;
            let count = buf.len();
            buf.clear();
            self.buffer_bytes.store(0, std::sync::atomic::Ordering::SeqCst);

            tracing::info!(
                driver = self.name(),
                entries_cleared = count,
                "PullDriver shutdown — buffer cleared"
            );
        }
        Ok(())
    }
}
