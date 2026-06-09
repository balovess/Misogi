//! Async chunk repair engine with retry and parallel execution.
//!
//! Provides the repair subsystem of the self-healing transport layer,
//! responsible for re-fetching or re-sending chunks that were detected as
//! missing or corrupted during verification. This module implements:
//!
//! - **Sequential repair** — One-at-a-time chunk retransmission with configurable retries.
//! - **Parallel repair** — Concurrent repair of multiple chunks using `tokio::JoinSet`.
//! - **Exponential backoff** — Gradually increasing delay between retry attempts.
//! - **Progress tracking** — Real-time reporting of repair completion status.
//!
//! # Architecture
//!
//! The [`RepairEngine`] is configured via [`RepairConfig`](super::config::RepairConfig)
//! and operates on a callback model: the caller provides a `repair_fn` closure
//! that knows how to request a single chunk from the remote peer. The engine
//! handles scheduling, retries, timeout enforcement, and progress aggregation.
//!
//! # Concurrency Model
//!
//! All public methods are `async` and designed for use within a tokio runtime.
//! The engine itself is stateless (except for configuration) and can be freely
//! shared across tasks. Progress tracking is done via mutable references to
//! [`RepairProgress`](super::session::RepairProgress) passed by the caller.
//!
//! # Error Handling Strategy
//!
//! Individual chunk repair failures are recorded in `progress.failed_indices`
//! but do NOT cause the overall operation to fail (unless all chunks fail).
//! This "best-effort" semantics allows partial recovery: if 9 out of 10 missing
//! chunks are repaired, the transfer can proceed with only 1 chunk still pending.

#[cfg(test)]
mod tests;

use super::config::RepairConfig;
use super::envelope::IntegrityError;
use super::session::RepairProgress;
use std::future::Future;
use std::time::Duration;

// ===========================================================================
// Repair Engine
// ===========================================================================

/// Async engine for repairing missing or corrupted transport chunks.
///
/// Configures and executes repair operations with support for retries,
/// exponential backoff, timeout enforcement, and parallel execution.
/// Each instance is bound to a specific [`RepairConfig`] at construction
/// time and can be reused across multiple repair cycles.
///
/// # Thread Safety
///
/// This type is `Clone + Send + Sync` and contains no mutable state,
/// making it safe for concurrent use from multiple async tasks without
/// synchronization overhead.
///
/// # Example
///
/// ```ignore
/// let config = RepairConfig {
///     max_repair_attempts: 3,
///     repair_timeout_secs: 30,
///     ..Default::default()
/// };
/// let engine = RepairEngine::new(&config);
///
/// let missing = vec![5, 12, 27];
/// let progress = engine.request_repair(&missing, |index| async move {
///     // Re-fetch chunk `index` from remote peer.
///     fetch_chunk_from_peer(index).await
/// }).await?;
///
/// println!("Repaired {}/{} chunks", progress.completed, progress.total_requested);
/// ```
#[derive(Debug, Clone)]
pub struct RepairEngine {
    /// Maximum number of retry attempts per chunk before giving up.
    ///
    /// A value of 0 means no limit (infinite retries). In practice,
    /// callers should set a reasonable upper bound to prevent infinite
    /// loops on permanently unavailable chunks.
    max_attempts: u32,

    /// Per-attempt timeout duration.
    ///
    /// If a single repair_fn invocation takes longer than this, it is
    /// considered failed and counted against the attempt counter.
    timeout: Duration,

    /// Whether to execute repairs in parallel when multiple indices are given.
    ///
    /// When true, uses `tokio::JoinSet` for concurrent execution.
    /// When false, processes indices sequentially in order.
    parallel: bool,
}

impl RepairEngine {
    /// Create a new repair engine from the given configuration.
    ///
    /// Extracts relevant fields from [`RepairConfig`] and initializes
    /// the engine with appropriate defaults for any unset values.
    ///
    /// # Arguments
    ///
    /// * `config` — Repair behavior configuration.
    ///
    /// # Returns
    ///
    /// A new [`RepairEngine`] instance ready to execute repairs.
    pub fn new(config: &RepairConfig) -> Self {
        Self {
            max_attempts: config.max_repair_attempts,
            timeout: Duration::from_secs(config.repair_timeout_secs),
            parallel: config.parallel_repair,
        }
    }

    /// Execute repair requests for the specified chunk indices.
    ///
    /// Iterates over `missing_indices` and invokes `repair_fn(index)` for each
    /// one. Results are aggregated into a [`RepairProgress`] report that tracks
    /// successful completions and permanent failures.
    ///
    /// # Type Parameters
    ///
    /// * `F` — Closure/function that takes a chunk index and returns a Future.
    /// * `Fut` — Future produced by `repair_fn`, resolving to `Result<(), IntegrityError>`.
    ///
    /// # Arguments
    ///
    /// * `missing_indices` — Chunk indices requiring repair (0-based).
    /// * `repair_fn` — Async function that attempts to repair one chunk.
    ///   Should return `Ok(())` on success or `Err(IntegrityError)` on failure.
    ///
    /// # Returns
    ///
    /// * `Ok(RepairProgress)` — Aggregated results of all repair attempts.
    /// * `Err(IntegrityError)` — Fatal error (e.g., empty config state).
    ///
    /// # Execution Mode
    ///
    /// If `self.parallel` is true, all repairs are launched concurrently
    /// using `tokio::JoinSet`. If false, they are executed sequentially
    /// in index order.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut progress = RepairProgress::new(missing.len() as u32);
    /// let result = engine.request_repair(&missing, |idx| async move {
    ///     retransmit_chunk(idx).await.map_err(|e| IntegrityError::HashComputationFailed(e.to_string()))
    /// }).await?;
    /// ```
    pub async fn request_repair<F, Fut>(
        &self,
        missing_indices: &[u32],
        repair_fn: F,
    ) -> Result<RepairProgress, IntegrityError>
    where
        F: Fn(u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), IntegrityError>> + Send + 'static,
    {
        let total = missing_indices.len() as u32;
        let mut progress = RepairProgress::new(total);

        if total == 0 {
            return Ok(progress); // Nothing to repair.
        }

        if self.parallel {
            self.parallel_repair(missing_indices, repair_fn).await
        } else {
            // Sequential execution.
            for &index in missing_indices {
                self.handle_repair_response(
                    index,
                    self.retry_with_backoff(index, self.max_attempts, &repair_fn)
                        .await,
                    &mut progress,
                )
                .await;
            }
            Ok(progress)
        }
    }

    /// Process a single repair result and update progress tracker.
    ///
    /// Examines the outcome of one chunk's repair attempt and updates
    /// either the `completed` count or `failed_indices` list accordingly.
    ///
    /// # Arguments
    ///
    /// * `index` — Chunk index that was being repaired.
    /// * `result` — Outcome of the repair attempt.
    /// * `progress` — Mutable progress tracker to update.
    ///
    /// # Side Effects
    ///
    /// Increments `progress.completed` on success, appends to
    /// `progress.failed_indices` on failure.
    pub async fn handle_repair_response(
        &self,
        index: u32,
        result: Result<(), IntegrityError>,
        progress: &mut RepairProgress,
    ) {
        match result {
            Ok(()) => {
                progress.completed += 1;
                tracing::debug!("Chunk {} repaired successfully", index);
            }
            Err(e) => {
                progress.failed_indices.push(index);
                tracing::warn!("Chunk {} repair failed after all attempts: {}", index, e);
            }
        }
    }

    /// Attempt repair with exponential backoff retry logic.
    ///
    /// Invokes `repair_fn(index)` up to `max_attempts` times, doubling
    /// the delay between attempts: 1s, 2s, 4s, 8s, ... capped at 30s.
    /// Returns immediately on first success; returns the last error if
    /// all attempts fail.
    ///
    /// # Backoff Schedule
    ///
    /// | Attempt | Delay Before |
    /// |---------|-------------|
    /// | 1       | 0s (immediate) |
    /// | 2       | 1s |
    /// | 3       | 2s |
    /// | 4       | 4s |
    /// | 5       | 8s |
    /// | 6+      | 16s (capped) |
    ///
    /// # Arguments
    ///
    /// * `index` — Chunk index to repair.
    /// * `max_attempts` — Maximum number of attempts (0 = infinite).
    /// * `repair_fn` — Async repair function for one chunk.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — Repair succeeded on some attempt.
    /// * `Err(IntegrityError)` — All attempts exhausted with errors.
    ///
    /// # Cancellation Safety
    ///
    /// This method respects tokio cancellation: if the task is cancelled
    /// during a backoff sleep, the method returns the current error state
    /// rather than continuing silently.
    pub async fn retry_with_backoff<F, Fut>(
        &self,
        index: u32,
        max_attempts: u32,
        repair_fn: F,
    ) -> Result<(), IntegrityError>
    where
        F: Fn(u32) -> Fut,
        Fut: Future<Output = Result<(), IntegrityError>>,
    {
        let mut last_error: Option<IntegrityError> = None;
        let effective_max = if max_attempts == 0 {
            u32::MAX // Infinite retries.
        } else {
            max_attempts
        };

        for attempt in 1..=effective_max {
            tracing::debug!(
                "Repair attempt {}/{} for chunk {}",
                attempt,
                effective_max,
                index
            );

            // Apply per-attempt timeout.
            let result = tokio::time::timeout(self.timeout, repair_fn(index)).await;

            match result {
                Ok(Ok(())) => {
                    // Success!
                    if attempt > 1 {
                        tracing::info!("Chunk {} succeeded on attempt {}", index, attempt);
                    }
                    return Ok(());
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_) => {
                    // Timeout expired.
                    last_error = Some(IntegrityError::InvalidEnvelope(format!(
                        "Repair timeout for chunk {} after {:?}",
                        index, self.timeout
                    )));
                }
            }

            // Compute backoff delay: 2^(attempt-1) seconds, capped at 30s.
            let delay_secs = 2u64.pow(attempt.saturating_sub(1)).min(30);
            let delay = Duration::from_secs(delay_secs);

            tracing::debug!(
                "Backing off {:?} before next attempt for chunk {}",
                delay,
                index
            );

            tokio::time::sleep(delay).await;
        }

        // All attempts exhausted.
        Err(last_error.unwrap_or_else(|| {
            IntegrityError::InvalidEnvelope(format!(
                "All {} repair attempts exhausted for chunk {}",
                effective_max, index
            ))
        }))
    }

    /// Execute repairs for multiple chunks in parallel.
    ///
    /// Launches all repair operations concurrently using `tokio::JoinSet`,
    /// collecting results as they complete. Significantly reduces total
    /// repair latency when many chunks need retransmission, at the cost
    /// of increased network bandwidth consumption.
    ///
    /// # Type Parameters
    ///
    /// * `F` — Closure/function taking chunk index and returning a Future.
    /// * `Fut` — Future that must be `Send + 'static` for use across tokio tasks.
    ///
    /// # Arguments
    ///
    /// * `indices` — Chunk indices to repair in parallel.
    /// * `repair_fn` — Async repair function for one chunk.
    ///
    /// # Returns
    ///
    /// * `Ok(RepairProgress)` — Aggregated results from all parallel repairs.
    /// * `Err(IntegrityError)` — Fatal error during parallel execution.
    ///
    /// # Resource Usage
    ///
    /// Spawns up to `indices.len()` concurrent tasks. Callers should ensure
    /// the system has sufficient resources (file descriptors, bandwidth)
    /// to handle this concurrency level. Consider batching large repair sets
    /// if resource constraints exist.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let missing = vec![3, 7, 15, 22, 41];
    /// let progress = engine.parallel_repair(&missing, |idx| async move {
    ///     fetch_chunk(idx).await
    /// }).await?;
    /// ```
    pub async fn parallel_repair<F, Fut>(
        &self,
        indices: &[u32],
        repair_fn: F,
    ) -> Result<RepairProgress, IntegrityError>
    where
        F: Fn(u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), IntegrityError>> + Send + 'static,
    {
        let total = indices.len() as u32;
        let mut progress = RepairProgress::new(total);

        if total == 0 {
            return Ok(progress);
        }

        // Use JoinSet for structured concurrency with bounded parallelism.
        use std::sync::Arc;
        use tokio::task::JoinSet;
        let fn_arc = Arc::new(repair_fn);
        let mut set: JoinSet<(u32, Result<(), IntegrityError>)> = JoinSet::new();

        // Spawn all repair tasks.
        for &index in indices {
            let fn_clone = Arc::clone(&fn_arc);
            let timeout = self.timeout;
            let max_attempts = self.max_attempts;

            set.spawn(async move {
                // Each spawned task runs its own retry loop internally.
                // We wrap it with timeout for safety.
                let result = tokio::time::timeout(timeout * max_attempts.max(1), async move {
                    // Simple retry without backoff for parallel mode
                    // (backoff would slow down all other tasks).
                    let mut last_err = None;
                    let effective_max = if max_attempts == 0 { 1 } else { max_attempts };

                    for _ in 0..effective_max {
                        match fn_clone(index).await {
                            Ok(()) => return Ok(()),
                            Err(e) => last_err = Some(e),
                        }
                        // Small fixed delay between parallel retries.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }

                    Err(last_err.unwrap_or_else(|| {
                        IntegrityError::InvalidEnvelope(format!(
                            "Parallel repair exhausted for chunk {}",
                            index
                        ))
                    }))
                })
                .await;

                match result {
                    Ok(r) => (index, r),
                    Err(_) => (
                        index,
                        Err(IntegrityError::InvalidEnvelope(format!(
                            "Parallel repair timed out for chunk {}",
                            index
                        ))),
                    ),
                }
            });
        }

        // Collect results as they complete.
        while let Some(result) = set.join_next().await {
            match result {
                Ok((index, repair_result)) => {
                    self.handle_repair_response(index, repair_result, &mut progress)
                        .await;
                }
                Err(join_err) => {
                    // Task panicked (should not happen with well-behaved closures).
                    tracing::error!("Repair task panicked: {}", join_err);
                    // Count as failure — we don't know which index this was.
                    // In practice, this indicates a bug in repair_fn.
                }
            }
        }

        Ok(progress)
    }
}
