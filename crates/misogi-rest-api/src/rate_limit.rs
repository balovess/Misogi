//! Sliding-Window Rate Limiter
//!
//! Implements a per-API-key sliding window rate limiter backed by
//! [`DashMap`](dashmap::DashMap) for lock-free concurrent access.
//!
//! # Algorithm
//!
//! Each API key maintains a bucket of request timestamps within a configurable
//! time window. On each incoming request:
//!
//! 1. Evict timestamps older than the window duration
//! 2. Count remaining timestamps in the window
//! 3. If count < limit → allow, record timestamp, return remaining quota
//! 4. If count >= limit → deny, calculate reset time from oldest entry
//!
//! # Cleanup Strategy
//!
//! Expired buckets (no requests within 2x window duration) are lazily evicted
//! on each [`RateLimiter::check`] call to prevent unbounded memory growth
//! from abandoned API keys.
//!
//! # Thread Safety
//!
//! All operations use `DashMap`'s shard-level locking, allowing high concurrency
//! across different API keys with minimal contention.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Result of a single rate-limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed within the current window.
    pub allowed: bool,

    /// Number of requests remaining before the limit is hit (0 if denied).
    pub remaining: u32,

    /// Unix timestamp (or relative instant) when the window resets.
    /// Clients should retry after this time.
    pub reset_at: Instant,
}

/// Per-client sliding-window bucket tracking request timestamps.
struct SlidingWindowBucket {
    /// Sorted (by insertion order) request timestamps within the current window.
    request_timestamps: Vec<Instant>,

    /// Duration of the sliding window (e.g., 60 seconds).
    window_duration: Duration,
}

impl SlidingWindowBucket {
    /// Create a new empty bucket with the given window duration.
    fn new(window_duration: Duration) -> Self {
        Self {
            request_timestamps: Vec::new(),
            window_duration,
        }
    }

    /// Remove timestamps that fall outside the current window.
    ///
    /// Returns the number of timestamps retained after eviction.
    fn evict_expired(&mut self, now: Instant) -> usize {
        let cutoff = now - self.window_duration;
        if let Some(first_valid) = self.request_timestamps.iter().position(|&ts| ts > cutoff) {
            self.request_timestamps.drain(..first_valid);
        } else {
            self.request_timestamps.clear();
        }
        self.request_timestamps.len()
    }

    /// Record a new request timestamp and return the updated count.
    fn record(&mut self, ts: Instant) -> usize {
        self.request_timestamps.push(ts);
        self.request_timestamps.len()
    }

    /// Check whether this bucket has had any recent activity.
    ///
    /// Returns `true` if the bucket is stale (no requests within 2x window),
    /// making it eligible for removal from the map.
    fn is_stale(&self, now: Instant) -> bool {
        if let Some(&last) = self.request_timestamps.last() {
            now.duration_since(last) > self.window_duration * 2
        } else {
            // Empty bucket is always stale
            true
        }
    }

    /// Calculate when the oldest request in the window will expire.
    ///
    /// Used to set the `Retry-After` / `reset_at` value for rate-limited responses.
    fn reset_at(&self) -> Instant {
        self.request_timestamps
            .first()
            .copied()
            .unwrap_or_else(Instant::now)
            + self.window_duration
    }
}

/// Concurrent sliding-window rate limiter keyed by API key (or any string identifier).
///
/// # Example
///
/// ```ignore
/// use misogi_rest_api::rate_limit::RateLimiter;
/// use std::time::Duration;
///
/// let limiter = RateLimiter::new(60, Duration::from_secs(60));
/// let result = limiter.check("api-key-abc123", 60)?;
/// assert!(result.allowed);
/// ```
pub struct RateLimiter {
    /// Per-key buckets storing request timestamps.
    buckets: DashMap<String, SlidingWindowBucket>,

    /// Maximum number of requests allowed per window per key.
    max_requests: u32,

    /// Duration of each sliding window.
    window_duration: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified limit and window.
    ///
    /// # Arguments
    ///
    /// * `max_requests` — maximum number of requests allowed per window per key
    /// * `window_duration` — length of the sliding window (e.g., 60 seconds)
    ///
    /// # Defaults
    ///
    /// When in doubt, use [`RateLimiter::default`] which gives 60 req/min
    /// over a 60-second window.
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            buckets: DashMap::new(),
            max_requests,
            window_duration,
        }
    }

    /// Check whether a request from the given API key should be allowed.
    ///
    /// Performs lazy cleanup of stale buckets on each invocation.
    ///
    /// # Arguments
    ///
    /// * `api_key` — unique identifier for the calling client (typically from
    ///   `X-API-Key` header or JWT `sub` claim)
    /// * `limit` — override limit for this specific key (uses the instance
    ///   default if `None`)
    ///
    /// # Returns
    ///
    /// A [`RateLimitResult`] indicating whether the request is allowed,
    /// how many requests remain, and when the window resets.
    #[tracing::instrument(skip(self), fields(api_key))]
    pub fn check(&self, api_key: &str, limit: Option<u32>) -> RateLimitResult {
        let effective_limit = limit.unwrap_or(self.max_requests);
        let now = Instant::now();

        // Lazily cleanup stale buckets (older than 2x window)
        self.retain_active_buckets(now);

        let mut bucket = self
            .buckets
            .entry(api_key.to_string())
            .or_insert_with(|| SlidingWindowBucket::new(self.window_duration));

        let count = bucket.evict_expired(now) as u32;

        if count < effective_limit {
            // Allow: record this request
            bucket.record(now);
            let remaining = effective_limit - count - 1;
            tracing::debug!(
                remaining,
                limit = effective_limit,
                "Rate limit check: allowed"
            );
            RateLimitResult {
                allowed: true,
                remaining,
                reset_at: now + self.window_duration,
            }
        } else {
            // Deny: rate limited
            let reset_at = bucket.reset_at();
            tracing::warn!(
                limit = effective_limit,
                reset_in_secs = reset_at.saturating_duration_since(now).as_secs(),
                "Rate limit check: denied"
            );
            RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at,
            }
        }
    }

    /// Remove all buckets that have been inactive for more than 2x the window
    /// duration. Called internally on each [`check`](Self::check) invocation.
    fn retain_active_buckets(&self, now: Instant) {
        self.buckets.retain(|_, bucket| !bucket.is_stale(now));
    }

    /// Return the number of currently tracked API keys (for monitoring/debugging).
    pub fn active_key_count(&self) -> usize {
        self.buckets.len()
    }

    /// Remove a specific API key's bucket (e.g., on key rotation or revocation).
    pub fn remove_key(&self, api_key: &str) {
        self.buckets.remove(api_key);
    }
}

impl Default for RateLimiter {
    /// Default rate limiter: 60 requests per 60-second window.
    fn default() -> Self {
        Self::new(60, Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));

        // First 3 requests should be allowed
        for i in 0..3 {
            let result = limiter.check("test-key", None);
            assert!(result.allowed, "Request {} should be allowed", i + 1);
        }

        // 4th request should be denied
        let result = limiter.check("test-key", None);
        assert!(!result.allowed, "4th request should be denied");
        assert_eq!(result.remaining, 0);
    }

    #[test]
    fn test_separate_keys_are_independent() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        let r1 = limiter.check("key-a", None);
        let r2 = limiter.check("key-b", None);
        assert!(r1.allowed);
        assert!(r2.allowed);

        // Exhaust key-a
        let _ = limiter.check("key-a", None);
        let r3 = limiter.check("key-a", None);
        assert!(!r3.allowed);

        // key-b should still have one slot left
        let r4 = limiter.check("key-b", None);
        assert!(r4.allowed);
    }

    #[test]
    fn test_stale_bucket_cleanup() {
        let limiter = RateLimiter::new(10, Duration::from_millis(100));
        
        // Add a key
        limiter.check("stale-key", None);
        assert_eq!(limiter.active_key_count(), 1);

        // Wait for the bucket to become stale (> 2x window)
        std::thread::sleep(Duration::from_millis(250));

        // Accessing a different key triggers lazy cleanup
        limiter.check("other-key", None);
        
        // Stale key should have been removed
        assert_eq!(limiter.active_key_count(), 1);
    }
}
