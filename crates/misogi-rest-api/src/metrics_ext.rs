//! Prometheus-Style Metrics Collector
//!
//! Provides a lightweight, thread-safe metrics collection system that exports
//! data in Prometheus text exposition format (version 0.0.4 compatible).
//!
//! Uses Rust atomics for counters/gauges and a simple histogram implementation
//! for scan duration tracking. No external Prometheus client library dependency
//! is required -- this crate is fully self-contained.
//!
//! # Metric Naming Convention
//!
//! All metric names follow the Prometheus convention:
//!
//! ```text
//! misogi_{metric_name}_{type}{label1="value1",label2="value2"}
//! ```
//!
//! # Thread Safety
//!
//! All metric updates use [`std::sync::atomic`] operations, enabling safe
//! concurrent access from multiple async handler tasks without locks.

#[allow(unused_imports)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Simple histogram tracking min/max/sum/count for a single metric.
///
/// Not a full Prometheus histogram with configurable buckets -- sufficient
/// for basic observability needs without external dependencies.
#[derive(Debug, Default)]
struct Histogram {
    /// Number of observations recorded.
    count: AtomicU64,

    /// Sum of all observed values.
    sum: AtomicU64,

    /// Minimum observed value (in milliseconds, fixed-point).
    min: AtomicU64,

    /// Maximum observed value (in milliseconds, fixed-point).
    max: AtomicU64,
}

impl Histogram {
    /// Record a new observation in seconds (converted to fixed-point millis * 1000).
    fn observe(&self, seconds: f64) {
        let value = (seconds * 1000.0) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);

        // CAS loop for min
        loop {
            let current = self.min.load(Ordering::Relaxed);
            if current == 0 || value < current {
                if self.min
                    .compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            } else {
                break;
            }
        }

        // CAS loop for max
        loop {
            let current = self.max.load(Ordering::Relaxed);
            if value > current {
                if self.max
                    .compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Export histogram in Prometheus text format.
    fn export(&self, name: &str) -> String {
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed);
        #[allow(unused_variables)]
        let min_val = self.min.load(Ordering::Relaxed);
        let max_val = self.max.load(Ordering::Relaxed);

        if count == 0 {
            return String::new();
        }

        format!(
            "# TYPE {name} summary\n\
             {name}{{quantile=\"0.5\"}} {avg:.6}\n\
             {name}{{quantile=\"1\"}} {max:.6}\n\
             {name}_sum {sum_millis:.6}\n\
             {name}_count {count}\n",
            name = name,
            avg = sum as f64 / count as f64 / 1000.0,
            max = max_val as f64 / 1000.0,
            sum_millis = sum as f64 / 1000.0,
            count = count,
        )
    }
}

/// Central metrics collector for the Misogi REST API.
///
/// Singleton-like structure holding all exported metrics. In practice,
/// one instance is stored in [`AppState`](crate::router::AppState) and
/// shared via `Arc` across all handler tasks.
///
/// # Example
///
/// ```ignore
/// use misogi_rest_api::metrics_ext::MetricsCollector;
///
/// let metrics = MetricsCollector::new();
/// metrics.inc_files_uploaded("strict");
/// metrics.record_scan_duration(1.234);
/// println!("{}", metrics.export());
/// ```
pub struct MetricsCollector {
    /// Counter: total files uploaded, labeled by policy name.
    files_uploaded: DashMap<String, AtomicU64>,

    /// Histogram: scan job duration in seconds.
    scan_duration: Histogram,

    /// Counter: total threats found, labeled by severity.
    threats_found: DashMap<String, AtomicU64>,

    /// Counter: total API requests, labeled by method, endpoint, and status.
    api_requests: DashMap<String, AtomicU64>,

    /// Gauge: currently active (in-flight) scan jobs.
    active_jobs: AtomicU64,

    /// Gauge: scanner health status (0 = unhealthy, 1 = healthy), labeled by name.
    scanner_health: DashMap<String, AtomicU64>,
}

// Re-use DashMap from rate_limit module's dependency
use dashmap::DashMap;

impl MetricsCollector {
    /// Create a new empty metrics collector with all counters initialized to zero.
    pub fn new() -> Self {
        Self {
            files_uploaded: DashMap::new(),
            scan_duration: Histogram::default(),
            threats_found: DashMap::new(),
            api_requests: DashMap::new(),
            active_jobs: AtomicU64::new(0),
            scanner_health: DashMap::new(),
        }
    }

    /// Increment the file upload counter for the given policy.
    ///
    /// # Arguments
    ///
    /// * `policy` -- name of the sanitization policy applied (used as label value)
    #[tracing::instrument(skip(self), fields(policy))]
    pub fn inc_files_uploaded(&self, policy: &str) {
        let counter = self
            .files_uploaded
            .entry(policy.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(policy, "Files uploaded counter incremented");
    }

    /// Record the duration of a scan operation.
    ///
    /// # Arguments
    ///
    /// * `seconds` -- wall-clock duration of the scan job in seconds
    #[tracing::instrument(skip(self), fields(duration_secs = seconds))]
    pub fn record_scan_duration(&self, seconds: f64) {
        self.scan_duration.observe(seconds);
        tracing::debug!(duration_secs = seconds, "Scan duration recorded");
    }

    /// Increment the threat counter for the given severity level.
    ///
    /// # Arguments
    ///
    /// * `severity` -- threat severity label (e.g., `"critical"`, `"high"`, `"medium"`, `"low"`)
    #[tracing::instrument(skip(self), fields(severity))]
    pub fn inc_threats_found(&self, severity: &str) {
        let counter = self
            .threats_found
            .entry(severity.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(severity, "Threats found counter incremented");
    }

    /// Increment the API request counter for the given method/endpoint/status combination.
    ///
    /// # Arguments
    ///
    /// * `method` -- HTTP method (e.g., `"GET"`, `"POST"`, `"DELETE"`)
    /// * `endpoint` -- request path (e.g., `"/api/v1/files"`)
    /// * `status` -- HTTP response status code (e.g., `200`, `404`)
    #[tracing::instrument(skip(self), fields(method, endpoint, status))]
    pub fn inc_api_request(&self, method: &str, endpoint: &str, status: u16) {
        let key = format!("{method},{endpoint},{status}");
        let counter = self
            .api_requests
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the gauge for currently active (in-flight) scan jobs.
    ///
    /// # Arguments
    ///
    /// * `count` -- current number of active jobs
    pub fn set_active_jobs(&self, count: u64) {
        self.active_jobs.store(count, Ordering::Relaxed);
    }

    /// Set the health gauge for a named scanner component.
    ///
    /// # Arguments
    ///
    /// * `name` -- scanner identifier (used as label value)
    /// * `healthy` -- `true` for healthy (gauge = 1), `false` for unhealthy (gauge = 0)
    pub fn set_scanner_healthy(&self, name: &str, healthy: bool) {
        let gauge = self
            .scanner_health
            .entry(name.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        gauge.store(if healthy { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Export all collected metrics in Prometheus text exposition format.
    ///
    /// Returns a string suitable for the `/metrics` endpoint response body
    /// with `Content-Type: text/plain; version=0.0.4; charset=utf-8`.
    ///
    /// # Output Format
    ///
    /// ```text
    /// # HELP misogi_files_uploaded_total Total number of files uploaded
    /// # TYPE misogi_files_uploaded_total counter
    /// misogi_files_uploaded_total{policy="default"} 42
    /// ...
    /// ```
    pub fn export(&self) -> String {
        let mut output = String::with_capacity(2048);

        // --- Files uploaded counter ---
        output.push_str("# HELP misogi_files_uploaded_total Total number of files uploaded\n");
        output.push_str("# TYPE misogi_files_uploaded_total counter\n");
        for entry in self.files_uploaded.iter() {
            output.push_str(&format!(
                "misogi_files_uploaded_total{{policy=\"{}\"}} {}\n",
                entry.key(),
                entry.value().load(Ordering::Relaxed),
            ));
        }

        // --- Scan duration histogram ---
        output.push_str("\n# HELP misogi_scan_duration_seconds Total time spent scanning files\n");
        output.push_str("# TYPE misogi_scan_duration_seconds summary\n");
        output.push_str(&self.scan_duration.export("misogi_scan_duration_seconds"));

        // --- Threats found counter ---
        output.push_str("# HELP misogi_threats_found_total Total number of threats detected\n");
        output.push_str("# TYPE misogi_threats_found_total counter\n");
        for entry in self.threats_found.iter() {
            output.push_str(&format!(
                "misogi_threats_found_total{{severity=\"{}\"}} {}\n",
                entry.key(),
                entry.value().load(Ordering::Relaxed),
            ));
        }

        // --- API requests counter ---
        output.push_str("# HELP misogi_api_requests_total Total number of API requests\n");
        output.push_str("# TYPE misogi_api_requests_total counter\n");
        for entry in self.api_requests.iter() {
            let parts: Vec<&str> = entry.key().splitn(3, ',').collect();
            if parts.len() == 3 {
                output.push_str(&format!(
                    "misogi_api_requests_total{{method=\"{}\",endpoint=\"{}\",status=\"{}\"}} {}\n",
                    parts[0],
                    parts[1],
                    parts[2],
                    entry.value().load(Ordering::Relaxed),
                ));
            }
        }

        // --- Active jobs gauge ---
        output.push_str("# HELP misogi_active_jobs_current Number of currently active scan jobs\n");
        output.push_str("# TYPE misogi_active_jobs_current gauge\n");
        output.push_str(&format!(
            "misogi_active_jobs_current {}\n",
            self.active_jobs.load(Ordering::Relaxed),
        ));

        // --- Scanner health gauge ---
        output.push_str("# HELP misogi_scanner_healthy Whether the scanner is healthy (1=healthy, 0=unhealthy)\n");
        output.push_str("# TYPE misogi_scanner_healthy gauge\n");
        for entry in self.scanner_health.iter() {
            output.push_str(&format!(
                "misogi_scanner_healthy{{scanner_name=\"{}\"}} {}\n",
                entry.key(),
                entry.value().load(Ordering::Relaxed),
            ));
        }

        output
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_metrics_export() {
        let m = MetricsCollector::new();
        m.inc_files_uploaded("default");
        m.inc_files_uploaded("strict");
        m.inc_threats_found("high");
        m.set_active_jobs(5);
        m.set_scanner_healthy("primary", true);

        let output = m.export();
        assert!(output.contains("misogi_files_uploaded_total"));
        assert!(output.contains("policy=\"default\""));
        assert!(output.contains("policy=\"strict\""));
        assert!(output.contains("misogi_threats_found_total"));
        assert!(output.contains("severity=\"high\""));
        assert!(output.contains("misogi_active_jobs_current 5"));
        assert!(output.contains("misogi_scanner_healthy"));
    }

    #[test]
    fn test_histogram_export() {
        let m = MetricsCollector::new();
        m.record_scan_duration(0.5);
        m.record_scan_duration(1.5);
        m.record_scan_duration(2.0);

        let output = m.export();
        assert!(output.contains("misogi_scan_duration_seconds"));
        assert!(output.contains("_count 3"));
    }

    #[test]
    fn test_api_request_labeling() {
        let m = MetricsCollector::new();
        m.inc_api_request("GET", "/api/v1/files", 200);
        m.inc_api_request("POST", "/api/v1/scan", 201);

        let output = m.export();
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("endpoint=\"/api/v1/files\""));
        assert!(output.contains("status=\"200\""));
        assert!(output.contains("method=\"POST\""));
    }
}
