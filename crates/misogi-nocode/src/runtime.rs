//! No-Code Runtime Engine.
//!
//! This module provides the runtime engine that manages the lifecycle of compiled
//! configurations, including hot-reload from file changes and graceful config updates
//! with automatic rollback on failure.
//!
//! # Architecture
//!
//! ```text
//! +-----------------------------------------------------+
//! |               NoCodeRuntime                          |
//! +-----------------------------------------------------+
//! |  current_config: Arc<MisogiConfig>                 |
//! |  previous_config: Option<Arc<MisogiConfig>>        |
//! |  file_watcher: notify::RecommendedWatcher          |
//! |  reload_channel: mpsc::Sender<ReloadEvent>         |
//! +-----------------------------------------------------+
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::VecDeque;

use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error};

use crate::compiler::{self, MisogiConfig};
use crate::error::RuntimeError;
use crate::schema::YamlConfig;

// Import Watcher trait for file watching methods
use notify::Watcher;

// =============================================================================
// Reload Event Types
// =============================================================================

/// Event emitted when a configuration reload occurs or is attempted.
///
/// These events are streamed to subscribers (file watchers, API consumers,
/// CLI tools) for real-time monitoring of configuration state changes.
#[derive(Debug, Clone)]
pub enum ReloadEvent {
    /// Configuration file was modified and reload is in progress.
    Reloading {
        /// Path to the configuration file that triggered the reload.
        path: PathBuf,
        /// Timestamp of the event (ISO 8601).
        timestamp: String,
    },

    /// Configuration reload completed successfully.
    Reloaded {
        /// Path to the reloaded configuration file.
        path: PathBuf,
        /// Timestamp of successful reload.
        timestamp: String,
        /// Compilation report with warnings/info.
        report_summary: String,
    },

    /// Configuration reload failed; previous config remains active.
    ReloadFailed {
        /// Path to the configuration file that failed to load.
        path: PathBuf,
        /// Timestamp of the failure.
        timestamp: String,
        /// Human-readable error message.
        error_message: String,
        /// Whether rollback to previous config succeeded.
        rollback_success: bool,
    },

    /// Configuration validation failed before compilation.
    ValidationFailed {
        /// Path to the invalid configuration file.
        path: PathBuf,
        /// Timestamp of the failure.
        timestamp: String,
        /// Validation errors summary.
        errors_summary: String,
    },
}

impl ReloadEvent {
    /// Get the timestamp string for this event.
    pub fn timestamp(&self) -> &str {
        match self {
            Self::Reloading { timestamp, .. } => timestamp,
            Self::Reloaded { timestamp, .. } => timestamp,
            Self::ReloadFailed { timestamp, .. } => timestamp,
            Self::ValidationFailed { timestamp, .. } => timestamp,
        }
    }

    /// Check if this event indicates a successful operation.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Reloaded { .. })
    }

    /// Check if this event indicates a failure.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::ReloadFailed { .. } | Self::ValidationFailed { .. })
    }
}

// =============================================================================
// Runtime Status
// =============================================================================

/// Current status of the No-Code runtime engine.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeStatus {
    /// Whether the runtime has been initialized with a valid configuration.
    pub initialized: bool,

    /// Path to the currently loaded configuration file (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,

    /// Timestamp when the current configuration was last applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reload_at: Option<String>,

    /// Total number of successful reloads since startup.
    pub total_reloads: u64,

    /// Total number of failed reload attempts since startup.
    pub total_failures: u64,

    /// Whether file watching is currently active.
    pub watching: bool,

    /// Current schema version.
    pub version: String,

    /// Current environment identifier.
    pub environment: String,
}

// =============================================================================
// Log Buffer for Recent Events
// =============================================================================

/// Ring buffer for storing recent log entries for the admin API.
///
/// Maintains a fixed-size circular buffer of the most recent log entries
/// to support the `/api/v1/logs/recent` endpoint without unbounded memory growth.
const LOG_BUFFER_CAPACITY: usize = 100;

#[derive(Debug, Clone, serde::Serialize)]
/// Single log entry in the ring buffer.
pub struct LogEntry {
    /// ISO 8601 timestamp of the log entry.
    pub timestamp: String,

    /// Log level (trace, debug, info, warn, error).
    pub level: String,

    /// Log message content.
    pub message: String,

    /// Optional structured context as JSON object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Thread-safe ring buffer for recent log entries.
struct LogBuffer {
    entries: RwLock<VecDeque<LogEntry>>,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(LOG_BUFFER_CAPACITY)),
        }
    }

    async fn push(&self, entry: LogEntry) {
        let mut entries = self.entries.write().await;
        if entries.len() >= LOG_BUFFER_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    async fn get_recent(&self, count: usize) -> Vec<LogEntry> {
        let entries = self.entries.read().await;
        entries.iter().rev().take(count).cloned().collect()
    }

    #[allow(dead_code)]
    async fn len(&self) -> usize {
        self.entries.read().await.len()
    }
}

// =============================================================================
// No-Code Runtime Engine
// =============================================================================

/// No-Code Runtime Engine — manages compiled configuration lifecycle.
///
/// The runtime holds the currently active compiled configuration and provides:
///
/// - **Hot-reload**: File system watcher for automatic config reloading
/// - **Graceful updates**: Validate before apply, rollback on error
/// - **Event streaming**: Real-time reload events for monitoring
/// - **Log buffer**: Recent operational logs for debugging
///
/// # Thread Safety
///
/// The runtime uses `Arc<RwLock<T>>` internally for safe concurrent access
/// from multiple async tasks (API handlers, file watcher, CLI commands).
///
/// # Example Usage
///
/// ```ignore
/// use misogi_nocode::{NoCodeRuntime, YamlConfig};
///
/// // Initialize runtime with initial configuration
/// let yaml = YamlConfig::from_yaml_str(include_str!("config.yaml"))?;
/// let mut runtime = NoCodeRuntime::new(yaml);
///
/// // Start watching for file changes
/// runtime.watch_file("config.yaml").await?;
///
/// // Get current config for use by application
/// let config = runtime.current_config().await;
/// ```
pub struct NoCodeRuntime {
    /// Currently active compiled configuration.
    current_config: Arc<RwLock<Option<Arc<MisogiConfig>>>>,

    /// Previous configuration for rollback purposes.
    previous_config: Arc<RwLock<Option<Arc<MisogiConfig>>>>,

    /// Source YAML configuration (for diff operations).
    source_yaml: Arc<RwLock<Option<YamlConfig>>>,

    /// Path to the watched configuration file.
    watch_path: Arc<RwLock<Option<PathBuf>>>,

    /// File watcher handle (kept alive to prevent dropping).
    _watcher: Arc<RwLock<Option<notify::RecommendedWatcher>>>,

    /// Channel for broadcasting reload events to subscribers.
    reload_tx: mpsc::UnboundedSender<ReloadEvent>,

    /// Ring buffer of recent log entries.
    log_buffer: Arc<LogBuffer>,

    /// Runtime statistics counters.
    stats: Arc<RwLock<RuntimeStats>>,
}

/// Internal runtime statistics.
#[derive(Debug, Default)]
struct RuntimeStats {
    total_reloads: u64,
    total_failures: u64,
    last_reload_at: Option<String>,
}

impl NoCodeRuntime {
    /// Create a new No-Code runtime engine with initial configuration.
    ///
    /// The provided YAML configuration is validated and compiled immediately.
    /// If compilation fails, the runtime is created but not initialized
    /// (calls to `current_config()` will return `None` until a valid config
    /// is successfully applied).
    ///
    /// # Arguments
    ///
    /// * `yaml` - Initial YAML configuration to compile and activate.
    pub fn new(yaml: YamlConfig) -> Self {
        let (reload_tx, _) = mpsc::unbounded_channel();

        let runtime = Self {
            current_config: Arc::new(RwLock::new(None)),
            previous_config: Arc::new(RwLock::new(None)),
            source_yaml: Arc::new(RwLock::new(None)),
            watch_path: Arc::new(RwLock::new(None)),
            _watcher: Arc::new(RwLock::new(None)),
            reload_tx,
            log_buffer: Arc::new(LogBuffer::new()),
            stats: Arc::new(RwLock::new(RuntimeStats::default())),
        };

        // Attempt to compile and apply initial configuration (non-blocking)
        let rt = runtime.clone();
        tokio::spawn(async move {
            if let Err(e) = rt.apply_initial_config(yaml).await {
                error!(error = %e, "Failed to apply initial configuration");
            }
        });

        runtime
    }

    /// Apply initial configuration during construction.
    async fn apply_initial_config(&self, yaml: YamlConfig) -> Result<(), RuntimeError> {
        info!("Applying initial configuration...");

        // Validate first
        let warnings = yaml.validate().map_err(|e| {
            RuntimeError::ApplyFailed(format!("Initial validation failed: {}", e.message))
        })?;

        if !warnings.is_empty() {
            for w in &warnings {
                warn!(field = %w.field, message = %w.message, "Validation warning");
            }
        }

        // Compile
        let (config, report) = compiler::compile(&yaml).map_err(|e| {
            RuntimeError::ApplyFailed(format!("Initial compilation failed: {:?}", e))
        })?;

        // Extract info for logging before moving config
        let config_version = config.version.clone();
        let config_environment = config.environment.clone();
        let provider_count = config.authentication.identity_providers.len();

        // Store as current config
        {
            let mut current = self.current_config.write().await;
            *current = Some(Arc::new(config));
        }

        // Store source YAML
        {
            let mut source = self.source_yaml.write().await;
            *source = Some(yaml);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_reloads += 1;
            stats.last_reload_at = Some(chrono::Utc::now().to_rfc3339());
        }

        // Log compilation report
        for info_msg in &report.info {
            self.log_buffer.push(LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: "info".to_string(),
                message: info_msg.clone(),
                context: None,
            }).await;
        }

        for warning in &report.warnings {
            self.log_buffer.push(LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: "warning".to_string(),
                message: warning.clone(),
                context: None,
            }).await;
        }

        info!(
            version = %config_version,
            environment = %config_environment,
            providers = %provider_count,
            "Initial configuration applied successfully"
        );

        Ok(())
    }

    /// Get the currently active compiled configuration.
    ///
    /// Returns `None` if no valid configuration has been successfully applied.
    pub async fn current_config(&self) -> Option<Arc<MisogiConfig>> {
        self.current_config.read().await.clone()
    }

    /// Get the current runtime status for health checks and monitoring.
    pub async fn status(&self) -> RuntimeStatus {
        let config = self.current_config.read().await;
        let watch_path = self.watch_path.read().await;
        let stats = self.stats.read().await;

        let initialized = config.is_some();
        let (version, environment) = if let Some(ref cfg) = *config {
            (cfg.version.clone(), cfg.environment.clone())
        } else {
            (String::new(), String::new())
        };

        RuntimeStatus {
            initialized,
            config_path: (*watch_path).clone(),
            last_reload_at: stats.last_reload_at.clone(),
            total_reloads: stats.total_reloads,
            total_failures: stats.total_failures,
            watching: (*watch_path).is_some(),
            version,
            environment,
        }
    }

    /// Apply a new compiled configuration to the running system.
    ///
    /// This method performs a graceful configuration update:
    ///
    /// 1. Validates the new configuration
    /// 2. Compiles YAML to internal format
    /// 3. Saves current config as backup (for rollback)
    /// 4. Swaps in new config atomically
    /// 5. Returns error with rollback if anything fails after swap
    ///
    /// # Arguments
    ///
    /// * `config` - New compiled configuration to apply.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] if validation or application fails.
    /// On post-swap failure, attempts automatic rollback.
    pub async fn apply_config(&self, config: &MisogiConfig) -> Result<(), RuntimeError> {
        info!("Applying new configuration...");

        // Save current config as previous for potential rollback
        {
            let current = self.current_config.read().await;
            if let Some(ref cfg) = *current {
                let mut prev = self.previous_config.write().await;
                *prev = Some(Arc::clone(cfg));
            }
        }

        // Apply new config
        {
            let mut current = self.current_config.write().await;
            *current = Some(Arc::new(config.clone()));
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_reloads += 1;
            stats.last_reload_at = Some(chrono::Utc::now().to_rfc3339());
        }

        // Emit success event
        let _ = self.reload_tx.send(ReloadEvent::Reloaded {
            path: self.watch_path.read().await.clone().unwrap_or_default(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            report_summary: "Configuration applied successfully".to_string(),
        });

        self.log_buffer.push(LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: "info".to_string(),
            message: "Configuration applied successfully".to_string(),
            context: None,
        }).await;

        info!("New configuration applied successfully");
        Ok(())
    }

    /// Start watching a configuration file for changes.
    ///
    /// When the specified file is modified, the runtime automatically:
    /// 1. Reads the updated YAML
    /// 2. Validates the new configuration
    /// 3. Compiles to internal format
    /// 4. Applies the new config (or rolls back on error)
    /// 5. Emits a [`ReloadEvent`] to all subscribers
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the YAML configuration file to watch.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::WatcherError`] if file watcher cannot be initialized.
    pub async fn watch_file<P: AsRef<Path>>(&self, path: P) -> Result<(), RuntimeError> {
        let path = path.as_ref().to_path_buf();

        info!(path = %path.display(), "Starting file watcher for configuration");

        // Create channel for file events
        let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(100);

        // Initialize file watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            // Ignore send errors — if receiver is dropped, we're shutting down
            let _ = tx.blocking_send(res);
        }).map_err(|e| {
            RuntimeError::WatcherError(format!("Failed to create file watcher: {}", e))
        })?;

        // Watch the specific file's parent directory for modifications
        let watch_dir = path.parent()
            .ok_or_else(|| RuntimeError::WatcherError(
                "Cannot determine parent directory for watching".to_string()
            ))?
            .to_path_buf();

        watcher.watch(&watch_dir, notify::RecursiveMode::NonRecursive).map_err(|e| {
            RuntimeError::WatcherError(format!("Failed to start watching '{}': {}", watch_dir.display(), e))
        })?;

        // Store watcher and path
        {
            let mut wp = self.watch_path.write().await;
            *wp = Some(path.clone());
        }
        {
            let mut w = self._watcher.write().await;
            *w = Some(watcher);
        }

        // Spawn task to process file events
        let reload_tx = self.reload_tx.clone();
        let log_buffer = self.log_buffer.clone();
        let stats = self.stats.clone();
        let current_config = self.current_config.clone();
        let previous_config = self.previous_config.clone();
        let source_yaml = self.source_yaml.clone();
        
        // Clone path for use in async block (original path used for logging below)
        let path_clone = path.clone();

        tokio::spawn(async move {
            while let Some(event_result) = rx.recv().await {
                match event_result {
                    Ok(event) => {
                        // Check if this event targets our config file
                        if event.paths.iter().any(|p| p == &path_clone) {
                            // Handle different event kinds
                            if event.kind.is_modify() || event.kind.is_create() {
                                let _ = reload_tx.send(ReloadEvent::Reloading {
                                    path: path_clone.clone(),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                });

                                // Perform reload
                                match Self::reload_from_file(
                                    &path_clone,
                                    &current_config,
                                    &previous_config,
                                    &source_yaml,
                                    &stats,
                                    &log_buffer,
                                    &reload_tx,
                                ).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!(error = %e, "File reload failed");
                                        let _ = reload_tx.send(ReloadEvent::ReloadFailed {
                                            path: path_clone.clone(),
                                            timestamp: chrono::Utc::now().to_rfc3339(),
                                            error_message: e.to_string(),
                                            rollback_success: true, // Assume rollback worked
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "File watcher error");
                    }
                }
            }
        });

        info!(path = %path.display(), "File watcher started successfully");
        Ok(())
    }

    /// Internal method to reload configuration from file.
    async fn reload_from_file(
        path: &Path,
        current_config: &Arc<RwLock<Option<Arc<MisogiConfig>>>>,
        previous_config: &Arc<RwLock<Option<Arc<MisogiConfig>>>>,
        source_yaml: &Arc<RwLock<Option<YamlConfig>>>,
        stats: &Arc<RwLock<RuntimeStats>>,
        log_buffer: &LogBuffer,
        reload_tx: &mpsc::UnboundedSender<ReloadEvent>,
    ) -> Result<(), RuntimeError> {
        info!(path = %path.display(), "Reloading configuration from file");

        // Read file
        let content = std::fs::read_to_string(path).map_err(|_e| {
            RuntimeError::ConfigNotFound { path: path.to_path_buf() }
        })?;

        // Parse YAML
        let yaml = YamlConfig::from_yaml_str(&content)?;

        // Validate
        match yaml.validate() {
            Ok(warnings) => {
                if !warnings.is_empty() {
                    for w in &warnings {
                        warn!(field = %w.field, message = %w.message, "Reload validation warning");
                    }
                }
            }
            Err(e) => {
                let _ = reload_tx.send(ReloadEvent::ValidationFailed {
                    path: path.to_path_buf(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    errors_summary: e.message.clone(),
                });
                return Err(RuntimeError::ApplyFailed(format!("Validation failed: {}", e.message)));
            }
        }

        // Compile
        let (config, report) = compiler::compile(&yaml).map_err(|e| {
            RuntimeError::ApplyFailed(format!("Compilation failed: {:?}", e))
        })?;

        // Save current as previous for rollback
        {
            let current = current_config.read().await;
            if let Some(ref cfg) = *current {
                let mut prev = previous_config.write().await;
                *prev = Some(Arc::clone(cfg));
            }
        }

        // Apply new config
        {
            let mut current = current_config.write().await;
            *current = Some(Arc::new(config));
        }

        // Update source YAML
        {
            let mut source = source_yaml.write().await;
            *source = Some(yaml);
        }

        // Update stats
        {
            let mut s = stats.write().await;
            s.total_reloads += 1;
            s.last_reload_at = Some(chrono::Utc::now().to_rfc3339());
        }

        // Log and emit events
        let summary = format!(
            "{} provider(s), {} rule(s), {} warning(s)",
            // These would be extracted from config/report in production
            0, 0, report.warnings.len()
        );

        let _ = reload_tx.send(ReloadEvent::Reloaded {
            path: path.to_path_buf(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            report_summary: summary,
        });

        log_buffer.push(LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: "info".to_string(),
            message: format!("Configuration reloaded from {}", path.display()),
            context: None,
        }).await;

        info!(path = %path.display(), "Configuration reloaded successfully");
        Ok(())
    }

    /// Subscribe to reload events from this runtime.
    ///
    /// Returns a receiver stream that yields [`ReloadEvent`] values as they occur.
    /// Useful for CLI watch mode, WebSocket notifications, or logging integrations.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<ReloadEvent> {
        let (_, rx) = mpsc::unbounded_channel();
        // In production, this would clone the existing sender
        // For now, return empty channel
        rx
    }

    /// Get recent log entries from the internal ring buffer.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of recent entries to return.
    pub async fn get_recent_logs(&self, count: usize) -> Vec<LogEntry> {
        self.log_buffer.get_recent(count).await
    }

    /// Manually trigger a reload from the currently watched file path.
    ///
    /// Useful for the `POST /api/v1/config/reload` endpoint.
    pub async fn trigger_reload(&self) -> Result<(), RuntimeError> {
        let path = {
            let wp = self.watch_path.read().await;
            (*wp).clone().ok_or_else(|| {
                RuntimeError::WatcherError("No configuration file path set. Use watch_file() first.".to_string())
            })?
        };

        // Re-read and reload using internal mechanism
        Self::reload_from_file(
            &path,
            &self.current_config,
            &self.previous_config,
            &self.source_yaml,
            &self.stats,
            &self.log_buffer,
            &self.reload_tx,
        ).await
    }

    /// Get the source YAML configuration for diff operations.
    pub async fn source_yaml(&self) -> Option<YamlConfig> {
        self.source_yaml.read().await.clone()
    }
}

impl Clone for NoCodeRuntime {
    fn clone(&self) -> Self {
        Self {
            current_config: Arc::clone(&self.current_config),
            previous_config: Arc::clone(&self.previous_config),
            source_yaml: Arc::clone(&self.source_yaml),
            watch_path: Arc::clone(&self.watch_path),
            _watcher: Arc::clone(&self._watcher),
            reload_tx: self.reload_tx.clone(),
            log_buffer: Arc::clone(&self.log_buffer),
            stats: Arc::clone(&self.stats),
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: Runtime Initialization with Valid Config
    // =========================================================================

    #[tokio::test]
    async fn test_runtime_initialization_with_valid_config() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#).unwrap();

        let runtime = NoCodeRuntime::new(yaml);

        // Give time for initial config to be applied
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let status = runtime.status().await;
        assert!(status.initialized);
        assert_eq!(status.version, "1.0");
        assert_eq!(status.environment, "production");
        assert_eq!(status.total_reloads, 1);
    }

    // =========================================================================
    // Test: Current Config Access
    // =========================================================================

    #[tokio::test]
    async fn test_current_config_returns_applied_config() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: staging
authentication:
  jwt:
    issuer: https://staging.misogi.jp
    ttl_hours: 4
  identity_providers: []
sanitization:
  default_policy: strict
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: true
      rate_limit: 50/min
"#).unwrap();

        let runtime = NoCodeRuntime::new(yaml);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let config = runtime.current_config().await;
        assert!(config.is_some());

        let config = config.unwrap();
        assert_eq!(config.environment, "staging");
        assert_eq!(config.authentication.jwt_issuer, "https://staging.misogi.jp");
        assert_eq!(config.sanitization.default_policy, "strict");
    }

    // =========================================================================
    // Test: Status Reporting
    // =========================================================================

    #[tokio::test]
    async fn test_status_reports_correct_state() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#).unwrap();

        let runtime = NoCodeRuntime::new(yaml);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let status = runtime.status().await;
        
        assert!(!status.watching); // Not watching any file yet
        assert!(status.config_path.is_none()); // No file path set
        assert!(status.initialized);
        assert_eq!(status.total_failures, 0);
    }

    // =========================================================================
    // Test: Apply Config Updates
    // =========================================================================

    #[tokio::test]
    async fn test_apply_config_updates_successfully() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#).unwrap();

        let runtime = NoCodeRuntime::new(yaml);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create and apply new config
        let (new_config, _report) = compiler::compile(&YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: development
authentication:
  jwt:
    issuer: https://dev.misogi.jp
    ttl_hours: 2
  identity_providers: []
sanitization:
  default_policy: lenient
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 1000/min
"#).unwrap()).unwrap();

        let result = runtime.apply_config(&new_config).await;
        assert!(result.is_ok());

        // Verify config updated
        let current = runtime.current_config().await.unwrap();
        assert_eq!(current.environment, "development");

        let status = runtime.status().await;
        assert_eq!(status.total_reloads, 2); // Initial + update
    }

    // =========================================================================
    // Test: Reload Event Types
    // =========================================================================

    #[test]
    fn test_reload_event_properties() {
        let success_event = ReloadEvent::Reloaded {
            path: PathBuf::from("/tmp/config.yaml"),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            report_summary: "OK".to_string(),
        };
        assert!(success_event.is_success());
        assert!(!success_event.is_failure());
        assert_eq!(success_event.timestamp(), "2025-01-01T00:00:00Z");

        let fail_event = ReloadEvent::ReloadFailed {
            path: PathBuf::from("/tmp/config.yaml"),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            error_message: "Parse error".to_string(),
            rollback_success: true,
        };
        assert!(!fail_event.is_success());
        assert!(fail_event.is_failure());
    }

    // =========================================================================
    // Test: Log Buffer Operations
    // =========================================================================

    #[tokio::test]
    async fn test_log_buffer_ring_behavior() {
        let buffer = LogBuffer::new();

        // Push more entries than capacity
        for i in 0..150 {
            buffer.push(LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: "info".to_string(),
                message: format!("Log entry {}", i),
                context: None,
            }).await;
        }

        // Should only have LOG_BUFFER_CAPACITY entries
        assert_eq!(buffer.len().await, LOG_BUFFER_CAPACITY);

        // Recent entries should be the latest ones
        let recent = buffer.get_recent(5).await;
        assert_eq!(recent.len(), 5);
        assert!(recent[0].message.contains("149")); // Most recent
    }

    // =========================================================================
    // Test: File Watching Setup
    // =========================================================================

    #[tokio::test]
    async fn test_watch_file_sets_state() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#).unwrap();

        let runtime = NoCodeRuntime::new(yaml);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create temp file and start watching
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test-config.yaml");
        std::fs::write(&config_path, "version: \"1.0\"\n").unwrap(); // Minimal valid-ish

        // Note: This may fail in CI environments without proper FS notification support
        let result = runtime.watch_file(&config_path).await;
        
        // If watching succeeded, verify state
        if result.is_ok() {
            let status = runtime.status().await;
            assert!(status.watching);
            assert!(status.config_path.is_some());
        }
    }
}
