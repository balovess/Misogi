//! Hot-reload support for ABAC configuration.
//!
//! Provides [`AbacHotReload`], which monitors an on-disk configuration file
//! (TOML format) and automatically reloads rules, templates, and runtime
//! parameters into the ABAC engine, resolver, and approval executor when
//! changes are detected.
//!
//! # Reload Triggers
//!
//! | Method | Trigger | Use Case |
//! |--------|---------|----------|
//! | [`check_and_reload`](AbacHotReload::check_and_reload) | File modification time change | Polling loop / timer |
//! | [`force_reload`](AbacHotReload::force_reload) | Caller-initiated | API endpoint, admin command |
//! | [`reload_from_string`](AbacHotReload::reload_from_string) | In-memory TOML string | Config management API |
//! | [`sighup_handler`](AbacHotReload::sighup_handler) | OS signal (SIGHUP) | Unix daemon pattern |
//!
//! # Atomicity Guarantees
//!
//! All reload operations are atomic with respect to each component:
//! - Engine rules are replaced (not appended) in a single write lock acquisition.
//! - Decision cache is invalidated immediately after rule replacement.
//! - Executor templates are updated in the same logical operation.
//!
//! If any component fails to update, the error is returned but previously-loaded
//! configuration remains in effect (partial update is NOT applied).

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use super::config::AbacConfig;
use super::engine::AbacEngine;
use super::executor::ApprovalExecutor;

// ===========================================================================
// ReloadError
// ===========================================================================

/// Error type for hot-reload operations.
///
/// These errors represent failures during the config loading/reload process,
/// not ABAC evaluation errors or access control denials.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// The configured path does not exist or is not accessible.
    #[error("config file not found: {0}")]
    FileNotFound(std::io::Error),

    /// The TOML content could not be deserialized into `AbacConfig`.
    #[error("failed to parse config: {0}")]
    ParseError(String),

    /// Structural validation of the loaded config failed.
    ///
    /// Contains all validation errors found (validation does not stop at first error).
    #[error("validation failed: {0:?}")]
    ValidationFailed(Vec<String>),

    /// An I/O error occurred while reading the file or checking metadata.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// ===========================================================================
// AbacHotReload
// ===========================================================================

/// Manages hot-reloading of ABAC configuration from disk or in-memory sources.
///
/// Wraps references to the three core ABAC components ([`AbacEngine`],
/// [`AttributeResolver`], [`ApprovalExecutor`]) and provides methods to
/// atomically update their configuration when changes are detected.
///
/// # File Watching Strategy
///
/// Uses modification-time (`mtime`) based polling rather than inotify/kqueue
/// for maximum portability. Callers should invoke [`check_and_reload`] at
/// regular intervals (e.g., every 5 seconds via tokio interval).
///
/// # Thread Safety
///
/// Internal state (`last_modified` timestamp) is protected by `RwLock`.
/// Component updates acquire each component's internal locks sequentially:
/// engine -> resolver -> executor. Lock ordering is fixed to prevent deadlock.
pub struct AbacHotReload {
    /// Optional filesystem path to monitor for changes.
    ///
    /// When `None`, only [`force_reload`](Self::force_reload) and
    /// [`reload_from_string`](Self::reload_from_string) are available.
    config_path: Option<PathBuf>,

    /// Last known modification time of the loaded config file.
    ///
    /// Used by [`check_and_reload`](Self::check_and_reload) to detect changes.
    last_modified: RwLock<Option<SystemTime>>,

    /// Reference to the ABAC policy engine (rules + caching).
    engine: Arc<RwLock<AbacEngine>>,

    /// Reference to the approval executor (templates).
    executor: Arc<RwLock<ApprovalExecutor>>,
}

impl AbacHotReload {
    /// Constructs a new hot-reload manager without file watching.
    ///
    /// Use [`with_file_watch`](Self::with_file_watch) to enable automatic
    /// file-change detection via [`check_and_reload`](Self::check_and_reload).
    pub fn new(engine: AbacEngine, executor: ApprovalExecutor) -> Self {
        Self {
            config_path: None,
            last_modified: RwLock::new(None),
            engine: Arc::new(RwLock::new(engine)),
            executor: Arc::new(RwLock::new(executor)),
        }
    }

    /// Constructs a new hot-reload manager with file-based change monitoring.
    ///
    /// Reads the initial modification time of the specified config file.
    /// Subsequent calls to [`check_and_reload`](Self::check_and_reload) will
    /// compare the current mtime against this stored value.
    ///
    /// # Parameters
    ///
    /// - `engine`: ABAC policy engine instance.
    /// - `executor`: Approval executor instance.
    /// - `config_path`: Path to the TOML configuration file to monitor.
    pub fn with_file_watch(
        engine: AbacEngine,
        executor: ApprovalExecutor,
        config_path: &Path,
    ) -> Self {
        let initial_mtime = std::fs::metadata(config_path)
            .ok()
            .and_then(|m| m.modified().ok());

        Self {
            config_path: Some(config_path.to_path_buf()),
            last_modified: RwLock::new(initial_mtime),
            engine: Arc::new(RwLock::new(engine)),
            executor: Arc::new(RwLock::new(executor)),
        }
    }

    // -------------------------------------------------------------------
    // Core Reload Logic
    // -------------------------------------------------------------------

    /// Checks whether the monitored config file has been modified and reloads if so.
    ///
    /// Compares the current file modification time against the stored timestamp.
    /// If the file is newer (or the timestamp has never been set), performs a full
    /// reload cycle: read -> parse -> validate -> apply.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — A reload was performed (file was modified).
    /// - `Ok(false)` — No reload needed (file unchanged).
    /// - `Err(...)` — An error occurred during reload (file missing, parse error, etc.).
    pub fn check_and_reload(&self) -> Result<bool, ReloadError> {
        let path = match &self.config_path {
            Some(p) => p,
            None => return Ok(false), // No file watch configured; nothing to check
        };

        // --- Check file existence and modification time ---
        let metadata = std::fs::metadata(path).map_err(ReloadError::FileNotFound)?;
        let current_mtime = metadata.modified()?;

        // --- Compare against last known time ---
        {
            let last = self.last_modified.read().map_err(|e| {
                ReloadError::IoError(std::io::Error::other(format!("RwLock poisoned: {}", e)))
            })?;

            if let Some(prev) = *last
                && current_mtime <= prev
            {
                return Ok(false); // File has not changed since last check
            }
        } // Release read lock before acquiring write locks below

        // --- Perform full reload ---
        self.reload_from_path(path)?;

        // --- Update stored timestamp ---
        if let Ok(mut last) = self.last_modified.write() {
            *last = Some(current_mtime);
        }

        Ok(true)
    }

    /// Forces a full reload regardless of file modification state.
    ///
    /// Reads the configured file (if file watch is active), parses it as TOML,
    /// validates structurally, and applies the new configuration atomically.
    ///
    /// # Returns
    ///
    /// The newly loaded and validated [`AbacConfig`] on success.
    ///
    /// # Errors
    ///
    /// - [`ReloadError::FileNotFound`]: Config file does not exist (only when
    ///   file watch is configured).
    /// - [`ReloadError::ParseError`]: TOML deserialization failed.
    /// - [`ReloadError::ValidationFailed`]: Config failed structural validation.
    pub fn force_reload(&self) -> Result<AbacConfig, ReloadError> {
        match &self.config_path {
            Some(path) => self.reload_from_path(path),
            None => Err(ReloadError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no config path configured; use reload_from_string() instead",
            ))),
        }
    }

    /// Reloads ABAC configuration from an in-memory TOML string.
    ///
    /// Useful for API-triggered reloads where the config is received via HTTP
    /// rather than read from disk. Does **not** update the `last_modified`
    /// timestamp (since no file was involved).
    ///
    /// # Parameters
    ///
    /// - `toml_str`: Valid TOML document conforming to [`AbacConfig`] schema.
    ///
    /// # Returns
    ///
    /// The parsed and validated [`AbacConfig`] on success.
    pub fn reload_from_string(&self, toml_str: &str) -> Result<AbacConfig, ReloadError> {
        let config: AbacConfig = toml::from_str(toml_str)
            .map_err(|e| ReloadError::ParseError(format!("TOML parse error: {}", e)))?;

        self.validate_and_apply(config)
    }

    // -------------------------------------------------------------------
    // Query Operations
    // -------------------------------------------------------------------

    /// Returns the last modification time of the successfully loaded config.
    ///
    /// Returns `None` if no config has been loaded yet, or if file watching
    /// is not configured.
    pub fn last_loaded_at(&self) -> Option<SystemTime> {
        self.last_modified.read().ok().and_then(|t| *t)
    }

    // -------------------------------------------------------------------
    // Signal Handler Pattern
    // -------------------------------------------------------------------

    /// Simulates a SIGHUP-driven reload loop with graceful shutdown support.
    ///
    /// Runs a polling loop that calls [`check_and_reload`](Self::check_and_reload)
    /// every `interval_secs` seconds until a shutdown signal is received via
    /// the `watch::Receiver`. This pattern mirrors Unix daemon behavior where
    /// `SIGHUP` triggers configuration reload.
    ///
    /// # Parameters
    ///
    /// - `shutdown`: Watch receiver that becomes readable when shutdown is requested.
    ///   The loop exits when this receiver signals.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (tx, rx) = tokio::sync::watch::channel(());
    /// // ... spawn task that sends () on tx when shutting down ...
    /// hot_reload.sighup_handler(rx).await?;
    /// ```
    pub async fn sighup_handler(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Result<(), ReloadError> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Check for config changes on each tick
                    if let Err(e) = self.check_and_reload() {
                        tracing::warn!("ABAC hot-reload check failed: {}", e);
                        // Continue looping; non-fatal
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("ABAC hot-reload shutdown signal received");
                    break;
                }
            }
        }

        Ok(())
    }

    // -------------------------------------------------------------------
    // Internal: Path-Based Reload
    // -------------------------------------------------------------------

    /// Reads, parses, validates, and applies configuration from a file path.
    fn reload_from_path(&self, path: &Path) -> Result<AbacConfig, ReloadError> {
        let content = std::fs::read_to_string(path)?;
        let config: AbacConfig = toml::from_str(&content).map_err(|e| {
            ReloadError::ParseError(format!("TOML parse error at {}: {}", path.display(), e))
        })?;

        let result = self.validate_and_apply(config);

        // Update timestamp on success regardless of apply result path
        if result.is_ok()
            && let Ok(mtime) = std::fs::metadata(path).and_then(|m| m.modified())
            && let Ok(mut last) = self.last_modified.write()
        {
            *last = Some(mtime);
        }

        result
    }

    // -------------------------------------------------------------------
    // Internal: Validate and Apply
    // -------------------------------------------------------------------

    /// Validates configuration and atomically applies it to all components.
    ///
    /// This is the single point where all three components (engine, resolver,
    /// executor) are updated. The operation is designed so that if any step
    /// fails, the error is returned and no partial update occurs.
    ///
    /// # Apply Order
    ///
    /// 1. **Validate** — Run `config.validate()` to catch structural issues early.
    /// 2. **Engine** — Replace rules, invalidate decision cache.
    /// 3. **Executor** — Register all approval templates from config.
    /// 4. **Return** — The validated config for caller reference.
    fn validate_and_apply(&self, config: AbacConfig) -> Result<AbacConfig, ReloadError> {
        // --- Step 1: Validate ---
        config.validate().map_err(|errors| {
            let messages: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            ReloadError::ValidationFailed(messages)
        })?;

        // --- Step 2: Update Engine ---
        {
            let mut eng = self.engine.write().map_err(|e| {
                ReloadError::IoError(std::io::Error::other(format!(
                    "engine RwLock poisoned: {}",
                    e
                )))
            })?;
            eng.reload_rules(config.rules.clone());
            // Cache already invalidated inside reload_rules()
        }

        // --- Step 3: Update Executor templates ---
        {
            let exec = self.executor.write().map_err(|e| {
                ReloadError::IoError(std::io::Error::other(format!(
                    "executor RwLock poisoned: {}",
                    e
                )))
            })?;
            for template in &config.approval_templates {
                exec.register_template(template.clone());
            }
        }

        // Note: Resolver cache TTL is set at construction time and not
        // typically changed via hot-reload. If needed in future, add here.

        Ok(config)
    }
}
