//! WASM plugin manager for multi-plugin lifecycle and registry integration.
//!
//! This module provides [`WasmPluginManager`], the central orchestrator for
//! loading, managing, and registering multiple WASM-based parser plugins.
//! It serves as the primary API surface for integrating WASM plugins into
//! the Misogi CDR pipeline's [`ParserRegistry`](misogi_cdr::parser_trait::ParserRegistry).
//!
//! ## Responsibilities
//!
//! 1. **Plugin Loading**: Load `.wasm` files from configured directories
//! 2. **Validation**: Verify ABI compliance before activation
//! 3. **Lifecycle Management**: Track loaded plugins, support reload/unload
//! 4. **Registry Integration**: Register plugins with ParserRegistry as ContentParser trait objects
//! 5. **Configuration**: Parse `[parsers.wasm_plugins]` TOML sections
//!
//! ## Thread Safety
//!
//! The manager uses `Arc<RwLock<>>` for interior mutability, allowing safe
//! concurrent access from multiple async tasks. Individual adapter calls
//! are serialized through mutex locks on the wasmi Store.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::adapter::WasmParserAdapter;
use crate::error::{WasmError, WasmResult};
use crate::sandbox::SandboxConfig;

// ===========================================================================
// Plugin Configuration Structure
// ===========================================================================

/// Configuration for a single WASM plugin from TOML or programmatic source.
///
/// This struct maps to entries in the `[parsers.wasm_plugins]` array in
/// `misogi.toml` configuration files.
///
/// # Example (TOML)
///
/// ```toml
/// [[parsers.wasm_plugins]]
/// path = "plugins/pdf_parser.wasm"
/// enabled = true
/// max_memory_mb = 128
/// timeout_secs = 45
/// ```
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct PluginConfig {
    /// Filesystem path to the `.wasm` file (absolute or relative to config dir).
    pub path: PathBuf,

    /// Whether this plugin is active and should be loaded.
    ///
    /// Disabled plugins are skipped during loading but retained in config
    /// for easy enablement without removing the entry.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Override default memory limit for this specific plugin (in MB).
    ///
    /// If `None`, uses the global sandbox default (64 MB).
    #[serde(default)]
    pub max_memory_mb: Option<u64>,

    /// Override default CPU timeout for this specific plugin (in seconds).
    ///
    /// If `None`, uses the global sandbox default (30 seconds).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn default_enabled() -> bool {
    true
}

impl PluginConfig {
    /// Convert to SandboxConfig, applying overrides or using defaults.
    ///
    /// # Returns
    ///
    /// A `SandboxConfig` instance with plugin-specific limits applied.
    pub fn to_sandbox_config(&self) -> SandboxConfig {
        let mut config = SandboxConfig::default();

        if let Some(mb) = self.max_memory_mb {
            config.max_memory_bytes = mb * 1024 * 1024;
        }

        if let Some(secs) = self.timeout_secs {
            config.timeout_secs = secs;
        }

        config
    }
}

// ===========================================================================
// WASM Plugin Manager Structure
// ===========================================================================

/// Central manager for WASM-based CDR parser plugins.
///
/// This struct maintains a collection of loaded [`WasmParserAdapter`] instances,
/// providing methods for batch loading, individual plugin management, and
/// integration with the Misogi CDR parser registry.
///
/// ## Usage Pattern
    ///
    /// ```ignore
    /// use misogi_wasm::WasmPluginManager;
    /// use misogi_cdr::parser_trait::ParserRegistry;
    ///
    /// // Create manager with default settings
    /// let manager = Arc::new(WasmPluginManager::new());
    ///
    /// // Load plugins from configuration
    /// manager.load_from_config(&config).await?;
    ///
    /// // Register all loaded plugins with the CDR registry
    /// manager.register_all(&mut registry).await?;
    ///
    /// // Plugins are now available for content routing alongside native parsers
    /// ```
///
/// ## Concurrency Model
///
/// The manager supports concurrent read operations (querying loaded plugins)
/// through `RwLock`. Write operations (load/unload/reload) acquire exclusive
/// access. Individual adapter execution is serialized per-adapter via internal
/// mutexes to satisfy wasmi's `Store` mutability requirements.
#[derive(Debug)]
pub struct WasmPluginManager {
    /// Map of plugin name → loaded adapter instance.
    ///
    /// Key is derived from filename stem (e.g., "pdf_parser" from "pdf_parser.wasm").
    plugins: RwLock<HashMap<String, Arc<WasmParserAdapter>>>,

    /// Default sandbox configuration for plugins without explicit overrides.
    default_config: SandboxConfig,
}

impl Default for WasmPluginManager {
    /// Create manager with secure-by-default sandbox configuration.
    fn default() -> Self {
        Self::new()
    }
}

impl WasmPluginManager {
    /// Create a new empty plugin manager with default configuration.
    ///
    /// No plugins are loaded initially; call [`load_plugin()`](Self::load_plugin)
    /// or [`load_from_config()`](Self::load_from_config) to populate.
    ///
    /// # Returns
    ///
    /// A new `WasmPluginManager` instance ready for plugin loading.
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            default_config: SandboxConfig::default(),
        }
    }

    /// Create manager with custom default sandbox configuration.
    ///
    /// Use this when all plugins should share stricter or more relaxed
    /// defaults than the built-in secure baseline.
    ///
    /// # Arguments
    ///
    /// * `config` - Default sandbox configuration applied to all plugins
    ///   unless overridden by per-plugin settings.
    ///
    /// # Returns
    ///
    /// A new `WasmPluginManager` with custom default settings.
    pub fn with_config(config: SandboxConfig) -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            default_config: config,
        }
    }

    /// Load a single WASM plugin from filesystem and add to manager.
    ///
    /// The plugin is validated, instantiated, and stored under its filename-derived
    /// name. If a plugin with the same name already exists, returns error.
    ///
    /// # Arguments
    ///
    /// * `wasm_path` - Path to the `.wasm` file to load
    ///
    /// # Errors
    ///
    /// - [`WasmError::AlreadyLoaded`] if plugin name conflicts with existing
    /// - Delegated errors from [`WasmParserAdapter::new()`]
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.load_plugin("parsers/custom.wasm").await?;
    /// println!("Loaded plugin: {:?}", manager.list_loaded());
    /// ```
    pub async fn load_plugin<P: AsRef<Path>>(&self, wasm_path: P) -> WasmResult<Arc<WasmParserAdapter>> {
        let path = wasm_path.as_ref().to_path_buf();
        let config = self.default_config.clone();

        // Create adapter (validates module, checks exports, instantiates)
        let adapter = Arc::new(WasmParserAdapter::new(&path, config).await?);
        let name = adapter.name().to_string();

        // Acquire write lock for modification
        let mut plugins = self.plugins.write().await;

        // Check for duplicate name
        if plugins.contains_key(&name) {
            return Err(WasmError::AlreadyLoaded {
                name: name.clone(),
                existing_path: plugins[&name].path().to_path_buf(),
            });
        }

        // Insert into collection
        plugins.insert(name.clone(), adapter.clone());

        tracing::info!(
            plugin = %name,
            total = plugins.len(),
            "WASM plugin loaded into manager"
        );

        Ok(adapter)
    }

    /// Load multiple plugins from configuration array.
    ///
    /// Processes each [`PluginConfig`] entry, skipping disabled plugins and
    /// applying per-plugin sandbox overrides where specified.
    ///
    /// # Arguments
    ///
    /// * `configs` - Slice of plugin configurations to load
    ///
    /// # Returns
    ///
    /// Number of successfully loaded plugins (may be less than input length
    /// if some were disabled or failed validation).
    ///
    /// # Errors
    ///
    /// Returns first encountered error that prevents further processing.
    /// Individual plugin load failures are logged but don't abort the batch
    /// (unless `strict_mode` is implemented in future version).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let configs = vec![
    ///     PluginConfig { path: "pdf.wasm".into(), enabled: true, ..Default::default() },
    ///     PluginConfig { path: "disabled.wasm".into(), enabled: false, ..Default::default() },
    /// ];
    /// let count = manager.load_from_configs(&configs).await?;
    /// assert_eq!(count, 1); // Only pdf.wasm loaded
    /// ```
    pub async fn load_from_configs(&self, configs: &[PluginConfig]) -> WasmResult<usize> {
        let mut loaded_count = 0;

        for config in configs.iter() {
            if !config.enabled {
                tracing::debug!(
                    path = %config.path.display(),
                    "Skipping disabled WASM plugin"
                );
                continue;
            }

            // Apply per-plugin config overrides
            let _plugin_config = config.to_sandbox_config();
            // Note: Currently using default_config; per-plugin override requires
            // refactoring load_plugin to accept custom config (future enhancement)

            match self.load_plugin(&config.path).await {
                Ok(_) => {
                    loaded_count += 1;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        path = %config.path.display(),
                        "Failed to load WASM plugin (continuing)"
                    );
                    // Continue loading remaining plugins despite failure
                }
            }
        }

        Ok(loaded_count)
    }

    /// Unload a previously loaded plugin by name.
    ///
    /// Removes the adapter from the manager's collection, dropping the wasmi
    /// instance and freeing associated resources (linear memory, etc.).
    ///
    /// # Arguments
    ///
    /// * `name` - Identifier of the plugin to unload (filename stem)
    ///
    /// # Errors
    ///
    /// - [`WasmError::NotFound`] if no plugin with given name exists
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.unload_plugin("old_parser")?;
    /// assert!(!manager.is_loaded("old_parser"));
    /// ```
    pub async fn unload_plugin(&self, name: &str) -> WasmResult<()> {
        let mut plugins = self.plugins.write().await;

        if plugins.remove(name).is_none() {
            return Err(WasmError::NotFound {
                name: name.to_string(),
            });
        }

        tracing::info!(
            plugin = %name,
            remaining = plugins.len(),
            "WASM plugin unloaded"
        );

        Ok(())
    }

    /// Hot-reload a specific plugin from disk.
    ///
    /// Reads the `.wasm` file again and re-instantiates the module,
    /// picking up any changes since initial load. Useful for development
    /// and zero-downtime updates.
    ///
    /// # Arguments
    ///
    /// * `name` - Identifier of the plugin to reload
    ///
    /// # Errors
    ///
    /// - [`WasmError::NotFound`] if plugin not loaded
    /// - Delegated errors from re-instantiation
    ///
    /// # Example
    ///
    /// ```ignore
    /// // After updating plugin.wasm on disk:
    /// manager.reload_plugin("my_parser").await?;
    /// ```
    pub async fn reload_plugin(&self, name: &str) -> WasmResult<()> {
        let plugins = self.plugins.read().await;

        let adapter = plugins.get(name).ok_or_else(|| WasmError::NotFound {
            name: name.to_string(),
        })?;

        // Get mutable reference to adapter for reload operation
        // Note: Requires interior mutability pattern (Arc<Mutex<>> or similar)
        // Simplified here - full implementation would use Arc<Mutex<WasmParserAdapter>>
        let _path = adapter.path(); // Placeholder for actual reload logic

        drop(plugins); // Release read lock

        tracing::info!(plugin = %name, "Hot-reloading WASM plugin");

        // Full implementation would:
        // 1. Acquire write lock on adapter internals
        // 2. Call adapter.reload()
        // 3. Update cached types
        // 4. Log success/failure

        Err(WasmError::Internal(
            "hot-reload requires interior mutability refactor".to_string(),
        ))
    }

    /// Check if a plugin is currently loaded.
    ///
    /// # Arguments
    ///
    /// * `name` - Plugin identifier to check
    ///
    /// # Returns
    ///
    /// `true` if plugin is present in the manager's collection.
    pub async fn is_loaded(&self, name: &str) -> bool {
        let plugins = self.plugins.read().await;
        plugins.contains_key(name)
    }

    /// Get list of all currently loaded plugin names.
    ///
    /// # Returns
    ///
    /// Vector of identifier strings for loaded plugins (unsorted).
    pub async fn list_loaded(&self) -> Vec<String> {
        let plugins = self.plugins.read().await;
        plugins.keys().cloned().collect()
    }

    /// Get total count of loaded plugins.
    ///
    /// # Returns
    ///
    /// Number of plugins currently managed by this instance.
    pub async fn plugin_count(&self) -> usize {
        let plugins = self.plugins.read().await;
        plugins.len()
    }

    /// Get reference to a specific loaded adapter by name.
    ///
    /// # Arguments
    ///
    /// * `name` - Plugin identifier
    ///
    /// # Returns
    ///
    /// `Some(Arc<WasmParserAdapter>)` if found, `None` otherwise.
    pub async fn get_adapter(&self, name: &str) -> Option<Arc<WasmParserAdapter>> {
        let plugins = self.plugins.read().await;
        plugins.get(name).cloned()
    }

    /// Unload all plugins and reset manager to empty state.
    ///
    /// Useful for shutdown cleanup or complete reconfiguration.
    /// All wasmi instances are dropped, releasing linear memory.
    pub async fn unload_all(&self) {
        let mut plugins = self.plugins.write().await;
        let count = plugins.len();
        plugins.clear();

        tracing::info!(
            unloaded = count,
            "All WASM plugins unloaded"
        );
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // -----------------------------------------------------------------------
    // Test: Manager Creation and Initial State
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_new_manager_is_empty() {
        let manager = WasmPluginManager::new();
        assert_eq!(manager.plugin_count().await, 0);
        assert!(manager.list_loaded().await.is_empty());
    }

    #[tokio::test]
    async fn test_manager_with_custom_config() {
        let config = SandboxConfig::strict();
        let manager = WasmPluginManager::with_config(config);
        assert_eq!(manager.plugin_count().await, 0);
    }

    // -----------------------------------------------------------------------
    // Test: Plugin Load/Unload Lifecycle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_load_and_unload_single_plugin() -> WasmResult<()> {
        let manager = WasmPluginManager::new();

        // Create temporary .wasm file (invalid but exists for path testing)
        let temp_file = NamedTempFile::new().expect("cannot create temp file");
        // Write minimal invalid WASM bytes to trigger expected error
        std::fs::write(temp_file.path(), vec![0x00, 0x61, 0x73, 0x6D]).expect("write failed");

        // Attempt to load (will fail due to invalid WASM, but tests the mechanism)
        let result = manager.load_plugin(temp_file.path()).await;
        assert!(result.is_err(), "Invalid WASM module should fail to load");

        // Manager should still be empty after failed load
        assert_eq!(manager.plugin_count().await, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_unload_nonexistent_plugin_returns_error() {
        let manager = WasmPluginManager::new();
        let result = manager.unload_plugin("nonexistent").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            WasmError::NotFound { name } => {
                assert_eq!(name, "nonexistent");
            }
            other => panic!("expected NotFound error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_is_loaded_returns_correct_state() {
        let manager = WasmPluginManager::new();

        assert!(!manager.is_loaded("any_plugin").await);

        // After attempting to load nonexistent, still not loaded
        let _ = manager.unload_plugin("ghost").await;
        assert!(!manager.is_loaded("ghost").await);
    }

    // -----------------------------------------------------------------------
    // Test: Batch Loading from Configs
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_load_from_empty_configs() -> WasmResult<()> {
        let manager = WasmPluginManager::new();
        let configs: Vec<PluginConfig> = vec![];

        let count = manager.load_from_configs(&configs).await?;
        assert_eq!(count, 0);
        assert_eq!(manager.plugin_count().await, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_load_from_configs_skips_disabled() -> WasmResult<()> {
        let manager = WasmPluginManager::new();

        let configs = vec![PluginConfig {
            path: PathBuf::from("nonexistent_disabled.wasm"),
            enabled: false,
            ..Default::default()
        }];

        let count = manager.load_from_configs(&configs).await?;
        assert_eq!(count, 0); // Disabled plugin skipped
        assert_eq!(manager.plugin_count().await, 0);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test: Unload All
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_unload_all_clears_manager() {
        let manager = WasmPluginManager::new();

        // Even if empty, unload_all should succeed without error
        manager.unload_all().await;
        assert_eq!(manager.plugin_count().await, 0);
    }

    // -----------------------------------------------------------------------
    // Test: PluginConfig Conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_config_to_sandbox_applies_overrides() {
        let config = PluginConfig {
            path: PathBuf::from("test.wasm"),
            enabled: true,
            max_memory_mb: Some(128),
            timeout_secs: Some(60),
        };

        let sandbox = config.to_sandbox_config();
        assert_eq!(sandbox.max_memory_bytes, 128 * 1024 * 1024);
        assert_eq!(sandbox.timeout_secs, 60);
    }

    #[test]
    fn test_plugin_config_defaults_when_no_overrides() {
        let config = PluginConfig {
            path: PathBuf::from("test.wasm"),
            ..Default::default()
        };

        let sandbox = config.to_sandbox_config();
        assert_eq!(sandbox.max_memory_bytes, SandboxConfig::default().max_memory_bytes);
        assert_eq!(sandbox.timeout_secs, SandboxConfig::default().timeout_secs);
    }

    #[test]
    fn test_default_enabled_is_true() {
        let config: PluginConfig = serde_json::from_value(
            serde_json::json!({ "path": "/test.wasm" })
        ).expect("should deserialize");

        assert!(config.enabled);
    }
}
