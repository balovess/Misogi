// =============================================================================
// StorageRegistry — Thread-Safe Storage Backend Manager (Pillar 2)
// =============================================================================
// Provides a centralized, concurrent-safe registry for [`StorageBackend`]
// instances. Enables runtime registration, lookup, removal, and convenience
// operations across multiple storage backends by name.
//
// # Architecture Position
//
// `StorageRegistry` sits between the plugin system and concrete backend
// implementations, serving as the single source of truth for "which backends
// are available in this runtime instance".
//
// # Thread Safety Model
//
// Internal state is protected by `RwLock<HashMap<...>>`. Read operations
// (`get`, `list`, `names`) acquire shared (read) locks and may proceed
// concurrently. Write operations (`register`, `remove`) acquire exclusive
// (write) locks and serialize with all other operations. Lock hold times
// are minimized: no I/O occurs while holding any lock.
//
// # Concurrency Guarantees
//
// - Multiple readers can access the registry simultaneously.
// - Writers block all readers and other writers during mutation.
// - No deadlock risk: only one lock exists; no nested acquisition.
// - Panic safety: `RwLock` is poisoning-aware; if a thread panics while
//   holding the lock, subsequent calls return `Err(PoisonError)`.
//
// # Default Backend Convention
//
// The registry recognizes the special name `"default"` as the default
// backend. Callers use `get_default()` to retrieve it without knowing
// the exact registered name. This enables configuration-driven default
// selection.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use tracing::{debug, info, warn};

use crate::traits::storage::{StorageBackend, StorageError, StorageInfo};
use crate::storage::local::{LocalConfig, LocalStorage};

#[cfg(feature = "storage-s3")]
use crate::storage::s3::{S3Config, S3Storage};

#[cfg(feature = "storage-azure")]
use crate::storage::azure_blob::{AzureBlobConfig, AzureBlobStorage};

#[cfg(feature = "storage-gcs")]
use crate::storage::gcs::{GcsConfig, GcsStorage};

use crate::storage::api_forward::{ApiForwardConfig, ApiForwardStorage, HttpMethod};

// ---------------------------------------------------------------------------
// StorageBackendInfo — Lightweight metadata for listed backends
// ---------------------------------------------------------------------------

/// Metadata snapshot of a registered storage backend.
///
/// Returned by [`StorageRegistry::list()`] to provide callers with a
/// summary of available backends without exposing the full trait object.
/// Contains only name and type identifier -- sufficient for UI display,
/// logging, and administrative dashboards.
///
/// # Fields
///
/// | Field         | Description                                    |
/// |---------------|------------------------------------------------|
/// | `name`        | Registration key used for lookup               |
/// | `backend_type`| Implementation identifier from `backend_type()` |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageBackendInfo {
    /// Registration name (unique within this registry).
    pub name: String,

    /// Backend type identifier (e.g., `"local"`, `"s3"`, `"api_forward"`).
    pub backend_type: String,
}

impl StorageBackendInfo {
    /// Create a new [`StorageBackendInfo`] from name and type strings.
    pub fn new(name: impl Into<String>, backend_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            backend_type: backend_type.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// TOML Configuration Parsers (for async backends without Deserialize)
// ---------------------------------------------------------------------------

/// Parse `[storage.azure_blob]` table into [`AzureBlobConfig`] manually.
///
/// Required fields: `account_name`, `credential`, `container`
/// Optional fields: `endpoint` (String), `sas_url_ttl_secs` (integer, default 3600)
#[cfg(feature = "storage-azure")]
fn parse_azure_blob_config(
    storage_table: &toml::Table,
) -> Result<AzureBlobConfig, StorageError> {
    let az_table = storage_table
        .get("azure_blob")
        .and_then(|v| v.as_table())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "missing or invalid [storage.azure_blob] table".into(),
            )
        })?;

    let account_name = az_table
        .get("account_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "[storage.azure_blob] requires 'account_name'".into(),
            )
        })?
        .to_string();

    let credential = az_table
        .get("credential")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "[storage.azure_blob] requires 'credential'".into(),
            )
        })?
        .to_string();

    let container = az_table
        .get("container")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "[storage.azure_blob] requires 'container'".into(),
            )
        })?
        .to_string();

    let endpoint = az_table
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(String::from);

    let sas_url_ttl_secs = az_table
        .get("sas_url_ttl_secs")
        .and_then(|v| v.as_integer())
        .unwrap_or(3600) as u64;

    let mut config = AzureBlobConfig::new(account_name, credential, container);
    if let Some(ep) = endpoint {
        config = config.with_endpoint(ep);
    }
    config = config.with_sas_url_ttl(sas_url_ttl_secs);

    Ok(config)
}

/// Parse `[storage.gcs]` table into [`GcsConfig`] manually.
///
/// Required fields: `bucket`
/// Optional fields: `service_account_json` (string), `service_account_key_path` (string), `base_url` (string)
#[cfg(feature = "storage-gcs")]
fn parse_gcs_config(
    storage_table: &toml::Table,
) -> Result<GcsConfig, StorageError> {
    let gcs_table = storage_table
        .get("gcs")
        .and_then(|v| v.as_table())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "missing or invalid [storage.gcs] table".into(),
            )
        })?;

    let bucket = gcs_table
        .get("bucket")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "[storage.gcs] requires 'bucket'".into(),
            )
        })?
        .to_string();

    let service_account_json = gcs_table
        .get("service_account_json")
        .and_then(|v| v.as_str())
        .map(String::from);

    let service_account_key_path = gcs_table
        .get("service_account_key_path")
        .and_then(|v| v.as_str())
        .map(String::from);

    let base_url = gcs_table
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut config = GcsConfig::new(bucket);
    if let Some(json) = service_account_json {
        config = config.with_service_account_json(json);
    }
    if let Some(path) = service_account_key_path {
        config = config.with_service_account_key_path(path);
    }
    if let Some(url) = base_url {
        config = config.with_base_url(url);
    }

    Ok(config)
}

/// Parse `[storage.s3]` table into [`S3Config`] manually.
///
/// Required fields: `bucket`, `region`, `access_key`, `secret_key`
/// Optional fields: `endpoint` (String), `presigned_url_ttl_secs` (integer), `path_style` (bool)
#[cfg(feature = "storage-s3")]
fn parse_s3_config(storage_table: &toml::Table) -> Result<S3Config, StorageError> {
    let s3_table = storage_table
        .get("s3")
        .and_then(|v| v.as_table())
        .ok_or_else(|| {
            StorageError::ConfigurationError(
                "missing or invalid [storage.s3] table".into(),
            )
        })?;

    let bucket = s3_table
        .get("bucket")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError("[storage.s3] requires 'bucket'".into())
        })?
        .to_string();

    let region = s3_table
        .get("region")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError("[storage.s3] requires 'region'".into())
        })?
        .to_string();

    let access_key = s3_table
        .get("access_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError("[storage.s3] requires 'access_key'".into())
        })?
        .to_string();

    let secret_key = s3_table
        .get("secret_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StorageError::ConfigurationError("[storage.s3] requires 'secret_key'".into())
        })?
        .to_string();

    let endpoint = s3_table
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(String::from);

    let presigned_url_ttl_secs = s3_table
        .get("presigned_url_ttl_secs")
        .and_then(|v| v.as_integer())
        .unwrap_or(3600) as u64;

    let path_style = s3_table
        .get("path_style")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(S3Config {
        bucket,
        region,
        endpoint,
        access_key,
        secret_key,
        presigned_url_ttl_secs,
        path_style,
        multipart: None,
    })
}

// ---------------------------------------------------------------------------
// StorageRegistry — Core Registry Struct
// ---------------------------------------------------------------------------

/// Thread-safe registry for managing multiple [`StorageBackend`] instances.
///
/// Acts as the central directory for all storage backends in the Misogi
/// runtime. Supports registration by name, retrieval, removal, listing,
/// and convenience methods that combine lookup + operation into single calls.
///
/// # Usage Pattern
///
/// ```ignore
/// let registry = StorageRegistry::new();
/// registry.register("primary", Box::new(local_storage))?;
/// registry.register("archive", Box::new(s3_storage))?;
///
/// // Convenience: store data without manually resolving the backend
/// let info = registry.put_to("primary", "doc.pdf", data).await?;
/// let data = registry.get_from("archive", "backup.tar").await?;
/// ```
///
/// # Default Backend
///
/// A backend registered under the name `"default"` is accessible via
/// [`StorageRegistry::get_default()`]. This is typically set during
/// configuration loading via [`StorageRegistry::from_config()`].
///
/// # Internal Representation
///
/// Backends are stored as `Arc<Box<dyn StorageBackend>>` internally:
/// - The outer `Arc` enables cheap cloning for [`get()`] return values.
/// - The inner `Box` is `Sized`, enabling [`remove()`] to extract ownership
///   via `Arc::try_unwrap()` when this is the sole reference.
pub struct StorageRegistry {
    /// Internal storage: name -> backend mapping protected by RwLock.
    ///
    /// `Arc<Box<dyn StorageBackend>>` is used instead of `Arc<dyn StorageBackend>`
    /// so that `remove()` can call `Arc::try_unwrap()` to recover ownership:
    /// `Box<T>` is always `Sized`, whereas `dyn Trait` is not.
    backends: RwLock<HashMap<String, Arc<Box<dyn StorageBackend>>>>,
}

impl StorageRegistry {
    /// Create an empty [`StorageRegistry`] with no registered backends.
    ///
    /// The registry starts empty. Backends must be registered via
    /// [`StorageRegistry::register()`] or loaded via
    /// [`StorageRegistry::from_config()`] before use.
    pub fn new() -> Self {
        debug!("StorageRegistry initialized (empty)");
        Self {
            backends: RwLock::new(HashMap::new()),
        }
    }

    // --- Registration Operations ---

    /// Register a storage backend under the given name.
    ///
    /// Takes ownership of the backend (via `Box<dyn StorageBackend>`)
    /// and wraps it in `Arc<>` for shared access. After registration,
    /// the backend is immediately visible to all threads via `get()`,
    /// `list()`, and convenience methods.
    ///
    /// # Arguments
    /// * `name` - Unique identifier for this backend (case-sensitive).
    /// * `backend` - The storage backend implementation to register.
    ///
    /// # Errors
    /// Returns [`StorageError::AlreadyExists`] if a backend is already
    /// registered under the same name. Callers must `remove()` first
    /// if they intend to replace an existing registration.
    ///
    /// # Example
    /// ```ignore
    /// let local = LocalStorage::new("/data/misogi")?;
    /// registry.register("production", Box::new(local))?;
    /// ```
    pub fn register(
        &self,
        name: &str,
        backend: Box<dyn StorageBackend>,
    ) -> Result<(), StorageError> {
        let mut guard = self
            .backends
            .write()
            .map_err(|e| StorageError::InternalError(format!("registry lock poisoned: {e}")))?;

        if guard.contains_key(name) {
            warn!(name = %name, "attempted duplicate backend registration");
            return Err(StorageError::AlreadyExists(format!(
                "backend '{name}' already registered"
            )));
        }

        let backend_type = backend.backend_type().to_string();
        guard.insert(name.to_string(), Arc::new(backend));
        info!(
            name = %name,
            backend_type = %backend_type,
            "storage backend registered"
        );
        Ok(())
    }

    /// Remove a registered backend and return ownership of it.
    ///
    /// After removal, the backend is no longer accessible via `get()` or
    /// convenience methods. The caller receives ownership (via `Box`),
    /// enabling clean shutdown or re-registration under a different name.
    ///
    /// # Arguments
    /// * `name` - The registration name to remove.
    ///
    /// # Errors
    /// - [`StorageError::NotFound`] if no backend is registered under the name.
    /// - [`StorageError::InternalError`] if outstanding `Arc` references exist,
    ///   preventing ownership recovery via `Arc::try_unwrap()`.
    ///
    /// # Note
    /// Any `Arc<>` clones previously returned by `get()` remain valid
    /// until all references are dropped. If such clones exist when `remove()`
    /// is called, the operation fails with an error and the registration
    /// remains intact.
    pub fn remove(&self, name: &str) -> Result<Box<dyn StorageBackend>, StorageError> {
        let mut guard = self
            .backends
            .write()
            .map_err(|e| StorageError::InternalError(format!("registry lock poisoned: {e}")))?;

        match guard.remove(name) {
            Some(arc) => {
                // Arc::try_unwrap succeeds only when this is the sole strong reference.
                // Since T = Box<dyn StorageBackend> IS Sized, this compiles and allows
                // us to recover the original Box that was passed to register().
                match Arc::try_unwrap(arc) {
                    Ok(backend_box) => {
                        info!(name = %name, "storage backend removed");
                        Ok(backend_box)
                    }
                    Err(arc) => {
                        // Other Arc clones still exist; cannot safely extract ownership.
                        warn!(
                            name = %name,
                            "cannot remove backend: outstanding Arc references exist \
                             (strong_count={})",
                            Arc::strong_count(&arc)
                        );
                        // Re-insert so the registration stays consistent.
                        guard.insert(name.to_string(), arc);
                        Err(StorageError::InternalError(format!(
                            "cannot remove backend '{name}': {} outstanding Arc reference(s) exist",
                            Arc::strong_count(
                                &guard.get(name).expect("just re-inserted")
                            )
                        )))
                    }
                }
            }
            None => {
                warn!(name = %name, "attempted removal of unregistered backend");
                Err(StorageError::NotFound(format!(
                    "backend '{name}' not found"
                )))
            }
        }
    }

    // --- Lookup Operations ---

    /// Retrieve a registered backend by name.
    ///
    /// Returns a clone of the internal `Arc<Box<dyn StorageBackend>>`,
    /// which auto-derefs to allow calling [`StorageBackend`] trait methods
    /// directly on the returned value.
    ///
    /// # Arguments
    /// * `name` - The registration name to look up.
    ///
    /// # Returns
    /// - `Some(Arc)` if the backend is registered.
    /// - `None` if no backend exists under that name.
    pub fn get(&self, name: &str) -> Option<Arc<Box<dyn StorageBackend>>> {
        let guard = self.backends.read().ok()?;

        guard.get(name).cloned()
    }

    /// Retrieve the `"default"` backend, if one was registered.
    ///
    /// Convenience shorthand for `get("default")`. Used when the
    /// application has configured a primary/default storage target
    /// and callers should not need to know its explicit name.
    ///
    /// # Returns
    /// - `Some(Arc)` if a backend named `"default"` exists.
    /// - `None` otherwise.
    pub fn get_default(&self) -> Option<Arc<Box<dyn StorageBackend>>> {
        self.get("default")
    }

    /// List all registered backends with their metadata.
    ///
    /// Returns a snapshot vector of [`StorageBackendInfo`] containing
    /// each backend's name and type identifier. The order is unspecified
    /// (depends on HashMap iteration order).
    ///
    /// # Returns
    /// Vector of [`StorageBackendInfo`]; empty if no backends registered.
    pub fn list(&self) -> Vec<StorageBackendInfo> {
        let guard = match self.backends.read() {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "registry lock poisoned during list()");
                return Vec::new();
            }
        };

        guard
            .iter()
            .map(|(name, backend)| StorageBackendInfo {
                name: name.clone(),
                backend_type: backend.backend_type().to_string(),
            })
            .collect()
    }

    /// List all registered backend names (metadata-free).
    ///
    /// Lighter-weight alternative to [`StorageRegistry::list()`] when
    /// only names are needed (e.g., for dropdown menus, validation).
    ///
    /// # Returns
    /// Vector of name strings; empty if no backends registered.
    pub fn names(&self) -> Vec<String> {
        let guard = match self.backends.read() {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "registry lock poisoned during names()");
                return Vec::new();
            }
        };

        guard.keys().cloned().collect()
    }

    // --- Convenience Operations ---

    /// Store data on a named backend (lookup + put combined).
    ///
    /// Resolves the backend by `name`, then invokes
    /// [`StorageBackend::put()`] on it. Eliminates the common pattern
    /// of `registry.get(name)?.put(key, data).await`.
    ///
    /// # Arguments
    /// * `name` - Registered backend name.
    /// * `key` - Storage key (passed through to the backend).
    /// * `data` - Binary content to store.
    ///
    /// # Errors
    /// - [`StorageError::NotFound`] if `name` is not registered.
    /// - Any error from the underlying `put()` operation.
    pub async fn put_to(
        &self,
        name: &str,
        key: &str,
        data: Bytes,
    ) -> Result<StorageInfo, StorageError> {
        let backend = self.get(name).ok_or_else(|| {
            StorageError::NotFound(format!("backend '{name}' not found"))
        })?;

        backend.put(key, data).await
    }

    /// Retrieve data from a named backend (lookup + get combined).
    ///
    /// Resolves the backend by `name`, then invokes
    /// [`StorageBackend::get()`] on it. Eliminates the common pattern
    /// of `registry.get(name)?.get(key).await`.
    ///
    /// # Arguments
    /// * `name` - Registered backend name.
    /// * `key` - Storage key (passed through to the backend).
    ///
    /// # Errors
    /// - [`StorageError::NotFound`] if `name` is not registered.
    /// - [`StorageError::NotFound`] if `key` does not exist in the backend.
    /// - Any error from the underlying `get()` operation.
    pub async fn get_from(&self, name: &str, key: &str) -> Result<Bytes, StorageError> {
        let backend = self.get(name).ok_or_else(|| {
            StorageError::NotFound(format!("backend '{name}' not found"))
        })?;

        backend.get(key).await
    }

    // --- Factory Method ---

    /// Build a [`StorageRegistry`] from TOML configuration.
    ///
    /// Parses a `toml::Value` expecting the following structure:
    ///
    /// ```toml
    /// [storage]
    /// type = "local"          # "local", "s3", or "api_forward"
    /// default = true          # optional: register as "default"
    ///
    /// [storage.local]         # backend-specific config section
    /// base_path = "/var/lib/misogi/data"
    /// create_dir_if_missing = true
    ///
    /// [storage.s3]            # only when type = "s3"
    /// bucket = "my-bucket"
    /// region = "us-east-1"
    ///
    /// [storage.api_forward]   # only when type = "api_forward"
    /// endpoint = "https://logs.example.com/api/ingest"
    /// ```
    ///
    /// # Arguments
    /// * `config` - Parsed TOML value containing `[storage]` table.
    ///
    /// # Errors
    /// - [`StorageError::ConfigurationError`] if `type` is missing or unknown,
    ///   or the required backend-specific config section is absent/malformed.
    /// - Backend-specific errors from construction (e.g., invalid path).
    pub fn from_config(config: &toml::Value) -> Result<Self, StorageError> {
        let storage_table = config
            .get("storage")
            .ok_or_else(|| {
                StorageError::ConfigurationError("missing [storage] table".into())
            })?
            .as_table()
            .ok_or_else(|| {
                StorageError::ConfigurationError("[storage] must be a table".into())
            })?;

        let backend_type = storage_table
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("local");

        let is_default = storage_table
            .get("default")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let registry = Self::new();

        match backend_type {
            "local" => {
                let local_config_value = config
                    .get("storage")
                    .and_then(|s| s.get("local"))
                    .ok_or_else(|| {
                        StorageError::ConfigurationError(
                            "missing [storage.local] config for type='local'".into(),
                        )
                    })?;

                let local_config: LocalConfig = local_config_value
                    .clone()
                    .try_into()
                    .map_err(|e| {
                        StorageError::ConfigurationError(format!(
                            "failed to parse [storage.local]: {e}"
                        ))
                    })?;

                let backend = LocalStorage::with_config(local_config)?;
                let reg_name = if is_default { "default" } else { "local" };
                registry.register(reg_name, Box::new(backend))?;
            }

            #[cfg(feature = "storage-s3")]
            "s3" => {
                let _s3_table = storage_table
                    .get("s3")
                    .and_then(|v| v.as_table())
                    .ok_or_else(|| {
                        StorageError::ConfigurationError(
                            "missing or invalid [storage.s3] table".into(),
                        )
                    })?;
                return Err(StorageError::ConfigurationError(
                    "S3 backend requires async initialization; \
                     use StorageRegistry::from_config_async() instead".into(),
                ));
            }

            #[cfg(not(feature = "storage-s3"))]
            "s3" => {
                return Err(StorageError::ConfigurationError(
                    "S3 backend requires 'storage-s3' feature flag".into(),
                ));
            }

            "api_forward" => {
                let af_table = config
                    .get("storage")
                    .and_then(|s| s.get("api_forward"))
                    .and_then(|v| v.as_table())
                    .ok_or_else(|| {
                        StorageError::ConfigurationError(
                            "missing or invalid [storage.api_forward] table".into(),
                        )
                    })?;

                // Manual TOML parsing since ApiForwardConfig does not derive Deserialize.
                let endpoint_str = af_table
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        StorageError::ConfigurationError(
                            "[storage.api_forward] requires 'endpoint' (URL string)".into(),
                        )
                    })?;

                let endpoint = endpoint_str.parse::<reqwest::Url>().map_err(|e| {
                    StorageError::ConfigurationError(format!(
                        "invalid endpoint URL '{endpoint_str}': {e}"
                    ))
                })?;

                let timeout_secs = af_table
                    .get("timeout_secs")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(30)
                    .max(1) as u64;

                let method_str = af_table
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("post");

                let method = match method_str.to_lowercase().as_str() {
                    "post" => HttpMethod::Post,
                    "put" => HttpMethod::Put,
                    other => {
                        return Err(StorageError::ConfigurationError(format!(
                            "unsupported HTTP method '{other}' (expected: post, put)"
                        )));
                    }
                };

                let auth_header = af_table
                    .get("auth_header")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Authorization")
                    .to_string();

                let auth_token = af_table
                    .get("auth_token")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let headers: HashMap<String, String> = af_table
                    .get("headers")
                    .and_then(|v| v.as_table())
                    .map(|t| {
                        t.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                let af_config = ApiForwardConfig {
                    endpoint,
                    headers,
                    auth_token,
                    auth_header,
                    timeout_secs,
                    method,
                };

                let backend = ApiForwardStorage::new(af_config)?;
                let reg_name = if is_default { "default" } else { "api_forward" };
                registry.register(reg_name, Box::new(backend))?;
            }

            #[cfg(feature = "storage-azure")]
            "azure_blob" => {
                let _config = parse_azure_blob_config(storage_table)?;
                return Err(StorageError::ConfigurationError(
                    "Azure Blob backend requires async initialization; \
                     use StorageRegistry::from_config_async() instead".into(),
                ));
            }

            #[cfg(not(feature = "storage-azure"))]
            "azure_blob" => {
                return Err(StorageError::ConfigurationError(
                    "Azure Blob backend requires 'storage-azure' feature flag".into(),
                ));
            }

            #[cfg(feature = "storage-gcs")]
            "gcs" => {
                let _config = parse_gcs_config(storage_table)?;
                return Err(StorageError::ConfigurationError(
                    "GCS backend requires async initialization; \
                     use StorageRegistry::from_config_async() instead".into(),
                ));
            }

            #[cfg(not(feature = "storage-gcs"))]
            "gcs" => {
                return Err(StorageError::ConfigurationError(
                    "GCS backend requires 'storage-gcs' feature flag".into(),
                ));
            }

            other => {
                return Err(StorageError::ConfigurationError(format!(
                    "unknown storage backend type: '{other}' \
                     (expected: 'local', 's3', 'azure_blob', 'gcs', 'api_forward')"
                )));
            }
        }

        info!(
            backend_type = %backend_type,
            is_default = is_default,
            "StorageRegistry built from TOML configuration"
        );

        Ok(registry)
    }

    /// Asynchronously build a [`StorageRegistry`] from TOML configuration.
    ///
    /// Extends [`StorageRegistry::from_config()`] to support backends that
    /// require async construction (Azure Blob Storage, Google Cloud Storage).
    ///
    /// # Supported Backend Types
    ///
    /// | Type           | Feature Flag   | Async? |
    /// |----------------|----------------|--------|
    /// | `"local"`      | (always)       | No     |
    /// | `"s3"`         | `storage-s3`   | No     |
    /// | `"api_forward"`| (always)       | No     |
    /// | `"azure_blob"` | `storage-azure`| **Yes**|
    /// | `"gcs"`        | `storage-gcs`  | **Yes**|
    pub async fn from_config_async(config: &toml::Value) -> Result<Self, StorageError> {
        let storage_table = config
            .get("storage")
            .ok_or_else(|| {
                StorageError::ConfigurationError("missing [storage] table".into())
            })?
            .as_table()
            .ok_or_else(|| {
                StorageError::ConfigurationError("[storage] must be a table".into())
            })?;

        let backend_type = storage_table
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("local");

        let is_default = storage_table
            .get("default")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        match backend_type {
            "local" | "api_forward" => {
                Self::from_config(config)
            }

            #[cfg(feature = "storage-s3")]
            "s3" => {
                let s3_config = parse_s3_config(storage_table)?;
                let backend = S3Storage::new(s3_config).await?;
                let registry = Self::new();
                let reg_name = if is_default { "default" } else { "s3" };
                registry.register(reg_name, Box::new(backend))?;
                Ok(registry)
            }

            #[cfg(not(feature = "storage-s3"))]
            "s3" => {
                Err(StorageError::ConfigurationError(
                    "S3 backend requires 'storage-s3' feature flag".into(),
                ))
            }

            #[cfg(feature = "storage-azure")]
            "azure_blob" => {
                let az_config = parse_azure_blob_config(storage_table)?;
                let backend = AzureBlobStorage::new(az_config).await?;
                let registry = Self::new();
                let reg_name = if is_default { "default" } else { "azure_blob" };
                registry.register(reg_name, Box::new(backend))?;
                Ok(registry)
            }

            #[cfg(not(feature = "storage-azure"))]
            "azure_blob" => {
                Err(StorageError::ConfigurationError(
                    "Azure Blob backend requires 'storage-azure' feature flag".into(),
                ))
            }

            #[cfg(feature = "storage-gcs")]
            "gcs" => {
                let gcs_config = parse_gcs_config(storage_table)?;
                let backend = GcsStorage::new(gcs_config).await?;
                let registry = Self::new();
                let reg_name = if is_default { "default" } else { "gcs" };
                registry.register(reg_name, Box::new(backend))?;
                Ok(registry)
            }

            #[cfg(not(feature = "storage-gcs"))]
            "gcs" => {
                Err(StorageError::ConfigurationError(
                    "GCS backend requires 'storage-gcs' feature flag".into(),
                ))
            }

            other => Err(StorageError::ConfigurationError(format!(
                "unknown storage backend type: '{other}' \
                 (expected: 'local', 's3', 'azure_blob', 'gcs', 'api_forward')"
            ))),
        }
    }

    /// Return the number of currently registered backends.
    ///
    /// Useful for testing, monitoring, and conditional logic based on
    /// whether any backends have been registered.
    pub fn len(&self) -> usize {
        match self.backends.read() {
            Ok(g) => g.len(),
            Err(_) => 0,
        }
    }

    /// Check whether the registry contains no registered backends.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for StorageRegistry {
    /// Create an empty registry (same as [`StorageRegistry::new()`]).
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StorageRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageRegistry")
            .field("backend_count", &self.len())
            .field("names", &self.names())
            .finish()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ---------------------------------------------------------------------------
    // Helper: create a real LocalStorage backed by a temp directory
    // ---------------------------------------------------------------------------

    fn make_test_local_backend(tmp_dir: &TempDir) -> LocalStorage {
        LocalStorage::with_config(LocalConfig {
            base_path: tmp_dir.path().to_path_buf(),
            create_dir_if_missing: false,
            default_permissions: None,
        })
        .expect("test LocalStorage creation must succeed")
    }

    // ---------------------------------------------------------------------------
    // Test 1: Basic registration and successful lookup
    // ---------------------------------------------------------------------------

    #[test]
    fn test_register_and_get() {
        let tmp_dir = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();
        let backend = make_test_local_backend(&tmp_dir);

        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        // Register should succeed
        let result = registry.register("primary", Box::new(backend));
        assert!(result.is_ok(), "registration should succeed: {:?}", result.err());

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);

        // Get should return Some
        let retrieved = registry.get("primary");
        assert!(retrieved.is_some(), "registered backend should be retrievable");

        // Get non-existent should return None
        assert!(registry.get("nonexistent").is_none());
    }

    // ---------------------------------------------------------------------------
    // Test 2: Duplicate registration rejection
    // ---------------------------------------------------------------------------

    #[test]
    fn test_register_duplicate_rejected() {
        let tmp_dir = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        let backend1 = make_test_local_backend(&tmp_dir);
        let backend2 = make_test_local_backend(&tmp_dir);

        registry
            .register("dup", Box::new(backend1))
            .expect("first registration should succeed");

        // Second registration with same name must fail
        let result = registry.register("dup", Box::new(backend2));
        assert!(result.is_err());

        match result.unwrap_err() {
            StorageError::AlreadyExists(msg) => {
                assert!(msg.contains("dup"), "error message should mention the name");
            }
            other => panic!("expected AlreadyExists, got: {:?}", other),
        }

        // Original backend should still be intact
        assert!(registry.get("dup").is_some());
        assert_eq!(registry.len(), 1);
    }

    // ---------------------------------------------------------------------------
    // Test 3: Get missing backend returns None
    // ---------------------------------------------------------------------------

    #[test]
    fn test_get_missing_returns_none() {
        let registry = StorageRegistry::new();

        assert!(registry.get("").is_none());
        assert!(registry.get("ghost").is_none());
        assert!(registry.get("unicode_name_special").is_none());
    }

    // ---------------------------------------------------------------------------
    // Test 4: List returns correct metadata for all backends
    // ---------------------------------------------------------------------------

    #[test]
    fn test_list_returns_all_backends() {
        let tmp_a = TempDir::new().expect("tempdir creation");
        let tmp_b = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        registry
            .register("alpha", Box::new(make_test_local_backend(&tmp_a)))
            .expect("register alpha");
        registry
            .register("beta", Box::new(make_test_local_backend(&tmp_b)))
            .expect("register beta");

        let list = registry.list();
        assert_eq!(list.len(), 2, "list should contain exactly 2 entries");

        // Verify both names appear
        let names: Vec<&str> = list.iter().map(|info| info.name.as_str()).collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));

        // Verify backend_type is populated correctly
        for info in &list {
            assert_eq!(info.backend_type, "local", "all test backends should report type='local'");
            assert!(!info.name.is_empty());
        }
    }

    // ---------------------------------------------------------------------------
    // Test 5: Names returns just the name strings
    // ---------------------------------------------------------------------------

    #[test]
    fn test_names_returns_only_names() {
        let tmp = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        registry
            .register("one", Box::new(make_test_local_backend(&tmp)))
            .expect("register one");
        registry
            .register("two", Box::new(make_test_local_backend(&tmp)))
            .expect("register two");
        registry
            .register("three", Box::new(make_test_local_backend(&tmp)))
            .expect("register three");

        let names = registry.names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"one".to_string()));
        assert!(names.contains(&"two".to_string()));
        assert!(names.contains(&"three".to_string()));
    }

    // ---------------------------------------------------------------------------
    // Test 6: Remove backend successfully (sole reference)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_remove_succeeds() {
        let tmp = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        registry
            .register("removable", Box::new(make_test_local_backend(&tmp)))
            .expect("register");

        assert_eq!(registry.len(), 1);

        // Remove should succeed (no outstanding Arc refs besides the map entry)
        let result = registry.remove("removable");
        assert!(result.is_ok(), "remove should succeed: {:?}", result.err());

        // Backend should no longer be accessible
        assert!(registry.get("removable").is_none());
        assert!(registry.is_empty());

        // Removing again should fail with NotFound
        let double_remove = registry.remove("removable");
        assert!(double_remove.is_err());
        match double_remove.unwrap_err() {
            StorageError::NotFound(msg) => {
                assert!(msg.contains("removable"));
            }
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    // ---------------------------------------------------------------------------
    // Test 7: Remove fails when outstanding Arc references exist
    // ---------------------------------------------------------------------------

    #[test]
    fn test_remove_fails_with_outstanding_refs() {
        let tmp = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        registry
            .register("shared", Box::new(make_test_local_backend(&tmp)))
            .expect("register");

        // Clone an Arc ref (simulating another holder)
        let _held_ref = registry.get("shared");

        // Remove should now fail because strong_count > 1
        let remove_result = registry.remove("shared");
        assert!(remove_result.is_err());

        match remove_result.unwrap_err() {
            StorageError::InternalError(msg) => {
                assert!(msg.contains("outstanding"), "should mention outstanding refs: {msg}");
            }
            other => panic!("expected InternalError, got: {:?}", other),
        }

        // Original registration should still be intact after failed removal
        assert!(registry.get("shared").is_some());
        assert_eq!(registry.len(), 1);
    }

    // ---------------------------------------------------------------------------
    // Test 8: get_default returns the "default"-named backend
    // ---------------------------------------------------------------------------

    #[test]
    fn test_get_default() {
        let tmp = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        // No default registered yet
        assert!(registry.get_default().is_none());

        registry
            .register("default", Box::new(make_test_local_backend(&tmp)))
            .expect("register default");

        assert!(registry.get_default().is_some());
        assert!(registry.get("default").is_some());
    }

    // ---------------------------------------------------------------------------
    // Test 9: Concurrent read access from multiple threads
    // ---------------------------------------------------------------------------

    #[test]
    fn test_concurrent_read_access() {
        let tmp = TempDir::new().expect("tempdir creation");
        let registry = Arc::new(StorageRegistry::new());

        // Pre-register some backends
        for i in 0..10 {
            let backend = make_test_local_backend(&tmp);
            registry
                .register(&format!("backend_{i}"), Box::new(backend))
                .unwrap_or_else(|_| panic!("register backend_{i}"));
        }

        let handle_count = 8;

        let handles: Vec<_> = (0..handle_count)
            .map(|thread_id| {
                let reg_clone = Arc::clone(&registry);
                std::thread::spawn(move || {
                    // Perform concurrent read-only operations
                    for round in 0..100 {
                        let _names = reg_clone.names();
                        let _list = reg_clone.list();

                        if round % 10 == 0 {
                            let _ = reg_clone.get("backend_0");
                        }
                    }

                    thread_id
                })
            })
            .collect();

        // All threads should complete without panic or deadlock
        for handle in handles {
            let id = handle.join().expect("thread should not panic");
            assert!(id < handle_count, "thread {id} returned unexpected value");
        }

        // Registry state should still be consistent
        assert_eq!(registry.len(), 10);
    }

    // ---------------------------------------------------------------------------
    // Test 10: from_config parses valid local storage TOML
    // ---------------------------------------------------------------------------

    #[test]
    fn test_from_config_local_valid() {
        let tmp = TempDir::new().expect("tempdir creation");
        // Use forward slashes in TOML for cross-platform compatibility
        let base_path = tmp.path().to_str().unwrap().replace('\\', "/");

        let toml_str = format!(
            r#"
            [storage]
            type = "local"
            default = true

            [storage.local]
            base_path = "{base_path}"
            create_dir_if_missing = true
            "#
        );

        let value: toml::Value = toml_str.parse().expect("valid TOML");
        let registry = StorageRegistry::from_config(&value);

        assert!(registry.is_ok(), "from_config should succeed: {:?}", registry.err());
        let registry = registry.unwrap();

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.get_default().is_some(), "default backend should be registered");

        let list = registry.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "default");
        assert_eq!(list[0].backend_type, "local");
    }

    // ---------------------------------------------------------------------------
    // Test 11: from_config rejects unknown backend type
    // ---------------------------------------------------------------------------

    #[test]
    fn test_from_config_unknown_type() {
        let toml_str = r#"
            [storage]
            type = "nonexistent_backend"
            "#;

        let value: toml::Value = toml_str.parse().expect("valid TOML");
        let result = StorageRegistry::from_config(&value);

        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(
                    msg.contains("unknown storage backend type"),
                    "should mention unknown type: {msg}"
                );
            }
            other => panic!("expected ConfigurationError, got: {:?}", other),
        }
    }

    // ---------------------------------------------------------------------------
    // Test 12: from_config rejects missing storage table
    // ---------------------------------------------------------------------------

    #[test]
    fn test_from_config_missing_storage_table() {
        let value: toml::Value = toml::from_str("[other]\nkey = \"value\"").unwrap();
        let result = StorageRegistry::from_config(&value);

        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("missing [storage] table"), "got: {msg}");
            }
            other => panic!("expected ConfigurationError, got: {:?}", other),
        }
    }

    // ---------------------------------------------------------------------------
    // Test 13: Debug output includes meaningful information
    // ---------------------------------------------------------------------------

    #[test]
    fn test_debug_format() {
        let tmp = TempDir::new().expect("tempdir creation");
        let registry = StorageRegistry::new();

        registry
            .register("debug_test", Box::new(make_test_local_backend(&tmp)))
            .expect("register");

        let debug_str = format!("{registry:?}");
        assert!(debug_str.contains("StorageRegistry"), "debug should show struct name");
        assert!(debug_str.contains("backend_count"), "debug should show count field");
        assert!(debug_str.contains("debug_test"), "debug should show registered name");
    }

    // ---------------------------------------------------------------------------
    // Test 14: Empty registry edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_empty_registry_operations() {
        let registry = StorageRegistry::new();

        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.list().is_empty());
        assert!(registry.names().is_empty());
        assert!(registry.get_default().is_none());
        assert!(registry.get("anything").is_none());

        // Remove from empty should fail
        let remove_result = registry.remove("ghost");
        assert!(remove_result.is_err());
        match remove_result.unwrap_err() {
            StorageError::NotFound(_) => {}
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    // ---------------------------------------------------------------------------
    // Test 15: StorageBackendInfo new constructor
    // ---------------------------------------------------------------------------

    #[test]
    fn test_storage_backend_info_new() {
        let info = StorageBackendInfo::new("my_backend", "s3-compatible");

        assert_eq!(info.name, "my_backend");
        assert_eq!(info.backend_type, "s3-compatible");

        // Verify PartialEq works
        let info2 = StorageBackendInfo::new("my_backend", "s3-compatible");
        assert_eq!(info, info2);

        let info3 = StorageBackendInfo::new("other", "local");
        assert_ne!(info, info3);
    }
}
