// =============================================================================
// LocalStorage — Filesystem-based StorageBackend Implementation (Pillar 2)
// =============================================================================
// Provides [`LocalStorage`], the default [`StorageBackend`] implementation using
// the local filesystem. Keys map to relative file paths under a configurable
// `base_path`. All I/O uses `tokio::fs` for async operation.
//
// # Safety
// - Path traversal (`..`, absolute paths, null bytes) rejected at validation.
// - Key length capped at 1024 UTF-8 bytes.
// - Delete is idempotent: non-existent keys return Ok(()).
// - ETags: SHA-256 hex digest for integrity verification.
//
// # Configuration
// Use [`LocalConfig`] (TOML-compatible) or construct via [`LocalStorage::new()`].

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, warn};

use crate::traits::storage::{StorageBackend, StorageError, StorageInfo};

/// Maximum allowed key length in UTF-8 bytes (aligns with S3 limit).
const MAX_KEY_LENGTH: usize = 1024;

/// Backend type identifier returned by [`StorageBackend::backend_type()`].
const BACKEND_TYPE: &str = "local";

// ---------------------------------------------------------------------------
// LocalConfig — TOML-deserializable Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`LocalStorage`] with serde support.
///
/// ```toml
/// [storage.local]
/// base_path = "/var/lib/misogi/data"
/// create_dir_if_missing = true
/// default_permissions = 0o755  # optional; Unix only
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalConfig {
    /// Root directory under which all objects are stored.
    pub base_path: PathBuf,
    /// Auto-create base_path and parent directories when false.
    #[serde(default = "default_create_dir")]
    pub create_dir_if_missing: bool,
    /// Default Unix permissions for new files (None = OS default).
    #[serde(default)]
    pub default_permissions: Option<u32>,
}

fn default_create_dir() -> bool {
    false
}

impl LocalConfig {
    /// Build a validated [`LocalStorage`] from this configuration.
    pub fn build(&self) -> Result<LocalStorage, StorageError> {
        LocalStorage::with_config(self.clone())
    }
}

// ---------------------------------------------------------------------------
// LocalStorage — Core Struct
// ---------------------------------------------------------------------------

/// Filesystem-backed storage backend implementing [`StorageBackend`].
///
/// **Consistency**: Strong (POSIX filesystem semantics).
/// **Thread safety**: `Send + Sync`; safe behind `Arc<>` across tokio tasks.
/// **Concurrency**: Different-key operations are fully concurrent; same-key
///   writes follow last-writer-wins semantics.
#[derive(Debug, Clone)]
pub struct LocalStorage {
    base_path: PathBuf,
    create_dir_if_missing: bool,
    #[allow(dead_code)]
    default_permissions: Option<u32>,
}

impl LocalStorage {
    /// Create a new [`LocalStorage`] backed by an existing directory.
    ///
    /// The base directory MUST exist. For auto-creation use
    /// [`LocalStorage::new_auto()`] or [`LocalStorage::with_config()`].
    ///
    /// # Errors
    /// Returns [`StorageError::ConfigurationError`] if path is missing or
    /// not a directory.
    pub fn new<P: Into<PathBuf>>(base_path: P) -> Result<Self, StorageError> {
        let base_path = base_path.into();
        Self::validate_base_path_sync(&base_path)?;
        Ok(Self {
            base_path,
            create_dir_if_missing: false,
            default_permissions: None,
        })
    }

    /// Create [`LocalStorage`] with automatic base directory creation.
    ///
    /// Creates `base_path` recursively if it does not exist.
    pub async fn new_auto<P: Into<PathBuf>>(base_path: P) -> Result<Self, StorageError> {
        let base_path = base_path.into();
        Self::validate_base_path(&base_path, true).await?;
        Ok(Self {
            base_path,
            create_dir_if_missing: true,
            default_permissions: None,
        })
    }

    /// Create [`LocalStorage`] from a [`LocalConfig`] (TOML-based setup).
    ///
    /// Validates and optionally creates the base directory per config.
    pub fn with_config(config: LocalConfig) -> Result<Self, StorageError> {
        if !config.base_path.exists() && config.create_dir_if_missing {
            std::fs::create_dir_all(&config.base_path).map_err(|e| {
                StorageError::ConfigurationError(format!(
                    "failed to create base_path '{}': {}",
                    config.base_path.display(),
                    e
                ))
            })?;
        }
        Self::validate_base_path_sync(&config.base_path)?;
        Ok(Self {
            base_path: config.base_path,
            create_dir_if_missing: config.create_dir_if_missing,
            default_permissions: config.default_permissions,
        })
    }

    // --- Internal: Key Resolution with Security Validation ---

    /// Resolve a storage key to an absolute filesystem path with validation.
    ///
    /// Rejects: empty keys, null bytes, paths exceeding [`MAX_KEY_LENGTH`],
    /// and any path traversal components (`..`).
    fn resolve_key(&self, key: &str) -> Result<PathBuf, StorageError> {
        if key.is_empty() {
            return Err(StorageError::ConfigurationError(
                "key must not be empty".into(),
            ));
        }
        if key.len() > MAX_KEY_LENGTH {
            return Err(StorageError::ConfigurationError(format!(
                "key length {} exceeds maximum of {}",
                key.len(),
                MAX_KEY_LENGTH
            )));
        }
        if key.contains('\0') {
            return Err(StorageError::ConfigurationError(
                "key must not contain null bytes".into(),
            ));
        }

        let candidate = self.base_path.join(key);

        // Reject path traversal components
        if candidate.components().any(|c| matches!(c, Component::ParentDir)) {
            warn!(key = %key, "rejected path traversal attempt");
            return Err(StorageError::ConfigurationError(format!(
                "key '{}' contains path traversal ('..')",
                key
            )));
        }

        // Defensive: ensure resolved path stays within base_path
        if !candidate.starts_with(&self.base_path) {
            return Err(StorageError::ConfigurationError(format!(
                "resolved path '{}' escapes base '{}'",
                candidate.display(),
                self.base_path.display()
            )));
        }

        Ok(candidate)
    }

    /// Compute SHA-256 etag as lowercase hex string (64 characters).
    #[inline]
    fn compute_etag(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    // --- Internal: Path Validation ---

    /// Async base path validator; creates directory if `auto_create` is true.
    async fn validate_base_path(
        path: &Path,
        auto_create: bool,
    ) -> Result<(), StorageError> {
        if !path.exists() {
            if auto_create {
                debug!(path = %path.display(), "creating storage base directory");
                tokio::fs::create_dir_all(path).await.map_err(|e| {
                    StorageError::ConfigurationError(format!(
                        "failed to create base_path '{}': {}",
                        path.display(),
                        e
                    ))
                })?;
            } else {
                return Err(StorageError::ConfigurationError(format!(
                    "base_path '{}' does not exist",
                    path.display()
                )));
            }
        }
        if !path.is_dir() {
            return Err(StorageError::ConfigurationError(format!(
                "base_path '{}' is not a directory",
                path.display()
            )));
        }
        Ok(())
    }

    /// Synchronous base path validator (for non-async constructors).
    fn validate_base_path_sync(path: &Path) -> Result<(), StorageError> {
        if !path.exists() {
            return Err(StorageError::ConfigurationError(format!(
                "base_path '{}' does not exist",
                path.display()
            )));
        }
        if !path.is_dir() {
            return Err(StorageError::ConfigurationError(format!(
                "base_path '{}' is not a directory",
                path.display()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StorageBackend Trait Implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl StorageBackend for LocalStorage {
    /// Store data at `<base_path>/<key>`. Creates parent dirs if configured.
    /// Computes SHA-256 etag. Last-writer-wins on overwrite.
    #[instrument(skip(self, data), fields(key = %key, size = data.len()))]
    async fn put(&self, key: &str, data: Bytes) -> Result<StorageInfo, StorageError> {
        let filepath = self.resolve_key(key)?;

        if self.create_dir_if_missing {
            if let Some(parent) = filepath.parent() {
                if !parent.exists() {
                    debug!(dir = %parent.display(), "creating parent directory");
                    tokio::fs::create_dir_all(parent).await?;
                }
            }
        }

        tokio::fs::write(&filepath, &data).await?;

        #[cfg(unix)]
        if let Some(mode) = self.default_permissions {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            tokio::fs::set_permissions(&filepath, perms).await?;
        }

        let etag = Self::compute_etag(&data);
        debug!(key = %key, size = data.len(), etag = %etag, "object stored");

        Ok(StorageInfo {
            key: key.to_string(),
            size: data.len() as u64,
            content_type: None,
            created_at: Some(Utc::now()),
            etag: Some(etag),
        })
    }

    /// Read file at `<base_path>/<key>`. Returns [`StorageError::NotFound`]
    /// if absent or not a regular file.
    #[instrument(skip(self), fields(key = %key))]
    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        let filepath = self.resolve_key(key)?;

        let metadata = tokio::fs::metadata(&filepath).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::IoError(e)
            }
        })?;

        if !metadata.is_file() {
            return Err(StorageError::NotFound(key.to_string()));
        }

        let data = tokio::fs::read(&filepath).await?;
        debug!(key = %key, size = data.len(), "object retrieved");
        Ok(Bytes::from(data))
    }

    /// Remove file at `<base_path>/<key>`. Idempotent: Ok(()) if absent.
    #[instrument(skip(self), fields(key = %key))]
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let filepath = self.resolve_key(key)?;
        match tokio::fs::remove_file(&filepath).await {
            Ok(()) => {
                debug!(key = %key, "object deleted");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(key = %key, "delete idempotent: already absent");
                Ok(())
            }
            Err(e) => Err(StorageError::IoError(e)),
        }
    }

    /// Check file existence via `tokio::fs::metadata`.
    #[instrument(skip(self), fields(key = %key))]
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let filepath = self.resolve_key(key)?;
        match tokio::fs::metadata(&filepath).await {
            Ok(m) => Ok(m.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::IoError(e)),
        }
    }

    /// Verify base_path exists, is a directory, and is writable (probe file).
    /// Target latency: <50ms on local filesystem.
    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), StorageError> {
        let meta =
            tokio::fs::metadata(&self.base_path).await.map_err(|e| {
                StorageError::InternalError(format!(
                    "health_check: cannot stat '{}': {}",
                    self.base_path.display(),
                    e
                ))
            })?;

        if !meta.is_dir() {
            return Err(StorageError::InternalError(format!(
                "health_check: '{}' is not a directory",
                self.base_path.display()
            )));
        }

        // Probe write access
        let probe = self.base_path.join(".misogi_health_probe");
        tokio::fs::write(&probe, b"probe").await.map_err(|e| {
            StorageError::PermissionDenied(format!(
                "health_check: cannot write to '{}': {}",
                self.base_path.display(),
                e
            ))
        })?;
        let _ = tokio::fs::remove_file(&probe).await;

        debug!(path = %self.base_path.display(), "health check passed");
        Ok(())
    }

    fn backend_type(&self) -> &'static str {
        BACKEND_TYPE
    }
}

// Unit tests reside in local_tests.rs (file count budget).
#[cfg(test)]
include!("local_tests.rs");
