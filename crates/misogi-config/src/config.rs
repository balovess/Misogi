//! Core configuration structures for Misogi system.
//!
//! Defines the [`MisogiConfig`] struct which is the central configuration
//! object for the entire Misogi file transfer system. Loads from TOML files,
//! supports environment variable overrides, and provides typed accessors for
//! each subsystem's configuration.
//!
//! # Configuration File Format
//!
//! The expected TOML structure:
//!
//! ```toml
//! [general]
//! environment = "production"
//! log_level = "info"
//!
//! [jwt]
//! issuer = "https://misogi.example.com"
//! audience = ["misogi-api"]
//! key_path = "/path/to/jwt_rsa.pem"
//! ttl_secs = 28800
//! refresh_ttl_secs = 604800
//!
//! [[identity_providers]]
//! type = "ldap"
//! id = "provider-unique-id"
//! enabled = true
//!
//! [storage]
//! backend = "filesystem"
//! base_path = "./data"
//! max_file_size_mb = 100
//!
//! [transport]
//! mode = "streaming"
//! buffer_size_kb = 64
//! chunk_size_mb = 10
//!
//! [parsers]
//! default_policy = "sanitize"
//! wasm_plugins_dir = "./plugins"
//! ```

use std::path::{Path, PathBuf};
use std::env;

use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};

use crate::error::ConfigError;

// ---------------------------------------------------------------------------
// Environment Variable Constants
// ---------------------------------------------------------------------------

/// Environment variable names for each configurable field.
mod env_vars {
    pub const JWT_ISSUER: &str = "MISOGI_JWT_ISSUER";
    pub const JWT_AUDIENCE: &str = "MISOGI_JWT_AUDIENCE";
    pub const JWT_KEY_PATH: &str = "MISOGI_JWT_KEY_PATH";
    pub const JWT_TTL_SECS: &str = "MISOGI_JWT_TTL_SECS";
    pub const JWT_REFRESH_TTL_SECS: &str = "MISOGI_JWT_REFRESH_TTL_SECS";
    pub const STORAGE_BACKEND: &str = "MISOGI_STORAGE_BACKEND";
    pub const STORAGE_BASE_PATH: &str = "MISOGI_STORAGE_BASE_PATH";
    pub const STORAGE_MAX_FILE_SIZE_MB: &str = "MISOGI_STORAGE_MAX_FILE_SIZE_MB";
    pub const TRANSPORT_MODE: &str = "MISOGI_TRANSPORT_MODE";
    pub const TRANSPORT_BUFFER_SIZE_KB: &str = "MISOGI_TRANSPORT_BUFFER_SIZE_KB";
    pub const TRANSPORT_CHUNK_SIZE_MB: &str = "MISOGI_TRANSPORT_CHUNK_SIZE_MB";
    pub const GENERAL_ENVIRONMENT: &str = "MISOGI_ENVIRONMENT";
    pub const GENERAL_LOG_LEVEL: &str = "MISOGI_LOG_LEVEL";
    pub const PARSERS_DEFAULT_POLICY: &str = "MISOGI_PARSERS_DEFAULT_POLICY";
    pub const PARSERS_WASM_PLUGINS_DIR: &str = "MISOGI_PARSERS_WASM_PLUGINS_DIR";
}

// ---------------------------------------------------------------------------
// Section Structures
// ---------------------------------------------------------------------------

/// General system configuration section.
///
/// Contains environment designation and logging settings that apply
/// to the entire Misogi system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GeneralConfig {
    /// Runtime environment: "production", "development", or "staging".
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Global log level: "trace", "debug", "info", "warn", or "error".
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_environment() -> String {
    "development".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            environment: default_environment(),
            log_level: default_log_level(),
        }
    }
}

/// JWT authentication configuration section.
///
/// Maps directly to [`misogi_auth::jwt::JwtConfig`](https://docs.rs/misogi-auth/latest/misogi_auth/jwt/struct.JwtConfig.html)
/// fields but uses seconds instead of hours for TTL values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JwtConfigSection {
    /// Token issuer identifier (typically a URL or service name).
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,

    /// Expected audience(s) for token validation.
    #[serde(default = "default_jwt_audience")]
    pub audience: Vec<String>,

    /// Path to PEM-encoded RSA private key for token issuance.
    #[serde(default)]
    pub key_path: Option<PathBuf>,

    /// Access token time-to-live in seconds.
    #[serde(default = "default_jwt_ttl_secs")]
    pub ttl_secs: u64,

    /// Refresh token time-to-live in seconds.
    #[serde(default = "default_jwt_refresh_ttl_secs")]
    pub refresh_ttl_secs: u64,
}

fn default_jwt_issuer() -> String {
    "misogi-default".to_string()
}

fn default_jwt_audience() -> Vec<String> {
    vec!["misogi-api".to_string()]
}

fn default_jwt_ttl_secs() -> u64 {
    28800 // 8 hours
}

fn default_jwt_refresh_ttl_secs() -> u64 {
    604800 // 7 days
}

impl Default for JwtConfigSection {
    fn default() -> Self {
        Self {
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
            key_path: None,
            ttl_secs: default_jwt_ttl_secs(),
            refresh_ttl_secs: default_jwt_refresh_ttl_secs(),
        }
    }
}

/// Identity provider configuration descriptor.
///
/// Represents a single identity provider entry in the `[[identity_providers]]`
/// array. Provider-specific fields are stored as raw TOML value for deferred
/// parsing by the respective provider plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IdentityProviderConfig {
    /// Provider type identifier: "ldap", "oidc", or "saml".
    #[serde(alias = "type")]
    pub provider_type: String,

    /// Unique identifier for this provider instance.
    pub id: String,

    /// Whether this provider is enabled for authentication.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Display name for administrative interfaces.
    #[serde(default)]
    pub display_name: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Storage backend configuration section.
///
/// Configures the storage layer used for file persistence across
/// filesystem, S3/MinIO/R2, and GCS backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageConfigSection {
    /// Storage backend type: "filesystem", "s3", or "gcs".
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// Base path or bucket prefix for stored files.
    #[serde(default = "default_storage_base_path")]
    pub base_path: PathBuf,

    /// Maximum allowed file size in megabytes.
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
}

fn default_storage_backend() -> String {
    "filesystem".to_string()
}

fn default_storage_base_path() -> PathBuf {
    PathBuf::from("./data")
}

fn default_max_file_size() -> u64 {
    100
}

impl Default for StorageConfigSection {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            base_path: default_storage_base_path(),
            max_file_size_mb: default_max_file_size(),
        }
    }
}

/// Transport layer configuration section.
///
/// Controls how data is transferred between nodes in the Misogi network,
/// including buffering strategy and chunking parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TransportConfigSection {
    /// Transfer mode: "streaming" or "buffered".
    #[serde(default = "default_transport_mode")]
    pub mode: String,

    /// Internal buffer size in kilobytes for buffered mode.
    #[serde(default = "default_buffer_size")]
    pub buffer_size_kb: u32,

    /// Chunk size in megabytes for large file transfers.
    #[serde(default = "default_chunk_size")]
    pub chunk_size_mb: u32,
}

fn default_transport_mode() -> String {
    "streaming".to_string()
}

fn default_buffer_size() -> u32 {
    64
}

fn default_chunk_size() -> u32 {
    10
}

impl Default for TransportConfigSection {
    fn default() -> Self {
        Self {
            mode: default_transport_mode(),
            buffer_size_kb: default_buffer_size(),
            chunk_size_mb: default_chunk_size(),
        }
    }
}

/// Parser and plugin configuration section.
///
/// Controls file parsing behavior, sanitization policies, and WASM plugin
/// loading directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ParsersConfigSection {
    /// Default sanitization policy: "sanitize", "reject", or "passthrough".
    #[serde(default = "default_parser_policy")]
    pub default_policy: String,

    /// Directory containing WASM parser plugins.
    #[serde(default = "default_wasm_dir")]
    pub wasm_plugins_dir: PathBuf,
}

fn default_parser_policy() -> String {
    "sanitize".to_string()
}

fn default_wasm_dir() -> PathBuf {
    PathBuf::from("./plugins")
}

impl Default for ParsersConfigSection {
    fn default() -> Self {
        Self {
            default_policy: default_parser_policy(),
            wasm_plugins_dir: default_wasm_dir(),
        }
    }
}

// ---------------------------------------------------------------------------
// Main Configuration Structure
// ---------------------------------------------------------------------------

/// Centralized configuration loader for the entire Misogi system.
///
/// `MisogiConfig` is the single source of truth for all runtime configuration.
/// It loads from TOML files, applies environment variable overrides, validates
/// all sections, and provides typed accessor methods for each subsystem.
///
/// # Lifecycle
///
/// 1. **Load**: Parse TOML file via [`MisogiConfig::from_file()`](Self::from_file)
///              or [`MisogiConfig::from_toml_str()`](Self::from_toml_str)
/// 2. **Override**: Apply environment variables (MISOGI_* prefix)
/// 3. **Validate**: Check all required fields and value ranges
/// 4. **Distribute**: Extract subsection configs via accessor methods
///
/// # Example
///
/// ```ignore
/// use misogi_config::MisogiConfig;
/// use std::path::Path;
///
/// let config = MisogiConfig::from_file(Path::new("config.toml"))?;
/// let jwt = config.jwt_config();
/// println!("JWT issuer: {}", jwt.issuer);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisogiConfig {
    /// General system configuration.
    #[serde(default)]
    pub general: GeneralConfig,

    /// JWT authentication configuration.
    #[serde(default)]
    pub jwt: Option<JwtConfigSection>,

    /// Identity provider configurations (LDAP, OIDC, SAML).
    #[serde(default)]
    pub identity_providers: Vec<IdentityProviderConfig>,

    /// Storage backend configuration.
    #[serde(default)]
    pub storage: Option<StorageConfigSection>,

    /// Transport layer configuration.
    #[serde(default)]
    pub transport: Option<TransportConfigSection>,

    /// Parser and plugin configuration.
    #[serde(default)]
    pub parsers: Option<ParsersConfigSection>,
}

impl MisogiConfig {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Load configuration from a TOML file at the specified path.
    ///
    /// This method performs the full configuration loading pipeline:
    /// 1. Read file contents from disk
    /// 2. Parse TOML syntax
    /// 3. Deserialize into `MisogiConfig` struct
    /// 4. Apply environment variable overrides
    /// 5. Validate all sections
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::FileNotFound`] if the file does not exist.
    /// Returns [`ConfigError::TomlParseError`] if the TOML syntax is invalid.
    /// Returns [`ConfigError::ValidationError`] if validation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = MisogiConfig::from_file(Path::new("/etc/misogi/config.toml"))?;
    /// ```
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        info!(path = %path.display(), "loading configuration from file");

        // Check file existence before attempting read
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }

        // Read file contents
        let contents = std::fs::read_to_string(path)?;

        // Delegate to string-based loader
        let mut config = Self::from_toml_str(&contents)?;

        // Apply environment variable overrides
        config.apply_env_overrides();

        // Validate configuration
        config.validate()?;

        info!(
            environment = %config.general.environment,
            "configuration loaded successfully"
        );

        Ok(config)
    }

    /// Load configuration from a TOML string (for testing or inline configs).
    ///
    /// Does NOT apply environment variable overrides or validation.
    /// Use [`MisogiConfig::from_file()`](Self::from_file) for production usage.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::TomlParseError`] if the TOML syntax is invalid.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let toml_str = r#"
    ///     [general]
    ///     environment = "production"
    /// "#;
    /// let config = MisogiConfig::from_toml_str(toml_str)?;
    /// ```
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        debug!("parsing configuration from TOML string");

        let config: MisogiConfig = toml::from_str(toml_str)?;

        Ok(config)
    }

    /// Create a configuration with development-friendly defaults.
    ///
    /// Suitable for local development and testing. All optional sections
    /// are populated with sensible defaults. Not recommended for production.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = MisogiConfig::default();
    /// assert_eq!(config.general.environment, "development");
    /// ```
    pub fn default() -> Self {
        debug!("creating default development configuration");

        Self {
            general: GeneralConfig::default(),
            jwt: Some(JwtConfigSection::default()),
            identity_providers: vec![],
            storage: Some(StorageConfigSection::default()),
            transport: Some(TransportConfigSection::default()),
            parsers: Some(ParsersConfigSection::default()),
        }
    }

    // -----------------------------------------------------------------------
    // Accessor Methods
    // -----------------------------------------------------------------------

    /// Extract the JWT configuration section.
    ///
    /// Returns the configured JWT section or defaults if not specified.
    /// Use this to construct [`misogi_auth::jwt::JwtConfig`](https://docs.rs/misogi-auth/latest/misogi_auth/jwt/struct.JwtConfig.html).
    ///
    /// # Panics
    ///
    /// This method never panics; it returns defaults if the section is missing.
    pub fn jwt_config(&self) -> JwtConfigSection {
        self.jwt.clone().unwrap_or_default()
    }

    /// Extract the storage configuration section.
    ///
    /// Returns the configured storage section or defaults if not specified.
    ///
    /// # Panics
    ///
    /// This method never panics; it returns defaults if the section is missing.
    pub fn storage_config(&self) -> StorageConfigSection {
        self.storage.clone().unwrap_or_default()
    }

    /// Extract the transport configuration section.
    ///
    /// Returns the configured transport section or defaults if not specified.
    ///
    /// # Panics
    ///
    /// This method never panics; it returns defaults if the section is missing.
    pub fn transport_config(&self) -> TransportConfigSection {
        self.transport.clone().unwrap_or_default()
    }

    /// Extract the parsers configuration section.
    ///
    /// Returns the configured parsers section or defaults if not specified.
    ///
    /// # Panics
    ///
    /// This method never panics; it returns defaults if the section is missing.
    pub fn parsers_config(&self) -> ParsersConfigSection {
        self.parsers.clone().unwrap_or_default()
    }

    /// Iterate over configured identity providers.
    ///
    /// Returns only enabled providers. Use this to initialize the
    /// [`IdentityRegistry`](https://docs.rs/misogi-auth/latest/misogi_auth/registry/struct.IdentityRegistry.html).
    ///
    /// # Example
    ///
    /// ```ignore
    /// for provider in config.identity_provider_configs() {
    ///     println!("Provider: {} ({})", provider.id, provider.provider_type);
    /// }
    /// ```
    pub fn identity_provider_configs(&self) -> Vec<IdentityProviderConfig> {
        self.identity_providers
            .iter()
            .filter(|p| p.enabled)
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /// Validate all configuration sections for correctness.
    ///
    /// Checks:
    /// - Environment value is one of: production, development, staging
    /// - Log level is valid tracing level
    /// - Storage backend is known type
    /// - Transport mode is valid
    /// - Buffer/chunk sizes are positive
    /// - JWT TTL values are reasonable (>0)
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ValidationError`] on first validation failure.
    pub fn validate(&self) -> Result<(), ConfigError> {
        debug!("validating configuration");

        self.validate_general()?;
        self.validate_jwt()?;
        self.validate_storage()?;
        self.validate_transport()?;
        self.validate_parsers()?;

        debug!("configuration validation passed");
        Ok(())
    }

    /// Validate general section.
    fn validate_general(&self) -> Result<(), ConfigError> {
        match self.general.environment.as_str() {
            "production" | "development" | "staging" => {}
            other => {
                return Err(ConfigError::ValidationError {
                    section: "general".to_string(),
                    field: "environment".to_string(),
                    reason: format!(
                        "invalid environment '{other}', expected one of: production, development, staging"
                    ),
                });
            }
        }

        match self.general.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                return Err(ConfigError::ValidationError {
                    section: "general".to_string(),
                    field: "log_level".to_string(),
                    reason: format!("invalid log level '{other}'"),
                });
            }
        }

        Ok(())
    }

    /// Validate JWT section if present.
    fn validate_jwt(&self) -> Result<(), ConfigError> {
        if let Some(ref jwt) = self.jwt {
            if jwt.ttl_secs == 0 {
                return Err(ConfigError::ValidationError {
                    section: "jwt".to_string(),
                    field: "ttl_secs".to_string(),
                    reason: "TTL must be greater than zero".to_string(),
                });
            }

            if jwt.refresh_ttl_secs < jwt.ttl_secs {
                warn!(
                    jwt_refresh_ttl = jwt.refresh_ttl_secs,
                    jwt_ttl = jwt.ttl_secs,
                    "refresh TTL is shorter than access TTL (unusual)"
                );
            }
        }

        Ok(())
    }

    /// Validate storage section if present.
    fn validate_storage(&self) -> Result<(), ConfigError> {
        if let Some(ref storage) = self.storage {
            match storage.backend.as_str() {
                "filesystem" | "s3" | "gcs" => {}
                other => {
                    return Err(ConfigError::ValidationError {
                        section: "storage".to_string(),
                        field: "backend".to_string(),
                        reason: format!(
                            "unknown backend '{other}', expected: filesystem, s3, gcs"
                        ),
                    });
                }
            }

            if storage.max_file_size_mb == 0 {
                return Err(ConfigError::ValidationError {
                    section: "storage".to_string(),
                    field: "max_file_size_mb".to_string(),
                    reason: "must be greater than zero".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate transport section if present.
    fn validate_transport(&self) -> Result<(), ConfigError> {
        if let Some(ref transport) = self.transport {
            match transport.mode.as_str() {
                "streaming" | "buffered" => {}
                other => {
                    return Err(ConfigError::ValidationError {
                        section: "transport".to_string(),
                        field: "mode".to_string(),
                        reason: format!(
                            "unknown mode '{other}', expected: streaming, buffered"
                        ),
                    });
                }
            }

            if transport.buffer_size_kb == 0 {
                return Err(ConfigError::ValidationError {
                    section: "transport".to_string(),
                    field: "buffer_size_kb".to_string(),
                    reason: "must be greater than zero".to_string(),
                });
            }

            if transport.chunk_size_mb == 0 {
                return Err(ConfigError::ValidationError {
                    section: "transport".to_string(),
                    field: "chunk_size_mb".to_string(),
                    reason: "must be greater than zero".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate parsers section if present.
    fn validate_parsers(&self) -> Result<(), ConfigError> {
        if let Some(ref parsers) = self.parsers {
            match parsers.default_policy.as_str() {
                "sanitize" | "reject" | "passthrough" => {}
                other => {
                    return Err(ConfigError::ValidationError {
                        section: "parsers".to_string(),
                        field: "default_policy".to_string(),
                        reason: format!(
                            "unknown policy '{other}', expected: sanitize, reject, passthrough"
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Environment Variable Overrides
    // -----------------------------------------------------------------------

    /// Apply MISOGI_* environment variable overrides to loaded configuration.
    ///
    /// Environment variables take precedence over TOML values. Only non-empty
    /// environment variable values override the configuration.
    ///
    /// Supported overrides:
    ///
    /// | Env Var | Section.Field |
    /// |---------|--------------|
    /// | `MISOGI_ENVIRONMENT` | general.environment |
    /// | `MISOGI_LOG_LEVEL` | general.log_level |
    /// | `MISOGI_JWT_ISSUER` | jwt.issuer |
    /// | `MISOGI_JWT_AUDIENCE` | jwt.audience (comma-separated) |
    /// | `MISOGI_JWT_KEY_PATH` | jwt.key_path |
    /// | `MISOGI_JWT_TTL_SECS` | jwt.ttl_secs |
    /// | `MISOGI_JWT_REFRESH_TTL_SECS` | jwt.refresh_ttl_secs |
    /// | `MISOGI_STORAGE_BACKEND` | storage.backend |
    /// | `MISOGI_STORAGE_BASE_PATH` | storage.base_path |
    /// | `MISOGI_STORAGE_MAX_FILE_SIZE_MB` | storage.max_file_size_mb |
    /// | `MISOGI_TRANSPORT_MODE` | transport.mode |
    /// | `MISOGI_TRANSPORT_BUFFER_SIZE_KB` | transport.buffer_size_kb |
    /// | `MISOGI_TRANSPORT_CHUNK_SIZE_MB` | transport.chunk_size_mb |
    /// | `MISOGI_PARSERS_DEFAULT_POLICY` | parsers.default_policy |
    /// | `MISOGI_PARSERS_WASM_PLUGINS_DIR` | parsers.wasm_plugins_dir |
    fn apply_env_overrides(&mut self) {
        debug!("applying environment variable overrides");

        // General section
        if let Ok(val) = env::var(env_vars::GENERAL_ENVIRONMENT) {
            if !val.is_empty() {
                info!(env_var = env_vars::GENERAL_ENVIRONMENT, value = %val, "overriding general.environment");
                self.general.environment = val;
            }
        }

        if let Ok(val) = env::var(env_vars::GENERAL_LOG_LEVEL) {
            if !val.is_empty() {
                info!(env_var = env_vars::GENERAL_LOG_LEVEL, value = %val, "overriding general.log_level");
                self.general.log_level = val;
            }
        }

        // JWT section
        if self.jwt.is_none() {
            self.jwt = Some(JwtConfigSection::default());
        }

        if let Some(ref mut jwt) = self.jwt {
            if let Ok(val) = env::var(env_vars::JWT_ISSUER) {
                if !val.is_empty() {
                    info!(env_var = env_vars::JWT_ISSUER, value = %val, "overriding jwt.issuer");
                    jwt.issuer = val;
                }
            }

            if let Ok(val) = env::var(env_vars::JWT_AUDIENCE) {
                if !val.is_empty() {
                    info!(env_var = env_vars::JWT_AUDIENCE, value = %val, "overriding jwt.audience");
                    jwt.audience = val.split(',').map(|s| s.trim().to_string()).collect();
                }
            }

            if let Ok(val) = env::var(env_vars::JWT_KEY_PATH) {
                if !val.is_empty() {
                    info!(env_var = env_vars::JWT_KEY_PATH, value = %val, "overriding jwt.key_path");
                    jwt.key_path = Some(PathBuf::from(val));
                }
            }

            if let Ok(val) = env::var(env_vars::JWT_TTL_SECS) {
                if let Ok(parsed) = val.parse::<u64>() {
                    info!(env_var = env_vars::JWT_TTL_SECS, value = parsed, "overriding jwt.ttl_secs");
                    jwt.ttl_secs = parsed;
                } else {
                    warn!(env_var = env_vars::JWT_TTL_SECS, value = %val, "failed to parse JWT TTL as integer");
                }
            }

            if let Ok(val) = env::var(env_vars::JWT_REFRESH_TTL_SECS) {
                if let Ok(parsed) = val.parse::<u64>() {
                    info!(env_var = env_vars::JWT_REFRESH_TTL_SECS, value = parsed, "overriding jwt.refresh_ttl_secs");
                    jwt.refresh_ttl_secs = parsed;
                } else {
                    warn!(env_var = env_vars::JWT_REFRESH_TTL_SECS, value = %val, "failed to parse JWT refresh TTL as integer");
                }
            }
        }

        // Storage section
        if self.storage.is_none() {
            self.storage = Some(StorageConfigSection::default());
        }

        if let Some(ref mut storage) = self.storage {
            if let Ok(val) = env::var(env_vars::STORAGE_BACKEND) {
                if !val.is_empty() {
                    info!(env_var = env_vars::STORAGE_BACKEND, value = %val, "overriding storage.backend");
                    storage.backend = val;
                }
            }

            if let Ok(val) = env::var(env_vars::STORAGE_BASE_PATH) {
                if !val.is_empty() {
                    info!(env_var = env_vars::STORAGE_BASE_PATH, value = %val, "overriding storage.base_path");
                    storage.base_path = PathBuf::from(val);
                }
            }

            if let Ok(val) = env::var(env_vars::STORAGE_MAX_FILE_SIZE_MB) {
                if let Ok(parsed) = val.parse::<u64>() {
                    info!(env_var = env_vars::STORAGE_MAX_FILE_SIZE_MB, value = parsed, "overriding storage.max_file_size_mb");
                    storage.max_file_size_mb = parsed;
                } else {
                    warn!(env_var = env_vars::STORAGE_MAX_FILE_SIZE_MB, value = %val, "failed to parse max file size as integer");
                }
            }
        }

        // Transport section
        if self.transport.is_none() {
            self.transport = Some(TransportConfigSection::default());
        }

        if let Some(ref mut transport) = self.transport {
            if let Ok(val) = env::var(env_vars::TRANSPORT_MODE) {
                if !val.is_empty() {
                    info!(env_var = env_vars::TRANSPORT_MODE, value = %val, "overriding transport.mode");
                    transport.mode = val;
                }
            }

            if let Ok(val) = env::var(env_vars::TRANSPORT_BUFFER_SIZE_KB) {
                if let Ok(parsed) = val.parse::<u32>() {
                    info!(env_var = env_vars::TRANSPORT_BUFFER_SIZE_KB, value = parsed, "overriding transport.buffer_size_kb");
                    transport.buffer_size_kb = parsed;
                } else {
                    warn!(env_var = env_vars::TRANSPORT_BUFFER_SIZE_KB, value = %val, "failed to parse buffer size as integer");
                }
            }

            if let Ok(val) = env::var(env_vars::TRANSPORT_CHUNK_SIZE_MB) {
                if let Ok(parsed) = val.parse::<u32>() {
                    info!(env_var = env_vars::TRANSPORT_CHUNK_SIZE_MB, value = parsed, "overriding transport.chunk_size_mb");
                    transport.chunk_size_mb = parsed;
                } else {
                    warn!(env_var = env_vars::TRANSPORT_CHUNK_SIZE_MB, value = %val, "failed to parse chunk size as integer");
                }
            }
        }

        // Parsers section
        if self.parsers.is_none() {
            self.parsers = Some(ParsersConfigSection::default());
        }

        if let Some(ref mut parsers) = self.parsers {
            if let Ok(val) = env::var(env_vars::PARSERS_DEFAULT_POLICY) {
                if !val.is_empty() {
                    info!(env_var = env_vars::PARSERS_DEFAULT_POLICY, value = %val, "overriding parsers.default_policy");
                    parsers.default_policy = val;
                }
            }

            if let Ok(val) = env::var(env_vars::PARSERS_WASM_PLUGINS_DIR) {
                if !val.is_empty() {
                    info!(env_var = env_vars::PARSERS_WASM_PLUGINS_DIR, value = %val, "overriding parsers.wasm_plugins_dir");
                    parsers.wasm_plugins_dir = PathBuf::from(val);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
