//! Misogi Configuration Types — Declarative application configuration
//!
//! This module defines the [`MisogiConfig`] structure which serves as the
//! single source of truth for all Misogi application configuration. It is
//! deserialized from TOML/JSON configuration files and consumed by the
//! [`MisogiApplicationBuilder`](super::MisogiApplicationBuilder) during
//! bootstrap.
//!
//! # Configuration Structure
//!
//! ```text
//! MisogiConfig
//! ├── jwt: JwtSection          — JWT issuer/validator settings
//! ├── identity_providers: []   — Pluggable identity provider configs
//! ├── storage: StorageSection  — Backend selection and parameters
//! ├── transport: TransportSection — HTTP/gRPC server settings
//! ├── parsers: ParsersSection  — CDR parser registry configuration
//! └── app: AppSection          — General application settings
//! ```

use serde::{Deserialize, Serialize};

// =============================================================================
// Identity Provider Configuration
// =============================================================================

/// Configuration entry for a single identity provider.
///
/// Each entry in the `[[identity_providers]]` array describes one pluggable
/// authentication backend (LDAP, OIDC, SAML) that should be registered with
/// the [`IdentityRegistry`](misogi_auth::registry::IdentityRegistry) at startup.
///
/// # Example (TOML)
///
/// ```toml
/// [[identity_providers]]
/// id = "ldap-corp"
/// type = "ldap"  # "ldap" | "oidc" | "saml"
/// enabled = true
///
/// [identity_providers.config]
/// url = "ldap://corp.dc.local:389"
/// base_dn = "dc=corp,dc=local"
/// bind_user = "cn=misogi,ou=services,dc=corp,dc=local"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IdentityProviderConfig {
    /// Unique identifier for this provider instance (used as registry key).
    pub id: String,

    /// Provider type identifier (determines which concrete implementation to create).
    ///
    /// Supported values:
    /// - `"ldap"` — LDAP / Active Directory provider
    /// - `"oidc"` — OpenID Connect / OAuth 2.0 provider
    /// - `"saml"` — SAML 2.0 Service Provider
    #[serde(rename = "type")]
    pub provider_type: String,

    /// Whether this provider should be registered and activated.
    ///
    /// Disabled providers are skipped during bootstrap but remain in config
    /// for easy activation by operators.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Human-readable display name for logs and error messages.
    #[serde(default)]
    pub name: Option<String>,

    /// Provider-specific configuration (structure depends on `provider_type`).
    ///
    /// For LDAP: contains `url`, `base_dn`, `bind_user`, `bind_password`, etc.
    /// For OIDC: contains `issuer_url`, `client_id`, `client_secret`, etc.
    /// For SAML: contains `idp_metadata_url`, `sp_entity_id`, etc.
    pub config: serde_json::Value,
}

fn default_enabled() -> bool {
    true
}

// =============================================================================
// Section Configurations
// =============================================================================

/// JWT authentication subsystem configuration.
///
/// Contains all settings needed to initialize both [`JwtValidator`](misogi_auth::jwt::JwtValidator)
/// and [`JwtIssuer`](misogi_auth::jwt::JwtIssuer) from a single config section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JwtSection {
    /// Issuer (`iss`) claim value for issued and validated tokens.
    pub issuer: String,

    /// Audience (`aud`) claim value for issued and validated tokens.
    pub audience: String,

    /// Filesystem path to PEM-encoded RSA private key (for token issuance).
    pub rsa_pem_path: std::path::PathBuf,

    /// Filesystem path to PEM-encoded RSA public key (for token validation).
    pub rsa_pub_pem_path: std::path::PathBuf,

    /// Access token time-to-live in hours (default: 8).
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: i64,

    /// Refresh token time-to-live in hours (default: 168 = 7 days).
    #[serde(default = "default_refresh_ttl_hours")]
    pub refresh_ttl_hours: i64,
}

fn default_ttl_hours() -> i64 {
    8
}

fn default_refresh_ttl_hours() -> i64 {
    168
}

/// Storage backend configuration section.
///
/// Selects and configures the storage backend implementation (local filesystem,
/// S3, Azure Blob, etc.) based on the `backend` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageSection {
    /// Backend type identifier (determines which implementation to instantiate).
    ///
    /// Supported values:
    /// - `"local"` — Local filesystem storage
    /// - `"s3"` — Amazon S3 or S3-compatible (MinIO, R2)
    /// - `"azure"` — Azure Blob Storage (future)
    /// - `"memory"` — In-memory storage (testing only)
    pub backend: String,

    /// Base directory for local filesystem backend (required when `backend = "local"`).
    #[serde(default)]
    pub base_path: Option<std::path::PathBuf>,

    /// S3 bucket name (required when `backend = "s3"`).
    #[serde(default)]
    pub bucket: Option<String>,

    /// S3 region (required when `backend = "s3"`).
    #[serde(default)]
    pub region: Option<String>,

    /// S3 endpoint URL (for MinIO or other S3-compatible services).
    #[serde(default)]
    pub endpoint_url: Option<String>,

    /// Additional backend-specific configuration passed through to implementation.
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Transport layer configuration section.
///
/// Contains HTTP/gRPC server binding addresses, TLS settings, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TransportSection {
    /// Host address for HTTP server binding (default: "0.0.0.0").
    #[serde(default = "default_http_host")]
    pub http_host: String,

    /// Port for HTTP server (default: 8080).
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Host address for gRPC server binding (default: "0.0.0.0").
    #[serde(default = "default_grpc_host")]
    pub grpc_host: String,

    /// Port for gRPC server (default: 9090).
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// Path to TLS certificate file (enables HTTPS/gRPCS when set).
    #[serde(default)]
    pub tls_cert_path: Option<std::path::PathBuf>,

    /// Path to TLS private key file (required when tls_cert_path is set).
    #[serde(default)]
    pub tls_key_path: Option<std::path::PathBuf>,

    /// Request timeout in seconds (default: 30).
    #[serde(default = "default_timeout_secs")]
    pub request_timeout_secs: u64,

    /// Maximum concurrent connections (default: 10000).
    #[serde(default = "max_connections")]
    pub max_connections: usize,
}

fn default_http_host() -> String {
    "0.0.0.0".to_string()
}

fn default_http_port() -> u16 {
    8080
}

fn default_grpc_host() -> String {
    "0.0.0.0".to_string()
}

fn default_grpc_port() -> u16 {
    9090
}

fn default_timeout_secs() -> u64 {
    30
}

fn max_connections() -> usize {
    10000
}

/// CDR parser registry configuration section.
///
/// Controls which content parsers are enabled and their priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ParsersSection {
    /// Enable PDF parser (default: true).
    #[serde(default = "default_true")]
    pub enable_pdf: bool,

    /// Enable OOXML (Office Open XML) parser (default: true).
    #[serde(default = "default_true")]
    pub enable_ooxml: bool,

    /// Enable ZIP archive parser (default: true).
    #[serde(default = "default_true")]
    pub enable_zip: bool,

    /// Maximum input file size in bytes (default: 100 MB).
    #[serde(default = "default_max_file_size")]
    pub max_file_size_bytes: u64,
}

fn default_true() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    100 * 1024 * 1024 // 100 MB
}

/// General application settings section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AppSection {
    /// Application environment (development, staging, production).
    #[serde(default = "default_env")]
    pub environment: String,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Graceful shutdown timeout in seconds (default: 30).
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

impl Default for AppSection {
    fn default() -> Self {
        Self {
            environment: default_env(),
            log_level: default_log_level(),
            shutdown_timeout_secs: default_shutdown_timeout(),
        }
    }
}

fn default_env() -> String {
    "production".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_shutdown_timeout() -> u64 {
    30
}

// =============================================================================
// Top-Level MisogiConfig
// =============================================================================

/// Complete Misogi application configuration — single source of truth.
///
/// This structure is deserialized from TOML or JSON configuration files and
/// consumed by [`MisogiApplicationBuilder`] during the bootstrap process.
/// All sections are optional to allow incremental configuration; missing
/// sections cause bootstrap errors only when the corresponding component
/// build method is called.
///
/// # Example (TOML)
///
/// ```toml
/// [jwt]
/// issuer = "misogi-auth"
/// audience = "misogi-api"
/// rsa_pem_path = "/etc/misogi/jwt/private.pem"
/// rsa_pub_pem_path = "/etc/misogi/jwt/public.pem"
/// ttl_hours = 8
///
/// [[identity_providers]]
/// id = "ldap-corp"
/// type = "ldap"
/// enabled = true
///
/// [storage]
/// backend = "local"
/// base_path = "/var/lib/misogi/data"
///
/// [transport]
/// http_port = 8080
/// grpc_port = 9090
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MisogiConfig {
    /// JWT authentication subsystem configuration.
    pub jwt: Option<JwtSection>,

    /// Ordered list of identity provider configurations.
    ///
    /// Each entry describes one pluggable authentication backend that will
    /// be registered with the IdentityRegistry during bootstrap.
    #[serde(default)]
    pub identity_providers: Vec<IdentityProviderConfig>,

    /// Storage backend configuration.
    pub storage: Option<StorageSection>,

    /// Transport layer (HTTP/gRPC) configuration.
    pub transport: Option<TransportSection>,

    /// CDR parser registry configuration.
    pub parsers: Option<ParsersSection>,

    /// General application settings.
    #[serde(default)]
    pub app: AppSection,
}

impl Default for MisogiConfig {
    fn default() -> Self {
        Self {
            jwt: None,
            identity_providers: Vec::new(),
            storage: None,
            transport: None,
            parsers: None,
            app: AppSection::default(),
        }
    }
}

impl MisogiConfig {
    /// Load configuration from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to the TOML configuration file
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::ConfigIOError`] if the file cannot be read,
    /// or [`BootstrapError::InvalidConfig`] if parsing fails.
    pub fn from_toml_file(path: &std::path::Path) -> Result<Self, super::BootstrapError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from a JSON file.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to the JSON configuration file
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::ConfigIOError`] if the file cannot be read,
    /// or [`BootstrapError::InvalidConfig`] if parsing fails.
    pub fn from_json_file(path: &std::path::Path) -> Result<Self, super::BootstrapError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Validate that all required sections for full build are present.
    ///
    /// Checks that `jwt`, `storage`, and `transport` sections exist.
    /// Does NOT validate field values within sections.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::MissingConfig`] for each missing required section.
    pub fn validate_for_full_build(&self) -> Result<(), Vec<super::BootstrapError>> {
        let mut errors = Vec::new();

        if self.jwt.is_none() {
            errors.push(super::BootstrapError::MissingConfig("jwt".to_string()));
        }
        if self.storage.is_none() {
            errors.push(super::BootstrapError::MissingConfig("storage".to_string()));
        }
        if self.transport.is_none() {
            errors.push(super::BootstrapError::MissingConfig("transport".to_string()));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if a specific configuration section exists.
    pub fn has_section(&self, section: &str) -> bool {
        match section {
            "jwt" => self.jwt.is_some(),
            "storage" => self.storage.is_some(),
            "transport" => self.transport.is_some(),
            "parsers" => self.parsers.is_some(),
            _ => false,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test Group 1: Default Values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_is_empty() {
        let config = MisogiConfig::default();
        assert!(config.jwt.is_none());
        assert!(config.identity_providers.is_empty());
        assert!(config.storage.is_none());
        assert!(config.transport.is_none());
        assert!(config.parsers.is_none());
    }

    #[test]
    fn test_default_app_section() {
        let app = AppSection::default();
        assert_eq!(app.environment, "production");
        assert_eq!(app.log_level, "info");
        assert_eq!(app.shutdown_timeout_secs, 30);
    }

    #[test]
    fn test_default_transport_section() {
        let transport = TransportSection {
            http_host: default_http_host(),
            http_port: default_http_port(),
            grpc_host: default_grpc_host(),
            grpc_port: default_grpc_port(),
            tls_cert_path: None,
            tls_key_path: None,
            request_timeout_secs: default_timeout_secs(),
            max_connections: max_connections(),
        };
        assert_eq!(transport.http_host, "0.0.0.0");
        assert_eq!(transport.http_port, 8080);
        assert_eq!(transport.grpc_port, 9090);
        assert_eq!(transport.request_timeout_secs, 30);
    }

    // -----------------------------------------------------------------------
    // Test Group 2: Serialization/Deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_serialize_minimal_config() {
        let config = MisogiConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("environment"));
        assert!(json.contains("production"));
    }

    #[test]
    fn test_deserialize_jwt_section() {
        let json = r#"{
            "jwt": {
                "issuer": "test-issuer",
                "audience": "test-audience",
                "rsa_pem_path": "/tmp/private.pem",
                "rsa_pub_pem_path": "/tmp/public.pem",
                "ttl_hours": 8,
                "refresh_ttl_hours": 168
            }
        }"#;
        let config: MisogiConfig = serde_json::from_str(json).unwrap();
        let jwt = config.jwt.expect("jwt section should be present");
        assert_eq!(jwt.issuer, "test-issuer");
        assert_eq!(jwt.audience, "test-audience");
        assert_eq!(jwt.ttl_hours, 8);
    }

    #[test]
    fn test_deserialize_identity_provider() {
        let json = r#"{
            "identity_providers": [{
                "id": "ldap-1",
                "type": "ldap",
                "enabled": true,
                "name": "Corporate LDAP",
                "config": {"url": "ldap://localhost"}
            }]
        }"#;
        let config: MisogiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.identity_providers.len(), 1);
        let provider = &config.identity_providers[0];
        assert_eq!(provider.id, "ldap-1");
        assert_eq!(provider.provider_type, "ldap");
        assert!(provider.enabled);
        assert_eq!(provider.name.as_deref(), Some("Corporate LDAP"));
    }

    // -----------------------------------------------------------------------
    // Test Group 3: Validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_empty_config_fails() {
        let config = MisogiConfig::default();
        let result = config.validate_for_full_build();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 3); // jwt, storage, transport
    }

    #[test]
    fn test_validate_complete_config_passes() {
        let config = MisogiConfig {
            jwt: Some(JwtSection {
                issuer: "test".to_string(),
                audience: "test".to_string(),
                rsa_pem_path: std::path::PathBuf::from("/tmp/p.pem"),
                rsa_pub_pem_path: std::path::PathBuf::from("/tmp/pub.pem"),
                ttl_hours: 8,
                refresh_ttl_hours: 168,
            }),
            storage: Some(StorageSection {
                backend: "local".to_string(),
                base_path: Some(std::path::PathBuf::from("/tmp/data")),
                bucket: None,
                region: None,
                endpoint_url: None,
                extra: serde_json::Map::new(),
            }),
            transport: Some(TransportSection {
                http_host: default_http_host(),
                http_port: 8080,
                grpc_host: default_grpc_host(),
                grpc_port: 9090,
                tls_cert_path: None,
                tls_key_path: None,
                request_timeout_secs: 30,
                max_connections: 10000,
            }),
            ..Default::default()
        };
        assert!(config.validate_for_full_build().is_ok());
    }

    #[test]
    fn test_has_section_check() {
        let mut config = MisogiConfig::default();
        assert!(!config.has_section("jwt"));

        config.jwt = Some(JwtSection {
            issuer: "test".to_string(),
            audience: "test".to_string(),
            rsa_pem_path: std::path::PathBuf::from("/tmp/p.pem"),
            rsa_pub_pem_path: std::path::PathBuf::from("/tmp/pub.pem"),
            ttl_hours: 8,
            refresh_ttl_hours: 168,
        });
        assert!(config.has_section("jwt"));
    }
}
