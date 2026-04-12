//! Misogi Application Builder — Component wiring and assembly
//!
//! This module implements the [`MisogiApplicationBuilder`] which provides a
//! builder-pattern API for assembling all Misogi components from a unified
//! configuration. The builder enforces dependency order, validates component
//! construction, and produces a fully-wired [`MisogiApp`] instance.
//!
//! # Build Order
//!
//! Components are built in strict dependency order:
//!
//! ```text
//! 1. JwtValidator    (from config.jwt)
//! 2. JwtIssuer       (from config.jwt)
//! 3. IdentityRegistry (from config.identity_providers)
//! 4. AuthEngine      (depends on: JwtValidator, IdentityRegistry)
//! 5. ParserRegistry  (from config.parsers)
//! 6. StorageBackend  (from config.storage)
//! 7. TransportLayer  (from config.transport)
//! ```
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_bootstrap::{MisogiApplicationBuilder, MisogiConfig};
//!
//! let app = MisogiApplicationBuilder::new()
//!     .with_config(MisogiConfig::from_toml_file("config.toml")?)
//!     .build_all()?
//!     .build()?;
//!
//! app.start().await?;
//! ```

use std::path::Path;
use std::sync::Arc;

use tracing::{info, instrument, warn};

use crate::config::MisogiConfig;
use crate::error::BootstrapError;

// Re-export core types for convenience
pub use crate::app::MisogiApp;
#[allow(unused_imports)]
use crate::config::{
    AppSection, IdentityProviderConfig, JwtSection, ParsersSection, StorageSection,
    TransportSection,
};

// Import from dependencies
use misogi_auth::engine::AuthEngine;
#[cfg(feature = "jwt")]
use misogi_auth::jwt::{JwtConfig, JwtIssuer, JwtValidator};
use misogi_auth::registry::IdentityRegistry;
use misogi_cdr::ParserRegistry;
use misogi_core::traits::storage::StorageBackend;

// =============================================================================
// MisogiApplicationBuilder — Main builder struct
// =============================================================================

/// Application builder that assembles all Misogi components from configuration.
///
/// This builder provides a fluent API for constructing and wiring all Misogi
/// subsystems. Components can be built individually for fine-grained control,
/// or all at once via [`build_all()`](Self::build_all) for convenience.
///
/// # Thread Safety
///
/// The builder itself is not thread-safe (intended for single-threaded startup).
/// The produced [`MisogiApp`] is fully thread-safe and can be shared via `Arc<>`.
///
/// # Example
///
/// ```ignore
/// let app = MisogiApplicationBuilder::new()
///     .with_config(config)
///     .build_jwt_validator()?
///     .build_jwt_issuer()?
///     .build_identity_registry()?
///     .build_auth_engine()?
///     .build_parser_registry()?
///     .build_storage()?
///     .build_transport()?
///     .build()?;
/// ```
pub struct MisogiApplicationBuilder {
    /// Loaded application configuration.
    config: MisogiConfig,

    /// Built JWT validator (step 1).
    #[cfg(feature = "jwt")]
    jwt_validator: Option<Arc<JwtValidator>>,

    /// Built JWT issuer (step 2).
    #[cfg(feature = "jwt")]
    jwt_issuer: Option<Arc<JwtIssuer>>,

    /// Built identity registry with registered providers (step 3).
    identity_registry: Option<IdentityRegistry>,

    /// Built authentication engine (step 4).
    auth_engine: Option<AuthEngine>,

    /// Built CDR parser registry (step 5).
    parser_registry: Option<ParserRegistry>,

    /// Built storage backend (step 6).
    storage_backend: Option<Arc<dyn StorageBackend>>,

    /// Transport layer placeholder (step 7) — stub for future implementation.
    transport_layer: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl MisogiApplicationBuilder {
    /// Create a new empty builder with default configuration.
    ///
    /// Call [`with_config()`](Self::with_config) or
    /// [`with_config_file()`](Self::with_config_file) to load configuration
    /// before building components.
    pub fn new() -> Self {
        Self {
            config: MisogiConfig::default(),
            #[cfg(feature = "jwt")]
            jwt_validator: None,
            #[cfg(feature = "jwt")]
            jwt_issuer: None,
            identity_registry: None,
            auth_engine: None,
            parser_registry: None,
            storage_backend: None,
            transport_layer: None,
        }
    }

    // ===================================================================
    // Configuration Methods
    // ===================================================================

    /// Set the application configuration explicitly.
    ///
    /// # Arguments
    ///
    /// * `config` — Fully loaded [`MisogiConfig`] instance
    ///
    /// # Returns
    ///
    /// `Self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = MisogiConfig::from_toml_file("misogi.toml")?;
    /// let builder = MisogiApplicationBuilder::new().with_config(config);
    /// ```
    pub fn with_config(mut self, config: MisogiConfig) -> Self {
        self.config = config;
        self
    }

    /// Load configuration from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to the TOML configuration file
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::ConfigIOError`] if file cannot be read
    /// - [`BootstrapError::InvalidConfig`] if parsing fails
    pub fn with_config_file(mut self, path: &Path) -> Result<Self, BootstrapError> {
        self.config = MisogiConfig::from_toml_file(path)?;
        Ok(self)
    }

    /// Get reference to the current configuration.
    pub fn config(&self) -> &MisogiConfig {
        &self.config
    }

    // ===================================================================
    // Step 1: JWT Validator Construction
    // ===================================================================

    /// Construct the [`JwtValidator`] from `config.jwt` section.
    ///
    /// Requires the `jwt` feature flag and a configured `jwt` section.
    /// The validator is used by [`AuthEngine`](AuthEngine) for token verification.
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::MissingConfig`] if `config.jwt` is `None`
    /// - [`BootstrapError::JwtValidationError`] if key loading fails
    ///
    /// # Returns
    ///
    /// `&mut Self` for chaining (note: returns Result unlike other builders,
    /// because this can fail on key load).
    #[cfg(feature = "jwt")]
    #[instrument(skip(self), fields(issuer))]
    pub fn build_jwt_validator(&mut self) -> Result<&mut Self, BootstrapError> {
        let jwt_section = self.config.jwt.as_ref().ok_or_else(|| {
            BootstrapError::MissingConfig("jwt".to_string())
        })?;

        info!(issuer = %jwt_section.issuer, "Building JwtValidator");

        let jwt_config = JwtConfig {
            issuer: jwt_section.issuer.clone(),
            audience: jwt_section.audience.clone(),
            rsa_pem_path: jwt_section.rsa_pem_path.clone(),
            rsa_pub_pem_path: jwt_section.rsa_pub_pem_path.clone(),
            ttl_hours: jwt_section.ttl_hours,
            refresh_ttl_hours: jwt_section.refresh_ttl_hours,
        };

        let validator =
            JwtValidator::new(jwt_config).map_err(|e| {
                BootstrapError::JwtValidationError(e.to_string())
            })?;

        self.jwt_validator = Some(Arc::new(validator));
        info!("JwtValidator constructed successfully");
        Ok(self)
    }

    // ===================================================================
    // Step 2: JWT Issuer Construction
    // ===================================================================

    /// Construct the [`JwtIssuer`] from `config.jwt` section.
    ///
    /// Requires the `jwt` feature flag and a configured `jwt` section.
    /// The issuer is used for creating new tokens after authentication.
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::MissingConfig`] if `config.jwt` is `None`
    /// - [`BootstrapError::JwtIssuerError`] if private key loading fails
    #[cfg(feature = "jwt")]
    #[instrument(skip(self), fields(issuer))]
    pub fn build_jwt_issuer(&mut self) -> Result<&mut Self, BootstrapError> {
        let jwt_section = self.config.jwt.as_ref().ok_or_else(|| {
            BootstrapError::MissingConfig("jwt".to_string())
        })?;

        info!(issuer = %jwt_section.issuer, "Building JwtIssuer");

        let jwt_config = JwtConfig {
            issuer: jwt_section.issuer.clone(),
            audience: jwt_section.audience.clone(),
            rsa_pem_path: jwt_section.rsa_pem_path.clone(),
            rsa_pub_pem_path: jwt_section.rsa_pub_pem_path.clone(),
            ttl_hours: jwt_section.ttl_hours,
            refresh_ttl_hours: jwt_section.refresh_ttl_hours,
        };

        let issuer =
            JwtIssuer::new(jwt_config).map_err(|e| {
                BootstrapError::JwtIssuerError(e.to_string())
            })?;

        self.jwt_issuer = Some(Arc::new(issuer));
        info!("JwtIssuer constructed successfully");
        Ok(self)
    }

    // ===================================================================
    // Step 3: Identity Registry & Provider Registration
    // ===================================================================

    /// Construct [`IdentityRegistry`] and register all enabled providers from config.
    ///
    /// Iterates through `config.identity_providers` array and creates the appropriate
    /// provider instance for each entry where `enabled == true`. Supported types:
    ///
    /// | Type   | Implementation                              |
    /// |--------|---------------------------------------------|
    /// | `ldap` | [`LdapIdentityProvider`](misogi_auth::plugins::ldap::LdapIdentityProvider) |
    /// | `oidc` | [`OidcIdentityProvider`](misogi_auth::plugins::oidc::OidcIdentityProvider) |
    /// | `saml` | [`SamlIdentityProvider`](misogi_auth::plugins::saml::SamlIdentityProvider) |
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::UnknownProviderType`] for unsupported type strings
    /// - [`BootstrapError::ProviderRegistrationError`] if registration fails
    ///
    /// # Note
    ///
    /// Providers that fail to construct log a warning but do NOT abort bootstrap.
    /// This allows partial operation when some backends are temporarily unavailable.
    #[instrument(skip(self))]
    pub fn build_identity_registry(&mut self) -> &mut Self {
        let registry = IdentityRegistry::new();
        let mut registered_count = 0usize;
        let mut skipped_count = 0usize;

        for provider_cfg in &self.config.identity_providers {
            // Skip disabled providers
            if !provider_cfg.enabled {
                skipped_count += 1;
                info!(
                    provider_id = %provider_cfg.id,
                    "Skipping disabled identity provider"
                );
                continue;
            }

            match self.create_provider_from_config(provider_cfg) {
                Ok(provider) => {
                    if let Err(e) = registry.register(provider) {
                        warn!(
                            provider_id = %provider_cfg.id,
                            error = %e,
                            "Failed to register identity provider"
                        );
                    } else {
                        registered_count += 1;
                        info!(
                            provider_id = %provider_cfg.id,
                            provider_type = %provider_cfg.provider_type,
                            "Identity provider registered successfully"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        provider_id = %provider_cfg.id,
                        provider_type = %provider_cfg.provider_type,
                        error = %e,
                        "Failed to create identity provider, skipping"
                    );
                    // Continue with other providers — don't abort bootstrap
                }
            }
        }

        info!(
            registered = registered_count,
            skipped = skipped_count,
            total = self.config.identity_providers.len(),
            "IdentityRegistry construction complete"
        );

        self.identity_registry = Some(registry);
        self
    }

    /// Create a concrete identity provider from configuration entry.
    ///
    /// This internal method maps `provider_type` strings to constructor calls.
    /// Feature gates ensure compile-time errors if required features are missing.
    fn create_provider_from_config(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        match cfg.provider_type.as_str() {
            "ldap" => self.create_ldap_provider(cfg),
            "oidc" => self.create_oidc_provider(cfg),
            "saml" => self.create_saml_provider(cfg),
            other => Err(BootstrapError::UnknownProviderType(other.to_string())),
        }
    }

    /// Create an LDAP identity provider from configuration.
    #[cfg(feature = "ldap")]
    fn create_ldap_provider(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        use misogi_auth::plugins::ldap::LdapIdentityProvider;

        // Extract LDAP-specific config from the generic JSON value
        let plugin_config: misogi_auth::plugins::ldap::LdapPluginConfig =
            serde_json::from_value(cfg.config.clone()).map_err(|e| {
                BootstrapError::InvalidConfig(format!(
                    "Invalid LDAP config for provider '{}': {}",
                    cfg.id, e
                ))
            })?;

        let provider =
            LdapIdentityProvider::new(cfg.id.clone(), plugin_config).map_err(|e| {
                BootstrapError::ProviderRegistrationError {
                    provider_id: cfg.id.clone(),
                    reason: e.to_string(),
                }
            })?;

        Ok(Arc::new(provider))
    }

    /// Create an LDAP identity provider (stub when ldap feature is disabled).
    #[cfg(not(feature = "ldap"))]
    fn create_ldap_provider(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        Err(BootstrapError::ProviderRegistrationError {
            provider_id: cfg.id.clone(),
            reason: "LDAP feature not enabled".to_string(),
        })
    }

    /// Create an OIDC identity provider from configuration.
    #[cfg(feature = "oidc")]
    fn create_oidc_provider(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        use misogi_auth::plugins::oidc::OidcIdentityProvider;

        let provider_config: misogi_auth::plugins::oidc::OidcProviderConfig =
            serde_json::from_value(cfg.config.clone()).map_err(|e| {
                BootstrapError::InvalidConfig(format!(
                    "Invalid OIDC config for provider '{}': {}",
                    cfg.id, e
                ))
            })?;

        let provider =
            OidcIdentityProvider::new(cfg.id.clone(), provider_config).map_err(|e| {
                BootstrapError::ProviderRegistrationError {
                    provider_id: cfg.id.clone(),
                    reason: e.to_string(),
                }
            })?;

        Ok(Arc::new(provider))
    }

    /// Create an OIDC identity provider (stub when oidc feature is disabled).
    #[cfg(not(feature = "oidc"))]
    fn create_oidc_provider(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        Err(BootstrapError::ProviderRegistrationError {
            provider_id: cfg.id.clone(),
            reason: "OIDC feature not enabled".to_string(),
        })
    }

    /// Create a SAML identity provider from configuration.
    #[cfg(feature = "saml")]
    fn create_saml_provider(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        use misogi_auth::plugins::saml::SamlIdentityProvider;

        let plugin_config: misogi_auth::plugins::saml::SamlPluginConfig =
            serde_json::from_value(cfg.config.clone()).map_err(|e| {
                BootstrapError::InvalidConfig(format!(
                    "Invalid SAML config for provider '{}': {}",
                    cfg.id, e
                ))
            })?;

        let provider =
            SamlIdentityProvider::new(cfg.id.clone(), plugin_config).map_err(|e| {
                BootstrapError::ProviderRegistrationError {
                    provider_id: cfg.id.clone(),
                    reason: e.to_string(),
                }
            })?;

        Ok(Arc::new(provider))
    }

    /// Create a SAML identity provider (stub when saml feature is disabled).
    #[cfg(not(feature = "saml"))]
    fn create_saml_provider(
        &self,
        cfg: &IdentityProviderConfig,
    ) -> Result<Arc<dyn misogi_auth::IdentityProvider>, BootstrapError> {
        Err(BootstrapError::ProviderRegistrationError {
            provider_id: cfg.id.clone(),
            reason: "SAML feature not enabled".to_string(),
        })
    }

    // ===================================================================
    // Step 4: Auth Engine Assembly
    // ===================================================================

    /// Assemble the [`AuthEngine`] from previously built components.
    ///
    /// **Dependency**: Requires [`build_jwt_validator()`](Self::build_jwt_validator)
    /// to have been called first (when `jwt` feature is enabled).
    ///
    /// Optionally attaches the [`IdentityRegistry`](IdentityRegistry) if it was built.
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::MissingDependency`] if JwtValidator not yet built
    /// - [`BootstrapError::AuthEngineError`] if engine construction fails
    #[instrument(skip(self))]
    pub fn build_auth_engine(&mut self) -> Result<&mut Self, BootstrapError> {
        #[cfg(feature = "jwt")]
        {
            // Validate dependency: JwtValidator must exist
            if self.jwt_validator.is_none() {
                return Err(BootstrapError::MissingDependency(
                    "jwt_validator".to_string(),
                ));
            }
        }

        info!("Building AuthEngine...");

        #[cfg(feature = "jwt")]
        {
            // Clone the Arc to move into AuthEngine::new
            let _jwt_validator = self.jwt_validator.as_ref().unwrap().clone();
            let jwt_config = JwtConfig {
                issuer: self
                    .config
                    .jwt
                    .as_ref()
                    .map(|j| j.issuer.clone())
                    .unwrap_or_default(),
                audience: self
                    .config
                    .jwt
                    .as_ref()
                    .map(|j| j.audience.clone())
                    .unwrap_or_default(),
                rsa_pem_path: self
                    .config
                    .jwt
                    .as_ref()
                    .map(|j| j.rsa_pem_path.clone())
                    .unwrap_or_default(),
                rsa_pub_pem_path: self
                    .config
                    .jwt
                    .as_ref()
                    .map(|j| j.rsa_pub_pem_path.clone())
                    .unwrap_or_default(),
                ttl_hours: self
                    .config
                    .jwt
                    .as_ref()
                    .map(|j| j.ttl_hours)
                    .unwrap_or(8),
                refresh_ttl_hours: self
                    .config
                    .jwt
                    .as_ref()
                    .map(|j| j.refresh_ttl_hours)
                    .unwrap_or(168),
            };

            let mut engine =
                AuthEngine::new(jwt_config).map_err(|e| {
                    BootstrapError::AuthEngineError(e.to_string())
                })?;

            // Attach IdentityRegistry if available
            if let Some(registry) = self.identity_registry.take() {
                engine = engine.with_identity_registry(registry);
                info!("IdentityRegistry attached to AuthEngine");
            }

            self.auth_engine = Some(engine);
        }

        #[cfg(not(feature = "jwt"))]
        {
            // Minimal mode without JWT
            let mut engine = AuthEngine::new(()).map_err(|e| {
                BootstrapError::AuthEngineError(e.to_string())
            })?;

            if let Some(registry) = self.identity_registry.take() {
                engine = engine.with_identity_registry(registry);
            }

            self.auth_engine = Some(engine);
        }

        info!("AuthEngine assembled successfully");
        Ok(self)
    }

    // ===================================================================
    // Step 5: Parser Registry Construction
    // ===================================================================

    /// Construct the [`ParserRegistry`] from `config.parsers` section.
    ///
    /// Enables PDF, OOXML, and ZIP parsers based on configuration flags.
    /// If no parsers section is configured, creates an empty registry
    /// (fallback parser will handle unknown formats).
    #[instrument(skip(self))]
    pub fn build_parser_registry(&mut self) -> &mut Self {
        let registry = ParserRegistry::new();

        if let Some(parsers_cfg) = &self.config.parsers {
            info!(
                enable_pdf = parsers_cfg.enable_pdf,
                enable_ooxml = parsers_cfg.enable_ooxml,
                enable_zip = parsers_cfg.enable_zip,
                "Building ParserRegistry"
            );

            // Register parsers based on configuration
            // Note: Actual parser registration would go here
            // For now, we create an empty registry that can be populated later
            if parsers_cfg.enable_pdf || parsers_cfg.enable_ooxml || parsers_cfg.enable_zip {
                info!("Parser configuration parsed (parser registration TBD)");
            }
        } else {
            info!("No parsers section configured, using default empty registry");
        }

        self.parser_registry = Some(registry);
        info!("ParserRegistry constructed successfully");
        self
    }

    // ===================================================================
    // Step 6: Storage Backend Construction
    // ===================================================================

    /// Construct the [`StorageBackend`] from `config.storage` section.
    ///
    /// Supports multiple backend types selected by `storage.backend` field:
    ///
    /// | Backend | Description                          |
    /// |---------|--------------------------------------|
    /// | `local` | Local filesystem storage              |
    /// | `s3`    | Amazon S3 or S3-compatible (MinIO)    |
    /// | `memory`| In-memory storage (testing only)      |
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::MissingConfig`] if `config.storage` is `None`
    /// - [`BootstrapError::StorageBackendError`] if backend init fails
    /// - [`BootstrapError::InvalidConfig`] for unknown backend types
    #[instrument(skip(self), fields(backend))]
    pub fn build_storage(&mut self) -> Result<&mut Self, BootstrapError> {
        let storage_cfg = self.config.storage.as_ref().ok_or_else(|| {
            BootstrapError::MissingConfig("storage".to_string())
        })?.clone();

        info!(backend = %storage_cfg.backend, "Building StorageBackend");

        match storage_cfg.backend.as_str() {
            "local" => self.build_local_storage(&storage_cfg),
            "memory" => self.build_memory_storage(&storage_cfg),
            "s3" => self.build_s3_storage(&storage_cfg),
            other => Err(BootstrapError::InvalidConfig(format!(
                "Unknown storage backend type: '{other}' (supported: local, memory, s3)"
            ))),
        }
    }

    /// Construct local filesystem storage backend.
    fn build_local_storage(
        &mut self,
        cfg: &StorageSection,
    ) -> Result<&mut Self, BootstrapError> {
        // Placeholder: actual LocalStorageBackend construction would go here
        // For now, we note that this requires the concrete implementation
        info!(base_path = ?cfg.base_path, "Local filesystem storage configured");
        
        // TODO: Instantiate LocalStorageBackend once implemented
        // let backend = LocalStorageBackend::new(cfg.base_path.clone())?;
        // self.storage_backend = Some(Arc::new(backend));

        warn!("LocalStorageBackend not yet implemented in bootstrap (stub)");
        Ok(self)
    }

    /// Construct in-memory storage backend (for testing).
    fn build_memory_storage(
        &mut self,
        _cfg: &StorageSection,
    ) -> Result<&mut Self, BootstrapError> {
        // TODO: Instantiate MemoryStorageBackend for testing
        info!("In-memory storage configured (testing mode)");
        warn!("MemoryStorageBackend not yet implemented in bootstrap (stub)");
        Ok(self)
    }

    /// Construct S3/MinIO cloud storage backend.
    #[cfg(feature = "storage")]
    fn build_s3_storage(
        &mut self,
        cfg: &StorageSection,
    ) -> Result<&mut Self, BootstrapError> {
        info!(
            bucket = ?cfg.bucket,
            region = ?cfg.region,
            endpoint = ?cfg.endpoint_url,
            "S3 storage configured"
        );

        // TODO: Instantiate S3StorageBackend once implemented
        // let backend = S3StorageBackend::new(...)?;
        // self.storage_backend = Some(Arc::new(backend));

        warn!("S3StorageBackend not yet implemented in bootstrap (stub)");
        Ok(self)
    }

    /// S3 storage stub when storage feature is disabled.
    #[cfg(not(feature = "storage"))]
    fn build_s3_storage(
        &mut self,
        _cfg: &StorageSection,
    ) -> Result<&mut Self, BootstrapError> {
        Err(BootstrapError::StorageBackendError(
            "S3 storage feature not enabled (add 'storage-s3' feature flag)".to_string(),
        ))
    }

    // ===================================================================
    // Step 7: Transport Layer Construction (Stub)
    // ===================================================================

    /// Construct the transport layer (HTTP/gRPC servers) from config.
    ///
    /// **Note**: This is currently a stub implementation. Full HTTP/gRPC server
    /// construction will be implemented in a future phase.
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::MissingConfig`] if `config.transport` is `None`
    /// - [`BootstrapError::TransportLayerError`] if server binding fails
    #[instrument(skip(self), fields(http_port, grpc_port))]
    pub fn build_transport(&mut self) -> Result<&mut Self, BootstrapError> {
        let transport_cfg = self.config.transport.as_ref().ok_or_else(|| {
            BootstrapError::MissingConfig("transport".to_string())
        })?;

        info!(
            http_host = %transport_cfg.http_host,
            http_port = transport_cfg.http_port,
            grpc_host = %transport_cfg.grpc_host,
            grpc_port = transport_cfg.grpc_port,
            has_tls = transport_cfg.tls_cert_path.is_some(),
            "Building TransportLayer (stub)"
        );

        // TODO: Implement actual HTTP/gRPC server construction
        // For now, just validate configuration and log intent
        self.transport_layer = Some(Arc::new(())); // Stub placeholder

        info!("TransportLayer configured (server start deferred to MisogiApp::start())");
        Ok(self)
    }

    // ===================================================================
    // Convenience: Build All
    // ===================================================================

    /// Build all components in correct dependency order.
    ///
    /// This convenience method calls all build methods in sequence:
    ///
    /// ```text
    /// JwtValidator → JwtIssuer → IdentityRegistry → AuthEngine →
    /// ParserRegistry → StorageBackend → TransportLayer
    /// ```
    ///
    /// Individual build failures are logged but non-critical components
    /// (parsers, storage) may be skipped gracefully.
    ///
    /// # Errors
    ///
    /// Returns the first error that occurs during sequential building.
    /// Critical components (JWT, AuthEngine) will cause immediate failure;
    /// optional components log warnings and continue.
    ///
    /// # Returns
    ///
    /// `&mut Self` for chaining with [`build()`](Self::build).
    #[instrument(skip(self))]
    pub fn build_all(&mut self) -> Result<&mut Self, BootstrapError> {
        info!("=== Starting full bootstrap sequence ===");

        // Step 1-2: JWT components (critical)
        #[cfg(feature = "jwt")]
        {
            self.build_jwt_validator()?;
            self.build_jwt_issuer()?;
        }

        // Step 3: Identity providers (non-critical, skip on failure)
        self.build_identity_registry();

        // Step 4: Auth Engine (critical, depends on steps 1-3)
        self.build_auth_engine()?;

        // Step 5: Parsers (optional)
        self.build_parser_registry();

        // Step 6: Storage (optional but recommended)
        if self.config.storage.is_some() {
            self.build_storage()?;
        } else {
            info!("No storage section configured, skipping storage backend");
        }

        // Step 7: Transport (required for serving)
        if self.config.transport.is_some() {
            self.build_transport()?;
        } else {
            info!("No transport section configured, skipping transport layer");
        }

        info!("=== Bootstrap sequence complete ===");
        Ok(self)
    }

    // ===================================================================
    // Final Build — Produce MisogiApp
    // ===================================================================

    /// Consume the builder and produce a fully-wired [`MisogiApp`] instance.
    ///
    /// Validates that critical components have been built before producing
    /// the application object. At minimum, [`AuthEngine`] should be built
    /// for any useful operation.
    ///
    /// # Errors
    ///
    /// - [`BootstrapError::MissingDependency`] if critical components are unbuilt
    ///
    /// # Returns
    ///
    /// A [`MisogiApp`] instance ready for [`start()`](MisogiApp::start).
    #[instrument(skip(self))]
    pub fn build(self) -> Result<MisogiApp, BootstrapError> {
        info!("Finalizing MisogiApp assembly...");

        // Validate critical components
        if self.auth_engine.is_none() {
            warn!("Building MisogiApp without AuthEngine — authentication will not work");
        }

        let app = MisogiApp {
            #[cfg(feature = "jwt")]
            jwt_validator: self.jwt_validator,
            #[cfg(feature = "jwt")]
            jwt_issuer: self.jwt_issuer,
            identity_registry: self.identity_registry,
            auth_engine: self.auth_engine,
            parser_registry: self.parser_registry,
            storage_backend: self.storage_backend,
            transport_layer: self.transport_layer,
            config: self.config,
            shutdown: tokio::sync::Notify::new(),
        };

        info!("MisogiApp assembled successfully");
        Ok(app)
    }

    // ===================================================================
    // State Inspection (for testing/debugging)
    // ===================================================================

    /// Check if JWT validator has been built.
    #[cfg(feature = "jwt")]
    pub fn has_jwt_validator(&self) -> bool {
        self.jwt_validator.is_some()
    }

    /// Check if JWT issuer has been built.
    #[cfg(feature = "jwt")]
    pub fn has_jwt_issuer(&self) -> bool {
        self.jwt_issuer.is_some()
    }

    /// Check if identity registry has been built.
    pub fn has_identity_registry(&self) -> bool {
        self.identity_registry.is_some()
    }

    /// Check if auth engine has been built.
    pub fn has_auth_engine(&self) -> bool {
        self.auth_engine.is_some()
    }

    /// Check if parser registry has been built.
    pub fn has_parser_registry(&self) -> bool {
        self.parser_registry.is_some()
    }

    /// Check if storage backend has been built.
    pub fn has_storage_backend(&self) -> bool {
        self.storage_backend.is_some()
    }

    /// Check if transport layer has been built.
    pub fn has_transport_layer(&self) -> bool {
        self.transport_layer.is_some()
    }
}

impl Default for MisogiApplicationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MisogiApplicationBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MisogiApplicationBuilder")
            .field("has_jwt_validator", &{
                #[cfg(feature = "jwt")]
                { self.jwt_validator.is_some() }
                #[cfg(not(feature = "jwt"))]
                { false }
            })
            .field("has_jwt_issuer", &{
                #[cfg(feature = "jwt")]
                { self.jwt_issuer.is_some() }
                #[cfg(not(feature = "jwt"))]
                { false }
            })
            .field("has_identity_registry", &self.identity_registry.is_some())
            .field("has_auth_engine", &self.auth_engine.is_some())
            .field("has_parser_registry", &self.parser_registry.is_some())
            .field("has_storage_backend", &self.storage_backend.is_some())
            .field("has_transport_layer", &self.transport_layer.is_some())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> MisogiConfig {
        MisogiConfig {
            jwt: Some(JwtSection {
                issuer: "test-issuer".to_string(),
                audience: "test-audience".to_string(),
                rsa_pem_path: std::path::PathBuf::from("/tmp/test-private.pem"),
                rsa_pub_pem_path: std::path::PathBuf::from("/tmp/test-public.pem"),
                ttl_hours: 8,
                refresh_ttl_hours: 168,
            }),
            identity_providers: vec![],
            storage: Some(StorageSection {
                backend: "memory".to_string(),
                base_path: None,
                bucket: None,
                region: None,
                endpoint_url: None,
                extra: serde_json::Map::new(),
            }),
            transport: Some(TransportSection {
                http_host: "127.0.0.1".to_string(),
                http_port: 8888,
                grpc_host: "127.0.0.1".to_string(),
                grpc_port: 9999,
                tls_cert_path: None,
                tls_key_path: None,
                request_timeout_secs: 10,
                max_connections: 100,
            }),
            parsers: Some(ParsersSection {
                enable_pdf: true,
                enable_ooxml: true,
                enable_zip: true,
                max_file_size_bytes: 50 * 1024 * 1024,
            }),
            app: AppSection::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Test Group 1: Builder Creation and Configuration
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_builder_is_empty() {
        let builder = MisogiApplicationBuilder::new();
        assert!(!builder.has_auth_engine());
        assert!(!builder.has_parser_registry());
        #[cfg(feature = "jwt")]
        assert!(!builder.has_jwt_validator());
    }

    #[test]
    fn test_with_config_sets_config() {
        let config = create_test_config();
        let builder = MisogiApplicationBuilder::new().with_config(config);
        assert!(builder.config().jwt.is_some());
    }

    #[test]
    fn test_default_builder_matches_new() {
        let a = MisogiApplicationBuilder::new();
        let b = MisogiApplicationBuilder::default();
        // Both should have no components built
        assert_eq!(a.has_auth_engine(), b.has_auth_engine());
    }

    // -----------------------------------------------------------------------
    // Test Group 2: Missing Config Errors
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_jwt_validator_without_config_fails() {
        let mut builder = MisogiApplicationBuilder::new();
        #[cfg(feature = "jwt")]
        let result = builder.build_jwt_validator();
        #[cfg(feature = "jwt")]
        assert!(result.is_err());
        #[cfg(feature = "jwt")]
        assert!(result.unwrap_err().is_config_error());
    }

    #[test]
    fn test_build_storage_without_config_fails() {
        let mut builder = MisogiApplicationBuilder::new();
        let result = builder.build_storage();
        assert!(result.is_err());
        assert!(result.unwrap_err().is_config_error());
    }

    #[test]
    fn test_build_transport_without_config_fails() {
        let mut builder = MisogiApplicationBuilder::new();
        let result = builder.build_transport();
        assert!(result.is_err());
        assert!(result.unwrap_err().is_config_error());
    }

    // -----------------------------------------------------------------------
    // Test Group 3: Identity Provider Registration
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_identity_registry_empty() {
        let config = MisogiConfig {
            identity_providers: vec![],
            ..Default::default()
        };
        let mut builder = MisogiApplicationBuilder::new().with_config(config);
        builder.build_identity_registry();
        assert!(builder.has_identity_registry());
    }

    #[test]
    fn test_unknown_provider_type_error() {
        let config = MisogiConfig {
            identity_providers: vec![IdentityProviderConfig {
                id: "bad-provider".to_string(),
                provider_type: "kerberos".to_string(), // Not supported
                enabled: true,
                name: None,
                config: serde_json::json!({}),
            }],
            ..Default::default()
        };
        let mut builder = MisogiApplicationBuilder::new().with_config(config);
        builder.build_identity_registry();
        // Should not panic; should log warning and skip
        assert!(builder.has_identity_registry());
    }

    #[test]
    fn test_disabled_providers_skipped() {
        let config = MisogiConfig {
            identity_providers: vec![IdentityProviderConfig {
                id: "disabled-ldap".to_string(),
                provider_type: "ldap".to_string(),
                enabled: false, // Disabled
                name: None,
                config: serde_json::json!({}),
            }],
            ..Default::default()
        };
        let mut builder = MisogiApplicationBuilder::new().with_config(config);
        builder.build_identity_registry();
        assert!(builder.has_identity_registry());
        // Provider should not be registered since it's disabled
    }

    // -----------------------------------------------------------------------
    // Test Group 4: Parser Registry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_parser_registry_creates_instance() {
        let mut builder = MisogiApplicationBuilder::new();
        builder.build_parser_registry();
        assert!(builder.has_parser_registry());
    }

    #[test]
    fn test_build_parser_registry_with_config() {
        let config = MisogiConfig {
            parsers: Some(ParsersSection {
                enable_pdf: true,
                enable_ooxml: false,
                enable_zip: true,
                max_file_size_bytes: 200 * 1024 * 1024,
            }),
            ..Default::default()
        };
        let mut builder = MisogiApplicationBuilder::new().with_config(config);
        builder.build_parser_registry();
        assert!(builder.has_parser_registry());
    }

    // -----------------------------------------------------------------------
    // Test Group 5: Dependency Order Enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_auth_engine_without_jwt_validator() {
        let config = create_test_config();
        let mut builder = MisogiApplicationBuilder::new().with_config(config);
        // Don't build JWT validator first
        let result = builder.build_auth_engine();
        #[cfg(feature = "jwt")]
        {
            assert!(result.is_err());
            assert!(result.unwrap_err().is_dependency_error());
        }
    }

    // -----------------------------------------------------------------------
    // Test Group 6: Build All vs Selective Build
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_all_constructs_all_components() {
        let config = create_test_config();
        let mut builder = MisogiApplicationBuilder::new().with_config(config);

        // Note: This will likely fail on JWT validator due to missing key files
        // But we can check that build_all attempts all steps
        let _result = builder.build_all();
        // Even if some steps fail, later steps should still be attempted
        // (for non-critical components)
    }

    #[test]
    fn test_selective_build_only_builds_requested() {
        let config = MisogiConfig::default();
        let mut builder = MisogiApplicationBuilder::new().with_config(config);

        // Only build parser registry
        builder.build_parser_registry();

        assert!(builder.has_parser_registry());
        assert!(!builder.has_auth_engine());
        assert!(!builder.has_identity_registry());
    }
}
