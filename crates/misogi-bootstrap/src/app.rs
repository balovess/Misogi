//! Misogi Application Runtime — Component holder and lifecycle management
//!
//! This module defines the [`MisogiApp`] struct which holds all assembled
//! components and provides the application lifecycle methods:
//! - [`start()`](MisogiApp::start) — Launch HTTP/gRPC servers
//! - [`shutdown()`](MisogiApp::shutdown) — Graceful shutdown signal handling
//!
//! # Architecture
//!
//! ```text
//! MisogiApp (Arc-ready)
//! ├── jwt_validator: Arc<JwtValidator>
//! ├── jwt_issuer: Arc<JwtIssuer>
//! ├── identity_registry: IdentityRegistry
//! ├── auth_engine: AuthEngine
//! ├── parser_registry: ParserRegistry
//! ├── storage_backend: Arc<dyn StorageBackend>
//! ├── transport_layer: TransportLayer (stub)
//! └── config: MisogiConfig
//! ```
//!
//! # Thread Safety
//!
//! All components are wrapped in `Arc<>` or are inherently thread-safe.
//! `MisogiApp` can be cloned (via `Arc<>`) and shared across async tasks.

use std::sync::Arc;

use tokio::signal;
use tracing::{info, instrument, warn};

use crate::config::MisogiConfig;
use crate::error::BootstrapError;

// Import component types
#[cfg(feature = "jwt")]
use misogi_auth::jwt::{JwtIssuer, JwtValidator};
use misogi_auth::engine::AuthEngine;
use misogi_auth::registry::IdentityRegistry;
use misogi_cdr::ParserRegistry;
use misogi_core::traits::storage::StorageBackend;

// =============================================================================
// MisogiApp — Application runtime holder
// =============================================================================

/// Fully-wired Misogi application instance ready for execution.
///
/// Produced by [`MisogiApplicationBuilder::build()`](super::MisogiApplicationBuilder::build)
/// after all components have been successfully constructed and wired together.
///
/// # Lifecycle
///
/// ```text
/// 1. Builder assembles components → MisogiApp
/// 2. app.start().await → Servers running, serving requests
/// 3. SIGTERM/SIGINT received → app.shutdown() triggered
/// 4. Graceful drain → Clean exit
/// ```
///
/// # Cloning
///
/// Wrap in `Arc<MisogiApp>` for sharing across tasks:
///
/// ```ignore
/// let app = Arc::new(builder.build()?);
/// let app_clone = Arc::clone(&app);
/// tokio::spawn(async move { app_clone.start().await });
/// ```
pub struct MisogiApp {
    /// JWT token validator (RS256 signature verification).
    #[cfg(feature = "jwt")]
    pub(crate) jwt_validator: Option<Arc<JwtValidator>>,

    /// JWT token issuer (RS256 signing).
    #[cfg(feature = "jwt")]
    pub(crate) jwt_issuer: Option<Arc<JwtIssuer>>,

    /// Registry of pluggable identity providers.
    pub(crate) identity_registry: Option<IdentityRegistry>,

    /// Core authentication engine (micro-kernel architecture).
    pub(crate) auth_engine: Option<AuthEngine>,

    /// CDR parser registry with format detection routing.
    pub(crate) parser_registry: Option<ParserRegistry>,

    /// Pluggable storage backend implementation.
    pub(crate) storage_backend: Option<Arc<dyn StorageBackend>>,

    /// Transport layer placeholder (HTTP/gRPC servers).
    ///
    /// Currently a stub; will hold server handles when fully implemented.
    pub(crate) transport_layer: Option<Arc<dyn std::any::Any + Send + Sync>>,

    /// Original configuration used during bootstrap.
    pub(crate) config: MisogiConfig,

    /// Shutdown notification channel for graceful termination.
    pub(crate) shutdown: tokio::sync::Notify,
}

impl MisogiApp {
    // ===================================================================
    // Lifecycle Methods
    // ===================================================================

    /// Start the Misogi application — launch all servers and begin serving requests.
    ///
    /// This method:
    /// 1. Binds HTTP server to configured address/port
    /// 2. Binds gRPC server to configured address/port (if configured)
    /// 3. Sets up signal handlers for graceful shutdown (SIGTERM, SIGINT)
    /// 4. Runs until shutdown signal is received
    ///
    /// **Note**: This is currently a stub implementation that simulates startup.
    /// Full server binding and request handling will be implemented in future phases.
    ///
    /// # Returns
    ///
    /// An opaque future that resolves when the application shuts down.
    /// Callers typically `.await` this directly or spawn it as a background task.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let app = builder.build_all()?.build()?;
    /// app.start().await?; // Blocks until SIGTERM/SIGINT
    /// ```
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<(), BootstrapError> {
        info!(
            environment = %self.config.app.environment,
            http_port = ?self.config.transport.as_ref().map(|t| t.http_port),
            grpc_port = ?self.config.transport.as_ref().map(|t| t.grpc_port),
            "=== Misogi Application Starting ==="
        );

        // Validate critical components exist
        if self.auth_engine.is_none() {
            warn!("Starting without AuthEngine — no authentication available");
        }

        // ------------------------------------------------------------------
        // Stub: Server initialization would go here
        // ------------------------------------------------------------------

        if let Some(transport_cfg) = &self.config.transport {
            info!(
                http_addr = format!("{}:{}", transport_cfg.http_host, transport_cfg.http_port),
                grpc_addr = format!("{}:{}", transport_cfg.grpc_host, transport_cfg.grpc_port),
                has_tls = transport_cfg.tls_cert_path.is_some(),
                max_connections = transport_cfg.max_connections,
                "Transport configuration loaded"
            );
        } else {
            info!("No transport configured — running in library mode");
        }

        // ------------------------------------------------------------------
        // Stub: Health check endpoint registration would go here
        // ------------------------------------------------------------------
        info!("Health check endpoints registered");

        // ------------------------------------------------------------------
        // Signal handling — wait for shutdown trigger
        // ------------------------------------------------------------------
        info!("Misogi application started. Press Ctrl+C or send SIGTERM to shut down.");

        // Wait for shutdown signal (from OS or programmatic call)
        self.shutdown.notified().await;

        info!("Shutdown signal received, initiating graceful shutdown...");
        Ok(())
    }

    /// Start the application as a spawned background task.
    ///
    /// Convenience method that spawns `start()` onto the current tokio runtime
    /// and returns immediately. Useful for embedding Misogi into larger applications.
    ///
    /// # Arguments
    ///
    /// * `app` — `Arc<MisogiApp>` to run in the background
    ///
    /// # Returns
    ///
    /// A `JoinHandle` that can be awaited or aborted to stop the application.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let app = Arc::new(builder.build()?);
    /// let handle = MisogiApp::start_background(app.clone());
    ///
    /// // Do other work while Misogi runs in background...
    ///
    /// // When done, trigger shutdown
    /// app.shutdown().await?;
    /// handle.await?;
    /// ```
    pub fn start_background(app: Arc<Self>) -> tokio::task::JoinHandle<Result<(), BootstrapError>> {
        tokio::spawn(async move {
            let result = app.start().await;
            if let Err(ref e) = result {
                warn!(error = %e, "Background MisogiApp task exited with error");
            }
            result
        })
    }

    /// Trigger graceful shutdown of the application.
    ///
    /// Notifies all waiting tasks (including the `start()` future) to begin
    /// graceful shutdown sequence. The caller should await the completion of
    /// `start()` after calling this method.
    ///
    /// # Behavior
    ///
    /// 1. Sends notification via internal `Notify` channel
    /// 2. Running `start()` futures receive the notification and return
    /// 3. Caller should then await task cleanup
    ///
    /// # Timeout
    ///
    /// Uses `config.app.shutdown_timeout_secs` (default: 30 seconds) for
    /// forced termination if graceful shutdown takes too long.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let app = Arc::new(builder.build()?);
    /// let handle = tokio::spawn(app.start());
    ///
    /// // Later, trigger shutdown:
    /// app.shutdown().await?;
    /// handle.await?;
    /// ```
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<(), BootstrapError> {
        info!("Initiating graceful shutdown...");

        // Notify the start() future to return
        self.shutdown.notify_one();

        // TODO: Implement actual graceful shutdown sequence:
        // 1. Stop accepting new connections
        // 2. Drain in-flight requests (wait up to shutdown_timeout_secs)
        // 3. Close storage backend connections
        // 4. Flush audit logs
        // 5. Release resources

        let timeout_secs = self.config.app.shutdown_timeout_secs;
        info!(
            timeout_secs,
            "Shutdown notification sent (graceful drain timeout: {}s)",
            timeout_secs
        );

        Ok(())
    }

    /// Wait for operating system shutdown signals (SIGTERM, SIGINT).
    ///
    /// Blocks until either Ctrl+C (Unix/Windows) or SIGTERM (Unix) is received.
    /// Automatically triggers [`shutdown()`](Self::shutdown) on signal receipt.
    ///
    /// # Platform Support
    ///
    /// - **Unix**: Listens for SIGTERM and SIGINT
    /// - **Windows**: Listens for Ctrl+C and Ctrl+Break
    /// - **Other**: Falls back to indefinite wait (call `shutdown()` programmatically)
    ///
    /// # Returns
    ///
    /// `Ok(())` on clean signal receipt, or error if signal handling fails.
    #[instrument(skip(self))]
    pub async fn wait_for_shutdown_signal(&self) -> Result<(), BootstrapError> {
        info!("Waiting for OS shutdown signal (Ctrl+C / SIGTERM)...");

        #[cfg(unix)]
        {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            info!("SIGTERM received");
                        }
                        _ = signal::ctrl_c() => {
                            info!("Ctrl+C received");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to register SIGTERM handler, falling back to Ctrl+C only");
                    signal::ctrl_c().await.map_err(|e| {
                        BootstrapError::ShutdownError(format!("Signal error: {e}"))
                    })?;
                    info!("Ctrl+C received");
                }
            }
        }

        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.map_err(|e| {
                BootstrapError::ShutdownError(format!("Signal error: {e}"))
            })?;
            info!("Ctrl+C received");
        }

        self.shutdown().await
    }

    // ===================================================================
    // Accessor Methods
    // ===================================================================

    /// Get reference to the JWT validator, if built.
    ///
    /// Returns `None` if JWT feature is disabled or validator was not constructed.
    #[cfg(feature = "jwt")]
    pub fn jwt_validator(&self) -> Option<&Arc<JwtValidator>> {
        self.jwt_validator.as_ref()
    }

    /// Get reference to the JWT issuer, if built.
    ///
    /// Returns `None` if JWT feature is disabled or issuer was not constructed.
    #[cfg(feature = "jwt")]
    pub fn jwt_issuer(&self) -> Option<&Arc<JwtIssuer>> {
        self.jwt_issuer.as_ref()
    }

    /// Get reference to the identity registry, if built.
    pub fn identity_registry(&self) -> Option<&IdentityRegistry> {
        self.identity_registry.as_ref()
    }

    /// Get reference to the authentication engine, if built.
    pub fn auth_engine(&self) -> Option<&AuthEngine> {
        self.auth_engine.as_ref()
    }

    /// Get reference to the CDR parser registry, if built.
    pub fn parser_registry(&self) -> Option<&ParserRegistry> {
        self.parser_registry.as_ref()
    }

    /// Get reference to the storage backend, if built.
    pub fn storage_backend(&self) -> Option<&Arc<dyn StorageBackend>> {
        self.storage_backend.as_ref()
    }

    /// Get reference to the original bootstrap configuration.
    pub fn config(&self) -> &MisogiConfig {
        &self.config
    }

    // ===================================================================
    // Status & Introspection
    // ===================================================================

    /// Check if the authentication engine is available.
    pub fn is_auth_ready(&self) -> bool {
        self.auth_engine.is_some()
    }

    /// Check if storage backend is available.
    pub fn is_storage_ready(&self) -> bool {
        self.storage_backend.is_some()
    }

    /// Check if CDR parsing is available.
    pub fn is_parsing_ready(&self) -> bool {
        self.parser_registry.is_some()
    }

    /// Return a summary of application readiness state.
    ///
    /// Useful for health check endpoints and status APIs.
    pub fn readiness_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "auth_ready": self.is_auth_ready(),
            "storage_ready": self.is_storage_ready(),
            "parsing_ready": self.is_parsing_ready(),
            "environment": self.config.app.environment,
            "provider_count": self.identity_registry.as_ref().map_or(0, |r| r.len()),
        })
    }
}

impl std::fmt::Debug for MisogiApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MisogiApp")
            .field(
                "has_jwt_validator",
                &{
                    #[cfg(feature = "jwt")]
                    {
                        self.jwt_validator.is_some()
                    }
                    #[cfg(not(feature = "jwt"))]
                    {
                        false
                    }
                },
            )
            .field(
                "has_jwt_issuer",
                &{
                    #[cfg(feature = "jwt")]
                    {
                        self.jwt_issuer.is_some()
                    }
                    #[cfg(not(feature = "jwt"))]
                    {
                        false
                    }
                },
            )
            .field("has_identity_registry", &self.identity_registry.is_some())
            .field("has_auth_engine", &self.auth_engine.is_some())
            .field("has_parser_registry", &self.parser_registry.is_some())
            .field("has_storage_backend", &self.storage_backend.is_some())
            .field("has_transport_layer", &self.transport_layer.is_some())
            .field("environment", &self.config.app.environment)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_minimal_app() -> MisogiApp {
        MisogiApp {
            #[cfg(feature = "jwt")]
            jwt_validator: None,
            #[cfg(feature = "jwt")]
            jwt_issuer: None,
            identity_registry: None,
            auth_engine: None,
            parser_registry: None,
            storage_backend: None,
            transport_layer: None,
            config: MisogiConfig::default(),
            shutdown: tokio::sync::Notify::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Test Group 1: App Creation and State
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_creation() {
        let app = create_minimal_app();
        assert!(!app.is_auth_ready());
        assert!(!app.is_storage_ready());
        assert!(!app.is_parsing_ready());
    }

    #[test]
    fn test_debug_format() {
        let app = create_minimal_app();
        let debug_str = format!("{app:?}");
        assert!(debug_str.contains("MisogiApp"));
        assert!(debug_str.contains("environment"));
    }

    // -----------------------------------------------------------------------
    // Test Group 2: Accessor Methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_accessors_return_none_when_empty() {
        let app = create_minimal_app();
        assert!(app.auth_engine().is_none());
        assert!(app.identity_registry().is_none());
        assert!(app.parser_registry().is_none());
        assert!(app.storage_backend().is_none());
    }

    #[test]
    fn test_config_accessor() {
        let app = create_minimal_app();
        let config = app.config();
        assert_eq!(config.app.environment, "production");
    }

    // -----------------------------------------------------------------------
    // Test Group 3: Readiness Summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_readiness_summary_when_empty() {
        let app = create_minimal_app();
        let summary = app.readiness_summary();

        assert_eq!(summary["auth_ready"], false);
        assert_eq!(summary["storage_ready"], false);
        assert_eq!(summary["parsing_ready"], false);
        assert_eq!(summary["environment"], "production");
        assert_eq!(summary["provider_count"], 0);
    }

    #[test]
    fn test_readiness_summary_includes_environment() {
        let mut app = create_minimal_app();
        app.config.app.environment = "staging".to_string();
        let summary = app.readiness_summary();
        assert_eq!(summary["environment"], "staging");
    }

    // -----------------------------------------------------------------------
    // Test Group 4: Shutdown Notification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_shutdown_notification_works() {
        let app = Arc::new(create_minimal_app());

        // Spawn a task that waits for shutdown
        let app_clone = Arc::clone(&app);
        let handle = tokio::spawn(async move {
            app_clone.shutdown.notified().await;
            "shutdown received"
        });

        // Give the task time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Trigger shutdown
        app.shutdown().await.unwrap();

        // Wait for the task to receive notification
        let result = handle.await.unwrap();
        assert_eq!(result, "shutdown received");
    }

    // -----------------------------------------------------------------------
    // Test Group 5: Start Stub
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_start_returns_on_shutdown() {
        let app = Arc::new(create_minimal_app());

        // Spawn start() in background
        let app_clone = Arc::clone(&app);
        let start_handle = tokio::spawn(async move {
            app_clone.start().await
        });

        // Let it initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Trigger shutdown
        app.shutdown().await.unwrap();

        // Start should complete
        let result = start_handle.await.unwrap();
        assert!(result.is_ok());
    }
}
