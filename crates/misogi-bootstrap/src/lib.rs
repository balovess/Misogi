//! Misogi Bootstrap — Application Assembly and Component Wiring
//!
//! This crate provides the unified entry point for assembling all Misogi components
//! from a declarative configuration. It implements the **Builder Pattern** for
//! dependency injection and enforces strict build order to ensure correct component
//! wiring.
//!
//! # Architecture Overview
//!
//! ```text
//! MisogiConfig (TOML/JSON)
//!       │
//!       ▼
//! MisogiApplicationBuilder ──build_all()──▶ MisogiApp
//!  │                              │
//!  ├── build_jwt_validator()      │ Holds:
//!  ├── build_jwt_issuer()        │  • JwtValidator (Arc)
//!  ├── build_identity_registry()  │  • JwtIssuer (Arc)
//!  ├── build_auth_engine()        │  • IdentityRegistry
//!  ├── build_parser_registry()    │  • AuthEngine
//!  ├── build_storage()            │  • ParserRegistry
//!  └── build_transport()          │  • StorageBackend (dyn)
//!                                 │  • TransportLayer (stub)
//!                                 │
//!                                 ▼
//!                         app.start().await
//!                         app.shutdown().await
//! ```
//!
//! # Quick Start
//!
//! ```ignore
//! use misogi_bootstrap::{MisogiApplicationBuilder, MisogiConfig};
//!
//! // Load configuration from file
//! let config = MisogiConfig::from_toml_file("misogi.toml")?;
//!
//! // Build all components and create application instance
//! let app = MisogiApplicationBuilder::new()
//!     .with_config(config)
//!     .build_all()?      // Build everything in dependency order
//!     .build()?;         // Produce the final MisogiApp
//!
//! // Start serving requests (blocks until shutdown signal)
//! app.start().await?;
//! ```
//!
//! # Feature Flags
//!
//! | Feature   | Description                                    | Default |
//! |-----------|------------------------------------------------|---------|
//! | `jwt`     | Enable JWT authentication components           | yes     |
//! | `ldap`    | Enable LDAP/AD identity provider support        | no      |
//! | `oidc`    | Enable OIDC/OAuth2 identity provider support    | no      |
//! | `saml`    | Enable SAML 2.0 identity provider support       | no      |
//! | `storage` | Enable S3/MinIO cloud storage backend           | no      |
//!
//! # Build Order
//!
//! Components are built in strict dependency order. The builder enforces this
//! at runtime, returning [`BootstrapError::MissingDependency`] if order is violated:
//!
//! 1. **JwtValidator** — Token validation (requires: config.jwt)
//! 2. **JwtIssuer** — Token issuance (requires: config.jwt)
//! 3. **IdentityRegistry** — Provider registry (requires: nothing)
//! 4. **AuthEngine** — Auth core (requires: JwtValidator, optionally IdentityRegistry)
//! 5. **ParserRegistry** — CDR routing (requires: nothing)
//! 6. **StorageBackend** — Object storage (requires: config.storage)
//! 7. **TransportLayer** — HTTP/gRPC servers (requires: config.transport)
//!
//! # Error Handling
//!
//! All bootstrap operations return [`BootstrapError`] with detailed context:
//!
//! - Configuration errors → Fix config file and retry
//! - Dependency errors → Adjust build method call order
//! - Component errors → Check keys, permissions, network connectivity
//!
//! # Thread Safety
//!
//! - [`MisogiApplicationBuilder`] is **not** thread-safe (single-threaded startup only)
//! - [`MisogiApp`] is fully thread-safe when wrapped in `Arc<>`
//! - All internal components use `Arc<>` for zero-cost sharing across async tasks

// --- Public modules ---

/// Error types for bootstrap operations.
pub mod error;

/// Application configuration types (MisogiConfig and sections).
pub mod config;

/// Application builder — assembles all components from configuration.
pub mod builder;

/// Application runtime holder — lifecycle management.
pub mod app;

// --- Re-exports for convenience ---

/// Comprehensive error type for all bootstrap operations.
pub use error::BootstrapError;

/// Complete application configuration structure.
pub use config::MisogiConfig;

/// Application builder with fluent API for component assembly.
pub use builder::MisogiApplicationBuilder;

/// Fully-wired application instance ready for execution.
pub use app::MisogiApp;

// --- Re-export configuration section types ---

pub use config::{
    AppSection, IdentityProviderConfig, JwtSection, ParsersSection,
    StorageSection, TransportSection,
};

// =============================================================================
// Prelude — convenient re-exports for common patterns
// =============================================================================

/// Prelude module with commonly used types.
///
/// Import with `use misogi_bootstrap::prelude::*;` for quick access.
pub mod prelude {
    pub use super::{BootstrapError, MisogiApp, MisogiConfig, MisogiApplicationBuilder};
}
