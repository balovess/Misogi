//! Misogi Configuration — Centralized TOML Configuration Loader
//!
//! Provides a unified configuration system that loads from TOML files and
//! distributes configuration to all subsystems (Auth, CDR, Storage, Transport).
//!
//! # Architecture
//!
//! Configuration flow:
//! 1. Load from TOML file or string
//! 2. Apply MISOGI_* environment variable overrides (optional)
//! 3. Validate all sections
//! 4. Distribute to subsystems via accessor methods
//!
//! # Feature Flags
//!
//! | Feature    | Description                              |
//! |------------|------------------------------------------|
//! | `auth`     | Enable JWT configuration section         |
//! | `cdr`      | Enable CDR configuration section (future) |
//! | `storage`  | Enable storage backend configuration     |
//! | `transport`| Enable transport layer configuration     |
//! | `full`     | Enable all subsystem configurations      |
//!
//! # Quick Start
//!
//! ```ignore
//! use misogi_config::MisogiConfig;
//! use std::path::Path;
//!
//! // Load from file (with env overrides + validation)
//! let config = MisogiConfig::from_file(Path::new("misogi.toml"))?;
//!
//! // Extract subsystem configs
//! let jwt = config.jwt_config();
//! let storage = config.storage_config();
//! let transport = config.transport_config();
//!
//! // Iterate identity providers
//! for provider in config.identity_provider_configs() {
//!     println!("Provider: {} ({})", provider.id, provider.provider_type);
//! }
//! ```

pub mod error;
pub mod config;

// --- Public exports ---
pub use error::ConfigError;
pub use config::{
    MisogiConfig,
    GeneralConfig,
    JwtConfigSection,
    IdentityProviderConfig,
    StorageConfigSection,
    TransportConfigSection,
    ParsersConfigSection,
};
