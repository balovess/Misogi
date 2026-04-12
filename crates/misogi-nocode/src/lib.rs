//! # Misogi No-Code Integration Layer
//!
//! YAML-based declarative configuration system enabling government IT staff
//! to configure Misogi without writing Rust code.
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    No-Code Layer                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Layer 1: schema.rs   — YAML Schema Definition              │
//! │    ↓ Defines the complete YAML structure with validation     │
//! │  Layer 2: compiler.rs — YAML → MisogiConfig Compiler        │
//! │    ↓ Transforms YAML to internal config structs             │
//! │  Layer 3: runtime.rs  — Hot-Reload Runtime Engine           │
//! │    ↓ Manages config lifecycle and graceful reloads          │
//! │  Layer 4: api.rs      — Admin REST API Control Plane         │
//! │    ↓ HTTP endpoints for config management                   │
//! │  Layer 5: cli.rs      — misogi-admin CLI Tool               │
//! │    ↓ Command-line interface for operations                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Design Principles
//!
//! - **Accessibility**: YAML format chosen over TOML for better readability by non-developers
//! - **Safety**: All configurations validated before application; rollback on error
//! - **Transparency**: Detailed compilation reports with warnings and errors
//! - **Zero-Trust**: Secrets masked in all API responses and logs
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_nocode::{YamlConfig, NoCodeRuntime};
//!
//! // Parse and validate YAML configuration
//! let yaml_config = YamlConfig::from_yaml_str(include_str!("config.yaml"))?;
//!
//! // Validate schema integrity
//! let errors = yaml_config.validate()?;
//! assert!(errors.is_empty(), "Configuration has validation errors");
//!
//! // Initialize runtime with hot-reload capability
//! let runtime = NoCodeRuntime::new(yaml_config);
//! runtime.watch_file("config.yaml").await?;
//! ```

pub mod error;
pub mod schema;
pub mod compiler;
pub mod runtime;
pub mod health;
pub mod api;
pub mod cli;

// Re-export primary types for ergonomic imports
pub use error::{YamlError, ValidationError, CompileError, RuntimeError, ApiError};
pub use schema::YamlConfig;
pub use compiler::{compile, CompileReport};
pub use runtime::NoCodeRuntime;
pub use api::create_admin_router;
pub use health::build_health_router;
