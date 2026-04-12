//! # Misogi WASM Plugin Runtime
//!
//! Sandboxed WebAssembly runtime for hot-loading external content parsers
//! in the Misogi CDR (Content Disarm & Reconstruction) pipeline.
//!
//! ## Architecture
//!
//! This crate provides a secure, isolated execution environment for WASM-based
//! parser plugins using the **wasmi** interpreter (chosen for its lightweight,
//! deterministic execution model without JIT compilation overhead).
//!
//! ## Security Model
//!
//! - **Memory limits**: Configurable heap size (default 64 MB)
//! - **CPU timeout**: Execution time limits (default 30 seconds)
//! - **No filesystem access**: No host FS imports exposed to plugins
//! - **No network access**: No socket/network imports exposed
//! - **Controlled imports**: Only memory allocation and logging functions

pub mod abi;
pub mod adapter;
pub mod error;
pub mod manager;
pub mod sandbox;

pub use adapter::WasmParserAdapter;
pub use error::{WasmError, WasmResult};
pub use manager::WasmPluginManager;
pub use sandbox::SandboxConfig;

/// Crate version for debugging and logging purposes.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of simultaneous WASM plugin instances.
pub const MAX_PLUGINS: usize = 256;

/// Default memory limit for WASM sandbox (64 MB).
pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

/// Default CPU timeout for WASM execution (30 seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
