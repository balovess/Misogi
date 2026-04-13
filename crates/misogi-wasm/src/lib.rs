//! # Misogi WASM Module — Dual-Target Runtime
//!
//! This crate supports **two compilation targets** with distinct use cases:
//!
//! | Target | Use Case | Key Dependency |
//! |--------|----------|----------------|
//! | `x86_64-pc-windows-msvc` / `x86_64-unknown-linux-gnu` | Server-side WASM plugin runtime | `wasmi` interpreter |
//! | `wasm32-unknown-unknown` | Browser / Edge runtime | `wasm-bindgen` FFI |
//!
//! ## Native Target (`feature = "native"`, default)
//!
//! Sandboxed WebAssembly runtime for hot-loading external content parsers
//! in the Misogi CDR pipeline using the **wasmi** interpreter.
//!
//! ### Security Model (Native)
//!
//! - Memory limits: Configurable heap size (default 64 MB)
//! - CPU timeout: Execution time limits (default 30 seconds)
//! - No filesystem access: No host FS imports exposed to plugins
//! - No network access: No socket/network imports exposed
//! - Controlled imports: Only memory allocation and logging functions
//!
//! ## Browser Target (`feature = "browser"`)
//!
//! Client-side CDR sanitization via `wasm-bindgen`, enabling browser-based
//! file processing without server round-trips. Exposes FFI functions:
//! - `sanitize_pdf()` — PDF JavaScript/macro removal
//! - `sanitize_office()` — OOXML VBA macro stripping
//! - `scan_pii()` — Japanese PII pattern detection
//! - `detect_file_type()` — Magic byte file type identification
//!
//! ## Shared Code (`wasm_compat`)
//!
//! Core sanitization logic in [`wasm_compat`] is **target-agnostic** and
//! used by both compilation paths.

// ===========================================================================
// Target-Agnostic Modules (always compiled)
// ===========================================================================

/// In-memory sanitizer implementations shared across all targets.
///
/// Contains [`WasmPdfSanitizer`], [`WasmOfficeSanitizer`], PII scan adapters,
/// and hash utilities that operate purely on `&[u8]` / `Vec<u8>` buffers.
pub mod wasm_compat;

/// Crate version for debugging and logging purposes.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of simultaneous WASM plugin instances.
pub const MAX_PLUGINS: usize = 256;

/// Default memory limit for WASM sandbox (64 MB).
pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

/// Default CPU timeout for WASM execution (30 seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

// ===========================================================================
// Native-Only Modules (wasmi plugin runtime, feature-gated)
// ===========================================================================

#[cfg(feature = "native")]
pub mod abi;

#[cfg(feature = "native")]
pub mod adapter;

#[cfg(feature = "native")]
pub mod error;

#[cfg(feature = "native")]
pub mod manager;

#[cfg(feature = "native")]
pub mod sandbox;

// Re-exports for native target consumers
#[cfg(feature = "native")]
pub use adapter::WasmParserAdapter;

#[cfg(feature = "native")]
pub use error::{WasmError, WasmResult};

#[cfg(feature = "native")]
pub use manager::WasmPluginManager;

#[cfg(feature = "native")]
pub use sandbox::SandboxConfig;

// ===========================================================================
// Browser-Only Modules (wasm-bindgen FFI, feature-gated)
// ===========================================================================

#[cfg(feature = "browser")]
pub mod ffi;

#[cfg(feature = "browser")]
pub mod js_glue;
