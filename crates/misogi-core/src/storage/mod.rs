// =============================================================================
// Misogi Core — Storage Backend Implementations
// =============================================================================
//! Concrete implementations of the [`StorageBackend`] trait (Pillar 2).
//!
//! Each module in this directory provides a pluggable storage backend that
//! can be instantiated at runtime via the plugin registry or direct
//! construction with provider-specific configuration.
//!
//! # Available Backends
//!
//! | Module            | Type Identifier | Description                          |
//! |-------------------|-----------------|--------------------------------------|
//! | [`local`]         | `"local"`       | Local filesystem backend (default)    |
//! | [`api_forward`]   | `"api_forward"` | Write-only HTTP API forwarder        |
//! | [`s3`]            | `"s3"`          | S3-compatible cloud storage          |
//!
//! # Adding a New Backend
//!
//! 1. Create a new `your_backend.rs` file in this directory.
//! 2. Implement the [`StorageBackend`](crate::traits::storage::StorageBackend) trait.
//! 3. Register the module below with `pub mod your_backend;`.
//! 4. Re-export the public types from this module's parent if needed.

pub mod api_forward;
pub mod local;
pub mod registry;

#[cfg(feature = "storage-s3")]
pub mod s3;

#[cfg(feature = "storage-s3")]
pub mod s3_multipart;

#[cfg(feature = "storage-azure")]
pub mod azure_blob;

#[cfg(feature = "storage-gcs")]
pub mod gcs;

// Re-exports for ergonomic imports from crate root level
pub use api_forward::{ApiForwardConfig, ApiForwardStorage, HttpMethod};
pub use local::{LocalConfig, LocalStorage};
pub use registry::{StorageBackendInfo, StorageRegistry};

#[cfg(feature = "storage-s3")]
pub use s3::{S3Config, S3Storage};

#[cfg(feature = "storage-s3")]
pub use s3_multipart::S3MultipartConfig;

#[cfg(feature = "storage-azure")]
pub use azure_blob::{AzureBlobConfig, AzureBlobStorage};

#[cfg(feature = "storage-gcs")]
pub use gcs::{GcsConfig, GcsStorage};
