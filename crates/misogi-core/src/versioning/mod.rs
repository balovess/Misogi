//! Multi-version API management for enterprise-grade stability.
//!
//! This module implements Google's API Design Guide principles for
//! version control in gRPC (package-level) and REST (URL-path) APIs,
//! tailored for Japanese B2B/B2G deployment scenarios with multi-year
//! migration windows.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                    versioning/                               |
//! |                                                             |
//! |  api_version.rs          -> ApiVersion enum + path parsing   |
//! |  api_semver.rs           -> Semantic Version struct (MAJOR.MINOR.PATCH) |
//! |  protocol_adapter.rs     -> ProtocolAdapter trait + errors   |
//! |  versioned_types.rs      -> VersionedRequest/Response        |
//! |  deprecation_middleware.rs -> Axum [DEPRECATION] warning     |
//! |  compatibility_adapter.rs  -> v1 <-> v2 data converter       |
//! |  downgrade_adapter.rs      -> v2->v1 field stripper           |
//! |  sunset_policy.rs         -> Lifecycle phase machine          |
//! |  grpc_version_interceptor.rs -> gRPC version-aware interceptor|
//! +-------------------------------------------------------------+
//! ```
//!
//! # Lifecycle States
//!
//! ```text
//! STABLE --> DEPRECATED (warning only)
//!          --> SUNSET_SOFT (rate limit + headers)
//!                 --> SUNSET_HARD (410 Gone)
//!                       --> REMOVED (404)
//! ```

pub mod api_version;
pub mod api_semver;
pub mod protocol_adapter;
pub mod versioned_types;
pub mod deprecation_middleware;
pub mod compatibility_adapter;
pub mod downgrade_adapter;
pub mod sunset_policy;
#[cfg(feature = "grpc")]
pub mod grpc_version_interceptor;

// Re-exports with clear naming to avoid conflicts
pub use api_version::ApiVersion as EnumApiVersion;
pub use api_semver::{ApiVersion, ParseVersionError};
pub use protocol_adapter::{AdapterError, ProtocolAdapter};
pub use versioned_types::{VersionedRequest, VersionedResponse};
pub use deprecation_middleware::{DeprecationConfig, deprecation_warning_middleware};
pub use compatibility_adapter::{ChunkCompatAdapter, AdaptDirection, AdaptedResult};
pub use downgrade_adapter::{DowngradeAdapter, DowngradeBuilder, default_v1_fields};
pub use sunset_policy::{SunsetPhase, VersionSunsetPolicy};
#[cfg(feature = "grpc")]
pub use grpc_version_interceptor::{
    GrpcVersionInterceptor,
    GrpcVersionConfig,
    GrpcVersionConfigBuilder,
    VersionInterceptorError,
};
