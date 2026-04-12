//! API version identification and extraction utilities.
//!
//! Provides a strongly-typed representation of API versions used across
//! gRPC packages, REST URL paths, and wire protocol headers.
//!
//! # Usage
//!
//! ```rust,ignore
//! use misogi_core::versioning::ApiVersion;
//!
//! let ver = ApiVersion::from_uri_path("/api/v1/upload");
//! assert_eq!(ver, Some(ApiVersion::V1));
//!
//! println!("{}", ApiVersion::V2); // "v2"
//! println!("{}", ApiVersion::V1.url_prefix()); // "/api/v1"
//! ```

use serde::{Deserialize, Serialize};

/// Supported API versions for the Misogi platform.
///
/// Each variant corresponds to a distinct set of proto packages,
/// REST URL prefixes, and wire-format message schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiVersion {
    /// V1 — Current stable production release.
    ///
    /// Proto package: `misogi.file_transfer.v1`
    /// URL prefix: `/api/v1`
    V1,

    /// V2 — Future release with AI-enhanced semantic sanitization.
    ///
    /// Proto package: `misogi.file_transfer.v2`
    /// URL prefix: `/api/v2`
    V2,
}

impl ApiVersion {
    /// Parse version from a URL path segment string.
    ///
    /// # Arguments
    /// * `segment` - A path component like `"v1"` or `"v2"`.
    ///
    /// # Returns
    /// `Some(variant)` if the segment matches a known version, `None` otherwise.
    pub fn from_path_segment(segment: &str) -> Option<Self> {
        match segment {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }

    /// Extract API version from a full URI path.
    ///
    /// Supports patterns:
    /// - `/api/vN/...` (standard REST convention)
    /// - `/grpc/vN/...` (gRPC-gateway style)
    /// - `/vN/...` (direct version prefix)
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ApiVersion::from_uri_path("/api/v1/upload"), Some(V1));
    /// assert_eq!(ApiVersion::from_uri_path("/api/v2/sanitize"), Some(V2));
    /// assert_eq!(ApiVersion::from_uri_path("/health"), None);
    /// ```
    pub fn from_uri_path(path: &str) -> Option<Self> {
        let segments: Vec<&str> = path.split('/').collect();
        for (i, seg) in segments.iter().enumerate() {
            if (*seg == "api" || *seg == "grpc") && i + 1 < segments.len() {
                if let Some(ver) = Self::from_path_segment(segments[i + 1]) {
                    return Some(ver);
                }
            }
            if let Some(ver) = Self::from_path_segment(seg) {
                if i == 1 { return Some(ver); }
            }
        }
        None
    }

    /// Return the next (newer) version, if one exists.
    ///
    /// Used for generating RFC 8594 `Link: ...; rel="successor-version"` headers.
    pub fn successor(&self) -> Option<Self> {
        match self {
            Self::V1 => Some(Self::V2),
            Self::V2 => None,
        }
    }

    /// Return the previous (older) version, if one exists.
    ///
    /// Used for backward-compatibility checks and adapter selection.
    pub fn predecessor(&self) -> Option<Self> {
        match self {
            Self::V1 => None,
            Self::V2 => Some(Self::V1),
        }
    }

    /// Convert to proto package suffix for gRPC service discovery.
    ///
    /// # Example
    /// ```
    /// assert_eq!(ApiVersion::V1.proto_package_suffix(), ".file_transfer.v1");
    /// ```
    pub fn proto_package_suffix(&self) -> &'static str {
        match self {
            Self::V1 => ".file_transfer.v1",
            Self::V2 => ".file_transfer.v2",
        }
    }

    /// Return the REST URL path prefix for this version.
    ///
    /// # Example
    /// ```
    /// assert_eq!(ApiVersion::V1.url_prefix(), "/api/v1");
    /// ```
    pub fn url_prefix(&self) -> &'static str {
        match self {
            Self::V1 => "/api/v1",
            Self::V2 => "/api/v2",
        }
    }

    /// Check if this version is considered "legacy" (non-latest).
    pub fn is_legacy(&self) -> bool {
        !matches!(self, Self::V2)
    }

    /// Returns true if this is the latest supported version.
    pub fn is_latest(&self) -> bool {
        matches!(self, Self::V2)
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
        }
    }
}

impl Default for ApiVersion {
    fn default() -> Self {
        Self::V1
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_path_segment_v1() {
        assert_eq!(ApiVersion::from_path_segment("v1"), Some(ApiVersion::V1));
    }

    #[test]
    fn test_from_path_segment_v2() {
        assert_eq!(ApiVersion::from_path_segment("v2"), Some(ApiVersion::V2));
    }

    #[test]
    fn test_from_path_segment_unknown() {
        assert_eq!(ApiVersion::from_path_segment("v99"), None);
        assert_eq!(ApiVersion::from_path_segment(""), None);
    }

    #[test]
    fn test_from_uri_path_api_prefix() {
        assert_eq!(
            ApiVersion::from_uri_path("/api/v1/upload"),
            Some(ApiVersion::V1)
        );
        assert_eq!(
            ApiVersion::from_uri_path("/api/v2/sanitize/abc123"),
            Some(ApiVersion::V2)
        );
    }

    #[test]
    fn test_from_uri_path_no_version() {
        assert_eq!(ApiVersion::from_uri_path("/health"), None);
        assert_eq!(ApiVersion::from_uri_path("/version"), None);
    }

    #[test]
    fn test_successor_chain() {
        assert_eq!(ApiVersion::V1.successor(), Some(ApiVersion::V2));
        assert_eq!(ApiVersion::V2.successor(), None);
    }

    #[test]
    fn test_predecessor_chain() {
        assert_eq!(ApiVersion::V1.predecessor(), None);
        assert_eq!(ApiVersion::V2.predecessor(), Some(ApiVersion::V1));
    }

    #[test]
    fn test_proto_package_suffix() {
        assert_eq!(ApiVersion::V1.proto_package_suffix(), ".file_transfer.v1");
        assert_eq!(ApiVersion::V2.proto_package_suffix(), ".file_transfer.v2");
    }

    #[test]
    fn test_url_prefix() {
        assert_eq!(ApiVersion::V1.url_prefix(), "/api/v1");
        assert_eq!(ApiVersion::V2.url_prefix(), "/api/v2");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ApiVersion::V1), "v1");
        assert_eq!(format!("{}", ApiVersion::V2), "v2");
    }

    #[test]
    fn test_default_is_v1() {
        assert_eq!(ApiVersion::default(), ApiVersion::V1);
    }

    #[test]
    fn test_legacy_and_latest_flags() {
        assert!(ApiVersion::V1.is_legacy());
        assert!(!ApiVersion::V1.is_latest());
        assert!(!ApiVersion::V2.is_legacy());
        assert!(ApiVersion::V2.is_latest());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let v = ApiVersion::V2;
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ApiVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, ApiVersion::V2);
    }
}
