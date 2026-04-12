//! Version-aware request and response wrapper types.
//!
//! Provides generic newtype wrappers that attach protocol version metadata
//! to payloads, ensuring version information is never separated from its data.

use crate::versioning::api_semver::ApiVersion;
use serde::{Deserialize, Serialize};

// =============================================================================
// VersionedRequest — Version-aware request wrapper
// =============================================================================

/// Generic newtype wrapper attaching protocol version metadata to request payloads.
///
/// Enables type-safe version-aware processing throughout the request pipeline.
///
/// # Type Parameters
///
/// * `T` - The inner request payload type (typically a deserialized struct).
///
/// # Examples
///
/// ```
/// let req = VersionedRequest::new(
///     UploadRequest { file_id: "abc123".into() },
///     ApiVersion::new(2, 1, 0),
/// );
/// assert_eq!(req.version, ApiVersion::new(2, 1, 0));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedRequest<T> {
    /// The actual request payload.
    pub inner: T,

    /// Protocol version of this request's wire format.
    pub version: ApiVersion,
}

impl<T> VersionedRequest<T> {
    /// Create a new versioned request wrapper.
    #[inline]
    #[must_use]
    pub fn new(inner: T, version: ApiVersion) -> Self {
        Self { inner, version }
    }

    /// Decompose into inner payload and version.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> (T, ApiVersion) {
        (self.inner, self.version)
    }

    /// Reference the inner payload immutably.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably reference the inner payload.
    #[inline]
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Map over the inner payload type, preserving version metadata.
    #[inline]
    #[must_use]
    pub fn map<U, F>(self, f: F) -> VersionedRequest<U>
    where
        F: FnOnce(T) -> U,
    {
        VersionedRequest {
            inner: f(self.inner),
            version: self.version,
        }
    }

    /// Fallibly map over the inner payload with error propagation.
    #[inline]
    pub fn try_map<U, E, F>(self, f: F) -> Result<VersionedRequest<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        Ok(VersionedRequest {
            inner: f(self.inner)?,
            version: self.version,
        })
    }
}

// =============================================================================
// VersionedResponse — Version-aware response wrapper
// =============================================================================

/// Generic newtype wrapper attaching protocol version metadata to response payloads.
///
/// Mirror structure of [`VersionedRequest`] for server→client direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedResponse<T> {
    /// The actual response payload.
    pub inner: T,

    /// Protocol version of this response's wire format.
    pub version: ApiVersion,
}

impl<T> VersionedResponse<T> {
    /// Create a new versioned response wrapper.
    #[inline]
    #[must_use]
    pub fn new(inner: T, version: ApiVersion) -> Self {
        Self { inner, version }
    }

    /// Decompose into inner payload and version.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> (T, ApiVersion) {
        (self.inner, self.version)
    }

    /// Reference the inner payload immutably.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably reference the inner payload.
    #[inline]
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Map over the inner payload type, preserving version metadata.
    #[inline]
    #[must_use]
    pub fn map<U, F>(self, f: F) -> VersionedResponse<U>
    where
        F: FnOnce(T) -> U,
    {
        VersionedResponse {
            inner: f(self.inner),
            version: self.version,
        }
    }

    /// Fallibly map over the inner payload with error propagation.
    #[inline]
    pub fn try_map<U, E, F>(self, f: F) -> Result<VersionedResponse<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        Ok(VersionedResponse {
            inner: f(self.inner)?,
            version: self.version,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestPayload {
        id: String,
        value: i32,
    }

    #[test]
    fn test_versioned_request_creation_and_access() {
        let req = VersionedRequest::new(
            TestPayload { id: "req-001".to_string(), value: 42 },
            ApiVersion::new(2, 1, 0),
        );

        assert_eq!(req.version, ApiVersion::new(2, 1, 0));
        assert_eq!(req.inner.id, "req-001");
        assert_eq!(req.inner.value, 42);
    }

    #[test]
    fn test_versioned_request_decomposition() {
        let req = VersionedRequest::new(vec![1, 2, 3], ApiVersion::new(1, 0, 0));
        let (inner, ver) = req.into_inner();

        assert_eq!(inner, vec![1, 2, 3]);
        assert_eq!(ver, ApiVersion::new(1, 0, 0));
    }

    #[test]
    fn test_versioned_request_map_preserves_version() {
        let req = VersionedRequest::new(5i32, ApiVersion::new(1, 0, 0));
        let mapped = req.map(|x| x * 2);

        assert_eq!(mapped.inner, 10);
        assert_eq!(mapped.version, ApiVersion::new(1, 0, 0));
    }

    #[test]
    fn test_versioned_request_try_map_success() {
        let req = VersionedRequest::new(10i32, ApiVersion::new(2, 0, 0));
        let result: Result<VersionedRequest<i32>, &'static str> = req.try_map(|x| Ok(x + 1));

        assert!(result.is_ok());
        assert_eq!(result.unwrap().inner, 11);
    }

    #[test]
    fn test_versioned_request_try_map_failure() {
        let req = VersionedRequest::new(10i32, ApiVersion::new(2, 0, 0));
        let result: Result<VersionedRequest<i32>, &'static str> =
            req.try_map(|_| Err("transformation failed"));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "transformation failed");
    }

    #[test]
    fn test_versioned_request_serde_roundtrip() {
        let original = VersionedRequest::new(
            TestPayload { id: "test".to_string(), value: 42 },
            ApiVersion::new(1, 2, 3),
        );

        let json = serde_json::to_string(&original).unwrap();
        let decoded: VersionedRequest<TestPayload> = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.inner.id, "test");
        assert_eq!(decoded.version, ApiVersion::new(1, 2, 3));
    }

    #[test]
    fn test_versioned_response_symmetry() {
        let resp = VersionedResponse::new(vec![7, 8, 9], ApiVersion::new(3, 0, 0));
        let (inner, ver) = resp.into_inner();

        assert_eq!(inner, vec![7, 8, 9]);
        assert_eq!(ver, ApiVersion::new(3, 0, 0));
    }

    #[test]
    fn test_versioned_response_map() {
        let resp = VersionedResponse::new("original".to_string(), ApiVersion::new(1, 0, 0));
        let upper = resp.map(|s| s.to_uppercase());

        assert_eq!(upper.inner, "ORIGINAL");
        assert_eq!(upper.version, ApiVersion::new(1, 0, 0));
    }
}
