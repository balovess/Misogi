//! Cross-version protocol adaptation trait and error types.
//!
//! Defines the core abstraction for bidirectional protocol version
//! transformation with enterprise-grade error handling.

use crate::versioning::api_semver::ApiVersion;
use std::fmt;

// =============================================================================
// AdapterError — Protocol adaptation failure types
// =============================================================================

/// Comprehensive error taxonomy for protocol adaptation operations.
///
/// Each variant captures sufficient context for audit logging, debugging,
/// and client-side error reporting without exposing internal implementation details.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdapterError {
    /// Requested version pair is not supported by this adapter.
    #[error("Unsupported version transition: {0} → {1}")]
    UnsupportedVersion(ApiVersion, ApiVersion),

    /// Failed to deserialize incoming bytes into the source version's schema.
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    /// Failed to serialize adapted data into target version's wire format.
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Required field not found in source message during adaptation.
    #[error("Required field not found: '{0}'")]
    FieldNotFound(String),

    /// Type mismatch between source and target field schemas.
    #[error("Incompatible field types between source and target schemas")]
    IncompatibleTypes,

    /// Unknown or unrecognized field encountered during deserialization.
    #[error("Unknown field encountered: '{0}'")]
    UnknownField(String),
}

// =============================================================================
// ProtocolAdapter — Core trait for cross-version protocol transformation
// =============================================================================

/// Trait for bidirectional cross-version protocol adaptation.
///
/// Implementors provide concrete transformation logic between different
/// protocol versions, handling field mapping, type coercion, default value
/// injection, and unknown field handling.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync`, enabling safe concurrent use
/// across async tasks without synchronization overhead.
///
/// # Object Safety
///
/// This trait is **object-safe** by design, allowing usage as
/// `dyn ProtocolAdapter` trait objects for runtime polymorphism.
pub trait ProtocolAdapter: Send + Sync + fmt::Debug {
    /// Adapt a request payload from source version to target version.
    ///
    /// Handles client→server direction transformations including field renaming,
    /// type coercion, and default value injection.
    fn adapt_request(
        &self,
        request: Vec<u8>,
        from_version: &ApiVersion,
        to_version: &ApiVersion,
    ) -> Result<Vec<u8>, AdapterError>;

    /// Adapt a response payload from source version to target version.
    ///
    /// Handles server→client direction transformations, typically stripping
    /// extension fields when downgrading or wrapping with defaults when upgrading.
    fn adapt_response(
        &self,
        response: Vec<u8>,
        from_version: &ApiVersion,
        to_version: &ApiVersion,
    ) -> Result<Vec<u8>, AdapterError>;

    /// Return the list of versions this adapter can handle.
    fn supported_versions(&self) -> Vec<ApiVersion>;

    /// Return a human-readable identifier for this adapter instance.
    fn adapter_name(&self) -> &'static str;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple mock adapter for testing trait object safety.
    #[derive(Debug)]
    struct MockIdentityAdapter;

    impl ProtocolAdapter for MockIdentityAdapter {
        fn adapt_request(
            &self,
            request: Vec<u8>,
            from_version: &ApiVersion,
            to_version: &ApiVersion,
        ) -> Result<Vec<u8>, AdapterError> {
            let supported = self.supported_versions();
            if !supported.contains(from_version) || !supported.contains(to_version) {
                return Err(AdapterError::UnsupportedVersion(*from_version, *to_version));
            }
            Ok(request)
        }

        fn adapt_response(
            &self,
            response: Vec<u8>,
            from_version: &ApiVersion,
            to_version: &ApiVersion,
        ) -> Result<Vec<u8>, AdapterError> {
            let supported = self.supported_versions();
            if !supported.contains(from_version) || !supported.contains(to_version) {
                return Err(AdapterError::UnsupportedVersion(*from_version, *to_version));
            }
            Ok(response)
        }

        fn supported_versions(&self) -> Vec<ApiVersion> {
            vec![ApiVersion::new(1, 0, 0), ApiVersion::new(2, 0, 0)]
        }

        fn adapter_name(&self) -> &'static str {
            "mock-identity"
        }
    }

    #[test]
    fn test_mock_adapter_metadata() {
        let adapter = MockIdentityAdapter;
        assert_eq!(adapter.adapter_name(), "mock-identity");
        assert_eq!(adapter.supported_versions().len(), 2);
    }

    #[test]
    fn test_mock_adapter_adapt_success() {
        let adapter = MockIdentityAdapter;
        let input = b"{\"test\": true}".to_vec();
        let result = adapter.adapt_request(input.clone(), &ApiVersion::new(1, 0, 0), &ApiVersion::new(2, 0, 0));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input);
    }

    #[test]
    fn test_mock_adapter_unsupported_version() {
        let adapter = MockIdentityAdapter;
        let result = adapter.adapt_request(b"data".to_vec(), &ApiVersion::new(9, 9, 9), &ApiVersion::new(9, 9, 9));
        assert!(result.is_err());

        match result.unwrap_err() {
            AdapterError::UnsupportedVersion(from, to) => {
                assert_eq!(from, ApiVersion::new(9, 9, 9));
                assert_eq!(to, ApiVersion::new(9, 9, 9));
            }
            other => panic!("Expected UnsupportedVersion, got {:?}", other),
        }
    }

    #[test]
    fn test_trait_object_safety() {
        let adapter: Box<dyn ProtocolAdapter> = Box::new(MockIdentityAdapter);
        assert_eq!(adapter.adapter_name(), "mock-identity");

        let result = adapter.adapt_response(b"test".to_vec(), &ApiVersion::new(1, 0, 0), &ApiVersion::new(2, 0, 0));
        assert!(result.is_ok());
    }

    #[test]
    fn test_adapter_error_display() {
        let v1 = ApiVersion::new(1, 0, 0);
        let v2 = ApiVersion::new(2, 0, 0);

        let err = AdapterError::UnsupportedVersion(v1, v2);
        let msg = format!("{}", err);
        assert!(msg.contains("1.0.0") && msg.contains("2.0.0"));

        let err = AdapterError::FieldNotFound("user_id".to_string());
        assert!(format!("{}", err).contains("user_id"));

        let err = AdapterError::UnknownField("ext".to_string());
        assert!(format!("{}", err).contains("ext"));
    }
}
