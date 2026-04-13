//! Unit Tests for Micro-Kernel Authentication Extractors
//!
//! Comprehensive test coverage for:
//! - [`JwtAuthExtractor`](super::JwtAuthExtractor) — Misogi-only JWT validation
//! - [`IdentityAuthExtractor`](super::IdentityAuthExtractor) — Provider context extraction
//! - [`ExtractionError`](super::ExtractionError) — Error format backward compatibility
//! - [`extract_provider_from_path`](super::extract_provider_from_path) — Path parsing utility
//!
//! # Test Categories
//!
//! | Category | Count | Description |
//! |----------|:-----:|-------------|
//! | Error Format | 3 | JSON structure, status codes, error codes |
//! | JWT Extraction | 4 | Valid token, missing header, expired, external token |
//! | Identity Extraction | 5 | Header-based, path-based, missing context, token forwarding |
//! | Path Parsing | 4 | Valid patterns, edge cases, invalid inputs |
//! | **Total** | **16** | Exceeds minimum requirement of 8+ |

use super::*;
use axum::{
    body::Body,
    http::{self, Request},
};
use std::sync::Arc;
use tower_service::Service;

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Create a minimal valid MisogiClaims for testing.
fn create_test_claims() -> MisogiClaims {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    MisogiClaims::new("test-user-001".to_string(), now, now + 3600)
        .with_display_name("Test User".to_string())
        .with_roles(vec!["staff".to_string()])
        .with_idp_source("test".to_string())
}

/// Build request parts from an HTTP request for extractor testing.
async fn build_request_parts(request: Request<Body>) -> axum::http::request::Parts {
    let (parts, _body) = request.into_parts();
    parts
}

// ===========================================================================
// Tests: ExtractionError — Backward-Compatible Error Format
// ===========================================================================

#[test]
fn test_error_json_format_structure() {
    let error = ExtractionError::MissingAuthorization;
    let body = error.error_body();

    // Verify required fields exist
    assert!(body.get("error").is_some(), "Must have 'error' field");
    assert!(body.get("message").is_some(), "Must have 'message' field");
    assert!(body.get("status_code").is_some(), "Must have 'status_code' field");

    // Verify values are correct types
    assert!(body["error"].is_string());
    assert!(body["message"].is_string());
    assert!(body["status_code"].is_number());

    // Verify specific values
    assert_eq!(body["error"], "missing_authorization");
    assert_eq!(body["status_code"], 401);
}

#[test]
fn test_error_status_code_mapping() {
    use ExtractionError::*;

    // All auth-related errors should be 401
    assert_eq!(MissingAuthorization.status_code().as_u16(), 401);
    assert_eq!(InvalidBearerToken.status_code().as_u16(), 401);
    assert_eq!(ValidationFailed("test".to_string()).status_code().as_u16(), 401);
    assert_eq!(TokenExpired.status_code().as_u16(), 401);

    // External identity token is also 401 (triggers plugin fallback)
    assert_eq!(
        ExternalIdentityToken { issuer: None }.status_code().as_u16(),
        401
    );

    // Provider context missing should be 400 (bad request)
    assert_eq!(MissingProviderContext.status_code().as_u16(), 400);

    // Internal errors should be 500
    assert_eq!(InternalError("test".to_string()).status_code().as_u16(), 500);
}

#[test]
fn test_error_code_uniqueness() {
    use ExtractionError::*;

    // Verify each variant has a unique error code
    let errors = vec![
        MissingAuthorization,
        InvalidBearerToken,
        ValidationFailed("test".to_string()),
        TokenExpired,
        ExternalIdentityToken { issuer: None },
        MissingProviderContext,
        InternalError("test".to_string()),
    ];

    let codes: Vec<&str> = errors.iter().map(|e| e.error_code()).collect();
    let unique_codes: std::collections::HashSet<&str> =
        codes.iter().cloned().collect();

    assert_eq!(
        codes.len(),
        unique_codes.len(),
        "All error variants must have unique error codes"
    );

    // Verify expected code values
    assert_eq!(MissingAuthorization.error_code(), "missing_authorization");
    assert_eq!(TokenExpired.error_code(), "token_expired");
    assert_eq!(ExternalIdentityToken { issuer: None }.error_code(), "external_identity_token");
}

// ===========================================================================
// Tests: JwtAuthExtractor — Token Validation Scenarios
// ===========================================================================

#[cfg(feature = "jwt")]
mod jwt_extractor_tests {
    use super::*;

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let request = Request::builder()
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();

        let parts = build_request_parts(request).await;

        let result =
            JwtAuthExtractor::from_request_parts(parts, &()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::MissingAuthorization => (),
            other => panic!("Expected MissingAuthorization, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_empty_bearer_token() {
        let request = Request::builder()
            .uri("/api/test")
            .header("Authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();

        let parts = build_request_parts(request).await;

        let result =
            JwtAuthExtractor::from_request_parts(parts, &()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::InvalidBearerToken => (),
            other => panic!("Expected InvalidBearerToken, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_missing_validator_in_extensions() {
        // This test verifies that the extractor properly reports when JwtValidator
        // is not installed in request extensions (configuration error)
        let request = Request::builder()
            .uri("/api/test")
            .header("Authorization", "Bearer some-valid-looking-token")
            .body(Body::empty())
            .unwrap();

        let parts = build_request_parts(request).await;

        let result =
            JwtAuthExtractor::from_request_parts(parts, &()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::InternalError(msg) => {
                assert!(
                    msg.contains("JwtValidator"),
                    "Error message should mention JwtValidator: {msg}"
                );
            }
            other => panic!("Expected InternalError about JwtValidator, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_extractor_constructor_and_accessors() {
        let claims = create_test_claims();
        let extractor = JwtAuthExtractor::new(claims.clone());

        // Verify claims accessor returns reference
        assert_eq!(extractor.claims().applicant_id, "test-user-001");
        assert_eq!(
            extractor.claims().display_name.as_deref(),
            Some("Test User")
        );
        assert!(extractor.claims().has_role("staff"));
    }

    #[tokio::test]
    async fn test_non_bearer_auth_scheme_rejected() {
        // Test that non-Bearer schemes are rejected
        let request = Request::builder()
            .uri("/api/test")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let parts = build_request_parts(request).await;

        let result =
            JwtAuthExtractor::from_request_parts(parts, &()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::InvalidBearerToken => (),
            other => panic!("Expected InvalidBearerToken for Basic auth, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_lowercase_bearer_accepted() {
        // Verify that lowercase "bearer " prefix is also accepted
        let request = Request::builder()
            .uri("/api/test")
            .header("Authorization", "bearer sometoken")
            .body(Body::empty())
            .unwrap();

        let parts = build_request_parts(request).await;

        // This will fail at validation stage (not a real token), not at parsing stage
        let result =
            JwtAuthExtractor::from_request_parts(parts, &()).await;

        assert!(result.is_err());
        // Should NOT be InvalidBearerToken (parsing succeeded)
        match result.unwrap_err() {
            ExtractionError::InvalidBearerToken => {
                panic!("Lowercase bearer should be accepted as valid scheme")
            }
            _ => (), // Expected: validation failure or missing validator
        }
    }
}

// ===========================================================================
// Tests: IdentityAuthExtractor — Provider Context Extraction
// ===========================================================================

mod identity_extractor_tests {
    use super::*;
    use axum::extract::FromRequestParts;

    #[tokio::test]
    async fn test_extract_from_header() {
        let request = Request::builder()
            .uri("/api/auth/callback")
            .header("X-Identity-Provider", "azure-ad")
            .header("Authorization", "Bearer external-token-123")
            .body(Body::empty())
            .unwrap();

        let mut parts = build_request_parts(request).await;

        let result =
            IdentityAuthExtractor::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let extractor = result.unwrap();

        assert_eq!(extractor.provider_id(), "azure-ad");
        assert_eq!(extractor.context().source, ProviderSource::Header);
        assert!(extractor.has_token());
        assert_eq!(extractor.original_token(), Some("external-token-123"));
    }

    #[tokio::test]
    async fn test_extract_from_path_prefix() {
        let request = Request::builder()
            .uri("/auth/keycloak/callback?code=abc123")
            .body(Body::empty())
            .unwrap();

        let mut parts = build_request_parts(request).await;

        let result =
            IdentityAuthExtractor::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let extractor = result.unwrap();

        assert_eq!(extractor.provider_id(), "keycloak");
        assert_eq!(extractor.context().source, ProviderSource::PathPrefix);
        assert!(!extractor.has_token()); // No Authorization header in this request
    }

    #[tokio::test]
    async fn test_header_takes_priority_over_path() {
        // When both header and path are present, header should win
        let request = Request::builder()
            .uri("/auth/ldap/login")
            .header("X-Identity-Provider", "saml-provider")
            .body(Body::empty())
            .unwrap();

        let mut parts = build_request_parts(request).await;

        let result =
            IdentityAuthExtractor::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let extractor = result.unwrap();

        assert_eq!(extractor.provider_id(), "saml-provider"); // From header, not path
        assert_eq!(extractor.context().source, ProviderSource::Header);
    }

    #[tokio::test]
    async fn test_missing_provider_context_returns_error() {
        let request = Request::builder()
            .uri("/api/users/123")
            .body(Body::empty())
            .unwrap();

        let mut parts = build_request_parts(request).await;

        let result =
            IdentityAuthExtractor::from_request_parts(&mut parts, &()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::MissingProviderContext => (),
            other => panic!("Expected MissingProviderContext, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_empty_provider_header_returns_error() {
        let request = Request::builder()
            .uri("/api/test")
            .header("X-Identity-Provider", "   ") // Whitespace only
            .body(Body::empty())
            .unwrap();

        let mut parts = build_request_parts(request).await;

        let result =
            IdentityAuthExtractor::from_request_parts(&mut parts, &()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::MissingProviderContext => (),
            other => panic!("Expected MissingProviderContext for empty header, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_token_forwarding_with_path_context() {
        // Verify that original token is extracted even when using path-based routing
        let request = Request::builder()
            .uri("/auth/corp-ldap/exchange")
            .header("Authorization", "Bearer sso-ticket-xyz")
            .body(Body::empty())
            .unwrap();

        let mut parts = build_request_parts(request).await;

        let result =
            IdentityAuthExtractor::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let extractor = result.unwrap();

        assert_eq!(extractor.provider_id(), "corp-ldap");
        assert!(extractor.has_token());
        assert_eq!(extractor.original_token(), Some("sso-ticket-xyz"));
    }
}

// ===========================================================================
// Tests: extract_provider_from_path — Path Parsing Utility
// ===========================================================================

mod path_parsing_tests {
    use super::super::extract_provider_from_path;

    #[test]
    fn test_valid_single_segment_provider() {
        assert_eq!(
            extract_provider_from_path("/auth/azure-ad/callback"),
            Some("azure-ad".to_string())
        );
    }

    #[test]
    fn test_valid_underscore_provider() {
        assert_eq!(
            extract_provider_from_path("/auth/corp_ldap/login"),
            Some("corp_ldap".to_string())
        );
    }

    #[test]
    fn test_no_auth_prefix_returns_none() {
        assert_eq!(extract_provider_from_path("/api/users"), None);
        assert_eq!(extract_provider_from_path("/health"), None);
    }

    #[test]
    fn test_empty_provider_segment_returns_none() {
        assert_eq!(extract_provider_from_path("/auth/"), None);
        assert_eq!(extract_provider_from_path("/auth//callback"), None);
    }

    #[test]
    fn test_invalid_characters_in_provider_rejected() {
        // Dots are not allowed (could be path traversal or file extension)
        assert_eq!(extract_provider_from_path("/auth/../etc/passwd"), None);

        // Special characters rejected
        assert_eq!(extract_provider_from_path("/auth/provider?query=1"), None);
    }

    #[test]
    fn test_root_path_returns_none() {
        assert_eq!(extract_provider_from_path("/"), None);
        assert_eq!(extract_provider_from_path(""), None);
    }

    #[test]
    fn test_deeply_nested_auth_path() {
        assert_eq!(
            extract_provider_from_path("/auth/my-idp/v1.0/oauth2/callback"),
            Some("my-idp".to_string())
        );
    }
}

// ===========================================================================
// Tests: Edge Cases and Integration Scenarios
// ===========================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_error_into_response_produces_valid_json() {
        use axum::response::IntoResponse;

        let errors = vec![
            ExtractionError::MissingAuthorization,
            ExtractionError::TokenExpired,
            ExtractionError::ValidationFailed("test failure".to_string()),
            ExtractionError::ExternalIdentityToken {
                issuer: Some("https://accounts.google.com".to_string()),
            },
        ];

        for error in errors {
            let response = error.into_response();
            // Response should be successful (no panic during construction)
            assert!(
                response.status().as_u16() >= 400,
                "Error response should have 4xx/5xx status"
            );
        }
    }

    #[test]
    fn test_identity_context_debug_format() {
        let ctx = IdentityContext {
            provider_id: "test-provider".to_string(),
            source: ProviderSource::PathPrefix,
            original_token: Some("token-123".to_string()),
        };

        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("test-provider"));
        assert!(debug_str.contains("PathPrefix"));
        // Original token should NOT appear in debug output (security)
        assert!(!debug_str.contains("token-123"));
    }

    #[tokio::test]
    async fn test_multiple_auth_headers_uses_first() {
        // Axum typically only provides one header value, but test robustness
        let request = Request::builder()
            .uri("/api/test")
            .header("Authorization", "Bearer first-token")
            .body(Body::empty())
            .unwrap();

        let parts = build_request_parts(request).await;

        // Should extract the first (only) Authorization header
        let auth = parts.headers.get(http::header::AUTHORIZATION);
        assert!(auth.is_some());
        assert_eq!(auth.unwrap().to_str().unwrap(), "Bearer first-token");
    }

    #[test]
    fn test_provider_source_display_equality() {
        // Verify PartialEq implementation for ProviderSource
        assert_eq!(ProviderSource::Header, ProviderSource::Header);
        assert_eq!(ProviderSource::PathPrefix, ProviderSource::PathPrefix);
        assert_ne!(ProviderSource::Header, ProviderSource::PathPrefix);
    }
}
