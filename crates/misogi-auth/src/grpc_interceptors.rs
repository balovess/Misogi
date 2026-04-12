//! gRPC Interceptors for Micro-Kernel Authentication Architecture
//!
//! Provides tonic-compatible request interceptors that validate authentication
//! for gRPC services using the new micro-kernel architecture:
//!
//! - **[`JwtGrpcInterceptor`]**: Validates Misogi-issued JWTs via [`JwtValidator`](super::jwt::validator::JwtValidator)
//! - **Backward-compatible**: Re-exports legacy interceptor constructors with deprecation notices
//!
//! # Architecture Migration (Phase 7)
//!
//! This module implements the refactored gRPC interceptor design:
//! - **Direct JwtValidator usage**: No longer wraps `AuthEngine`; uses validator directly
//! - **Misogi-only tokens**: External IdP tokens are rejected (must use identity plugins)
//! - **Consistent error mapping**: All auth failures return `UNAUTHENTICATED` status
//!
//! # Usage Example
//!
//! ```ignore
//! use tonic::transport::Server;
//! use misogi_auth::grpc_interceptors::JwtGrpcInterceptor;
//! use std::sync::Arc;
//!
//! let validator = Arc::new(JwtValidator::new(jwt_config)?);
//! let interceptor = JwtGrpcInterceptor::new(validator);
//!
//! Server::builder()
//!     .interceptor(interceptor)
//!     .add_service(my_grpc_service)
//!     .serve(addr)
//!     .await?;
//! ```

use std::sync::Arc;
use tracing::{debug, instrument, warn};

use crate::claims::MisogiClaims;
#[cfg(feature = "jwt")]
use crate::jwt::validator::JwtValidator;

// ===========================================================================
// JwtGrpcInterceptor — Misogi-Issued JWT Validation
// ===========================================================================

/// gRPC request interceptor that validates **only** Misogi-issued JWT tokens.
///
/// # Micro-Kernel Architecture (Phase 7)
///
/// This interceptor is specifically designed for the new architecture where:
/// - **Token validation**: Uses [`JwtValidator::validate`](JwtValidator::validate) directly
///   (RS256 signature verification + issuer/audience claim checking)
/// - **External IdP tokens**: Explicitly REJECTED — these must be processed by
///   identity provider plugins before reaching gRPC services
/// - **No OIDC validation**: OIDC token validation is handled by [`OidcIdentityPlugin`](super::plugins::oidc)
///
/// # Interception Flow
///
/// ```text
/// gRPC Request Received
///     |
///     v
/// +----------------------+
/// | Extract Authorization| ---> Missing: UNAUTHENTICATED "Missing Authorization header"
/// | header from metadata  |
/// +----------------------+
///     |
///     v
/// +----------------------+
/// | Parse Bearer token    | ---> Invalid format: UNAUTHENTICATED "Invalid token format"
/// +----------------------+
///     |
///     v
/// +----------------------+
/// | Validate via          | ---> Signature fail: UNAUTHENTICATED "Invalid credentials"
/// | JwtValidator          | ---> Expired: UNAUTHENTICATED "Token has expired"
/// | (RS256 + iss/aud)     | ---> Issuer mismatch: UNAUTHENTICATED "External identity token"
/// +----------------------+
///     |
///     v
/// +----------------------+
/// | Insert MisogiClaims   |
/// | into extensions       |
/// +----------------------+
///     |
///     v
/// Pass to gRPC handler
/// ```
///
/// # Thread Safety
///
/// This interceptor is `Clone + Send + Sync` and safe to share across gRPC connections.
/// Internally uses `Arc<JwtValidator>` for zero-cost cloning.
///
/// # Error Behavior
///
/// All authentication failures return `tonic::Status::unauthenticated()` with a
/// human-readable message. The specific error cases are:
///
/// | Condition | Status Code | Message |
/// |-----------|:-----------:|--------|
/// | Missing header | UNAUTHENTICATED | "Missing Authorization header" |
/// | Empty/malformed token | UNAUTHENTICATED | "Invalid Bearer token format" |
/// | Bad signature | UNAUTHENTICATED | "Invalid authentication credentials" |
/// | Token expired | UNAUTHENTICATED | "Token has expired" |
/// | External IdP token | UNAUTHENTICATED | "External identity token not accepted" |
#[cfg(feature = "jwt")]
pub struct JwtGrpcInterceptor {
    /// Shared reference to the JWT validator (holds RSA public key).
    validator: Arc<JwtValidator>,
}

#[cfg(feature = "jwt")]
impl JwtGrpcInterceptor {
    /// Create a new JWT gRPC interceptor with the given validator.
    ///
    /// The validator must be initialized with the correct RSA public key and
    /// issuer/audience configuration matching your Misogi deployment.
    ///
    /// # Arguments
    ///
    /// * `validator` - Shared reference to a configured [`JwtValidator`] instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = JwtConfig { /* ... */ };
    /// let validator = Arc::new(JwtValidator::new(config)?);
    /// let interceptor = JwtGrpcInterceptor::new(validator);
    /// ```
    pub fn new(validator: Arc<JwtValidator>) -> Self {
        debug!("JwtGrpcInterceptor created");
        Self { validator }
    }

    /// Validate a Bearer token string and return the extracted claims.
    ///
    /// Internal method used by the interceptor's `call` method.
    /// Maps [`JwtError`](crate::jwt::JwtError) variants to appropriate
    /// `tonic::Status` responses.
    ///
    /// # Arguments
    ///
    /// * `token` - Raw Bearer token string from Authorization header
    ///
    /// # Returns
    ///
    /// - `Ok(MisogiClaims)` on successful validation
    /// - `Err(tonic::Status)` with UNAUTHENTICATED code on any failure
    fn validate_token(&self, token: &str) -> Result<MisogiClaims, tonic::Status> {
        self.validator.validate(token).map_err(|e| match e {
            crate::jwt::JwtError::TokenExpired => {
                warn!("gRPC interceptor: token expired");
                tonic::Status::unauthenticated("Token has expired")
            }
            crate::jwt::JwtError::InvalidSignature => {
                warn!("gRPC interceptor: invalid signature");
                tonic::Status::unauthenticated("Invalid authentication credentials")
            }
            crate::jwt::JwtError::ClaimValidationFailed(msg) => {
                // Check if this is an external IdP token (issuer/audience mismatch)
                if msg.contains("issuer") || msg.contains("audience") {
                    debug!(
                        error = %msg,
                        "gRPC interceptor: external identity token rejected"
                    );
                    return tonic::Status::unauthenticated(
                        "External identity token not acceptable — use identity plugin",
                    );
                }

                warn!(error = %msg, "gRPC interceptor: claim validation failed");
                tonic::Status::unauthenticated(format!("Token validation failed: {}", msg))
            }
            crate::jwt::JwtError::MalformedToken(msg) => {
                warn!(error = %msg, "gRPC interceptor: malformed token");
                tonic::Status::unauthenticated(format!("Malformed token: {}", msg))
            }
            e => {
                warn!(error = %e, "gRPC interceptor: unexpected validation error");
                tonic::Status::unauthenticated("Internal authentication error")
            }
        })
    }
}

#[cfg(feature = "jwt")]
impl Clone for JwtGrpcInterceptor {
    fn clone(&self) -> Self {
        Self {
            validator: Arc::clone(&self.validator),
        }
    }
}

#[cfg(feature = "jwt")]
impl tonic::service::Interceptor for JwtGrpcInterceptor {
    #[instrument(skip(self, request), fields(interceptor = "jwt_grpc"))]
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        // Step 1: Extract Authorization header from gRPC metadata
        let metadata = request.metadata();
        let auth_header = metadata
            .get("authorization")
            .or_else(|| metadata.get("Authorization")) // Case-insensitive fallback
            .and_then(|v| v.to_str().ok());

        // Step 2: Handle missing authorization header
        let auth_header = match auth_header {
            Some(header) => header,
            None => {
                warn!("gRPC request missing Authorization header");
                return Err(tonic::Status::unauthenticated(
                    "Missing Authorization header",
                ));
            }
        };

        // Step 3: Parse Bearer token scheme
        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .unwrap_or(auth_header)
            .trim();

        if token.is_empty() {
            warn!("gRPC request has empty Bearer token");
            return Err(tonic::Status::unauthenticated(
                "Invalid Bearer token format",
            ));
        }

        // Step 4: Validate token using JwtValidator
        let claims = self.validate_token(token)?;

        // Step 5: Insert validated claims into request extensions
        // Downstream handlers can extract this via request.extensions()
        debug!(
            applicant_id = %claims.applicant_id,
            idp_source = %claims.idp_source,
            "gRPC request authenticated successfully"
        );
        request.extensions_mut().insert(claims);

        Ok(request)
    }
}

// ===========================================================================
// Backward-Compatible Constructor Functions
// ===========================================================================

/// Create a tonic gRPC interceptor that validates Misogi-issued JWT tokens.
///
/// Convenience function to construct a [`JwtGrpcInterceptor`] from an
/// `Arc<JwtValidator>`.
///
/// # Parameters
///
/// - `validator`: Shared reference to a configured [`JwtValidator`].
///   Must be initialized with the correct RSA public key PEM and issuer/audience settings.
///
/// # Returns
///
/// A [`JwtGrpcInterceptor`] ready for use with `tonic::Server::builder().interceptor()`.
///
/// # Example
///
/// ```ignore
/// use tonic::transport::Server;
/// use misogi_auth::grpc_interceptors::create_jwt_grpc_interceptor;
/// use std::sync::Arc;
///
/// let validator = Arc::new(JwtValidator::new(config)?);
/// let interceptor = create_jwt_grpc_interceptor(validator);
///
/// Server::builder()
///     .interceptor(interceptor)
///     .add_service(my_service.into_export())
///     .serve(addr)
///     .await?;
/// ```
#[cfg(feature = "jwt")]
pub fn create_jwt_grpc_interceptor(
    validator: Arc<JwtValidator>,
) -> JwtGrpcInterceptor {
    JwtGrpcInterceptor::new(validator)
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests;
