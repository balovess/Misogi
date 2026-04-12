//! API Error Types — HTTP-Status-Mapped Error Enumeration
//!
//! Defines the canonical error type for the Misogi REST API. Every handler
//! returns `Result<T, ApiError>` where [`ApiError`] maps cleanly to both
//! HTTP status codes and machine-readable error codes suitable for programmatic
//! client handling.
//!
//! # Error Hierarchy
//!
//! | HTTP Status | Variant(s)                    | Error Code(s)                          |
//! |-------------|-------------------------------|----------------------------------------|
//! | 400         | `BadRequest`                  | `INVALID_REQUEST`, `FILE_TOO_LARGE`,   |
//! |             |                               | `INVALID_POLICY`                       |
//! | 401         | `Unauthorized`                | `UNAUTHORIZED`, `EXPIRED_TOKEN`,       |
//! |             |                               | `INVALID_API_KEY`                      |
//! | 403         | `Forbidden`                   | `INSUFFICIENT_PERMISSIONS`             |
//! | 404         | `NotFound`                    | `FILE_NOT_FOUND`, `POLICY_NOT_FOUND`,  |
//! |             |                               | `JOB_NOT_FOUND`                        |
//! | 409         | `Conflict`                    | `DUPLICATE_RESOURCE`                   |
//! | 429         | `TooManyRequests`             | `RATE_LIMITED`                         |
//! | 500         | `Internal`                    | `INTERNAL_ERROR`, `SCAN_FAILED`,       |
//! |             |                               | `DEPENDENCY_UNAVAILABLE`               |

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

/// Canonical error type for the Misogi REST API.
///
/// Each variant carries a machine-readable `error_code` (stable string identifier)
/// and maps to a specific HTTP status code via the [`IntoResponse`] implementation.
///
/// # Example
///
/// ```ignore
/// use misogi_rest_api::error::ApiError;
///
/// Err(ApiError::not_found(
///     ApiError::FILE_NOT_FOUND,
///     "File not found",
///     Some(json!({"file_id": "uuid-here"})),
/// ))
/// ```
#[derive(Debug, Error)]
pub enum ApiError {
    // ------------------------------------------------------------------
    // 4xx — Client Errors
    // ------------------------------------------------------------------

    /// Resource not found (HTTP 404).
    #[error("{message}")]
    NotFound {
        /// Machine-readable error code (e.g., `"FILE_NOT_FOUND"`).
        code: &'static str,
        /// Human-readable message.
        message: String,
        /// Optional structured details.
        details: Option<serde_json::Value>,
    },

    /// Malformed request (HTTP 400).
    #[error("{message}")]
    BadRequest {
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },

    /// Authentication missing or invalid (HTTP 401).
    #[error("{message}")]
    Unauthorized {
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },

    /// Authenticated but insufficient permissions (HTTP 403).
    #[error("{message}")]
    Forbidden {
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },

    /// Resource conflict (e.g., duplicate key) (HTTP 409).
    #[error("{message}")]
    Conflict {
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },

    /// Rate limit exceeded (HTTP 429).
    #[error("{message}")]
    TooManyRequests {
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },

    // ------------------------------------------------------------------
    // 5xx — Server Errors
    // ------------------------------------------------------------------

    /// Internal server error (HTTP 500).
    #[error("{message}")]
    Internal {
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },
}

// ---------------------------------------------------------------------------
// Static error code constants
// ---------------------------------------------------------------------------

impl ApiError {
    /// File resource not found.
    pub const FILE_NOT_FOUND: &'static str = "FILE_NOT_FOUND";
    /// Policy resource not found.
    pub const POLICY_NOT_FOUND: &'static str = "POLICY_NOT_FOUND";
    /// Scan job not found.
    pub const JOB_NOT_FOUND: &'static str = "JOB_NOT_FOUND";

    /// Generic invalid request payload.
    pub const INVALID_REQUEST: &'static str = "INVALID_REQUEST";
    /// File exceeds size limit.
    pub const FILE_TOO_LARGE: &'static str = "FILE_TOO_LARGE";
    /// Invalid policy configuration.
    pub const INVALID_POLICY: &'static str = "INVALID_POLICY";

    /// Missing or invalid authentication credentials.
    pub const UNAUTHORIZED: &'static str = "UNAUTHORIZED";
    /// Authentication token has expired.
    pub const EXPIRED_TOKEN: &'static str = "EXPIRED_TOKEN";
    /// Invalid or unrecognized API key.
    pub const INVALID_API_KEY: &'static str = "INVALID_API_KEY";

    /// User lacks required role/permission.
    pub const INSUFFICIENT_PERMISSIONS: &'static str = "INSUFFICIENT_PERMISSIONS";

    /// Resource already exists (conflict on unique constraint).
    pub const DUPLICATE_RESOURCE: &'static str = "DUPLICATE_RESOURCE";

    /// Client exceeded rate limit.
    pub const RATE_LIMITED: &'static str = "RATE_LIMITED";

    /// Unexpected internal failure.
    pub const INTERNAL_ERROR: &'static str = "INTERNAL_ERROR";
    /// Scan engine reported failure.
    pub const SCAN_FAILED: &'static str = "SCAN_FAILED";
    /// External dependency unreachable.
    pub const DEPENDENCY_UNAVAILABLE: &'static str = "DEPENDENCY_UNAVAILABLE";
}

// ---------------------------------------------------------------------------
// Constructors — ergonomic factory methods for common error patterns
// ---------------------------------------------------------------------------

impl ApiError {
    /// Create a 404 Not Found error.
    ///
    /// # Arguments
    ///
    /// * `code` — stable error identifier from constants above
    /// * `message` — human-readable description
    /// * `details` — optional structured context (field errors, IDs, etc.)
    pub fn not_found(code: &'static str, message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::NotFound { code, message: message.into(), details }
    }

    /// Create a 400 Bad Request error.
    pub fn bad_request(code: &'static str, message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::BadRequest { code, message: message.into(), details }
    }

    /// Create a 401 Unauthorized error.
    pub fn unauthorized(code: &'static str, message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::Unauthorized { code, message: message.into(), details }
    }

    /// Create a 403 Forbidden error.
    pub fn forbidden(code: &'static str, message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::Forbidden { code, message: message.into(), details }
    }

    /// Create a 409 Conflict error.
    pub fn conflict(code: &'static str, message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::Conflict { code, message: message.into(), details }
    }

    /// Create a 429 Too Many Requests error.
    pub fn rate_limited(message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::TooManyRequests { code: Self::RATE_LIMITED, message: message.into(), details }
    }

    /// Create a 500 Internal Server Error.
    pub fn internal(code: &'static str, message: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self::Internal { code, message: message.into(), details }
    }

    /// Return the machine-readable error code for this variant.
    ///
    /// This string is stable across API versions and suitable for
    /// programmatic client-side error handling (switch/case).
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound { code, .. } => *code,
            Self::BadRequest { code, .. } => *code,
            Self::Unauthorized { code, .. } => *code,
            Self::Forbidden { code, .. } => *code,
            Self::Conflict { code, .. } => *code,
            Self::TooManyRequests { code, .. } => *code,
            Self::Internal { code, .. } => *code,
        }
    }

    /// Return the human-readable error message.
    pub fn error_message(&self) -> &str {
        match self {
            Self::NotFound { message, .. }
            | Self::BadRequest { message, .. }
            | Self::Unauthorized { message, .. }
            | Self::Forbidden { message, .. }
            | Self::Conflict { message, .. }
            | Self::TooManyRequests { message, .. }
            | Self::Internal { message, .. } => message,
        }
    }

    /// Map this error to its HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Build the JSON error response body.
    fn error_body(&self) -> serde_json::Value {
        json!({
            "error": self.error_code(),
            "message": self.error_message(),
            "details": match self {
                Self::NotFound { details, .. }
                | Self::BadRequest { details, .. }
                | Self::Unauthorized { details, .. }
                | Self::Forbidden { details, .. }
                | Self::Conflict { details, .. }
                | Self::TooManyRequests { details, .. }
                | Self::Internal { details, .. } => details.clone(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Axum IntoResponse integration
// ---------------------------------------------------------------------------

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = self.error_body();

        (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response()
    }
}
