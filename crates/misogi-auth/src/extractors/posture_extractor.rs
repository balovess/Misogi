//! Posture-Aware Authentication Extractor for Axum
//!
//! Combines JWT validation, device fingerprint verification, and posture checking
//! into a single atomic authentication step. Implements [`axum::extract::FromRequestParts`]
//! for seamless integration into Axum handler signatures.
//!
//! # Authentication Pipeline
//!
//! ```text
//! HTTP Request
//!   │
//!   ├─ Step 1: Authorization header → JWT validation → ValidatedClaims
//!   │           (misogi_auth::jwt::JwtAuthenticator)
//!   │
//!   ├─ Step 2: X-Device-Fingerprint → collect → validate_binding()
//!   │           (device::collector + device::validator)
//!   │
//!   ├─ Step 3: User-Agent → OS detection → build_device_posture()
//!   │           (posture::os_detector + posture::edr_bridge)
//!   │
//!   └─ Step 4: PostureChecker.evaluate() → Allow / Warn / Block
//!             (posture::checker)
//!
//! On success → PostureAuthResult { claims, device_id, fingerprint, posture }
//! On failure → 401 (auth), 403 (fingerprint/posture), 400 (missing header)
//! ```
//!
//! # Feature Flags
//!
//! Requires `posture` + `axum` (+ `jwt` for token validation).
//! EDR integration additionally requires `defender` or `falcon`.

use std::sync::Arc;

use axum::{
    http::{self, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

#[cfg(feature = "jwt")]
use crate::jwt::ValidatedClaims;
use crate::device::collector::collect_fingerprint_from_header;
use crate::device::fingerprint::DeviceFingerprint;
use crate::device::validator::{FingerprintBindError, FingerprintValidator};
#[cfg(feature = "jwt")]
use crate::middleware::{AuthEngine, AuthError};
use crate::posture::os_detector::parse_os_from_user_agent;
use crate::posture::{PostureChecker, PostureEvaluationResult};
use crate::posture::edr_bridge::build_client_report_posture;
#[cfg(any(feature = "defender", feature = "falcon"))]
use crate::posture::edr_bridge::convert_edr_to_posture;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Header name for device fingerprint transmission.
pub const DEVICE_FINGERPRINT_HEADER: &str = "x-device-fingerprint";

/// Maximum allowed size for the base64-encoded fingerprint payload (4 KiB).
///
/// Prevents DoS via oversized headers while accommodating all signal data.
const MAX_FINGERPRINT_HEADER_BYTES: usize = 4096;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Controls behavior of [`PostureAwareExtractor`].
///
/// All fields have sensible defaults for Japanese government / enterprise use.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PostureExtractorConfig {
    /// Whether device fingerprint is mandatory (true) or optional (false).
    ///
    /// When `false`, requests without a fingerprint skip Steps 2–4 and
    /// return only JWT-validated claims (legacy compatibility mode).
    pub require_fingerprint: bool,

    /// Failure action when posture check fails but auth succeeded.
    ///
    /// - `Warn`: allow request but include posture warnings in result
    /// - `Block`: reject with 403 Forbidden
    /// - `Allow`: always allow regardless of posture score
    pub default_failure_action: crate::posture::types::FailureAction,

    /// Whether to require User-Agent header for OS detection.
    ///
    /// When true, missing UA causes 400 Bad Request.
    pub require_user_agent: bool,
}

impl Default for PostureExtractorConfig {
    fn default() -> Self {
        Self {
            require_fingerprint: true,
            default_failure_action: crate::posture::types::FailureAction::Warn,
            require_user_agent: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared State (injected via axum::Extension)
// ---------------------------------------------------------------------------

/// Aggregated state required by [`PostureAwareExtractor`].
///
/// Must be registered as `axum::Extension<Arc<PostureExtractorState>>`
/// in the router before any handler using [`PostureAwareExtractor`].
///
/// # Example
///
/// ```ignore
/// let state = Arc::new(PostureExtractorState {
///     auth_engine,
///     posture_checker: Arc::new(PostureChecker::new(policy)),
///     fingerprint_validator: Arc::new(FingerprintValidator::new(config, secret)),
///     edr_provider: None,
///     config: PostureExtractorConfig::default(),
/// });
///
/// app.route("/api/protected", get(handler))
///    .layer(axum::Extension(state))
/// ```
pub struct PostureExtractorState {
    /// JWT / multi-backend authentication engine.
    #[cfg(feature = "jwt")]
    pub auth_engine: Arc<AuthEngine>,

    /// Device posture policy evaluator.
    pub posture_checker: Arc<PostureChecker>,

    /// Fingerprint validator with built-in replay cache.
    pub fingerprint_validator: Arc<FingerprintValidator>,

    /// Optional EDR provider for server-side posture queries.
    ///
    /// When `None`, falls back to client-report-only mode via
    /// [`build_client_report_posture`].
    #[cfg(any(feature = "defender", feature = "falcon"))]
    pub edr_provider: Option<Arc<dyn crate::edr::traits::EdrProvider>>,

    /// Behavior configuration.
    pub config: PostureExtractorConfig,
}

// ---------------------------------------------------------------------------
// Result Type
// ---------------------------------------------------------------------------

/// Combined output of successful posture-aware authentication.
///
/// Contains all three validation results so handlers can make fine-grained
/// authorization decisions based on individual components.
#[derive(Debug, Clone)]
pub struct PostureAuthResult {
    /// Validated JWT claims (identity + roles).
    #[cfg(feature = "jwt")]
    pub claims: ValidatedClaims,

    /// Stable device identifier (HMAC-SHA256 of fingerprint signals).
    pub device_id: String,

    /// Raw validated fingerprint (for logging / audit trail).
    pub fingerprint: DeviceFingerprint,

    /// Posture evaluation outcome (score, checks, remediation steps).
    pub posture: PostureEvaluationResult,
}

// ---------------------------------------------------------------------------
// Rejection Types
// ---------------------------------------------------------------------------

/// Errors returned by [`PostureAwareExtractor`] on authentication failure.
///
/// Each variant maps to a distinct HTTP status code to help clients
/// distinguish between identity failure (401) and device compliance failure (403).
#[derive(Debug, thiserror::Error)]
pub enum PostureRejection {
    /// JWT token invalid or expired → **401 Unauthorized**.
    #[error("authentication failed: {0}")]
    Unauthorized(#[cfg(feature = "jwt")] AuthError),

    /// Device fingerprint missing, invalid, or mismatched → **403 Forbidden**.
    #[error("fingerprint validation failed: {0}")]
    FingerprintInvalid(String),

    /// Device posture check did not pass → **403 Forbidden** (not 401!).
    #[error("posture check failed: score={score}, action={action}")]
    PostureFailed {
        score: u8,
        action: String,
        failed_checks: Vec<String>,
    },

    /// Required request header absent → **400 Bad Request**.
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
}

impl IntoResponse for PostureRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized(e) => {
                #[cfg(feature = "jwt")]
                let body = e.error_body();
                #[cfg(not(feature = "jwt"))]
                let body = json!({"error": "unauthorized", "message": "authentication required"});
                (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
            }
            Self::FingerprintInvalid(msg) => (
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "error": "fingerprint_invalid",
                    "message": msg,
                })),
            )
                .into_response(),
            Self::PostureFailed { score, action, failed_checks } => (
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "error": "posture_check_failed",
                    "posture_score": score,
                    "failed_checks": failed_checks,
                    "action": action,
                })),
            )
                .into_response(),
            Self::MissingHeader(name) => (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "error": "missing_header",
                    "header": name,
                    "message": format!("Required header '{name}' is missing"),
                })),
            )
                .into_response(),
        }
    }
}

// ---------------------------------------------------------------------------
// Axum Extractor Implementation
// ---------------------------------------------------------------------------

/// Axum extractor that performs JWT + Fingerprint + Posture authentication.
///
/// Implements [`axum::extract::FromRequestParts`] to integrate seamlessly
/// into handler function signatures:
///
/// ```ignore
/// async fn protected_handler(
///     auth: PostureAwareExtractor,
/// ) -> impl IntoResponse {
///     json!({
///         "user": auth.0.claims.sub,
///         "device_id": auth.0.device_id,
///         "posture_score": auth.0.posture.posture.posture_score,
///     })
/// }
/// ```
///
/// # Required Headers
///
/// | Header                  | Required | Description                          |
/// |-------------------------|----------|--------------------------------------|
/// | `Authorization`         | Yes      | `Bearer <jwt_token>`                 |
/// | `X-Device-Fingerprint`  | Config.  | Base64 JSON of [`DeviceFingerprint`] |
/// | `User-Agent`            | Config.  | Browser/client UA string            |
///
/// # State Dependency
///
/// Requires [`PostureExtractorState`] injected via `axum::Extension`.
#[cfg(all(feature = "axum", feature = "posture"))]
pub struct PostureAwareExtractor(pub PostureAuthResult);

#[cfg(all(feature = "axum", feature = "posture"))]
impl<S> axum::extract::FromRequestParts<S> for PostureAwareExtractor
where
    S: Send + Sync + 'static,
{
    type Rejection = PostureRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let state = parts
            .extensions
            .get::<Arc<PostureExtractorState>>()
            .cloned()
            .ok_or_else(|| PostureRejection::MissingHeader("__extension_state"))?;

        // Step 1: Extract and validate JWT Bearer token
        #[cfg(feature = "jwt")]
        let claims = extract_jwt(&parts.headers, &state)?;

        // Step 2: Extract and validate device fingerprint
        let (device_id, fingerprint) =
            extract_fingerprint(&parts.headers, &state, Some(&claims))?;

        // Step 3: Detect OS from User-Agent
        let ua = extract_user_agent(&parts.headers, &state.config)?;
        let detected_os = parse_os_from_user_agent(&ua);

        // Step 4: Build device posture (EDR or client-report)
        let device_posture = build_device_posture(
            &detected_os,
            &fingerprint,
            &state,
            &device_id,
        );

        // Step 5: Evaluate posture against policy
        let eval = state.posture_checker.evaluate(device_posture);

        if !eval.allowed {
            match state.config.default_failure_action {
                crate::posture::types::FailureAction::Block => {
                    return Err(PostureRejection::PostureFailed {
                        score: eval.posture.posture_score,
                        action: "block".into(),
                        failed_checks: eval.failed_critical_checks.clone(),
                    });
                }
                _ => {} // Warn/Allow: fall through with posture warning in result
            }
        }

        #[cfg(feature = "jwt")]
        let result = PostureAuthResult {
            claims,
            device_id,
            fingerprint,
            posture: eval,
        };
        #[cfg(not(feature = "jwt"))]
        let result = PostureAuthResult {
            device_id,
            fingerprint,
            posture: eval,
        };

        Ok(Self(result))
    }
}

// ---------------------------------------------------------------------------
// Internal: Step 1 — JWT Extraction
// ---------------------------------------------------------------------------

#[cfg(feature = "jwt")]
fn extract_jwt(
    headers: &http::HeaderMap,
    state: &PostureExtractorState,
) -> Result<ValidatedClaims, PostureRejection> {
    let auth_header = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| PostureRejection::MissingHeader("Authorization"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .unwrap_or(auth_header)
        .trim();

    if token.is_empty() {
        return Err(PostureRejection::Unauthorized(AuthError::MissingCredentials));
    }

    state
        .auth_engine
        .validate_token(token)
        .map_err(|e| PostureRejection::Unauthorized(e))
}

// ---------------------------------------------------------------------------
// Internal: Step 2 — Fingerprint Extraction & Validation
// ---------------------------------------------------------------------------

fn extract_fingerprint(
    headers: &http::HeaderMap,
    state: &PostureExtractorState,
    #[cfg(feature = "jwt")] claims: Option<&ValidatedClaims>,
) -> Result<(String, DeviceFingerprint), PostureRejection> {
    let fp_header = headers
        .get(DEVICE_FINGERPRINT_HEADER)
        .and_then(|v| v.to_str().ok());

    let fp_header = match fp_header {
        Some(h) if !h.is_empty() => h,
        _ if state.config.require_fingerprint => {
            return Err(PostureRejection::MissingHeader(DEVICE_FINGERPRINT_HEADER));
        }
        _ => {
            let dummy_fp = DeviceFingerprint {
                user_agent: crate::device::fingerprint::FingerprintSignal {
                    value_hash: "none".into(),
                    entropy_bits: 0.0,
                    is_stable: false,
                },
                canvas_hash: None,
                screen_resolution: crate::device::fingerprint::ScreenResolution::new(0, 0, 0, 0),
                collected_at: chrono::Utc::now(),
                confidence: 0.0,
            };
            return Ok(("no-fingerprint".into(), dummy_fp));
        }
    };

    if fp_header.len() > MAX_FINGERPRINT_HEADER_BYTES {
        return Err(PostureRejection::FingerprintInvalid(
            "fingerprint payload exceeds maximum size".into(),
        ));
    }

    let collected = collect_fingerprint_from_header(Some(fp_header)).map_err(|e| {
        PostureRejection::FingerprintInvalid(format!("parsing failed: {e}"))
    })?;

    let fingerprint = collected.ok_or_else(|| {
        PostureRejection::FingerprintInvalid("empty fingerprint payload".into())
    })?.fingerprint;

    let computed_id = fingerprint.compute_device_id(
        &state.fingerprint_validator.secret(),
    );

    #[cfg(feature = "jwt")]
    if let Some(claims) = claims {
        let bound_id = &claims.device_id;
        state
            .fingerprint_validator
            .validate_binding(&fingerprint, bound_id)
            .map_err(|e| match e {
                FingerprintBindError::DeviceIdMismatch { .. } => {
                    PostureRejection::FingerprintInvalid(
                        "device_id does not match JWT claim".into(),
                    )
                }
                FingerprintBindError::ReplayDetected => {
                    PostureRejection::FingerprintInvalid(
                        "potential replay attack detected".into(),
                    )
                }
                other => PostureRejection::FingerprintInvalid(other.to_string()),
            })?;
    } else {
        state
            .fingerprint_validator
            .validate_for_registration(&fingerprint)
            .map_err(|e| PostureRejection::FingerprintInvalid(e.to_string()))?;
    }

    Ok((computed_id, fingerprint))
}

// ---------------------------------------------------------------------------
// Internal: Step 3 — User-Agent Extraction
// ---------------------------------------------------------------------------

fn extract_user_agent(
    headers: &http::HeaderMap,
    config: &PostureExtractorConfig,
) -> Result<String, PostureRejection> {
    let ua = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if ua.is_empty() && config.require_user_agent {
        Err(PostureRejection::MissingHeader("User-Agent"))
    } else {
        Ok(ua.to_string())
    }
}

// ---------------------------------------------------------------------------
// Internal: Step 4 — Posture Building
// ---------------------------------------------------------------------------

fn build_device_posture(
    detected_os: &crate::posture::types::OsPosture,
    fingerprint: &DeviceFingerprint,
    _state: &PostureExtractorState,
    _device_id: &str,
) -> crate::posture::types::DevicePosture {
    #[cfg(any(feature = "defender", feature = "falcon"))]
    {
        if let Some(ref provider) = _state.edr_provider {
            if let Ok(edr_posture) = provider.get_device_posture(_device_id) {
                return convert_edr_to_posture(&edr_posture, Some(detected_os));
            }
        }
    }

    build_client_report_posture(detected_os, fingerprint)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let cfg = PostureExtractorConfig::default();
        assert!(cfg.require_fingerprint);
        assert_eq!(
            cfg.default_failure_action,
            crate::posture::types::FailureAction::Warn
        );
        assert!(!cfg.require_user_agent);
    }

    #[test]
    fn test_rejection_serialization_unauthorized() {
        #[cfg(feature = "jwt")]
        let rej = PostureRejection::Unauthorized(AuthError::ExpiredToken);
        #[cfg(not(feature = "jwt"))]
        let rej = PostureRejection::MissingHeader("test");
        let resp = rej.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_rejection_fingerprint_invalid_is_403() {
        let rej = PostureRejection::FingerprintInvalid("replay detected".into());
        let resp = rej.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_rejection_posture_failed_is_403_not_401() {
        let rej = PostureRejection::PostureFailed {
            score: 25,
            action: "block".into(),
            failed_checks: vec!["os_supported".into()],
        };
        let resp = rej.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_rejection_missing_header_is_400() {
        let rej = PostureRejection::MissingHeader("X-Custom-Header");
        let resp = rej.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_constants_are_valid() {
        assert!(!DEVICE_FINGERPRINT_HEADER.is_empty());
        assert!(MAX_FINGERPRINT_HEADER_BYTES > 0);
        assert!(MAX_FINGERPRINT_HEADER_BYTES <= 8192);
    }
}
