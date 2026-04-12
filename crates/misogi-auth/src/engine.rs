//! AuthEngine — Micro-Kernel Authentication Core
//!
//! Provides a slim, focused authentication engine that holds only:
//! - [`JwtValidator`] for RS256 token validation
//! - Optional [`IdentityRegistry`] for pluggable identity providers
//! - API key validation for service accounts
//! - Audit logging with bounded ring buffer
//!
//! # Architecture
//!
//! ```text
//! +------------------+     Token / Key      +------------------+
//! |   gRPC / HTTP    | -------------------> |   AuthEngine     |
//! |   Request        |                      |  +-------------+ |
//! |                  | <------------------- |  | JwtValidator | |
//! +------------------+  Validated Claims    |  +-------------+ |
//!                                         |  +-------------+ |
//!                                         |  | IdRegistry   | |
//!                                         |  | (optional)   | |
//!                                         |  +-------------+ |
//!                                         |  +-------------+ |
//!                                         |  | API Keys     | |
//!                                         |  +-------------+ |
//!                                         +------------------+
//! ```
//!
//! # Design Principles
//!
//! - **Micro-Kernel**: Only core auth logic; no LDAP/OIDC/SAML direct coupling
//! - **Pluggable Providers**: External backends via [`IdentityRegistry`]
//! - **Thread-Safe**: All public methods are `&self` and safe for concurrent use
//! - **Zero-Cost Abstraction`: Feature-gated JWT; no overhead when disabled
//!
//! # Migration from Legacy
//!
//! The legacy `AuthEngine` in [`middleware`](super::middleware) directly integrated
//! LDAP, OIDC, and SAML providers. This refactored version delegates all
//! external provider logic to [`IdentityRegistry`], keeping the engine slim
//! and focused on token validation and API key management.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use tracing::{info, instrument, warn};

#[cfg(feature = "jwt")]
use super::jwt::{JwtConfig, JwtValidator, JwtError};
use super::provider::{
    AuthRequest, MisogiIdentity,
};
use super::role::UserRole;
use crate::registry::IdentityRegistry;

// ---------------------------------------------------------------------------
// Re-exported Types (backward compatibility)
// ---------------------------------------------------------------------------

/// Authentication strategy for multi-backend attempts.
///
/// Controls behavior when multiple identity providers are configured.
/// See [`middleware::AuthStrategy`](super::middleware::AuthStrategy) for full docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrategy {
    /// Try all providers; merge claims from successful ones.
    Sequential,
    /// Return on first successful authentication (fastest).
    FirstMatch,
    /// Require ALL providers to succeed (strictest).
    Required,
}

impl Default for AuthStrategy {
    fn default() -> Self {
        Self::FirstMatch
    }
}

impl std::fmt::Display for AuthStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential"),
            Self::FirstMatch => write!(f, "first_match"),
            Self::Required => write!(f, "required"),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit Event Types
// ---------------------------------------------------------------------------

/// Classification of audit events recorded by the authentication engine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuditEventType {
    /// Successful authentication via any backend.
    AuthSuccess,
    /// Failed authentication attempt.
    AuthFailure,
    /// Token exchange operation.
    TokenExchange,
    /// Session logout / token revocation.
    Logout,
    /// Configuration change to the auth engine.
    ConfigChange,
}

/// A single audit event recorded by the authentication engine.
///
/// Captures who, what, when, and where for compliance and debugging.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// UTC timestamp when this event occurred.
    pub timestamp: DateTime<Utc>,
    /// Classification of this event type.
    pub event_type: AuditEventType,
    /// User identifier involved in this event.
    pub user_id: Option<String>,
    /// Client IP address (provided by caller).
    pub ip_address: Option<String>,
    /// Human-readable details about this event.
    pub details: String,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(event_type: AuditEventType, details: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            user_id: None,
            ip_address: None,
            details: details.into(),
        }
    }

    /// Builder-style: set the user ID.
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    /// Builder-style: set the client IP address.
    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }
}

// ---------------------------------------------------------------------------
// Service Account (API Key)
// ---------------------------------------------------------------------------

/// Service account representing an API key for machine-to-machine auth.
///
/// Used by [`AuthEngine::validate_api_key`] to authenticate service calls.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceAccount {
    /// Unique identifier for this API key (used as the key value itself).
    pub key_id: String,
    /// Human-readable name of the service account.
    pub name: String,
    /// Roles assigned to this service account.
    pub roles: Vec<UserRole>,
    /// Timestamp when this API key was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiration timestamp. `None` means no expiration.
    pub expires_at: Option<DateTime<Utc>>,
}

impl ServiceAccount {
    /// Check whether this service account's API key has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Comprehensive error type for authentication engine operations.
///
/// Maps cleanly to both gRPC Status codes and HTTP status codes.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The provided token could not be validated.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// The provided token has expired.
    #[error("token expired")]
    ExpiredToken,
    /// No credentials were provided.
    #[error("missing credentials")]
    MissingCredentials,
    /// The API key is invalid or unrecognized.
    #[error("invalid API key")]
    InvalidApiKey,
    /// Internal error during processing.
    #[error("internal error: {0}")]
    InternalError(String),
}

impl AuthError {
    /// Map this error to an HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidToken(_) | Self::InvalidApiKey => 401,
            Self::ExpiredToken => 401,
            Self::MissingCredentials => 401,
            Self::InternalError(_) => 500,
        }
    }

    /// Machine-readable error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidToken(_) => "invalid_token",
            Self::ExpiredToken => "expired_token",
            Self::MissingCredentials => "missing_credentials",
            Self::InvalidApiKey => "invalid_api_key",
            Self::InternalError(_) => "internal_error",
        }
    }

    /// Serialize into a JSON error response body.
    pub fn error_body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.error_code(),
            "message": self.to_string(),
            "status_code": self.http_status(),
        })
    }
}

// ---------------------------------------------------------------------------
// Role Mapping Rule
// ---------------------------------------------------------------------------

/// Rule for mapping external group names to internal roles.
#[derive(Debug, Clone)]
pub struct RoleMappingRule {
    /// Regex pattern to match against external group names.
    pub source_group_pattern: regex::Regex,
    /// Internal role to assign when pattern matches.
    pub target_role: UserRole,
    /// Priority level (lower = higher priority = evaluated first).
    pub priority: u32,
}

impl RoleMappingRule {
    /// Create a new role mapping rule.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Regex string for matching group names
    /// * `target_role` - Internal role on match
    /// * `priority` - Evaluation priority (lower = first)
    pub fn new(
        pattern: &str,
        target_role: UserRole,
        priority: u32,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            source_group_pattern: regex::Regex::new(pattern)?,
            target_role,
            priority,
        })
    }

    /// Test if this rule matches the given group name.
    pub fn matches(&self, group_name: &str) -> bool {
        self.source_group_pattern.is_match(group_name)
    }
}

/// Default enterprise role mapping rules.
fn default_role_mapping_rules() -> Vec<RoleMappingRule> {
    vec![
        // Admin groups (highest priority)
        RoleMappingRule::new(r"(?i)(admin|administrator|domain.admins)", UserRole::Admin, 10)
            .expect("hardcoded admin regex is valid"),
        // Approver groups
        RoleMappingRule::new(r"(?i)(approver|manager|supervisor)", UserRole::Approver, 20)
            .expect("hardcoded approver regex is valid"),
        // Default staff (lowest priority — catch-all not needed; default is Staff)
    ]
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum number of audit events retained in ring buffer.
const DEFAULT_AUDIT_LOG_MAX_SIZE: usize = 10_000;

// ===========================================================================
// AuthEngine — Micro-Kernel Core
// ===========================================================================

/// Slim authentication engine — micro-kernel architecture.
///
/// Holds only essential components:
/// - [`JwtValidator`] for RS256 token verification
/// - Optional [`IdentityRegistry`] for pluggable external providers
/// - In-memory API key store for service accounts
/// - Bounded audit log ring buffer
///
/// # Thread Safety
///
/// This struct is designed to be wrapped in `Arc<>` and shared across
/// async tasks. All mutation methods use internal synchronization.
///
/// # Example
///
/// ```ignore
/// let engine = AuthEngine::new(jwt_config)?;
/// let claims = engine.validate_token(&token)?;
/// ```
pub struct AuthEngine {
    /// RS256 JWT validator (available when `jwt` feature is enabled).
    #[cfg(feature = "jwt")]
    jwt_validator: Arc<JwtValidator>,

    /// Optional registry of pluggable identity providers.
    identity_registry: Arc<RwLock<Option<IdentityRegistry>>>,

    /// Configured API keys for service account authentication.
    api_keys: HashMap<String, ServiceAccount>,

    /// Strategy for multi-provider authentication attempts.
    auth_strategy: AuthStrategy,

    /// Rules for mapping external groups to internal roles.
    role_mapping_rules: Vec<RoleMappingRule>,

    /// Ring buffer of audit events (bounded memory usage).
    audit_log: std::sync::Mutex<Vec<AuditEvent>>,

    /// Maximum capacity of audit log ring buffer.
    audit_log_max_size: usize,
}

impl AuthEngine {
    /// Create a new AuthEngine with JWT validation support.
    ///
    /// Initializes the JWT validator from the provided configuration.
    /// Identity providers can be added later via [`with_identity_registry`](Self::with_identity_registry).
    ///
    /// # Arguments
    ///
    /// * `config` - JWT configuration including RSA public key path
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InternalError`] if JWT validator initialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = JwtConfig { /* ... */ };
    /// let engine = AuthEngine::new(config)?;
    /// ```
    #[cfg(feature = "jwt")]
    #[instrument(skip(config), fields(strategy = "first_match"))]
    pub fn new(config: JwtConfig) -> Result<Self, AuthError> {
        let jwt_validator = Arc::new(JwtValidator::new(config).map_err(|e| {
            AuthError::InternalError(format!("JWT validator init failed: {e}"))
        })?);

        info!(
            strategy = %AuthStrategy::FirstMatch,
            audit_capacity = DEFAULT_AUDIT_LOG_MAX_SIZE,
            "AuthEngine (micro-kernel) initialized"
        );

        Ok(Self {
            jwt_validator,
            identity_registry: Arc::new(RwLock::new(None)),
            api_keys: HashMap::new(),
            auth_strategy: AuthStrategy::FirstMatch,
            role_mapping_rules: default_role_mapping_rules(),
            audit_log: std::sync::Mutex::new(Vec::with_capacity(DEFAULT_AUDIT_LOG_MAX_SIZE)),
            audit_log_max_size: DEFAULT_AUDIT_LOG_MAX_SIZE,
        })
    }

    /// Create a new AuthEngine without JWT support (minimal mode).
    ///
    /// Use this when only API key validation or external provider
    /// authentication is needed. JWT operations will return errors.
    #[cfg(not(feature = "jwt"))]
    pub fn new(_config: ()) -> Result<Self, AuthError> {
        info!(
            strategy = %AuthStrategy::FirstMatch,
            audit_capacity = DEFAULT_AUDIT_LOG_MAX_SIZE,
            "AuthEngine (micro-kernel) initialized [JWT-disabled]"
        );

        Ok(Self {
            identity_registry: Arc::new(RwLock::new(None)),
            api_keys: HashMap::new(),
            auth_strategy: AuthStrategy::FirstMatch,
            role_mapping_rules: default_role_mapping_rules(),
            audit_log: std::sync::Mutex::new(Vec::with_capacity(DEFAULT_AUDIT_LOG_MAX_SIZE)),
            audit_log_max_size: DEFAULT_AUDIT_LOG_MAX_SIZE,
        })
    }

    /// Attach an [`IdentityRegistry`] for pluggable provider support.
    ///
    /// Enables authentication via external identity providers (LDAP, OIDC, SAML, etc.)
    /// that have been registered with the registry.
    ///
    /// # Arguments
    ///
    /// * `registry` - Pre-configured registry containing registered providers
    ///
    /// # Returns
    ///
    /// `Self` for builder-style chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut registry = IdentityRegistry::new();
    /// registry.register(Box::new(my_ldap_provider))?;
    /// let engine = AuthEngine::new(jwt_config)?.with_identity_registry(registry);
    /// ```
    pub fn with_identity_registry(self, registry: IdentityRegistry) -> Self {
        let provider_count = registry.len();
        if let Ok(mut guard) = self.identity_registry.write() {
            *guard = Some(registry);
        }
        info!(
            provider_count,
            "IdentityRegistry attached to AuthEngine"
        );
        self.record_audit_event(
            AuditEvent::new(
                AuditEventType::ConfigChange,
                format!("IdentityRegistry attached ({provider_count} providers)"),
            )
        );
        self
    }

    // ===================================================================
    // Configuration Methods
    // ===================================================================

    /// Set the authentication strategy for multi-provider attempts.
    pub fn set_auth_strategy(&mut self, strategy: AuthStrategy) {
        info!(old = %self.auth_strategy, new = %strategy, "AuthStrategy updated");
        self.auth_strategy = strategy;
        self.record_audit_event(
            AuditEvent::new(AuditEventType::ConfigChange, format!("auth_strategy changed to {strategy}"))
        );
    }

    /// Set custom role mapping rules (replaces built-in defaults).
    pub fn set_role_mapping_rules(&mut self, rules: Vec<RoleMappingRule>) {
        info!(count = rules.len(), "Role mapping rules updated");
        self.role_mapping_rules = rules;
        self.record_audit_event(
            AuditEvent::new(AuditEventType::ConfigChange, "role_mapping_rules updated")
        );
    }

    /// Set the maximum capacity of the audit log ring buffer.
    pub fn set_audit_log_max_size(&mut self, max_size: usize) {
        if max_size == 0 {
            warn!("Attempted to set audit_log_max_size to 0, ignoring");
            return;
        }
        self.audit_log_max_size = max_size;
        info!(max_size, "Audit log max size updated");
    }

    // ===================================================================
    // Core Authentication Methods
    // ===================================================================

    /// Validate a JWT token string using the internal [`JwtValidator`].
    ///
    /// Delegates to [`JwtValidator::validate`] for cryptographic signature
    /// verification and claim validation.
    ///
    /// # Arguments
    ///
    /// * `token` - JWS Compact Serialization string to validate
    ///
    /// # Returns
    ///
    /// The extracted [`MisogiClaims`](super::claims::MisogiClaims) on success.
    ///
    /// # Errors
    ///
    /// - [`AuthError::MissingCredentials`] — empty token
    /// - [`AuthError::InvalidToken`] — signature/claim validation failed
    /// - [`AuthError::ExpiredToken`] — token has expired
    /// - [`AuthError::InternalError`] — JWT feature not enabled
    #[instrument(skip(self, token), fields(token_len = token.len()))]
    pub fn validate_token(&self, token: &str) -> Result<crate::claims::MisogiClaims, AuthError> {
        if token.is_empty() {
            return Err(AuthError::MissingCredentials);
        }

        #[cfg(feature = "jwt")]
        {
            self.jwt_validator.validate(token).map_err(|e: JwtError| match e {
                JwtError::TokenExpired => AuthError::ExpiredToken,
                JwtError::InvalidSignature => {
                    AuthError::InvalidToken("Signature verification failed".to_string())
                }
                other => AuthError::InvalidToken(other.to_string()),
            })
        }

        #[cfg(not(feature = "jwt"))]
        Err(AuthError::InternalError("JWT feature not enabled".to_string()))
    }

    /// Validate an API key and return the associated service account.
    ///
    /// # Arguments
    ///
    /// * `key` - API key string to validate
    ///
    /// # Errors
    ///
    /// - [`AuthError::MissingCredentials`] — empty key
    /// - [`AuthError::InvalidApiKey`] — key not found in configured key set
    #[instrument(skip(self, key))]
    pub fn validate_api_key(&self, key: &str) -> Result<ServiceAccount, AuthError> {
        if key.is_empty() {
            return Err(AuthError::MissingCredentials);
        }

        self.api_keys.get(key).cloned().ok_or_else(|| {
            warn!(key_preview = &key[..key.len().min(8)], "Invalid API key");
            AuthError::InvalidApiKey
        })
    }

    /// Register an API key for service account authentication.
    ///
    /// **Warning**: Not thread-safe for concurrent registration. Call during startup.
    pub fn register_api_key(&mut self, account: ServiceAccount) {
        let key_id = account.key_id.clone();
        let name = account.name.clone();
        info!(key_id = %key_id, name = %name, "API key registered");
        self.api_keys.insert(key_id.clone(), account);
        self.record_audit_event(
            AuditEvent::new(AuditEventType::ConfigChange, format!("API key registered: {name}"))
                .with_user_id(&key_id)
        );
    }

    /// Authenticate via a registered identity provider.
    ///
    /// Delegates to [`IdentityRegistry::authenticate`] if a registry is attached.
    /// This is the primary entry point for external provider authentication
    /// (LDAP, OIDC, SAML, etc.).
    ///
    /// # Arguments
    ///
    /// * `provider_id` - Unique identifier of the target provider
    /// * `request` - Authentication request (credentials, authorization code, etc.)
    ///
    /// # Returns
    ///
    /// A normalized [`MisogiIdentity`] on success.
    ///
    /// # Errors
    ///
    /// - [`AuthError::InternalError`] — no registry attached or provider not found
    /// - Wrapped [`IdentityError`] — provider-specific authentication failure
    #[instrument(skip(self, request), fields(provider_id))]
    pub async fn authenticate_via_provider(
        &self,
        provider_id: &str,
        request: AuthRequest,
    ) -> Result<MisogiIdentity, AuthError> {
        let registry = self.identity_registry.read().map_err(|e| {
            AuthError::InternalError(format!("Registry lock poisoned: {e}"))
        })?;

        let registry = registry.as_ref().ok_or_else(|| {
            AuthError::InternalError(format!(
                "No IdentityRegistry attached. Cannot authenticate via provider '{provider_id}'"
            ))
        })?;

        registry
            .authenticate(provider_id, &request)
            .await
            .map_err(|e| AuthError::InternalError(format!("Provider auth failed: {e}")))
    }

    // ===================================================================
    // Audit Log
    // ===================================================================

    /// Record an audit event into the ring buffer.
    ///
    /// Thread-safe: uses Mutex internally. Old events evicted when over capacity.
    fn record_audit_event(&self, event: AuditEvent) {
        match self.audit_log.lock() {
            Ok(mut log) => {
                log.push(event);
                while log.len() > self.audit_log_max_size {
                    log.remove(0);
                }
            }
            Err(poisoned) => {
                warn!("Audit log mutex poisoned, recovering");
                let mut log = poisoned.into_inner();
                log.push(event);
                while log.len() > self.audit_log_max_size {
                    log.remove(0);
                }
            }
        }
    }

    /// Query audit events with optional time range and type filtering.
    ///
    /// Returns events in chronological order (oldest first).
    pub fn get_audit_events(
        &self,
        since: Option<DateTime<Utc>>,
        filter: Option<AuditEventType>,
    ) -> Vec<AuditEvent> {
        let log = match self.audit_log.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Audit log mutex poisoned during query");
                poisoned.into_inner()
            }
        };

        log.iter()
            .filter(|evt| {
                if let Some(since_time) = since {
                    if evt.timestamp < since_time {
                        return false;
                    }
                }
                if let Some(ref filter_type) = filter {
                    if evt.event_type != *filter_type {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Clear all audit events from the log.
    pub fn clear_audit_log(&self) {
        if let Ok(mut log) = self.audit_log.lock() {
            let count = log.len();
            log.clear();
            info!(count, "Audit log cleared");
        }
    }

    // ===================================================================
    // Accessors
    // ===================================================================

    /// Get the current authentication strategy.
    pub fn auth_strategy(&self) -> AuthStrategy {
        self.auth_strategy
    }

    /// Get reference to the JWT validator (if available).
    #[cfg(feature = "jwt")]
    pub fn jwt_validator(&self) -> &Arc<JwtValidator> {
        &self.jwt_validator
    }

    /// Check if an IdentityRegistry is attached.
    pub fn has_identity_registry(&self) -> bool {
        self.identity_registry
            .read()
            .map(|r| r.is_some())
            .unwrap_or(false)
    }

    /// Get the number of registered API keys.
    pub fn api_key_count(&self) -> usize {
        self.api_keys.len()
    }
}

// ===========================================================================
// Tests (separated file per line-limit policy)
// ===========================================================================

#[cfg(test)]
mod tests;
