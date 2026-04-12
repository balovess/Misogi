//! Misogi Standard JWT Claims Structure
//!
//! Defines [`MisogiClaims`] — the canonical claims payload for all JWT tokens issued
//! and consumed within the Misogi ecosystem. This structure serves as the single source
//! of truth for token claim semantics across all authentication backends (JWT, OIDC,
//! SAML-to-JWT translation).
//!
//! # Design Principles
//!
//! - **Extensibility**: The `extra` field with `#[serde(flatten)]` allows arbitrary
//!   custom claims without breaking schema evolution.
//! - **Auditability**: `original_subject` and `issuer_dn` preserve IdP provenance for
//!   compliance tracing.
//! - **Interoperability**: Field names follow RFC 7519 registered claims where possible,
//!   with Misogi-specific prefixes for domain-specific fields.
//!
//! # Claim Categories
//!
//! | Category    | Fields                              | Purpose                        |
//! |-------------|-------------------------------------|--------------------------------|
//! | Required    | `applicant_id`, `iat`, `exp`        | Identity + temporal validity   |
//! | Standard    | `display_name`, `roles`, `idp_source`| Presentation + authorization   |
//! | Audit       | `original_subject`, `issuer_dn`     | IdP chain traceability         |
//! | Extension   | `extra` (flattened)                 | Forward-compatible custom data |
//!
//! # Example
//!
//! ```ignore
//! use misogi_auth::claims::MisogiClaims;
//!
//! let claims = MisogiClaims::new("user-001".to_string(), 1700000000, 1700003600)
//!     .with_display_name("\u7530\u4e2d \u592a\u90ce".to_string())
//!     .with_roles(vec!["staff".to_string()])
//!     .with_idp_source("ldap".to_string());
//!
//! let json = serde_json::to_string(&claims).unwrap();
//! assert!(json.contains("applicant_id"));
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Claims Structure
// ---------------------------------------------------------------------------

/// Standard JWT claims structure for the Misogi project.
///
/// Encapsulates all required, standard, audit, and extension fields that may appear
/// in a Misogi-issued or Misogi-consumed JWT token. Designed to be:
/// - **Serializable** to/from JSON (via serde) for JWT payload encoding
/// - **Extensible** via the flattened `extra` map for forward compatibility
/// - **Auditable** via `original_subject` / `issuer_dn` for IdP chain tracing
///
/// # Required Fields (MUST be present)
///
/// - `applicant_id`: Unique identifier of the authenticated subject
/// - `iat`: Issued-at timestamp as UNIX seconds since epoch
/// - `exp`: Expiration timestamp as UNIX seconds since epoch
///
/// # Standard Fields (SHOULD be present when available)
///
/// - `display_name`: Human-readable name of the subject
/// - `roles`: Role strings granted to this subject
/// - `idp_source`: Identifier of the identity provider
///
/// # Audit Fields (populated by IdP integration layers)
///
/// - `original_subject`: Raw subject identifier from the upstream IdP
/// - `issuer_dn`: Distinguished Name of the issuing entity
///
/// # Extension Field
///
/// - `extra`: Arbitrary key-value pairs flattened into top-level JSON object
///
/// # Security Considerations
///
/// - `exp` MUST always be validated at token consumption time
/// - `original_subject` may contain sensitive identifiers; sanitize in logs
/// - `roles` should be validated against known role enumerations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisogiClaims {
    // ------------------------------------------------------------------
    // Required Fields
    // ------------------------------------------------------------------

    /// Unique identifier of the applicant (authenticated subject).
    ///
    /// Typically an employee number, UPN, UUID, or other stable identifier.
    /// This is the primary lookup key for authorization decisions.
    ///
    /// **Format**: Non-empty UTF-8 string. Recommended max length: 256 chars.
    pub applicant_id: String,

    /// Issued-at timestamp — UNIX seconds since epoch (UTC).
    ///
    /// Records when the token was originally created. Used for age-based
    /// validation, audit trail reconstruction, and clock skew calculations.
    pub iat: u64,

    /// Expiration timestamp — UNIX seconds since epoch (UTC).
    ///
    /// After this timestamp, the token MUST be considered invalid regardless
    /// of signature validity. Consumers must check this field.
    ///
    /// **Recommended TTL**: 1–8 hours for access tokens; 7 days for refresh.
    pub exp: u64,

    // ------------------------------------------------------------------
    // Standard Fields
    // ------------------------------------------------------------------

    /// Human-readable display name of the authenticated subject.
    ///
    /// Intended for UI presentation only — NOT for authorization decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Role strings granted to this subject within the Misogi system.
    ///
    /// Each string corresponds to a role variant or custom role defined
    /// by the deployment. Authorization middleware checks membership here.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Identifier of the identity provider (IdP) that authenticated this subject.
    ///
    /// Examples: `"ldap"`, `"oidc-keycloak"`, `"saml-gcloud"`, `"local"`.
    pub idp_source: String,

    // ------------------------------------------------------------------
    // Audit Fields
    // ------------------------------------------------------------------

    /// Original subject identifier from the upstream identity provider.
    ///
    /// Preserves the raw subject value BEFORE any mapping/transformation.
    /// Essential for cross-referencing with IdP audit logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_subject: Option<String>,

    /// Distinguished Name (DN) of the issuing entity (certificate or IdP).
    ///
    /// Captures the X.509 DN or SAML/OIDC entity identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_dn: Option<String>,

    // ------------------------------------------------------------------
    // Extension Field (flattened)
    // ------------------------------------------------------------------

    /// Arbitrary extension claims, serialized as top-level JSON fields.
    ///
    /// Uses `#[serde(flatten)]` so entries become sibling fields alongside
    /// named fields during serialization. Enables forward-compatible custom
    /// claims without struct modification.
    ///
    /// **Conflict resolution**: Avoid reserved names: `applicant_id`, `iat`,
    /// `exp`, `display_name`, `roles`, `idp_source`, `original_subject`,
    /// `issuer_dn`.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Construction API
// ---------------------------------------------------------------------------

impl MisogiClaims {
    /// Create a new [`MisogiClaims`] instance with only required fields.
    ///
    /// Optional fields default to:
    /// - `display_name` -> None
    /// - `roles` -> []
    /// - `idp_source` -> "unknown"
    /// - `original_subject` -> None
    /// - `issuer_dn` -> None
    /// - `extra` -> {}
    ///
    /// # Arguments
    ///
    /// * `applicant_id` — Unique identifier of the authenticated subject
    /// * `iat` — Issued-at timestamp (UNIX seconds)
    /// * `exp` — Expiration timestamp (UNIX seconds, must be > `iat`)
    pub fn new(applicant_id: String, iat: u64, exp: u64) -> Self {
        Self {
            applicant_id,
            iat,
            exp,
            display_name: None,
            roles: Vec::new(),
            idp_source: String::from("unknown"),
            original_subject: None,
            issuer_dn: None,
            extra: HashMap::new(),
        }
    }

    /// Builder-style method: set the display name.
    pub fn with_display_name(mut self, name: String) -> Self {
        self.display_name = Some(name);
        self
    }

    /// Builder-style method: set the roles list (replaces existing).
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Builder-style method: append a single role to the existing list.
    pub fn add_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Builder-style method: set the identity provider source identifier.
    pub fn with_idp_source(mut self, source: String) -> Self {
        self.idp_source = source;
        self
    }

    /// Builder-style method: set the original subject from upstream IdP.
    pub fn with_original_subject(mut self, sub: String) -> Self {
        self.original_subject = Some(sub);
        self
    }

    /// Builder-style method: set the issuer distinguished name.
    pub fn with_issuer_dn(mut self, dn: String) -> Self {
        self.issuer_dn = Some(dn);
        self
    }

    /// Builder-style method: insert a key-value pair into extra extensions.
    pub fn with_extra(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Validate temporal consistency of the claims.
    ///
    /// Checks that:
    /// - `exp` > `iat` (positive lifetime)
    /// - `iat` is not in the distant future (> 60s clock skew tolerance)
    ///
    /// Returns `Ok(())` on success, `Err(String)` describing first violation.
    pub fn validate_temporal(&self) -> Result<(), String> {
        if self.exp <= self.iat {
            return Err(format!(
                "exp ({}) must be greater than iat ({})",
                self.exp, self.iat
            ));
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.iat.saturating_sub(now_secs) > 60 {
            return Err(format!(
                "iat ({}) is too far in the future (now: {}, delta: {}s)",
                self.iat,
                now_secs,
                self.iat.saturating_sub(now_secs)
            ));
        }

        Ok(())
    }

    /// Check whether these claims contain a specific role (case-sensitive).
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Calculate the token lifetime in seconds (`exp - iat`).
    ///
    /// Returns 0 if `exp <= iat` (invalid state).
    pub fn lifetime_seconds(&self) -> u64 {
        self.exp.saturating_sub(self.iat)
    }
}

// ---------------------------------------------------------------------------
// Tests (separated to satisfy line limit)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
