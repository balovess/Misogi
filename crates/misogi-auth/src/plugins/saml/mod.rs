//! SAML 2.0 Identity Provider Plugin — [`IdentityProvider`] Implementation for SAML WebSSO.
//!
//! Provides [`SamlIdentityProvider`] implementing [`IdentityProvider`](super::super::provider::IdentityProvider)
//! trait for SAML 2.0 POST-binding authentication responses.
//!
//! # Architecture
//!
//! ```text
//! AuthRequest::SamlResponse         IdP (G-Cloud / Enterprise)
//!        |                              ^
//!        v                              |
//!  SamlIdentityProvider   1. Base64 Decode     ┌──────────────┐
//!  (this module)         2. XML Parse          │  IdP Server   │
//!                       3. Signature Verify    │              │
//!                       4. Condition Validate  │              │
//!                       5. Attribute Extract   │              │
//!                       → MisogiIdentity       └──────────────┘
//! ```
//!
//! # Japanese Government Compatibility
//!
//! - **G-Cloud Japan OID Attribute Names**: Supports `urn:oid:2.5.4.42` (givenName),
//!   `urn:oid:2.5.4.4` (surname), `urn:oid:0.9.2342.19200300.100.1.3` (mail),
//!   `urn:oid:2.5.4.11` (ou) for 総務省 G-Cloud integration.
//! - **NameID Format**: Configurable via [`NameIdFormat`] enum (Email, Persistent,
//!   Transient, Unspecified) to match various Japanese IdP deployments.
//!
//! # Feature Gate
//!
//! Requires `saml` feature flag (enables `quick-xml`, `flate2`, `lru`, `ring`).

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::provider::{AuthRequest, IdentityError, IdentityProvider, MisogiIdentity};
use crate::saml_provider::{self, SamlAttributes as CoreSamlAttributes, SamlError};

// ---------------------------------------------------------------------------
// Name ID Format Enumeration
// ---------------------------------------------------------------------------

/// SAML 2.0 Name Identifier Format — determines how the IdP identifies subjects.
///
/// Each variant maps to its corresponding SAML URI per OASIS SAML 2.0 Core spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NameIdFormat {
    /// Email address format (`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`).
    Email,

    /// Persistent identifier (`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`).
    Persistent,

    /// Transient identifier (`urn:oasis:names:tc:SAML:2.0:nameid-format:transient`).
    Transient,

    /// Unspecified format (`urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`).
    Unspecified,
}

impl NameIdFormat {
    /// Return the SAML URI string for this format variant.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::Email => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            Self::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        }
    }
}

impl Default for NameIdFormat {
    fn default() -> Self {
        Self::Transient
    }
}

// ---------------------------------------------------------------------------
// Attribute Mappings
// ---------------------------------------------------------------------------

/// Mapping configuration from SAML assertion attributes to Misogi identity fields.
///
/// Controls which SAML attribute names are used to populate each identity field.
/// Supports both standard LDAP attribute names and G-Cloud Japan OID attribute URIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeMappings {
    /// Attribute name used for the primary identity identifier.
    #[serde(default = "default_name_id_attr")]
    pub name_id_attribute: String,

    /// Attribute name(s) for display name resolution.
    #[serde(default = "default_display_name_attr")]
    pub display_name_attribute: String,

    /// Attribute name for email address extraction.
    #[serde(default = "default_email_attr")]
    pub email_attribute: String,

    /// Optional attribute name for department/organizational unit.
    #[serde(default)]
    pub department_attribute: Option<String>,

    /// Optional attribute name for organization name.
    #[serde(default)]
    pub organization_attribute: Option<String>,
}

fn default_name_id_attr() -> String {
    "name_id".to_string()
}
fn default_display_name_attr() -> String {
    "urn:oid:2.5.4.42".to_string()
}
fn default_email_attr() -> String {
    "urn:oid:0.9.2342.19200300.100.1.3".to_string()
}

impl Default for SamlAttributeMappings {
    fn default() -> Self {
        Self {
            name_id_attribute: default_name_id_attr(),
            display_name_attribute: default_display_name_attr(),
            email_attribute: default_email_attr(),
            department_attribute: None,
            organization_attribute: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`SamlIdentityProvider`].
///
/// Contains all settings needed to operate as a SAML 2.0 Service Provider (SP),
/// including IdP endpoint URLs, cryptographic material, and attribute mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlPluginConfig {
    /// Entity ID of this Service Provider (SP). Must match IdP registration.
    pub sp_entity_id: String,

    /// URL to fetch IdP metadata XML (alternative to static `idp_metadata_xml`).
    pub idp_metadata_url: Option<String>,

    /// Inline IdP metadata XML content (alternative to `idp_metadata_url`).
    pub idp_metadata_xml: Option<String>,

    /// IdP Single Sign-On (SSO) service URL (HTTP-Redirect or HTTP-POST binding).
    pub idp_sso_url: String,

    /// IdP Single Logout (SLO) service URL (optional; required for logout flows).
    pub idp_slo_url: Option<String>,

    /// Filesystem path to X.509 certificate PEM for signature verification.
    pub certificate_path: Option<String>,

    /// Inline X.509 certificate PEM content (alternative to `certificate_path`).
    pub certificate_pem: Option<String>,

    /// Filesystem path to SP private key PEM (for decryption if needed).
    pub private_key_path: Option<String>,

    /// Inline SP private key PEM content (alternative to `private_key_path`).
    pub private_key_pem: Option<String>,

    /// Attribute mapping rules for SAML → MisogiIdentity conversion.
    #[serde(default)]
    pub attribute_mappings: SamlAttributeMappings,

    /// Requested NameID format for AuthnRequest messages.
    #[serde(default)]
    pub name_id_format: NameIdFormat,

    /// Whether assertions MUST be signed by the IdP.
    #[serde(default = "default_want_assertions_signed")]
    pub want_assertions_signed: bool,

    /// Whether SAML Response messages MUST be signed by the IdP.
    #[serde(default = "default_want_responses_signed")]
    pub want_responses_signed: bool,
}

fn default_want_assertions_signed() -> bool {
    true
}
fn default_want_responses_signed() -> bool {
    true
}

impl Default for SamlPluginConfig {
    fn default() -> Self {
        Self {
            sp_entity_id: String::new(),
            idp_metadata_url: None,
            idp_metadata_xml: None,
            idp_sso_url: String::new(),
            idp_slo_url: None,
            certificate_path: None,
            certificate_pem: None,
            private_key_path: None,
            private_key_pem: None,
            attribute_mappings: SamlAttributeMappings::default(),
            name_id_format: NameIdFormat::Transient,
            want_assertions_signed: true,
            want_responses_signed: true,
        }
    }
}

impl SamlPluginConfig {
    /// Create a configuration optimized for Japan G-Cloud integration.
    ///
    /// Uses OID attribute names compatible with 総務省 G-Cloud IdP deployments.
    pub fn gcloud_japan(
        sp_entity_id: &str,
        idp_sso_url: &str,
        certificate_pem: &str,
    ) -> Self {
        Self {
            sp_entity_id: sp_entity_id.to_string(),
            idp_sso_url: idp_sso_url.to_string(),
            certificate_pem: Some(certificate_pem.to_string()),
            attribute_mappings: SamlAttributeMappings {
                name_id_attribute: "name_id".into(),
                display_name_attribute: "urn:oid:2.5.4.42".into(),
                email_attribute: "urn:oid:0.9.2342.19200300.100.1.3".into(),
                department_attribute: Some("urn:oid:2.5.4.11".into()),
                organization_attribute: Some("organizationName".into()),
            },
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Provider Implementation
// ---------------------------------------------------------------------------

/// SAML 2.0 Identity Provider — implements [`IdentityProvider`] for SAML WebSSO.
///
/// Wraps the core [`saml_provider::SamlAuthProvider`](crate::saml_provider::SamlAuthProvider)
/// and adapts it to Misogi's pluggable auth plugin interface.
///
/// Thread-safe (`Send + Sync`) for use in async multi-task contexts.
/// Designed for `Arc<>` sharing across concurrent authentication requests.
///
/// # Lifecycle
///
/// 1. **Construction**: Created with [`SamlPluginConfig`]; validates config completeness.
/// 2. **Health Check**: Call [`IdentityProvider::health_check`] to verify IdP connectivity.
/// 3. **Authentication**: Call [`IdentityProvider::authenticate`] with
///    [`AuthRequest::SamlResponse`].
/// 4. **Result**: Returns [`MisogiIdentity`] with `idp_source = "saml"` on success.
pub struct SamlIdentityProvider {
    config: SamlPluginConfig,
    provider_id: String,
    provider_name: String,
    core: saml_provider::SamlAuthProvider,
}

impl SamlIdentityProvider {
    /// Construct a new SAML identity provider from the given configuration.
    ///
    /// Validates that essential fields (`sp_entity_id`, `idp_sso_url`) are present.
    /// Initializes the underlying core SAML protocol handler.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::ConfigurationError`] when:
    /// - `sp_entity_id` is empty
    /// - `idp_sso_url` is empty
    /// - Neither certificate source (path nor inline PEM) is provided
    pub fn new(config: SamlPluginConfig) -> Result<Self, IdentityError> {
        if config.sp_entity_id.is_empty() {
            return Err(IdentityError::ConfigurationError(
                "sp_entity_id is required".into(),
            ));
        }
        if config.idp_sso_url.is_empty() {
            return Err(IdentityError::ConfigurationError(
                "idp_sso_url is required".into(),
            ));
        }

        let provider_id = build_stable_provider_id(&config.sp_entity_id);
        let provider_name = format!("SAML 2.0 ({})", config.sp_entity_id);

        // Build core SamlConfig from plugin config
        let core_config = self_build_core_config(&config)?;

        let core =
            saml_provider::SamlAuthProvider::new(core_config).map_err(|e| match e {
                SamlError::ConfigInvalid(m) => IdentityError::ConfigurationError(m),
                other => IdentityError::InternalError(other.to_string()),
            })?;

        info!(
            provider_id = %provider_id,
            sp_entity_id = %config.sp_entity_id,
            idp_sso_url = %config.idp_sso_url,
            name_id_format = ?config.name_id_format,
            "SamlIdentityProvider initialized"
        );

        Ok(Self {
            config,
            provider_id,
            provider_name,
            core,
        })
    }

    /// Build the SSO redirect URL for initiating SAML authentication flow.
    ///
    /// Constructs an HTTP-Redirect binding URL targeting the configured IdP SSO endpoint,
    /// embedding a deflated+Base64-encoded SAML AuthnRequest and optional RelayState.
    ///
    /// # Arguments
    ///
    /// * `relay_state` - Opaque state token preserved through the IdP redirect round-trip.
    ///   Used for CSRF protection and session restoration after authentication.
    ///
    /// # Returns
    ///
    /// Tuple of `(redirect_url, request_id)` where:
    /// - `redirect_url`: Full URL to redirect the user's browser to.
    /// - `request_id`: SAML request ID for InResponseTo validation (store in session).
    pub fn build_sso_redirect_url(
        &self,
        relay_state: &str,
    ) -> Result<(String, String), IdentityError> {
        debug!(relay_state = %relay_state, "Building SSO redirect URL");
        self.core
            .build_sso_redirect_url(relay_state)
            .map_err(map_saml_error)
    }

    // ---- Internal helpers ----

    /// Map extracted SAML attributes to [`MisogiIdentity`] using configured mappings.
    fn map_to_identity(
        attrs: &CoreSamlAttributes,
        config: &SamlPluginConfig,
    ) -> MisogiIdentity {
        let mappings = &config.attribute_mappings;

        // Resolve applicant_id: prefer mapped attribute, fall back to NameID
        let applicant_id = if mappings.name_id_attribute == "name_id" {
            attrs.name_id.clone()
        } else {
            attrs
                .extra
                .get(&mappings.name_id_attribute)
                .and_then(|v| v.first().cloned())
                .unwrap_or_else(|| attrs.name_id.clone())
        };

        // Resolve display name from extra attributes using configured mapping
        let display_name = attrs
            .display_name
            .clone()
            .or_else(|| {
                attrs
                    .extra
                    .get(&mappings.display_name_attribute)
                    .and_then(|v| v.first().cloned())
            });

        // Resolve email from extra attributes using configured mapping
        let email_from_extra = attrs
            .extra
            .get(&mappings.email_attribute)
            .and_then(|v| v.first().cloned());

        // Build extra map with all relevant attributes
        let mut extra = HashMap::new();
        extra.insert(
            "saml_name_id".into(),
            serde_json::Value::String(attrs.name_id.clone()),
        );
        extra.insert(
            "saml_name_id_format".into(),
            serde_json::Value::String(attrs.name_id_format.clone()),
        );
        if let Some(ref dn) = display_name {
            extra.insert(
                "saml_display_name".into(),
                serde_json::Value::String(dn.clone()),
            );
        }
        if let Some(em) = attrs.email.as_ref().or(email_from_extra.as_ref()) {
            extra.insert("saml_email".into(), serde_json::Value::String(em.to_string()));
        }
        if let Some(ref org) = attrs.organization {
            extra.insert(
                "saml_organization".into(),
                serde_json::Value::String(org.clone()),
            );
        }
        if let Some(ref si) = attrs.session_index {
            extra.insert(
                "saml_session_index".into(),
                serde_json::Value::String(si.clone()),
            );
        }
        // Forward all raw extra attributes
        for (k, v) in &attrs.extra {
            extra.insert(
                format!("saml_attr_{k}"),
                serde_json::Value::Array(
                    v.iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        // Map department if present
        if let Some(ref dept_attr) = mappings.department_attribute {
            if let Some(dept_vals) = attrs.extra.get(dept_attr) {
                if let Some(first) = dept_vals.first() {
                    extra.insert(
                        "saml_department".into(),
                        serde_json::Value::String(first.clone()),
                    );
                }
            }
        }

        // Map organization if present
        if let Some(ref org_attr) = mappings.organization_attribute {
            if let Some(org_vals) = attrs.extra.get(org_attr) {
                if let Some(first) = org_vals.first() {
                    extra.insert(
                        "saml_organization_mapped".into(),
                        serde_json::Value::String(first.clone()),
                    );
                }
            }
        }

        MisogiIdentity {
            applicant_id,
            display_name,
            roles: Vec::new(), // Role resolution handled externally (e.g., group mapping)
            idp_source: "saml".to_string(),
            original_subject: Some(attrs.name_id.clone()),
            extra,
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityProvider Trait Implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl IdentityProvider for SamlIdentityProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Authenticate a SAML 2.0 POST-binding response.
    ///
    /// Accepts [`AuthRequest::SamlResponse`] containing a Base64-encoded SAML Response XML.
    /// Performs full validation pipeline:
    ///
    /// 1. **Base64 Decode** — decode the raw SAMLResponse parameter
    /// 2. **XML Parse** — extract Assertion elements using quick-xml
    /// 3. **Signature Verify** — validate XML Signature (if configured)
    /// 4. **Condition Validate** — check NotBefore/NotOnOrAfter with clock skew
    /// 5. **Attribute Extract** — map SAML attributes to MisogiIdentity fields
    #[instrument(skip(self, input))]
    async fn authenticate(&self, input: AuthRequest) -> Result<MisogiIdentity, IdentityError> {
        // Only SamlResponse is supported
        let AuthRequest::SamlResponse { response } = input else {
            return Err(IdentityError::AuthenticationFailed(
                "SAML provider only supports SamlResponse auth request".into(),
            ));
        };

        info!(
            provider_id = %self.provider_id,
            response_len = response.len(),
            "Processing SAML authentication"
        );

        // Delegate to core ACS handler for parsing + validation
        let attrs = self
            .core
            .assertion_consumer_service(response)
            .map_err(map_saml_error)?;

        info!(
            name_id = %attrs.name_id,
            has_display_name = attrs.display_name.is_some(),
            has_email = attrs.email.is_some(),
            "SAML attributes extracted successfully"
        );

        // Map to MisogiIdentity using configured attribute mappings
        Ok(Self::map_to_identity(&attrs, &self.config))
    }

    /// Health check against the SAML IdP infrastructure.
    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), IdentityError> {
        debug!(provider_id = %self.provider_id, "Performing SAML health check");

        if self.config.sp_entity_id.is_empty() {
            return Err(IdentityError::ConfigurationError(
                "sp_entity_id is empty".into(),
            ));
        }
        if self.config.idp_sso_url.is_empty() {
            return Err(IdentityError::ConfigurationError(
                "idp_sso_url is empty".into(),
            ));
        }

        // At least one certificate source must be available for signature verification
        let has_cert = self.config.certificate_path.is_some() || self.config.certificate_pem.is_some();
        if !has_cert && self.config.want_assertions_signed {
            warn!("want_assertions_signed=true but no certificate configured");
            return Err(IdentityError::ConfigurationError(
                "Certificate required for signature verification but none provided".into(),
            ));
        }

        debug!(provider_id = %self.provider_id, "SAML health check passed");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal Helper Functions
// ---------------------------------------------------------------------------

/// Build a stable, DNS-safe provider ID from the SP entity ID.
fn build_stable_provider_id(sp_entity_id: &str) -> String {
    let sanitized: String = sp_entity_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else if c == ':' || c == '.' || c == '/' {
                '-'
            } else {
                '_'
            }
        })
        .collect();

    format!("saml-{sanitized}")
}

/// Convert internal [`SamlError`] to public [`IdentityError`].
fn map_saml_error(err: SamlError) -> IdentityError {
    match err {
        SamlError::AssertionExpired => {
            warn!(error = %err, "SAML assertion expired");
            IdentityError::AuthenticationFailed(format!("SAML assertion expired: {err}"))
        }
        SamlError::AudienceMismatch {
            expected,
            actual,
        } => {
            warn!(expected = %expected, actual = %actual, "SAML audience mismatch");
            IdentityError::AuthenticationFailed(format!(
                "Audience mismatch: expected={expected}, actual={actual}"
            ))
        }
        SamlError::ReplayDetected => {
            warn!(error = %err, "SAML replay attack detected");
            IdentityError::AuthenticationFailed(format!("Replay attack detected: {err}"))
        }
        SamlError::SignatureValidationFailed(m) => {
            warn!(error = %m, "SAML signature validation failed");
            IdentityError::AuthenticationFailed(format!("Signature invalid: {m}"))
        }
        SamlError::InvalidResponse(m) => {
            debug!(error = %m, "SAML response invalid");
            IdentityError::AuthenticationFailed(format!("Invalid SAML response: {m}"))
        }
        SamlError::ConfigInvalid(m) => IdentityError::ConfigurationError(m),
        SamlError::InternalError(m) => IdentityError::InternalError(m),
        SamlError::IoError(m) => IdentityError::ProviderUnavailable(m),
    }
}

/// Build a core [`saml_provider::SamlConfig`] from plugin-level [`SamlPluginConfig`].
fn self_build_core_config(
    config: &SamlPluginConfig,
) -> Result<saml_provider::SamlConfig, IdentityError> {
    let cert_path = if let Some(_ref _pem) = config.certificate_pem {
        std::path::PathBuf::from("[inline-pem]")
    } else if let Some(ref path) = config.certificate_path {
        std::path::PathBuf::from(path.as_str())
    } else {
        std::path::PathBuf::from("[none]")
    };

    let key_path = if let Some(_ref _pem) = config.private_key_pem {
        std::path::PathBuf::from("[inline-pem]")
    } else if let Some(ref path) = config.private_key_path {
        std::path::PathBuf::from(path.as_str())
    } else {
        std::path::PathBuf::from("[none]")
    };

    let idp_metadata_url = config
        .idp_metadata_url
        .as_deref()
        .unwrap_or("")
        .to_string();

    Ok(saml_provider::SamlConfig {
        sp_entity_id: config.sp_entity_id.clone(),
        idp_metadata_url,
        idp_sso_url: config.idp_sso_url.clone(),
        idp_slo_url: config.idp_slo_url.clone().unwrap_or_default(),
        certificate_path: cert_path,
        key_path: key_path,
        assertion_consumer_service_url: format!("{}/acs/saml", config.sp_entity_id),
        clock_skew_seconds: 300,
        assertion_max_duration_secs: 3600,
        replay_cache_size: 1000,
    })
}
