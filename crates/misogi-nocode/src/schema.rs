//! YAML Schema Definition for Misogi No-Code Configuration.
//!
//! This module defines the complete YAML configuration schema as serde-serializable
//! structs with comprehensive validation support for Japanese government IT deployments.
//!
//! # Schema Overview
//!
//! The YAML schema is organized into five major sections:
//!
//! | Section            | Purpose                                      | Required |
//! |--------------------|----------------------------------------------|----------|
//! | `authentication`   | JWT, identity providers (LDAP, OIDC, SAML)    | Yes      |
//! | `sanitization`     | File sanitization policies and rules          | Yes      |
//! | `routing`          | Incoming request routing and rate limiting    | Yes      |
//! | `retention`        | File retention and archival policies          | Optional |
//! | `notifications`    | Error and event notification channels         | Optional |
//!
//! # Example Configuration
//!
//! ```yaml
//! version: "1.0"
//! environment: production
//!
//! authentication:
//!   jwt:
//!     issuer: https://misogi.gov.jp
//!     ttl_hours: 8
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{ValidationError, YamlError};

// =============================================================================
// Root Configuration Structure
// =============================================================================

/// Root YAML configuration structure for the complete Misogi No-Code system.
///
/// This struct represents the top-level deserialization target for YAML
/// configuration files. All sections are validated upon parsing to ensure
/// configuration integrity before compilation.
///
/// # YAML Structure
///
/// ```yaml
/// version: "1.0"           # Schema version (required)
/// environment: production  # Deployment environment (required)
/// authentication: ...      # Authentication settings (required)
/// sanitization: ...        # Sanitization rules (required)
/// routing: ...             # Routing configuration (required)
/// retention: ...           # Retention policies (optional)
/// notifications: ...       # Notification channels (optional)
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct YamlConfig {
    /// Schema version string for format compatibility checking.
    ///
    /// Currently supported versions: "1.0". Future versions may introduce
    /// breaking changes that require migration.
    #[serde(default = "default_version")]
    pub version: String,

    /// Deployment environment identifier.
    ///
    /// Used for environment-specific defaults and validation rules.
    /// Valid values: "development", "staging", "production".
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Authentication and identity provider configuration.
    ///
    /// This section defines JWT settings, LDAP/OIDC/SAML identity providers,
    /// and attribute mapping rules for user authentication.
    pub authentication: AuthenticationConfig,

    /// File sanitization policy and rule definitions.
    ///
    /// Controls how uploaded files are sanitized based on file type,
    /// content classification, and security requirements.
    pub sanitization: SanitizationConfig,

    /// Incoming request routing and access control rules.
    ///
    /// Defines path-based routing, authentication requirements, rate limiting,
    /// and provider restrictions per route.
    pub routing: RoutingConfig,

    /// File retention and archival policies (optional).
    ///
    /// Specifies how long files are retained and where archived data is stored.
    /// Defaults to 365-day retention if not specified.
    #[serde(default)]
    pub retention: Option<RetentionConfig>,

    /// Notification channel configuration (optional).
    ///
    /// Defines email, webhook, and other notification channels for error
    /// alerts and operational events.
    #[serde(default)]
    pub notifications: Option<NotificationConfig>,
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_environment() -> String {
    "production".to_string()
}

// =============================================================================
// Authentication Configuration
// =============================================================================

/// Authentication section root structure.
///
/// Manages JWT token configuration and identity provider registrations
/// for multi-factor authentication in government environments.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthenticationConfig {
    /// JSON Web Token issuer and lifetime configuration.
    pub jwt: JwtConfig,

    /// Identity provider configurations (LDAP, OIDC, SAML).
    ///
    /// At least one identity provider must be configured and enabled
    /// for the system to accept authenticated requests.
    #[serde(default)]
    pub identity_providers: Vec<IdentityProviderConfig>,
}

/// JWT token configuration for session management.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    /// Token issuer URL or identifier string.
    ///
    /// Must be a valid HTTPS URL for production environments.
    /// Example: `https://misogi.gov.jp`
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,

    /// Token time-to-live in hours.
    ///
    /// Range: 1-168 (1 hour to 7 days). Government systems typically use 8 hours.
    #[serde(default = "default_jwt_ttl")]
    pub ttl_hours: u32,
}

fn default_jwt_issuer() -> String {
    "https://misogi.gov.jp".to_string()
}

fn default_jwt_ttl() -> u32 {
    8
}

/// Identity provider type enumeration.
///
/// Supports the three primary authentication protocols used by Japanese
/// government agencies: LDAP/Active Directory, OpenID Connect, and SAML.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityProviderType {
    /// LDAP / Active Directory integration.
    Ldap,

    /// OpenID Connect / OAuth 2.0 provider.
    Oidc,

    /// SAML 2.0 Service Provider.
    Saml,
}

/// Single identity provider configuration entry.
///
/// Each identity provider defines connection parameters, attribute mappings,
/// and protocol-specific settings for user authentication.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdentityProviderConfig {
    /// Human-readable name for this identity provider.
    ///
    /// Used in logs, API responses, and admin UI displays.
    /// Example: `"内閣庁LDAP"` or `"G-Cloud SSO"`
    pub name: String,

    /// Provider type determining protocol and connection method.
    #[serde(rename = "type")]
    pub r#type: IdentityProviderType,

    /// Whether this provider is currently enabled.
    ///
    /// Disabled providers are parsed but not used for authentication.
    #[serde(default = "default_true")]
    pub enabled: bool,

    // ---- LDAP-specific fields ----

    /// LDAP server URL (required when type=ldap).
    ///
    /// Must use `ldaps://` for secure connections in production.
    /// Example: `ldaps://ldap.cao.go.jp`
    #[serde(default)]
    pub url: Option<String>,

    /// LDAP base distinguished name for user searches.
    ///
    /// Example: `DC=gov,DC=jp`
    #[serde(default)]
    pub base_dn: Option<String>,

    /// LDAP bind credentials for service account.
    ///
    /// Format: `cn=username,OU=Unit,DC=domain`
    #[serde(default)]
    pub bind_cn: Option<String>,

    // ---- OIDC-specific fields ----

    /// OIDC issuer URL (required when type=oidc).
    ///
    /// Example: `https://accounts.gcloud.go.jp`
    #[serde(default)]
    pub issuer: Option<String>,

    /// OIDC client identifier registered with the IdP.
    ///
    /// Supports environment variable references: `${OIDC_CLIENT_ID}`
    #[serde(default)]
    pub client_id: Option<String>,

    /// OIDC client secret (should use env var reference).
    ///
    /// Example: `${OIDC_CLIENT_SECRET}`
    #[serde(default)]
    pub client_secret: Option<String>,

    /// OAuth2 scopes to request from the IdP.
    ///
    /// Default: `[openid, profile, email]`
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,

    /// Whether to enforce PKCE (Proof Key for Code Exchange).
    #[serde(default = "default_true")]
    pub pkce: bool,

    // ---- Common fields ----

    /// Attribute mapping from IdP claims to Misogi user attributes.
    ///
    /// Maps external attribute names to internal identifiers:
    /// - `uid`: Unique identifier (sAMAccountName, sub)
    /// - `display_name`: Full name (displayName, name)
    /// - `email`: Email address (mail, email)
    #[serde(default)]
    pub attribute_mappings: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

// =============================================================================
// Sanitization Configuration
// =============================================================================

/// Sanitization policy level enumeration.
///
/// Three-tier policy system matching MIC guidelines for Japanese government
/// document handling with increasing levels of security.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SanitizationPolicyLevel {
    /// Maximum security — destroys all embedded logic, converts to flat representation.
    Strict,

    /// Balanced — removes JS/VBA/macros while preserving editability.
    Standard,

    /// Minimal — basic sanitization only, preserves most content.
    Lenient,
}

impl Default for SanitizationPolicyLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// Sanitization configuration root structure.
///
/// Defines default policy and file-type-specific rules for the CDR
/// (Content Disarm & Reconstruction) pipeline.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SanitizationConfig {
    /// Default sanitization policy applied when no specific rule matches.
    #[serde(default)]
    pub default_policy: SanitizationPolicyLevel,

    /// Ordered list of file-type-specific sanitization rules.
    ///
    /// Rules are evaluated in order; first match wins.
    #[serde(default)]
    pub rules: Vec<SanitizationRule>,
}

/// Single sanitization rule matching file patterns to policies.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SanitizationRule {
    /// Glob pattern for file matching (e.g., "*.pdf", "*.docx;*.xlsx").
    pub match_pattern: String,

    /// Sanitization policy to apply for matched files.
    pub policy: SanitizationPolicyLevel,

    /// Whether to strip metadata from matched files.
    #[serde(default)]
    pub strip_metadata: bool,

    /// Whether to flatten PDF annotations.
    #[serde(default)]
    pub flatten_annotations: bool,

    /// Whether to remove VBA macros from Office documents.
    #[serde(default)]
    pub remove_macros: bool,

    /// Whether to remove embedded scripts from documents.
    #[serde(default)]
    pub remove_scripts: bool,
}

// =============================================================================
// Routing Configuration
// =============================================================================

/// Routing configuration root structure.
///
/// Defines incoming request routing rules with authentication requirements,
/// rate limiting, and provider-based access control.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingConfig {
    /// Ordered list of incoming request routing rules.
    ///
    /// Rules are evaluated in order; first match wins. A catch-all rule
    /// should be defined last to handle unmatched requests.
    pub incoming: Vec<RoutingRule>,
}

/// Single routing rule for incoming request handling.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingRule {
    /// Glob pattern for URL path matching.
    ///
    /// Examples:
    /// - `"*/internal/*"` — Internal API endpoints
    /// - `"*/public/*"` — Publicly accessible endpoints
    /// - `"*"` — Catch-all (must be last)
    pub source_pattern: String,

    /// Whether authentication is required for this route.
    #[serde(default = "default_true")]
    pub require_auth: bool,

    /// Allowed identity providers for this route (empty = all allowed).
    ///
    /// Provider names must match configured identity provider names.
    #[serde(default)]
    pub allowed_providers: Vec<String>,

    /// Rate limit in requests per minute.
    ///
    /// Format: `<count>/min`. Use 0 for unlimited.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: String,
}

fn default_rate_limit() -> String {
    "100/min".to_string()
}

// =============================================================================
// Retention Configuration
// =============================================================================

/// Retention and archival policy configuration.
///
/// Controls how long files are retained based on classification and
/// defines archival destinations for long-term storage.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetentionConfig {
    /// Default retention period in days for unclassified files.
    #[serde(default = "default_retention_days")]
    pub default_days: u32,

    /// Classification-specific retention rules.
    ///
    /// Rules are evaluated in order; first match wins.
    #[serde(default)]
    pub rules: Vec<RetentionRule>,
}

fn default_retention_days() -> u32 {
    365
}

/// Single retention rule for classified file paths.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetentionRule {
    /// Glob pattern matching file paths subject to this rule.
    pub match_pattern: String,

    /// Retention period in days for matched files.
    ///
    /// Government records typically require 7 years (2555 days).
    pub days: u32,

    /// Archival destination for expired files (optional).
    ///
    /// Example: `"cold_storage"`, `"tape_archive"`
    #[serde(default)]
    pub archive_to: Option<String>,
}

// =============================================================================
// Notification Configuration
// =============================================================================

/// Notification channel type enumeration.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationChannel {
    /// Email notification via SMTP.
    Email,

    /// HTTP webhook notification.
    Webhook,

    /// Syslog integration.
    Syslog,

    /// Slack/Teams chat notification.
    Chat,
}

/// Error severity level for notification filtering.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ErrorSeverity {
    /// System-critical error requiring immediate attention.
    Critical,

    /// High-priority error affecting functionality.
    High,

    /// Medium-priority warning worth investigating.
    Medium,

    /// Low-priority informational notice.
    Low,
}

/// Notification configuration root structure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotificationConfig {
    /// Error notification channel configurations.
    #[serde(default)]
    pub on_error: Vec<NotificationRule>,
}

/// Single notification rule defining channel and trigger conditions.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotificationRule {
    /// Notification delivery channel.
    pub channel: NotificationChannel,

    /// Recipient addresses for this notification.
    ///
    /// For email: list of email addresses.
    /// For webhook: not used (url field instead).
    #[serde(default)]
    pub recipients: Vec<String>,

    /// Webhook URL (required when channel=webhook).
    ///
    /// Supports environment variable references: `${WEBHOOK_URL}`
    #[serde(default)]
    pub url: Option<String>,

    /// Severity levels that trigger this notification.
    ///
    /// If empty, all severity levels trigger notifications.
    #[serde(default)]
    pub severity: Vec<ErrorSeverity>,
}

// =============================================================================
// Implementation: Parsing and Validation
// =============================================================================

impl YamlConfig {
    /// Parse a YAML configuration from a string slice.
    ///
    /// This is the primary entry point for loading YAML configurations from
    /// files, environment variables, or API payloads.
    ///
    /// # Arguments
    ///
    /// * `yaml_str` - YAML-formatted configuration string.
    ///
    /// # Returns
    ///
    /// A fully populated [`YamlConfig`] instance on success.
    ///
    /// # Errors
    ///
    /// Returns [`YamlError::Parse`] if the YAML syntax is invalid or the
    /// structure does not match the expected schema.
    ///
    /// # Example
    ///
    /// ```
    /// # use misogi_nocode::schema::YamlConfig;
    /// let yaml = r#"
    /// version: "1.0"
    /// authentication:
    ///   jwt:
    ///     issuer: https://example.com
    ///     ttl_hours: 8
    ///   identity_providers: []
    /// sanitization:
    ///   default_policy: standard
    ///   rules: []
    /// routing:
    ///   incoming: []
    /// "#;
    /// let config = YamlConfig::from_yaml_str(yaml).unwrap();
    /// assert_eq!(config.version, "1.0");
    /// ```
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, YamlError> {
        serde_yaml::from_str(yaml_str).map_err(|e| {
            // Extract line/column information from serde_yaml error if available
            let (line, column) = Self::extract_location(&e);
            YamlError::Parse {
                message: e.to_string(),
                line,
                column,
            }
        })
    }

    /// Load YAML configuration from a filesystem path.
    ///
    /// Reads the specified file and parses it as a YAML configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the YAML configuration file.
    ///
    /// # Errors
    ///
    /// - [`YamlError::Io`] if the file cannot be read.
    /// - [`YamlError::Parse`] if the YAML content is invalid.
    pub fn from_file(path: &std::path::Path) -> Result<Self, YamlError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    /// Validate this configuration and collect all errors.
    ///
    /// Unlike typical validation that fails on the first error, this method
    /// collects ALL validation errors into a single vector so IT staff can
    /// fix multiple issues in one pass.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec::<ValidationError>::empty())` if no errors found.
    /// - `Err(YamlError::Validation)` if one or more errors detected.
    ///
    /// # Validation Checks Performed
    ///
    /// 1. **Required fields**: All mandatory fields present and non-empty.
    /// 2. **Value ranges**: Numeric fields within acceptable bounds.
    /// 3. **Regex patterns**: URL formats, identifier formats.
    /// 4. **Cross-references**: Provider names referenced in routing exist.
    /// 5. **Semantic integrity**: Logical consistency between sections.
    pub fn validate(&self) -> Result<Vec<ValidationError>, ValidationError> {
        let mut errors = Vec::new();

        // Validate version
        self.validate_version(&mut errors);

        // Validate environment
        self.validate_environment(&mut errors);

        // Validate authentication section
        self.validate_authentication(&mut errors);

        // Validate sanitization section
        self.validate_sanitization(&mut errors);

        // Validate routing section
        self.validate_routing(&mut errors);

        // Validate retention section (if present)
        if let Some(ref retention) = self.retention {
            self.validate_retention(retention, &mut errors);
        }

        // Validate cross-references between sections
        self.validate_cross_references(&mut errors);

        // Filter to only error-severity items for the Err case
        let error_count = errors.iter().filter(|e| e.is_error()).count();

        if error_count > 0 {
            Err(ValidationError {
                field: "root".to_string(),
                message: format!("{} validation error(s) detected", error_count),
                severity: crate::error::ValidationSeverity::Error,
                suggestion: Some("Review all validation errors and fix them before compiling".to_string()),
            })
        } else {
            Ok(errors)
        }
    }

    // -----------------------------------------------------------------
    // Private Validation Methods
    // -----------------------------------------------------------------

    fn validate_version(&self, errors: &mut Vec<ValidationError>) {
        if self.version.is_empty() {
            errors.push(ValidationError::new(
                "version",
                "version must not be empty",
            ).with_suggestion("Set version to \"1.0\""));
        } else if !["1.0"].contains(&self.version.as_str()) {
            errors.push(ValidationError::warning(
                "version",
                format!("version '{}' is not officially supported", self.version),
            ).with_suggestion("Use version \"1.0\" for compatibility"));
        }
    }

    fn validate_environment(&self, errors: &mut Vec<ValidationError>) {
        let valid_environments = ["development", "staging", "production"];
        if !valid_environments.contains(&self.environment.as_str()) {
            errors.push(ValidationError::new(
                "environment",
                format!("invalid environment '{}', must be one of: {}", 
                    self.environment, valid_environments.join(", "))
            ).with_suggestion("Use 'production' for government deployments"));
        }
    }

    fn validate_authentication(&self, errors: &mut Vec<ValidationError>) {
        // Validate JWT config
        if self.authentication.jwt.issuer.is_empty() {
            errors.push(ValidationError::new(
                "authentication.jwt.issuer",
                "JWT issuer must not be empty",
            ).with_suggestion("Set issuer to your domain, e.g., 'https://misogi.gov.jp'"));
        } else if !self.authentication.jwt.issuer.starts_with("https://") && 
                  self.environment == "production" {
            errors.push(ValidationError::new(
                "authentication.jwt.issuer",
                "JWT issuer must use HTTPS in production",
            ).with_suggestion("Change 'http://' to 'https://'"));
        }

        // Validate TTL range
        if self.authentication.jwt.ttl_hours < 1 || self.authentication.jwt.ttl_hours > 168 {
            errors.push(ValidationError::new(
                "authentication.jwt.ttl_hours",
                format!("TTL must be between 1-168 hours, got {}", 
                    self.authentication.jwt.ttl_hours),
            ).with_suggestion("Use 8 hours for standard government sessions"));
        }

        // Validate at least one enabled provider exists
        let has_enabled_provider = self.authentication.identity_providers
            .iter()
            .any(|p| p.enabled);
        
        if !has_enabled_provider && !self.authentication.identity_providers.is_empty() {
            errors.push(ValidationError::new(
                "authentication.identity_providers",
                "At least one identity provider must be enabled",
            ));
        }

        // Validate each identity provider
        for (i, provider) in self.authentication.identity_providers.iter().enumerate() {
            let prefix = format!("authentication.identity_providers[{}]", i);

            if provider.name.is_empty() {
                errors.push(ValidationError::new(
                    format!("{}.name", prefix),
                    "Identity provider name must not be empty",
                ));
            }

            match provider.r#type {
                IdentityProviderType::Ldap => {
                    if provider.url.as_ref().map_or(true, |u| u.is_empty()) {
                        errors.push(ValidationError::new(
                            format!("{}.url", prefix),
                            "LDAP provider requires a URL",
                        ).with_suggestion("Set URL to 'ldaps://ldap.example.com'"));
                    }
                    if provider.base_dn.as_ref().map_or(true, |dn| dn.is_empty()) {
                        errors.push(ValidationError::new(
                            format!("{}.base_dn", prefix),
                            "LDAP provider requires base_dn",
                        ).with_suggestion("Set base_dn to 'DC=gov,DC=jp'"));
                    }
                }
                IdentityProviderType::Oidc => {
                    if provider.issuer.as_ref().map_or(true, |u| u.is_empty()) {
                        errors.push(ValidationError::new(
                            format!("{}.issuer", prefix),
                            "OIDC provider requires an issuer URL",
                        ));
                    }
                    if provider.client_id.as_ref().map_or(true, |id| id.is_empty()) {
                        errors.push(ValidationError::new(
                            format!("{}.client_id", prefix),
                            "OIDC provider requires client_id",
                        ).with_suggestion("Set client_id or use ${OIDC_CLIENT_ID}"));
                    }
                }
                IdentityProviderType::Saml => {
                    // SAML validation would require entity_id and sso_url
                    // These can be added as optional fields later
                }
            }
        }
    }

    fn validate_sanitization(&self, errors: &mut Vec<ValidationError>) {
        // Validate each sanitization rule
        for (i, rule) in self.sanitization.rules.iter().enumerate() {
            let prefix = format!("sanitization.rules[{}]", i);

            if rule.match_pattern.is_empty() {
                errors.push(ValidationError::new(
                    format!("{}.match_pattern", prefix),
                    "Sanitization rule must have a match pattern",
                ).with_suggestion("Use '*.pdf' for PDF files or '*' for catch-all"));
            }

            // Warn about lenient policy in production
            if rule.policy == SanitizationPolicyLevel::Lenient && self.environment == "production" {
                errors.push(ValidationError::warning(
                    format!("{}.policy", prefix),
                    "Lenient sanitization policy is not recommended for production",
                ).with_suggestion("Consider using 'strict' or 'standard' policy"));
            }
        }
    }

    fn validate_routing(&self, errors: &mut Vec<ValidationError>) {
        if self.routing.incoming.is_empty() {
            errors.push(ValidationError::new(
                "routing.incoming",
                "At least one routing rule must be defined",
            ).with_suggestion("Add a catch-all rule with source_pattern: '*'"));
        }

        // Validate each routing rule
        for (i, rule) in self.routing.incoming.iter().enumerate() {
            let prefix = format!("routing.incoming[{}]", i);

            if rule.source_pattern.is_empty() {
                errors.push(ValidationError::new(
                    format!("{}.source_pattern", prefix),
                    "Routing rule must have a source pattern",
                ));
            }

            // Validate rate limit format
            if !Self::is_valid_rate_limit(&rule.rate_limit) {
                errors.push(ValidationError::new(
                    format!("{}.rate_limit", prefix),
                    format!("Invalid rate limit format: '{}'. Expected '<number>/min'", rule.rate_limit),
                ).with_suggestion("Use '100/min', '1000/min', or '0/min' for unlimited"));
            }

            // Validate that allowed_providers reference existing providers
            for provider_name in &rule.allowed_providers {
                let provider_exists = self.authentication.identity_providers
                    .iter()
                    .any(|p| p.name == *provider_name);
                
                if !provider_exists {
                    errors.push(ValidationError::new(
                        format!("{}.allowed_providers", prefix),
                        format!("Referenced provider '{}' does not exist", provider_name),
                    ).with_suggestion("Check identity_providers section for correct provider names"));
                }
            }
        }
    }

    fn validate_retention(&self, retention: &RetentionConfig, errors: &mut Vec<ValidationError>) {
        // Validate default retention range
        if retention.default_days < 1 || retention.default_days > 36500 { // 100 years max
            errors.push(ValidationError::new(
                "retention.default_days",
                format!("Default retention must be 1-36500 days, got {}", retention.default_days),
            ));
        }

        // Validate each retention rule
        for (i, rule) in retention.rules.iter().enumerate() {
            let prefix = format!("retention.rules[{}]", i);

            if rule.match_pattern.is_empty() {
                errors.push(ValidationError::new(
                    format!("{}.match_pattern", prefix),
                    "Retention rule must have a match pattern",
                ));
            }

            if rule.days < 1 || rule.days > 36500 {
                errors.push(ValidationError::new(
                    format!("{}.days", prefix),
                    format!("Retention days must be 1-36500, got {}", rule.days),
                ));
            }
        }
    }

    fn validate_cross_references(&self, errors: &mut Vec<ValidationError>) {
        // Collect all provider names for reference validation
        let provider_names: Vec<&String> = self.authentication.identity_providers
            .iter()
            .map(|p| &p.name)
            .collect();

        // Check for duplicate provider names
        let mut seen = std::collections::HashSet::new();
        for (i, name) in provider_names.iter().enumerate() {
            if !seen.insert(*name) {
                errors.push(ValidationError::new(
                    format!("authentication.identity_providers[{}].name", i),
                    format!("Duplicate identity provider name: '{}'", name),
                ).with_suggestion("Each provider must have a unique name"));
            }
        }
    }

    /// Check if a rate limit string has valid format.
    fn is_valid_rate_limit(rate_limit: &str) -> bool {
        if rate_limit == "0/min" {
            return true; // Unlimited
        }

        let parts: Vec<&str> = rate_limit.split('/').collect();
        if parts.len() != 2 || parts[1] != "min" {
            return false;
        }

        parts[0].parse::<u64>().is_ok()
    }

    /// Extract line and column information from a serde_yaml error.
    fn extract_location(error: &serde_yaml::Error) -> (Option<usize>, Option<usize>) {
        // serde_yaml errors contain location info in their message
        let msg = error.to_string();
        
        // Try to extract line number from message like "at line X, column Y"
        let re = regex::Regex::new(r"at line (\d+),? column (\d+)").unwrap();
        if let Some(caps) = re.captures(&msg) {
            let line = caps.get(1).and_then(|m| m.as_str().parse().ok());
            let column = caps.get(2).and_then(|m| m.as_str().parse().ok());
            return (line, column);
        }

        (None, None)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: Minimal Valid Configuration Parsing
    // =========================================================================

    #[test]
    fn test_minimal_config_parses_successfully() {
        let yaml = r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#;

        let config = YamlConfig::from_yaml_str(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.environment, "production");
        assert_eq!(config.authentication.jwt.ttl_hours, 8);
        assert_eq!(config.sanitization.default_policy, SanitizationPolicyLevel::Standard);
        assert_eq!(config.routing.incoming.len(), 1);
    }

    // =========================================================================
    // Test: Full Configuration with All Sections
    // =========================================================================

    #[test]
    fn test_full_configuration_parsing() {
        let yaml = r#"
version: "1.0"
environment: production

authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  
  identity_providers:
    - name: "内閣庁LDAP"
      type: ldap
      url: ldaps://ldap.cao.go.jp
      base_dn: DC=gov,DC=jp
      bind_cn: cn=misogi_svc,OU=ServiceAccounts
      attribute_mappings:
        uid: sAMAccountName
        display_name: displayName
        email: mail
      enabled: true
    
    - name: "G-Cloud SSO"
      type: oidc
      issuer: https://accounts.gcloud.go.jp
      client_id: "${OIDC_CLIENT_ID}"
      client_secret: "${OIDC_CLIENT_SECRET}"
      scopes: [openid, profile, email]
      pkce: true

sanitization:
  default_policy: strict
  rules:
    - match_pattern: "*.pdf"
      policy: strict
      strip_metadata: true
      flatten_annotations: true
    - match_pattern: "*.docx;*.xlsx;*.pptx"
      policy: standard
      remove_macros: true
      remove_scripts: true
    - match_pattern: "*"
      policy: lenient

routing:
  incoming:
    - source_pattern: "*/internal/*"
      require_auth: true
      allowed_providers: ["内閣庁LDAP"]
      rate_limit: 1000/min
    - source_pattern: "*/public/*"
      require_auth: false
      rate_limit: 100/min

retention:
  default_days: 365
  rules:
    - match_pattern: "classified/*"
      days: 2555
      archive_to: cold_storage

notifications:
  on_error:
    - channel: email
      recipients: [secops@gov.jp]
      severity: [critical, high]
    - channel: webhook
      url: "${WEBHOOK_URL}"
"#;

        let config = YamlConfig::from_yaml_str(yaml).unwrap();
        assert_eq!(config.authentication.identity_providers.len(), 2);
        assert_eq!(config.sanitization.rules.len(), 3);
        assert_eq!(config.routing.incoming.len(), 2);
        assert!(config.retention.is_some());
        assert!(config.notifications.is_some());
    }

    // =========================================================================
    // Test: Validation Errors Collection
    // =========================================================================

    #[test]
    fn test_validate_collects_multiple_errors() {
        let yaml = r#"
version: ""
environment: invalid_env
authentication:
  jwt:
    issuer: ""
    ttl_hours: 9999
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming: []
"#;

        let config = YamlConfig::from_yaml_str(yaml).unwrap();
        let result = config.validate();

        assert!(result.is_err(), "Should fail validation with multiple errors");

        // Should include errors for version, environment, jwt.issuer, jwt.ttl_hours, routing
        let err = result.unwrap_err();
        assert!(err.message.contains("validation error"), "Error should mention count");
    }

    // =========================================================================
    // Test: Valid Configuration Passes Validation
    // =========================================================================

    #[test]
    fn test_valid_config_passes_validation() {
        let yaml = r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers:
    - name: TestLDAP
      type: ldap
      url: ldaps://ldap.test.com
      base_dn: DC=test,DC=com
      enabled: true
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#;

        let config = YamlConfig::from_yaml_str(yaml).unwrap();
        let warnings = config.validate().expect("Valid config should pass validation");
        
        // May have warnings but no errors
        assert!(!warnings.iter().any(|w| w.is_error()), "Should have no error-level validations");
    }

    // =========================================================================
    // Test: Invalid YAML Syntax Error
    // =========================================================================

    #[test]
    fn test_invalid_yaml_syntax_returns_parse_error() {
        let invalid_yaml = r#"
version: "1.0"
  indented_badly: true
"#;

        let result = YamlConfig::from_yaml_str(invalid_yaml);
        assert!(result.is_err(), "Invalid YAML should return parse error");

        match result.unwrap_err() {
            YamlError::Parse { .. } => {} // Expected
            other => panic!("Expected Parse error, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test: Cross-Reference Validation
    // =========================================================================

    #[test]
    fn test_cross_reference_validation_detects_missing_provider() {
        let yaml = r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers:
    - name: RealProvider
      type: ldap
      url: ldaps://ldap.test.com
      base_dn: DC=test,DC=com
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: true
      allowed_providers: [NonExistentProvider]
      rate_limit: 100/min
"#;

        let config = YamlConfig::from_yaml_str(yaml).unwrap();
        let result = config.validate();

        assert!(result.is_err(), "Should detect missing provider reference");
    }

    // =========================================================================
    // Test: Enum Deserialization
    // =========================================================================

    #[test]
    fn test_identity_provider_type_deserialization() {
        let yaml = r#"ldap"#;
        let config: IdentityProviderType = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config, IdentityProviderType::Ldap);

        let yaml = r#"oidc"#;
        let config: IdentityProviderType = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config, IdentityProviderType::Oidc);
    }

    #[test]
    fn test_sanitization_policy_deserialization() {
        let yaml = r#"strict"#;
        let config: SanitizationPolicyLevel = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config, SanitizationPolicyLevel::Strict);
    }

    // =========================================================================
    // Test: Rate Limit Format Validation
    // =========================================================================

    #[test]
    fn test_rate_limit_format_validation() {
        assert!(YamlConfig::is_valid_rate_limit("100/min"));
        assert!(YamlConfig::is_valid_rate_limit("1000/min"));
        assert!(YamlConfig::is_valid_rate_limit("0/min")); // Unlimited
        assert!(!YamlConfig::is_valid_rate_limit("invalid"));
        assert!(!YamlConfig::is_valid_rate_limit("100/hour")); // Wrong unit
        assert!(!YamlConfig::is_valid_rate_limit("abc/min")); // Non-numeric
    }

    // =========================================================================
    // Test: Environment Variable Reference Preservation
    // =========================================================================

    #[test]
    fn test_env_var_references_preserved_in_parsed_config() {
        let yaml = r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers:
    - name: TestOIDC
      type: oidc
      issuer: https://accounts.test.com
      client_id: "${MY_CLIENT_ID}"
      client_secret: "${MY_SECRET}"
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#;

        let config = YamlConfig::from_yaml_str(yaml).unwrap();
        let oidc_provider = &config.authentication.identity_providers[0];
        assert_eq!(oidc_provider.client_id.as_deref().unwrap(), "${MY_CLIENT_ID}");
        assert_eq!(oidc_provider.client_secret.as_deref().unwrap(), "${MY_SECRET}");
    }
}
