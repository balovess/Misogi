//! YAML-to-MisogiConfig Compiler.
//!
//! This module transforms validated YAML configuration structures into the internal
//! MisogiConfig representation used by the runtime engine.
//!
//! # Compilation Pipeline
//!
//! ```text
//! YamlConfig (validated)
//!     ↓ 1. Resolve environment variables (${VAR_NAME})
//!     ↓ 2. Expand YAML anchors/aliases (already done by serde_yaml)
//!     ↓ 3. Validate cross-references (provider names in routing)
//!     ↓ 4. Transform to internal types
//!     ↓ 5. Generate compilation report
//! MisogiConfig (compiled)
//! ```

use std::collections::HashMap;

use serde::Serialize;

use crate::error::CompileError;
use crate::schema::YamlConfig;

// =============================================================================
// Compiled Configuration Structure
// =============================================================================

/// Internal configuration representation after YAML compilation.
///
/// This struct holds the fully resolved and transformed configuration
/// ready for application to the running Misogi system. All environment
/// variable references have been resolved and all cross-references validated.
#[derive(Debug, Clone, Serialize)]
pub struct MisogiConfig {
    /// Schema version from source YAML.
    pub version: String,

    /// Deployment environment identifier.
    pub environment: String,

    /// Compiled authentication configuration.
    pub authentication: CompiledAuthConfig,

    /// Compiled sanitization rules.
    pub sanitization: CompiledSanitizationConfig,

    /// Compiled routing rules.
    pub routing: CompiledRoutingConfig,

    /// Compiled retention policies (if defined).
    pub retention: Option<CompiledRetentionConfig>,

    /// Compiled notification channels (if defined).
    pub notifications: Option<CompiledNotificationConfig>,
}

/// Compiled authentication configuration with resolved values.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledAuthConfig {
    /// JWT issuer URL (fully resolved).
    pub jwt_issuer: String,

    /// JWT token lifetime in seconds (converted from hours).
    pub jwt_ttl_seconds: u64,

    /// Resolved identity provider configurations.
    pub identity_providers: Vec<CompiledIdentityProvider>,
}

/// Single compiled identity provider.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledIdentityProvider {
    /// Provider name (unchanged from source).
    pub name: String,

    /// Provider type (unchanged from source).
    pub provider_type: String,

    /// Whether this provider is enabled.
    pub enabled: bool,

    /// Resolved connection URL (env vars expanded).
    pub url: Option<String>,

    /// Resolved base DN for LDAP providers.
    pub base_dn: Option<String>,

    /// Resolved bind CN for LDAP providers.
    pub bind_cn: Option<String>,

    /// Resolved OIDC issuer URL.
    pub issuer: Option<String>,

    /// Resolved client ID (env var expanded).
    pub client_id: Option<String>,

    /// Resolved OAuth2 scopes.
    pub scopes: Vec<String>,

    /// PKCE enforcement flag.
    pub pkce: bool,

    /// Attribute mappings (unchanged from source).
    pub attribute_mappings: HashMap<String, String>,
}

/// Compiled sanitization configuration.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledSanitizationConfig {
    /// Default policy level as string.
    pub default_policy: String,

    /// Compiled sanitization rules in evaluation order.
    pub rules: Vec<CompiledSanitizationRule>,
}

/// Single compiled sanitization rule.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledSanitizationRule {
    /// File match pattern (unchanged).
    pub match_pattern: String,

    /// Policy level as string.
    pub policy: String,

    /// Metadata stripping flag.
    pub strip_metadata: bool,

    /// Annotation flattening flag.
    pub flatten_annotations: bool,

    /// Macro removal flag.
    pub remove_macros: bool,

    /// Script removal flag.
    pub remove_scripts: bool,
}

/// Compiled routing configuration.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledRoutingConfig {
    /// Compiled routing rules in evaluation order.
    pub incoming: Vec<CompiledRoutingRule>,
}

/// Single compiled routing rule.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledRoutingRule {
    /// Source path pattern (unchanged).
    pub source_pattern: String,

    /// Authentication requirement flag.
    pub require_auth: bool,

    /// Allowed provider names (validated against existing providers).
    pub allowed_providers: Vec<String>,

    /// Rate limit as requests per minute (parsed from "N/min" format).
    pub rate_limit_per_min: u64,
}

/// Compiled retention configuration.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledRetentionConfig {
    /// Default retention period in days.
    pub default_days: u32,

    /// Compiled retention rules.
    pub rules: Vec<CompiledRetentionRule>,
}

/// Single compiled retention rule.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledRetentionRule {
    /// Path match pattern.
    pub match_pattern: String,

    /// Retention period in days.
    pub days: u32,

    /// Archival destination (if specified).
    pub archive_to: Option<String>,
}

/// Compiled notification configuration.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledNotificationConfig {
    /// Error notification rules.
    pub on_error: Vec<CompiledNotificationRule>,
}

/// Single compiled notification rule.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledNotificationRule {
    /// Notification channel type as string.
    pub channel: String,

    /// Recipient list (for email channel).
    pub recipients: Vec<String>,

    /// Webhook URL (resolved env vars).
    pub url: Option<String>,

    /// Severity levels that trigger this rule.
    pub severity: Vec<String>,
}

// =============================================================================
// Compilation Report
// =============================================================================

/// Detailed report generated during the compilation process.
///
/// The report captures warnings, informational messages, and transformation
/// details that help IT staff understand what changes were applied during
/// compilation.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CompileReport {
    /// Informational messages about the compilation process.
    #[serde(default)]
    pub info: Vec<String>,

    /// Warning messages about potential issues that didn't prevent compilation.
    #[serde(default)]
    pub warnings: Vec<String>,

    /// Count of environment variables resolved during compilation.
    #[serde(default)]
    pub env_vars_resolved: usize,

    /// Count of cross-references validated.
    #[serde(default)]
    pub cross_references_checked: usize,

    /// Timestamp when compilation completed (ISO 8601).
    #[serde(default)]
    pub compiled_at: Option<String>,
}

impl CompileReport {
    /// Create a new empty compilation report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an informational message to the report.
    pub fn add_info(&mut self, message: impl Into<String>) {
        self.info.push(message.into());
    }

    /// Add a warning message to the report.
    pub fn add_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    /// Check if the report contains any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Get total count of all messages (info + warnings).
    pub fn total_messages(&self) -> usize {
        self.info.len() + self.warnings.len()
    }
}

// =============================================================================
// Compiler Implementation
// =============================================================================

/// Compile a validated YAML configuration into internal MisogiConfig format.
///
/// This is the primary entry point for the compilation pipeline. It performs:
///
/// 1. **Environment Variable Resolution**: Expands `${VAR_NAME}` references
/// 2. **Cross-Reference Validation**: Ensures routing rules reference valid providers
/// 3. **Type Transformation**: Converts YAML types to internal representation
/// 4. **Report Generation**: Produces detailed compilation report
///
/// # Arguments
///
/// * `yaml` - Validated YAML configuration structure.
///
/// # Returns
///
/// A tuple of (`MisogiConfig`, `CompileReport`) on success.
///
/// # Errors
///
/// Returns [`CompileError`] if:
/// - Environment variable cannot be resolved
/// - Cross-reference integrity violation detected
/// - Value transformation fails
pub fn compile(yaml: &YamlConfig) -> Result<(MisogiConfig, CompileReport), CompileError> {
    let mut report = CompileReport::new();

    // Step 1: Compile authentication section
    let authentication = compile_authentication(&yaml.authentication, &mut report)?;

    // Step 2: Compile sanitization section
    let sanitization = compile_sanitization(&yaml.sanitization);

    // Step 3: Compile routing section with cross-reference validation
    let routing = compile_routing(&yaml.routing, &authentication.identity_providers, &mut report)?;

    // Step 4: Compile optional sections
    let retention = yaml.retention.as_ref().map(compile_retention);
    let notifications = match yaml.notifications.as_ref() {
        Some(n) => compile_notifications(n)?,
        None => None,
    };

    // Set compilation timestamp
    report.compiled_at = Some(chrono::Utc::now().to_rfc3339());

    let config = MisogiConfig {
        version: yaml.version.clone(),
        environment: yaml.environment.clone(),
        authentication,
        sanitization,
        routing,
        retention,
        notifications,
    };

    Ok((config, report))
}

// -----------------------------------------------------------------
// Section Compilers
// -----------------------------------------------------------------

/// Compile authentication configuration with environment variable resolution.
fn compile_authentication(
    auth: &crate::schema::AuthenticationConfig,
    report: &mut CompileReport,
) -> Result<CompiledAuthConfig, CompileError> {
    let jwt_ttl_seconds = (auth.jwt.ttl_hours as u64) * 3600;

    let mut identity_providers = Vec::new();

    for (i, provider) in auth.identity_providers.iter().enumerate() {
        let prefix = format!("identity_providers[{}]", i);
        
        // Resolve environment variables in provider fields
        let resolved_url = resolve_env_var(
            provider.url.as_deref(),
            &format!("{}.url", prefix),
        )?;
        
        let resolved_client_id = resolve_env_var(
            provider.client_id.as_deref(),
            &format!("{}.client_id", prefix),
        )?;

        let resolved_client_secret = resolve_env_var(
            provider.client_secret.as_deref(),
            &format!("{}.client_secret", prefix),
        )?;

        let resolved_issuer = resolve_env_var(
            provider.issuer.as_deref(),
            &format!("{}.issuer", prefix),
        )?;

        if resolved_url.is_some() || resolved_client_id.is_some() || 
           resolved_client_secret.is_some() || resolved_issuer.is_some() {
            report.env_vars_resolved += 1;
        }

        let compiled_provider = CompiledIdentityProvider {
            name: provider.name.clone(),
            provider_type: format!("{:?}", provider.r#type).to_lowercase(),
            enabled: provider.enabled,
            url: resolved_url,
            base_dn: provider.base_dn.clone(),
            bind_cn: provider.bind_cn.clone(),
            issuer: resolved_issuer,
            client_id: resolved_client_id,
            scopes: provider.scopes.clone(),
            pkce: provider.pkce,
            attribute_mappings: provider.attribute_mappings.clone(),
        };

        identity_providers.push(compiled_provider);
    }

    report.add_info(format!(
        "Compiled {} identity provider(s)",
        identity_providers.len()
    ));

    Ok(CompiledAuthConfig {
        jwt_issuer: auth.jwt.issuer.clone(),
        jwt_ttl_seconds,
        identity_providers,
    })
}

/// Compile sanitization configuration (no env var resolution needed).
fn compile_sanitization(sanitization: &crate::schema::SanitizationConfig) -> CompiledSanitizationConfig {
    let rules = sanitization
        .rules
        .iter()
        .map(|rule| CompiledSanitizationRule {
            match_pattern: rule.match_pattern.clone(),
            policy: format!("{:?}", rule.policy).to_lowercase(),
            strip_metadata: rule.strip_metadata,
            flatten_annotations: rule.flatten_annotations,
            remove_macros: rule.remove_macros,
            remove_scripts: rule.remove_scripts,
        })
        .collect();

    CompiledSanitizationConfig {
        default_policy: format!("{:?}", sanitization.default_policy).to_lowercase(),
        rules,
    }
}

/// Compile routing configuration with cross-reference validation.
fn compile_routing(
    routing: &crate::schema::RoutingConfig,
    providers: &[CompiledIdentityProvider],
    report: &mut CompileReport,
) -> Result<CompiledRoutingConfig, CompileError> {
    let provider_names: std::collections::HashSet<&str> = providers
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    let mut compiled_rules = Vec::new();

    for (i, rule) in routing.incoming.iter().enumerate() {
        let prefix = format!("incoming[{}]", i);

        // Validate allowed_providers exist
        for provider_name in &rule.allowed_providers {
            if !provider_names.contains(provider_name.as_str()) {
                return Err(CompileError::CrossReference {
                    path: format!("routing.{}", prefix),
                    message: format!(
                        "Identity provider '{}' referenced in routing rule does not exist",
                        provider_name
                    ),
                });
            }
            report.cross_references_checked += 1;
        }

        // Parse rate limit from "N/min" format
        let rate_limit_per_min = parse_rate_limit(&rule.rate_limit, &prefix)?;

        compiled_rules.push(CompiledRoutingRule {
            source_pattern: rule.source_pattern.clone(),
            require_auth: rule.require_auth,
            allowed_providers: rule.allowed_providers.clone(),
            rate_limit_per_min,
        });
    }

    report.add_info(format!(
        "Compiled {} routing rule(s)",
        compiled_rules.len()
    ));

    Ok(CompiledRoutingConfig {
        incoming: compiled_rules,
    })
}

/// Compile retention configuration.
fn compile_retention(retention: &crate::schema::RetentionConfig) -> CompiledRetentionConfig {
    let rules = retention
        .rules
        .iter()
        .map(|rule| CompiledRetentionRule {
            match_pattern: rule.match_pattern.clone(),
            days: rule.days,
            archive_to: rule.archive_to.clone(),
        })
        .collect();

    CompiledRetentionConfig {
        default_days: retention.default_days,
        rules,
    }
}

/// Compile notification configuration with environment variable resolution.
fn compile_notifications(
    notifications: &crate::schema::NotificationConfig,
) -> Result<Option<CompiledNotificationConfig>, CompileError> {
    let mut compiled_rules = Vec::new();

    for (i, rule) in notifications.on_error.iter().enumerate() {
        let prefix = format!("on_error[{}]", i);

        let resolved_url = resolve_env_var(
            rule.url.as_deref(),
            &format!("{}.url", prefix),
        )?;

        let severity_strings = rule
            .severity
            .iter()
            .map(|s| format!("{:?}", s).to_lowercase())
            .collect();

        compiled_rules.push(CompiledNotificationRule {
            channel: format!("{:?}", rule.channel).to_lowercase(),
            recipients: rule.recipients.clone(),
            url: resolved_url,
            severity: severity_strings,
        });
    }

    Ok(Some(CompiledNotificationConfig {
        on_error: compiled_rules,
    }))
}

// -----------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------

/// Resolve environment variable reference in a string value.
///
/// Supports the pattern `${VAR_NAME}` which is replaced with the value
/// of the environment variable `VAR_NAME`. If the variable is not found
/// or the input does not contain a reference pattern, returns the original value.
fn resolve_env_var(
    value: Option<&str>,
    path: &str,
) -> Result<Option<String>, CompileError> {
    let value = match value {
        Some(v) => v,
        None => return Ok(None),
    };

    // Check if this is an environment variable reference
    if let Some(var_name) = extract_env_var_ref(value) {
        std::env::var(&var_name).map(Some).map_err(|_| {
            CompileError::EnvResolution {
                var_name,
                path: path.to_string(),
            }
        })
    } else {
        Ok(Some(value.to_string()))
    }
}

/// Extract environment variable name from `${VAR_NAME}` pattern.
///
/// Returns None if the input does not match the expected pattern.
fn extract_env_var_ref(value: &str) -> Option<String> {
    let trimmed = value.trim();
    
    if trimmed.starts_with("${") && trimmed.ends_with("}") {
        let var_name = &trimmed[2..trimmed.len()-1];
        if !var_name.is_empty() && var_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(var_name.to_string());
        }
    }

    None
}

/// Parse rate limit string "N/min" to numeric value.
///
/// Special case: "0/min" means unlimited (returns u64::MAX).
fn parse_rate_limit(rate_limit: &str, path: &str) -> Result<u64, CompileError> {
    if rate_limit == "0/min" {
        return Ok(u64::MAX); // Unlimited
    }

    let parts: Vec<&str> = rate_limit.split('/').collect();
    
    if parts.len() != 2 || parts[1] != "min" {
        return Err(CompileError::ValueTransform {
            path: path.to_string(),
            message: format!(
                "Invalid rate limit format '{}'. Expected 'N/min' or '0/min'",
                rate_limit
            ),
        });
    }

    parts[0].parse::<u64>().map_err(|_| {
        CompileError::ValueTransform {
            path: path.to_string(),
            message: format!(
                "Invalid rate limit value '{}'. Must be a non-negative integer",
                parts[0]
            ),
        }
    })
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    // =========================================================================
    // Test: Successful Compilation of Minimal Config
    // =========================================================================

    #[test]
    fn test_compile_minimal_config_successfully() {
        let yaml = YamlConfig::from_yaml_str(r#"
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
"#).unwrap();

        let (config, report) = compile(&yaml).unwrap();

        assert_eq!(config.version, "1.0");
        assert_eq!(config.authentication.jwt_issuer, "https://misogi.gov.jp");
        assert_eq!(config.authentication.jwt_ttl_seconds, 8 * 3600);
        assert_eq!(config.routing.incoming[0].rate_limit_per_min, 100);
        assert!(!report.has_warnings());
    }

    // =========================================================================
    // Test: Environment Variable Resolution
    // =========================================================================

    #[test]
    fn test_compile_resolves_environment_variables() {
        // Set test environment variable
        unsafe { std::env::set_var("TEST_OIDC_CLIENT_ID", "my-test-client-id-12345"); }
        unsafe { std::env::set_var("TEST_WEBHOOK_URL", "https://hooks.example.com/misogi"); }

        let yaml = YamlConfig::from_yaml_str(r#"
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
      client_id: "${TEST_OIDC_CLIENT_ID}"
      client_secret: "${TEST_MISSING_SECRET}"
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
notifications:
  on_error:
    - channel: webhook
      url: "${TEST_WEBHOOK_URL}"
"#).unwrap();

        // Should fail because TEST_MISSING_SECRET is not set
        let result = compile(&yaml);
        assert!(result.is_err(), "Should fail on missing env var");

        match result.unwrap_err() {
            CompileError::EnvResolution { var_name, .. } => {
                assert_eq!(var_name, "TEST_MISSING_SECRET");
            }
            other => panic!("Expected EnvResolution error, got: {:?}", other),
        }

        // Cleanup
        unsafe { std::env::remove_var("TEST_OIDC_CLIENT_ID"); }
        unsafe { std::env::remove_var("TEST_WEBHOOK_URL"); }
    }

    #[test]
    fn test_compile_all_env_vars_resolved_successfully() {
        unsafe { std::env::set_var("MISOGI_TEST_CLIENT_ID", "resolved-client-id"); }
        unsafe { std::env::set_var("MISOGI_TEST_SECRET", "resolved-secret-value"); }
        unsafe { std::env::set_var("MISOGI_TEST_HOOK", "https://hooks.example.com/test"); }

        let yaml = YamlConfig::from_yaml_str(r#"
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
      client_id: "${MISOGI_TEST_CLIENT_ID}"
      client_secret: "${MISOGI_TEST_SECRET}"
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
notifications:
  on_error:
    - channel: webhook
      url: "${MISOGI_TEST_HOOK}"
"#).unwrap();

        let (config, report) = compile(&yaml).unwrap();

        // Verify resolved values
        let oidc_provider = &config.authentication.identity_providers[0];
        assert_eq!(oidc_provider.client_id.as_deref().unwrap(), "resolved-client-id");

        // Verify notification URL resolved
        let notif_rule = &config.notifications.unwrap().on_error[0];
        assert_eq!(notif_rule.url.as_deref().unwrap(), "https://hooks.example.com/test");

        // Verify report shows env var resolution
        assert!(report.env_vars_resolved > 0);

        // Cleanup
        unsafe { std::env::remove_var("MISOGI_TEST_CLIENT_ID"); }
        unsafe { std::env::remove_var("MISOGI_TEST_SECRET"); }
        unsafe { std::env::remove_var("MISOGI_TEST_HOOK"); }
    }

    // =========================================================================
    // Test: Cross-Reference Validation
    // =========================================================================

    #[test]
    fn test_compile_detects_invalid_cross_reference() {
        let yaml = YamlConfig::from_yaml_str(r#"
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
"#).unwrap();

        let result = compile(&yaml);
        assert!(result.is_err(), "Should fail on invalid cross-reference");

        match result.unwrap_err() {
            CompileError::CrossReference { path, message } => {
                assert!(path.contains("routing"));
                assert!(message.contains("NonExistentProvider"));
            }
            other => panic!("Expected CrossReference error, got: {:?}", other),
        }
    }

    #[test]
    fn test_compile_valid_cross_reference_passes() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers:
    - name: MyLDAP
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
      allowed_providers: [MyLDAP]
      rate_limit: 100/min
"#).unwrap();

        let (config, _report) = compile(&yaml).unwrap();
        assert_eq!(config.routing.incoming[0].allowed_providers, vec!["MyLDAP"]);
    }

    // =========================================================================
    // Test: Rate Limit Parsing
    // =========================================================================

    #[test]
    fn test_parse_rate_limit_valid_formats() {
        assert_eq!(parse_rate_limit("100/min", "test").unwrap(), 100);
        assert_eq!(parse_rate_limit("1000/min", "test").unwrap(), 1000);
        assert_eq!(parse_rate_limit("0/min", "test").unwrap(), u64::MAX);
    }

    #[test]
    fn test_parse_rate_limit_invalid_format() {
        assert!(parse_rate_limit("invalid", "test").is_err());
        assert!(parse_rate_limit("100/hour", "test").is_err());
        assert!(parse_rate_limit("abc/min", "test").is_err());
    }

    // =========================================================================
    // Test: TTL Conversion
    // =========================================================================

    #[test]
    fn test_jwt_ttl_conversion_to_seconds() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 24
  identity_providers: []
sanitization:
  default_policy: standard
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
"#).unwrap();

        let (config, _) = compile(&yaml).unwrap();
        assert_eq!(config.authentication.jwt_ttl_seconds, 24 * 3600);
    }

    // =========================================================================
    // Test: Compilation Report Generation
    // =========================================================================

    #[test]
    fn test_compilation_report_contains_info() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers:
    - name: Provider1
      type: ldap
      url: ldaps://ldap.test.com
      base_dn: DC=test,DC=com
    - name: Provider2
      type: oidc
      issuer: https://accounts.test.com
      client_id: test-client
sanitization:
  default_policy: strict
  rules:
    - match_pattern: "*.pdf"
      policy: strict
routing:
  incoming:
    - source_pattern: "*"
      require_auth: true
      allowed_providers: [Provider1]
      rate_limit: 100/min
    - source_pattern: "*/public/*"
      require_auth: false
      rate_limit: 50/min
"#).unwrap();

        let (_config, report) = compile(&yaml).unwrap();

        // Should have info about providers and rules
        assert!(report.info.iter().any(|i| i.contains("identity provider")));
        assert!(report.info.iter().any(|i| i.contains("routing rule")));
        assert!(report.compiled_at.is_some());
        assert!(report.cross_references_checked > 0);
    }

    // =========================================================================
    // Test: Optional Sections Handling
    // =========================================================================

    #[test]
    fn test_compile_without_optional_sections() {
        let yaml = YamlConfig::from_yaml_str(r#"
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
"#).unwrap();

        let (config, _report) = compile(&yaml).unwrap();

        assert!(config.retention.is_none());
        assert!(config.notifications.is_none());
    }

    #[test]
    fn test_compile_with_all_sections_populated() {
        let yaml = YamlConfig::from_yaml_str(r#"
version: "1.0"
environment: production
authentication:
  jwt:
    issuer: https://misogi.gov.jp
    ttl_hours: 8
  identity_providers: []
sanitization:
  default_policy: strict
  rules: []
routing:
  incoming:
    - source_pattern: "*"
      require_auth: false
      rate_limit: 100/min
retention:
  default_days: 365
  rules:
    - match_pattern: "classified/*"
      days: 2555
notifications:
  on_error:
    - channel: email
      recipients: [admin@example.com]
"#).unwrap();

        let (config, _report) = compile(&yaml).unwrap();

        assert!(config.retention.is_some());
        assert!(config.notifications.is_some());
        assert_eq!(config.retention.as_ref().unwrap().default_days, 365);
    }
}
