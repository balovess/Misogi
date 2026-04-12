//! Comprehensive unit tests for Misogi configuration system.
//!
//! Tests cover:
//! - File loading and parsing
//! - Error handling (missing file, invalid TOML, validation)
//! - Environment variable overrides
//! - Default configurations
//! - Partial configurations (missing optional sections)
//! - All section accessors and validators

use std::path::PathBuf;
use tempfile::NamedTempFile;

use super::*;
use crate::config::MisogiConfig;
use serial_test::serial;

// ---------------------------------------------------------------------------
// Helper: Create valid full configuration TOML string
// ---------------------------------------------------------------------------

/// Returns a complete, valid configuration with all sections populated.
fn full_config_toml() -> String {
    r#"
[general]
environment = "production"
log_level = "info"

[jwt]
issuer = "https://misogi.example.com"
audience = ["misogi-api"]
key_path = "/etc/misogi/jwt_rsa.pem"
ttl_secs = 28800
refresh_ttl_secs = 604800

[[identity_providers]]
type = "ldap"
id = "ldap-01"
enabled = true
display_name = "Corporate LDAP"

[[identity_providers]]
type = "oidc"
id = "oidc-01"
enabled = false
display_name = "External IdP"

[storage]
backend = "filesystem"
base_path = "/var/lib/misogi/data"
max_file_size_mb = 500

[transport]
mode = "streaming"
buffer_size_kb = 128
chunk_size_mb = 20

[parsers]
default_policy = "sanitize"
wasm_plugins_dir = "/opt/misogi/plugins"
"#
    .to_string()
}

// ===========================================================================
// Test Group 1: File Loading
// ===========================================================================

#[test]
#[serial]
fn test_from_file_success() {
    // Arrange: create temp file with valid config
    let mut temp_file = NamedTempFile::new().expect("failed to create temp file");
    use std::io::Write;
    write!(temp_file, "{}", full_config_toml()).expect("failed to write config");

    // Act: load from file
    let result = MisogiConfig::from_file(temp_file.path());

    // Assert: should succeed
    assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
    let config = result.unwrap();

    // Verify values loaded correctly
    assert_eq!(config.general.environment, "production");
    assert_eq!(config.jwt.as_ref().unwrap().issuer, "https://misogi.example.com");
    assert_eq!(config.storage.as_ref().unwrap().backend, "filesystem");
    assert_eq!(config.transport.as_ref().unwrap().mode, "streaming");
}

#[test]
fn test_from_file_missing_error() {
    let nonexistent = PathBuf::from("/tmp/misogi_config_nonexistent_12345.toml");
    let result = MisogiConfig::from_file(&nonexistent);

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::FileNotFound(path) => {
            assert!(path.to_str().unwrap().contains("nonexistent"));
        }
        other => panic!("Expected FileNotFound error, got: {}", other),
    }
}

// ===========================================================================
// Test Group 2: TOML String Parsing
// ===========================================================================

#[test]
fn test_from_toml_str_valid() {
    let toml_str = r#"
[general]
environment = "staging"
log_level = "debug"
"#;

    let result = MisogiConfig::from_toml_str(toml_str);
    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let config = result.unwrap();
    assert_eq!(config.general.environment, "staging");
    assert_eq!(config.general.log_level, "debug");
}

#[test]
fn test_from_toml_str_invalid_syntax() {
    let invalid_toml = r#"
[general
environment = "production"  # Missing closing bracket
"#;

    let result = MisogiConfig::from_toml_str(invalid_toml);
    assert!(result.is_err());

    match result.unwrap_err() {
        ConfigError::TomlParseError { line, column, message } => {
            // Note: `line` is usize (unsigned), so >= 0 is always true by type guarantee
            assert!(!message.is_empty(), "Error message should not be empty");
            println!("TOML parse error at {}:{}: {}", line, column, message);
        }
        other => panic!("Expected TomlParseError, got: {}", other),
    }
}

#[test]
fn test_from_toml_str_empty_string() {
    let result = MisogiConfig::from_toml_str("");
    assert!(result.is_ok(), "Empty TOML should be valid (all defaults)");

    let config = result.unwrap();
    assert_eq!(config.general.environment, "development"); // default value
}

// ===========================================================================
// Test Group 3: Default Configuration
// ===========================================================================

#[test]
fn test_default_configuration() {
    let config = MisogiConfig::default();

    // General defaults
    assert_eq!(config.general.environment, "development");
    assert_eq!(config.general.log_level, "info");

    // JWT defaults (should be Some with defaults)
    assert!(config.jwt.is_some());
    let jwt = config.jwt.as_ref().unwrap();
    assert_eq!(jwt.issuer, "misogi-default");
    assert_eq!(jwt.audience, vec!["misogi-api"]);
    assert_eq!(jwt.ttl_secs, 28800);
    assert_eq!(jwt.refresh_ttl_secs, 604800);

    // Storage defaults
    assert!(config.storage.is_some());
    let storage = config.storage.as_ref().unwrap();
    assert_eq!(storage.backend, "filesystem");
    assert_eq!(storage.base_path, PathBuf::from("./data"));
    assert_eq!(storage.max_file_size_mb, 100);

    // Transport defaults
    assert!(config.transport.is_some());
    let transport = config.transport.as_ref().unwrap();
    assert_eq!(transport.mode, "streaming");
    assert_eq!(transport.buffer_size_kb, 64);
    assert_eq!(transport.chunk_size_mb, 10);

    // Parsers defaults
    assert!(config.parsers.is_some());
    let parsers = config.parsers.as_ref().unwrap();
    assert_eq!(parsers.default_policy, "sanitize");
    assert_eq!(parsers.wasm_plugins_dir, PathBuf::from("./plugins"));
}

// ===========================================================================
// Test Group 4: Validation Errors
// ===========================================================================

#[test]
fn test_validate_invalid_environment() {
    let toml_str = r#"
[general]
environment = "invalid_env"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, .. } => {
            assert_eq!(section, "general");
            assert_eq!(field, "environment");
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

#[test]
fn test_validate_invalid_log_level() {
    let toml_str = r#"
[general]
environment = "production"
log_level = "verbose"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, .. } => {
            assert_eq!(section, "general");
            assert_eq!(field, "log_level");
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

#[test]
fn test_validate_invalid_storage_backend() {
    let toml_str = r#"
[general]
environment = "production"

[storage]
backend = "ftp"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, reason } => {
            assert_eq!(section, "storage");
            assert_eq!(field, "backend");
            assert!(reason.contains("unknown backend"));
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

#[test]
fn test_validate_invalid_transport_mode() {
    let toml_str = r#"
[general]
environment = "production"

[transport]
mode = "udp_broadcast"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, .. } => {
            assert_eq!(section, "transport");
            assert_eq!(field, "mode");
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

#[test]
fn test_validate_jwt_ttl_zero() {
    let toml_str = r#"
[general]
environment = "production"

[jwt]
issuer = "test"
ttl_secs = 0
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, .. } => {
            assert_eq!(section, "jwt");
            assert_eq!(field, "ttl_secs");
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

#[test]
fn test_validate_storage_max_size_zero() {
    let toml_str = r#"
[general]
environment = "production"

[storage]
backend = "s3"
max_file_size_mb = 0
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, .. } => {
            assert_eq!(section, "storage");
            assert_eq!(field, "max_file_size_mb");
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

#[test]
fn test_validate_transport_buffer_zero() {
    let toml_str = r#"
[general]
environment = "production"

[transport]
mode = "buffered"
buffer_size_kb = 0
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationError { section, field, .. } => {
            assert_eq!(section, "transport");
            assert_eq!(field, "buffer_size_kb");
        }
        other => panic!("Expected ValidationError, got: {}", other),
    }
}

// ===========================================================================
// Test Group 5: Section Accessors
// ===========================================================================

#[test]
fn test_jwt_config_accessor_with_section() {
    let toml_str = r#"
[jwt]
issuer = "custom-issuer"
audience = ["custom-aud"]
ttl_secs = 3600
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let jwt = config.jwt_config();

    assert_eq!(jwt.issuer, "custom-issuer");
    assert_eq!(jwt.audience, vec!["custom-aud"]);
    assert_eq!(jwt.ttl_secs, 3600);
}

#[test]
fn test_jwt_config_accessor_without_section_returns_defaults() {
    let toml_str = r#"
[general]
environment = "production"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let jwt = config.jwt_config(); // jwt is None in parsed config

    // Should return default values
    assert_eq!(jwt.issuer, "misogi-default");
    assert_eq!(jwt.ttl_secs, 28800);
}

#[test]
fn test_storage_config_accessor() {
    let toml_str = r#"
[storage]
backend = "s3"
base_path = "/bucket/prefix"
max_file_size_mb = 1000
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let storage = config.storage_config();

    assert_eq!(storage.backend, "s3");
    assert_eq!(storage.base_path, PathBuf::from("/bucket/prefix"));
    assert_eq!(storage.max_file_size_mb, 1000);
}

#[test]
fn test_transport_config_accessor() {
    let toml_str = r#"
[transport]
mode = "buffered"
buffer_size_kb = 256
chunk_size_mb = 50
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let transport = config.transport_config();

    assert_eq!(transport.mode, "buffered");
    assert_eq!(transport.buffer_size_kb, 256);
    assert_eq!(transport.chunk_size_mb, 50);
}

#[test]
fn test_identity_provider_configs_filters_disabled() {
    let toml_str = r#"
[[identity_providers]]
type = "ldap"
id = "ldap-active"
enabled = true

[[identity_providers]]
type = "oidc"
id = "oidc-disabled"
enabled = false

[[identity_providers]]
type = "saml"
id = "saml-active"
enabled = true
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let providers = config.identity_provider_configs();

    // Should only return enabled providers
    assert_eq!(providers.len(), 2);
    assert!(providers.iter().any(|p| p.id == "ldap-active"));
    assert!(providers.iter().any(|p| p.id == "saml-active"));
    assert!(!providers.iter().any(|p| p.id == "oidc-disabled"));
}

#[test]
fn test_identity_providers_empty_when_none_configured() {
    let toml_str = r#"
[general]
environment = "production"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();
    let providers = config.identity_provider_configs();

    assert!(providers.is_empty());
}

// ===========================================================================
// Test Group 6: Partial Configurations (Missing Optional Sections)
// ===========================================================================

#[test]
fn test_partial_config_only_general() {
    let toml_str = r#"
[general]
environment = "staging"
log_level = "warn"
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();

    // General is populated
    assert_eq!(config.general.environment, "staging");

    // All optional sections are None
    assert!(config.jwt.is_none());
    assert!(config.storage.is_none());
    assert!(config.transport.is_none());
    assert!(config.parsers.is_none());

    // But accessors return defaults
    let jwt = config.jwt_config();
    assert_eq!(jwt.issuer, "misogi-default"); // default

    let storage = config.storage_config();
    assert_eq!(storage.backend, "filesystem"); // default
}

#[test]
fn test_partial_config_general_and_jwt_only() {
    let toml_str = r#"
[general]
environment = "production"

[jwt]
issuer = "prod-jwt"
ttl_secs = 14400
"#;

    let config = MisogiConfig::from_toml_str(toml_str).unwrap();

    assert!(config.jwt.is_some());
    assert!(config.storage.is_none());
    assert!(config.transport.is_none());

    // Validation should pass (missing optional sections are OK)
    let result = config.validate();
    assert!(result.is_ok(), "Validation should succeed with partial config: {:?}", result.err());
}

// ===========================================================================
// Test Group 7: Full Configuration All Sections Present
// ===========================================================================

#[test]
fn test_full_config_all_sections_present() {
    let config = MisogiConfig::from_toml_str(&full_config_toml()).unwrap();

    // All sections should be present
    assert!(config.jwt.is_some());
    assert!(!config.identity_providers.is_empty());
    assert!(config.storage.is_some());
    assert!(config.transport.is_some());
    assert!(config.parsers.is_some());

    // Identity providers count
    assert_eq!(config.identity_providers.len(), 2);

    // Validate should succeed
    let result = config.validate();
    assert!(result.is_ok(), "Full config should validate: {:?}", result.err());

    // Check specific values
    assert_eq!(config.jwt.as_ref().unwrap().refresh_ttl_secs, 604800);
    assert_eq!(config.storage.as_ref().unwrap().max_file_size_mb, 500);
    assert_eq!(config.transport.as_ref().unwrap().buffer_size_kb, 128);
    assert_eq!(config.parsers.as_ref().unwrap().default_policy, "sanitize");
}

// ===========================================================================
// Test Group 8: Environment Variable Overrides
// ===========================================================================

#[test]
#[serial]
fn test_env_override_jwt_issuer() {
    // Set environment variable (unsafe in Rust 2024)
    unsafe { std::env::set_var("MISOGI_JWT_ISSUER", "env-overridden-issuer"); }

    let toml_str = r#"
[jwt]
issuer = "toml-issuer"
ttl_secs = 3600
"#;

    let mut config = MisogiConfig::from_toml_str(toml_str).unwrap();
    config.apply_env_overrides();

    // Env var should override TOML value
    assert_eq!(config.jwt.as_ref().unwrap().issuer, "env-overridden-issuer");

    // Cleanup (unsafe in Rust 2024)
    unsafe { std::env::remove_var("MISOGI_JWT_ISSUER"); }
}

#[test]
#[serial]
fn test_env_override_storage_backend() {
    unsafe { std::env::set_var("MISOGI_STORAGE_BACKEND", "s3"); }

    let toml_str = r#"
[storage]
backend = "filesystem"
"#;

    let mut config = MisogiConfig::from_toml_str(toml_str).unwrap();
    config.apply_env_overrides();

    assert_eq!(config.storage.as_ref().unwrap().backend, "s3");

    unsafe { std::env::remove_var("MISOGI_STORAGE_BACKEND"); }
}

#[test]
#[serial]
fn test_env_override_transport_mode() {
    unsafe { std::env::set_var("MISOGI_TRANSPORT_MODE", "buffered"); }

    let toml_str = r#"
[transport]
mode = "streaming"
"#;

    let mut config = MisogiConfig::from_toml_str(toml_str).unwrap();
    config.apply_env_overrides();

    assert_eq!(config.transport.as_ref().unwrap().mode, "buffered");

    unsafe { std::env::remove_var("MISOGI_TRANSPORT_MODE"); }
}

#[test]
#[serial]
fn test_env_override_general_environment() {
    unsafe { std::env::set_var("MISOGI_ENVIRONMENT", "staging"); }

    let toml_str = r#"
[general]
environment = "production"
"#;

    let mut config = MisogiConfig::from_toml_str(toml_str).unwrap();
    config.apply_env_overrides();

    assert_eq!(config.general.environment, "staging");

    unsafe { std::env::remove_var("MISOGI_ENVIRONMENT"); }
}

#[test]
#[serial]
fn test_env_override_empty_value_does_not_replace() {
    // Ensure clean state first (remove any existing value)
    unsafe { std::env::remove_var("MISOGI_JWT_ISSUER"); }

    // Empty string should NOT override existing value
    unsafe { std::env::set_var("MISOGI_JWT_ISSUER", ""); }

    let toml_str = r#"
[jwt]
issuer = "original-value"
"#;

    let mut config = MisogiConfig::from_toml_str(toml_str).unwrap();
    config.apply_env_overrides();

    // Should keep original TOML value when env var is empty
    assert_eq!(config.jwt.as_ref().unwrap().issuer, "original-value");

    // Cleanup (unsafe in Rust 2024)
    unsafe { std::env::remove_var("MISOGI_JWT_ISSUER"); }
}

#[test]
#[serial]
fn test_env_override_creates_missing_sections() {
    // Ensure clean state first (remove any existing value)
    unsafe { std::env::remove_var("MISOGI_STORAGE_BACKEND"); }

    // If env var is set but section doesn't exist in TOML,
    // the section should be created with defaults + env override
    unsafe { std::env::set_var("MISOGI_STORAGE_BACKEND", "gcs"); }

    let toml_str = r#"
[general]
environment = "production"
"#;

    let mut config = MisogiConfig::from_toml_str(toml_str).unwrap();
    config.apply_env_overrides();

    // Storage section should be created by env override
    assert!(config.storage.is_some());
    assert_eq!(config.storage.as_ref().unwrap().backend, "gcs");

    unsafe { std::env::remove_var("MISOGI_STORAGE_BACKEND"); }
}

// ===========================================================================
// Test Group 9: Edge Cases
// ===========================================================================

#[test]
fn test_config_clone_and_debug() {
    let config = MisogiConfig::default();

    // Clone should work
    let cloned = config.clone();
    assert_eq!(cloned.general.environment, config.general.environment);

    // Debug should work (used for logging)
    let debug_str = format!("{:?}", config);
    assert!(debug_str.contains("MisogiConfig"));
}

#[test]
fn test_serialize_deserialize_roundtrip() {
    let original = MisogiConfig::default();

    // Serialize to TOML string
    let toml_str = toml::to_string(&original)
        .expect("Serialization failed");

    // Deserialize back
    let deserialized: MisogiConfig = toml::from_str(&toml_str)
        .expect("Deserialization failed");

    // Values should match
    assert_eq!(
        original.general.environment,
        deserialized.general.environment
    );
    assert_eq!(
        original.jwt.as_ref().unwrap().ttl_secs,
        deserialized.jwt.as_ref().unwrap().ttl_secs
    );
}
