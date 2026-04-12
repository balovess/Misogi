//! LDAP Plugin Configuration — [`LdapPluginConfig`] and [`LdapAttributeMappings`].
//!
//! Defines all configuration structures for the LDAP identity provider plugin,
//! including connection settings, attribute mappings, and Japanese government
//! compatibility options.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Attribute Mapping Configuration
// ---------------------------------------------------------------------------

/// Configurable mapping between LDAP attribute names and Misogi identity fields.
///
/// Different LDAP deployments use different attribute names for the same
/// semantic data. This struct allows administrators to configure which
/// LDAP attributes map to which Misogi identity fields without code changes.
///
/// # Defaults (Active Directory)
///
/// | Field                    | Default Value       |
/// |--------------------------|--------------------|
/// | `uid_attribute`          | sAMAccountName     |
/// | `display_name_attribute` | displayName        |
/// | `email_attribute`       | mail               |
/// | `group_member_attribute`| member             |
/// | `group_name_attribute`  | cn                 |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAttributeMappings {
    /// LDAP attribute containing the user identifier (login name).
    pub uid_attribute: String,

    /// LDAP attribute containing the human-readable display name.
    pub display_name_attribute: String,

    /// LDAP attribute containing the email address.
    pub email_attribute: String,

    /// LDAP attribute on group entries that lists member DNs.
    pub group_member_attribute: String,

    /// LDAP attribute on group entries that contains the group name.
    pub group_name_attribute: String,
}

impl Default for LdapAttributeMappings {
    fn default() -> Self {
        Self {
            uid_attribute: "sAMAccountName".to_string(),
            display_name_attribute: "displayName".to_string(),
            email_attribute: "mail".to_string(),
            group_member_attribute: "member".to_string(),
            group_name_attribute: "cn".to_string(),
        }
    }
}

impl LdapAttributeMappings {
    /// Create OpenLDAP-standard attribute mappings (POSIX-compliant).
    pub fn openldap() -> Self {
        Self {
            uid_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            email_attribute: "mail".to_string(),
            group_member_attribute: "member".to_string(),
            group_name_attribute: "cn".to_string(),
        }
    }

    /// Create Active Directory default attribute mappings.
    pub fn active_directory() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Plugin Configuration
// ---------------------------------------------------------------------------

/// Complete configuration for [`super::LdapIdentityProvider`].
///
/// All fields are publicly configurable via TOML/YAML/ENV for deployment
/// flexibility. Sensitive fields (`bind_password`) should be sourced from
/// secrets management systems in production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapPluginConfig {
    // ---- Connection Settings ----

    /// List of LDAP server URLs for failover with round-robin selection.
    pub urls: Vec<String>,

    /// Base Distinguished Name of the directory information tree.
    pub base_dn: String,

    // ---- Service Account Credentials ----

    /// DN of the service account used for initial binding and searching.
    pub bind_dn: String,

    /// Password for the service account bind DN.
    #[serde(skip_serializing, default)]
    pub bind_password: String,

    // ---- User Search Configuration ----

    /// Base DN under which user entries are searched.
    pub user_search_base: String,

    /// LDAP search filter template for locating user entries.
    /// The `{username}` placeholder is replaced at runtime.
    pub user_filter: String,

    // ---- Group Search Configuration ----

    /// Base DN under which group entries are searched for membership resolution.
    /// Set to `None` to skip group resolution.
    pub group_search_base: Option<String>,

    /// Optional custom filter for group membership queries (`{user_dn}` placeholder).
    pub group_filter: Option<String>,

    // ---- Attribute Mappings ----

    /// Configurable mapping from LDAP attributes to Misogi identity fields.
    #[serde(default)]
    pub attribute_mappings: LdapAttributeMappings,

    // ---- Performance & Reliability ----

    /// Connection timeout in seconds for each LDAP operation. Default: 10.
    #[serde(default = "default_timeout")]
    pub connection_timeout_secs: u64,

    /// Maximum number of simultaneous connections per target URL. Default: 5.
    #[serde(default = "default_pool")]
    pub pool_size: usize,

    // ---- Japanese Government Compatibility ----

    /// Enable Shift-JIS encoding fallback for legacy JP gov directories.
    #[serde(default)]
    pub shift_jis_fallback: bool,
}

fn default_timeout() -> u64 { 10 }
fn default_pool() -> usize { 5 }

impl Default for LdapPluginConfig {
    fn default() -> Self {
        Self {
            urls: vec!["ldap://localhost:389".to_string()],
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_search_base: "ou=People,dc=example,dc=com".to_string(),
            user_filter: "(uid={username})".to_string(),
            group_search_base: None,
            group_filter: None,
            attribute_mappings: LdapAttributeMappings::default(),
            connection_timeout_secs: default_timeout(),
            pool_size: default_pool(),
            shift_jis_fallback: false,
        }
    }
}
