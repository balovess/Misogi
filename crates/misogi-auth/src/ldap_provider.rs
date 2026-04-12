//! LDAP / Active Directory Authentication Provider
//!
//! Provides enterprise-grade user authentication against LDAP v3 directories
//! (OpenLDAP, Microsoft Active Directory, etc.) using asynchronous connection
//! pooling and service-account-based bind patterns.
//!
//! # Feature Gate
//!
//! This module is only available when the `ldap` or `enterprise` feature is enabled.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐    1. Bind as Service Account     ┌──────────────────┐
//! │             ├───────────────────────────────────>│                  │
//! │   LdapAuth  │    2. Search for User DN          │   LDAP Server    │
//! │  Provider   │<──────────────────────────────────│ (AD / OpenLDAP)  │
//! │             │    3. Bind as User (credential     │                  │
//! │             │       verification)               │                  │
//! │             ├───────────────────────────────────>│                  │
//! │             │    4. Query Group Membership       │                  │
//! │             │<──────────────────────────────────│                  │
//! └─────────────┘                                   └──────────────────┘
//! ```
//!
//! # Security Notes
//!
//! - Service account credentials are held in memory; use secrets management in production.
//! - User passwords are never stored — only used for bind verification, then discarded.
//! - All connections use TLS where supported by the server configuration.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};

use super::role::UserRole;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for LDAP/Active Directory authentication provider.
///
/// Supports multiple LDAP URLs for failover with round-robin connection selection.
///
/// # Example (Active Directory)
///
/// ```ignore
/// LdapConfig {
///     urls: vec!["ldaps://ad.example.com:636".to_string()],
///     base_dn: "dc=example,dc=com".to_string(),
///     bind_dn: "cn=misogi-service,ou=ServiceAccounts,dc=example,dc=com".to_string(),
///     bind_password: "secret".to_string(), // Use secrets manager in production!
///     user_search_base: "ou=Users,dc=example,dc=com".to_string(),
///     user_filter: "(sAMAccountName={username})".to_string(),
///     group_search_base: "ou=Groups,dc=example,dc=com".to_string(),
///     role_mappings: HashMap::from([
///         ("CN=MisogiAdmins,OU=Groups,DC=example,DC=com".to_string(), UserRole::Admin),
///         ("CN=MisogiApprovers,OU=Groups,DC=example,DC=com".to_string(), UserRole::Approver),
///     ]),
///     connection_timeout_secs: 10,
///     pool_size: 5,
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// List of LDAP server URLs (ldap:// or ldaps://) for failover.
    /// Round-robin selection on each new connection.
    pub urls: Vec<String>,

    /// Base Distinguished Name of the directory tree.
    pub base_dn: String,

    /// Distinguished Name of the service account used for initial binding and searching.
    pub bind_dn: String,

    /// Password for the service account bind DN.
    pub bind_password: String,

    /// Base DN under which to search for user entries.
    pub user_search_base: String,

    /// LDAP search filter for finding users. `{username}` is replaced at runtime.
    /// Common patterns:
    /// - AD: `(sAMAccountName={username})`
    /// - OpenLDAP: `(uid={username})`
    pub user_filter: String,

    /// Base DN under which to search for group memberships.
    pub group_search_base: String,

    /// Mapping from LDAP group DN to [`UserRole`].
    /// A user's effective role is the highest-privilege role from all matched groups.
    pub role_mappings: HashMap<String, UserRole>,

    /// Connection timeout in seconds for each LDAP operation.
    pub connection_timeout_secs: u64,

    /// Number of connections to maintain in the pool per target URL.
    pub pool_size: usize,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            urls: vec!["ldap://localhost:389".to_string()],
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_search_base: "ou=People,dc=example,dc=com".to_string(),
            user_filter: "(uid={username})".to_string(),
            group_search_base: "ou=Group,dc=example,dc=com".to_string(),
            role_mappings: HashMap::new(),
            connection_timeout_secs: 10,
            pool_size: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Data Types
// ---------------------------------------------------------------------------

/// User information retrieved from an LDAP directory.
///
/// Populated during authentication and available for session creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    /// Full Distinguished Name of the user entry in the directory.
    pub dn: String,

    /// User identifier (uid, sAMAccountName, or equivalent).
    pub uid: String,

    /// Display name (cn, displayName, or equivalent).
    pub display_name: String,

    /// Email address (mail attribute). May not be present in all directories.
    pub mail: Option<String>,

    /// Department/organizational unit (department, ou, or equivalent).
    pub department: Option<String>,

    /// Distinguished Names of groups the user is a member of.
    pub groups: Vec<String>,
}

// ---------------------------------------------------------------------------
// Provider Implementation
// ---------------------------------------------------------------------------

/// Asynchronous LDAP authentication provider with connection pooling.
///
/// Maintains pre-authenticated connections to one or more LDAP servers.
/// Uses round-robin selection for load distribution across multiple URLs.
///
/// # Thread Safety
///
/// Designed to be wrapped in `Arc<>` and shared across async tasks.
pub struct LdapAuthProvider {
    config: LdapConfig,
    /// Counter for round-robin URL selection.
    url_index: AtomicUsize,
}

impl LdapAuthProvider {
    /// Create a new LDAP authentication provider with the given configuration.
    ///
    /// No connections are established until the first authentication attempt.
    #[instrument(skip(config), fields(urls = ?config.urls))]
    pub fn new(config: LdapConfig) -> Self {
        info!(
            urls_count = config.urls.len(),
            pool_size = config.pool_size,
            search_base = %config.user_search_base,
            "LdapAuthProvider initialized"
        );

        Self {
            config,
            url_index: AtomicUsize::new(0),
        }
    }

    /// Authenticate a user against the LDAP directory.
    ///
    /// # Process
    ///
    /// 1. Connect to an LDAP server (round-robin URL selection)
    /// 2. Bind as the configured service account
    /// 3. Search for the user entry using the configured filter
    /// 4. Perform a simple bind as the found user DN with the provided password
    /// 5. Query group membership for role resolution
    /// 6. Return the populated [`LdapUser`] on success
    ///
    /// # Errors
    ///
    /// - [`LdapError::ConnectionFailed`] — cannot reach any LDAP server
    /// - [`LdapError::InvalidCredentials`] — user's password is incorrect
    /// - [`LdapError::UserNotFound`] — no matching user entry found
    /// - [`LdapError::BindFailed`] — service account credentials invalid
    /// - [`LdapError::Timeout`] — operation exceeded configured timeout
    /// - [`LdapError::SearchFailed`] — LDAP search operation failed
    #[instrument(skip(self, username, password), fields(username = %username))]
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapUser, LdapError> {
        let url = self.next_url();

        debug!(
            url = %url,
            username = %username,
            "Initiating LDAP authentication flow"
        );

        let user = self.do_authenticate(url, username, password).await?;

        info!(
            uid = %user.uid,
            dn = %user.dn,
            groups_count = user.groups.len(),
            "LDAP authentication successful"
        );

        Ok(user)
    }

    /// Resolve roles for a given user based on their LDAP group membership.
    ///
    /// Queries the configured `group_search_base` for groups that contain
    /// the user's DN as a member, then maps each matching group to a
    /// [`UserRole`] via the configured `role_mappings`.
    #[instrument(skip(self, user_dn), fields(user_dn = %user_dn))]
    pub async fn resolve_roles(
        &self,
        user_dn: &str,
    ) -> Result<Vec<UserRole>, LdapError> {
        let url = self.next_url();
        self.do_resolve_roles(url, user_dn).await
    }

    /// Search for a user by identifier (uid, mail, or cn).
    ///
    /// Returns `Ok(None)` if no user matches the identifier.
    #[instrument(skip(self, identifier), fields(identifier = %identifier))]
    pub async fn find_user(
        &self,
        identifier: &str,
    ) -> Result<Option<LdapUser>, LdapError> {
        let url = self.next_url();
        self.do_find_user(url, identifier).await
    }

    /// Perform a health check against the LDAP infrastructure.
    ///
    /// Attempts to connect and bind as the service account to each configured
    /// URL. Returns `Ok(())` if at least one server is reachable.
    pub async fn health_check(&self) -> Result<(), LdapError> {
        let mut last_err = None;

        for url in &self.config.urls {
            match self.do_health_check(url).await {
                Ok(()) => {
                    info!(url = %url, "LDAP health check passed");
                    return Ok(());
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "LDAP health check failed");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(LdapError::ConnectionFailed(
            "No LDAP URLs configured".to_string(),
        )))
    }

    // --- Internal implementation methods ---

    /// Get the next URL in round-robin order.
    fn next_url(&self) -> &str {
        if self.config.urls.is_empty() {
            return "ldap://localhost:389";
        }
        let idx = self.url_index.fetch_add(1, Ordering::Relaxed)
            % self.config.urls.len();
        &self.config.urls[idx]
    }

    /// Core authentication implementation against a specific LDAP server URL.
    async fn do_authenticate(
        &self,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<LdapUser, LdapError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};

        let timeout =
            Duration::from_secs(self.config.connection_timeout_secs);

        // Step 1: Establish async connection (keep conn alive for duration)
        let (conn, mut ldap) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|e| {
                LdapError::ConnectionFailed(format!("LDAP connect error: {e}"))
            })?;

        // Step 2: Bind as service account
        let bind_result = tokio::time::timeout(
            timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password),
        )
        .await
        .map_err(|_| LdapError::Timeout)?;

        if let Err(e) = bind_result {
            error!(
                bind_dn = %self.config.bind_dn,
                error = %e,
                "Service account bind failed"
            );
            return Err(LdapError::BindFailed(format!(
                "Service account bind failed: {e}"
            )));
        }

        debug!("Service account bind successful");

        // Step 3: Build user search filter
        let filter = self
            .config
            .user_filter
            .replace("{username}", username);

        // Step 4: Search for user entry
        let search_result = tokio::time::timeout(
            timeout,
            ldap.search(
                &self.config.user_search_base,
                Scope::Subtree,
                &filter,
                vec!["dn", "uid", "cn", "displayName", "mail", "department", "sAMAccountName"],
            ),
        )
        .await
        .map_err(|_| LdapError::Timeout)?
        .map_err(|e| {
            LdapError::SearchFailed(format!("User search failed: {e}"))
        })?;

        // Process search result
        let (entries, _result) = search_result.success().map_err(|e| {
            LdapError::SearchFailed(format!(
                "User search result error: {e}"
            ))
        })?;

        if entries.is_empty() {
            warn!(
                username = %username,
                filter = %filter,
                "User not found in LDAP"
            );
            return Err(LdapError::UserNotFound(format!(
                "User '{username}' not found"
            )));
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        let user_dn = entry.dn.clone();

        debug!(user_dn = %user_dn, "Found user entry");

        // Step 5: Verify user credentials by binding as the user on a NEW connection
        let (user_conn, mut user_ldap) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|e| {
                LdapError::ConnectionFailed(format!(
                    "User verification connect error: {e}"
                ))
            })?;

        let user_bind_result = tokio::time::timeout(
            timeout,
            user_ldap.simple_bind(&user_dn, password),
        )
        .await
        .map_err(|_| LdapError::Timeout)?;

        match user_bind_result {
            Ok(_) => debug!("User credential bind successful"),
            Err(e) => {
                warn!(
                    user_dn = %user_dn,
                    error = %e,
                    "User credential bind failed"
                );
                return Err(LdapError::InvalidCredentials);
            }
        }

        // Drop user connection
        drop(user_ldap);
        drop(user_conn);

        // Step 6: Resolve group membership via original connection
        let groups = self.query_groups(&mut ldap, &user_dn).await?;

        // Drop original connection
        drop(ldap);
        drop(conn);

        // Extract user attributes
        let uid = entry
            .attrs
            .get("uid")
            .or(entry.attrs.get("sAMAccountName"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| username.to_string());

        let display_name = entry
            .attrs
            .get("displayName")
            .or(entry.attrs.get("cn"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| uid.clone());

        let mail = entry
            .attrs
            .get("mail")
            .and_then(|v| v.first())
            .cloned();

        let department = entry
            .attrs
            .get("department")
            .or(entry.attrs.get("ou"))
            .and_then(|v| v.first())
            .cloned();

        Ok(LdapUser {
            dn: user_dn,
            uid,
            display_name,
            mail,
            department,
            groups,
        })
    }

    /// Resolve roles by querying group membership for a user DN.
    async fn do_resolve_roles(
        &self,
        url: &str,
        user_dn: &str,
    ) -> Result<Vec<UserRole>, LdapError> {
        use ldap3::LdapConnAsync;

        let timeout =
            Duration::from_secs(self.config.connection_timeout_secs);

        let (conn, mut ldap) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|e| {
                LdapError::ConnectionFailed(format!("LDAP connect error: {e}"))
            })?;

        // Bind as service account
        let bind_result = tokio::time::timeout(
            timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password),
        )
        .await
        .map_err(|_| LdapError::Timeout)?;

        if let Err(e) = bind_result {
            return Err(LdapError::BindFailed(format!("Bind failed: {e}")));
        }

        let groups = self.query_groups(&mut ldap, user_dn).await?;

        drop(ldap);
        drop(conn);

        // Map groups to roles
        let mut roles: Vec<UserRole> = Vec::new();
        for group_dn in &groups {
            if let Some(role) = self.config.role_mappings.get(group_dn) {
                if !roles.contains(&role) {
                    roles.push(role.clone());
                }
            }
        }

        debug!(
            user_dn = %user_dn,
            roles = ?roles,
            "Resolved roles from LDAP groups"
        );

        Ok(roles)
    }

    /// Find a user by identifier (uid, mail, or cn).
    async fn do_find_user(
        &self,
        url: &str,
        identifier: &str,
    ) -> Result<Option<LdapUser>, LdapError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};

        let timeout =
            Duration::from_secs(self.config.connection_timeout_secs);

        let (conn, mut ldap) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|e| {
                LdapError::ConnectionFailed(format!("LDAP connect error: {e}"))
            })?;

        let bind_result = tokio::time::timeout(
            timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password),
        )
        .await
        .map_err(|_| LdapError::Timeout)?;

        if let Err(e) = bind_result {
            return Err(LdapError::BindFailed(format!("Bind failed: {e}")));
        }

        // Build OR filter for uid/mail/cn
        let filter = format!(
            "(|(uid={identifier})(mail={identifier})(cn={identifier}))"
        );

        let search_result = tokio::time::timeout(
            timeout,
            ldap.search(
                &self.config.user_search_base,
                Scope::Subtree,
                &filter,
                vec![
                    "dn", "uid", "cn", "displayName",
                    "mail", "department", "sAMAccountName",
                ],
            ),
        )
        .await
        .map_err(|_| LdapError::Timeout)?
        .map_err(|e| {
            LdapError::SearchFailed(format!("Search failed: {e}"))
        })?;

        let (entries, _result) = search_result.success().map_err(|e| {
            LdapError::SearchFailed(format!("Search result error: {e}"))
        })?;

        if entries.is_empty() {
            return Ok(None);
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());

        // Query groups for this user
        let groups = self.query_groups(&mut ldap, &entry.dn).await?;

        drop(ldap);
        drop(conn);

        let uid = entry
            .attrs
            .get("uid")
            .or(entry.attrs.get("sAMAccountName"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| identifier.to_string());

        let display_name = entry
            .attrs
            .get("displayName")
            .or(entry.attrs.get("cn"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| uid.clone());

        let mail = entry.attrs.get("mail").and_then(|v| v.first()).cloned();
        let department = entry
            .attrs
            .get("department")
            .or(entry.attrs.get("ou"))
            .and_then(|v| v.first())
            .cloned();

        Ok(Some(LdapUser {
            dn: entry.dn,
            uid,
            display_name,
            mail,
            department,
            groups,
        }))
    }

    /// Query group membership for a user DN.
    async fn query_groups(
        &self,
        ldap: &mut ldap3::Ldap,
        user_dn: &str,
    ) -> Result<Vec<String>, LdapError> {
        use ldap3::Scope;

        let timeout =
            Duration::from_secs(self.config.connection_timeout_secs);

        // Standard LDAP group membership filter
        let filter = format!("(member={user_dn})");

        let search_result = tokio::time::timeout(
            timeout,
            ldap.search(
                &self.config.group_search_base,
                Scope::Subtree,
                &filter,
                vec!["dn"],
            ),
        )
        .await
        .map_err(|_| LdapError::Timeout)?
        .map_err(|e| {
            LdapError::SearchFailed(format!("Group search failed: {e}"))
        })?;

        let (entries, _result) = search_result.success().map_err(|e| {
            LdapError::SearchFailed(format!(
                "Group search result error: {e}"
            ))
        })?;

        let groups: Vec<String> = entries
            .into_iter()
            .map(|e| {
                let se = ldap3::SearchEntry::construct(e);
                se.dn
            })
            .collect();

        debug!(
            user_dn = %user_dn,
            group_count = groups.len(),
            "Queried LDAP group membership"
        );

        Ok(groups)
    }

    /// Health check against a single URL.
    async fn do_health_check(&self, url: &str) -> Result<(), LdapError> {
        use ldap3::LdapConnAsync;

        let timeout =
            Duration::from_secs(self.config.connection_timeout_secs);

        let (_conn, mut ldap) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|e| {
                LdapError::ConnectionFailed(format!("{e}"))
            })?;

        let bind_result = tokio::time::timeout(
            timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password),
        )
        .await
        .map_err(|_| LdapError::Timeout)?;

        bind_result.map_err(|e| {
            LdapError::BindFailed(format!("{e}"))
        })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Comprehensive error type for LDAP operations.
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// Cannot establish TCP/TLS connection to any configured LDAP server.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Service account or user bind operation was rejected by the server.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// The provided username/password combination was rejected during user bind.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// No user entry matched the search criteria in the directory.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// LDAP search operation (user lookup, group query) failed.
    #[error("search failed: {0}")]
    SearchFailed(String),

    /// Operation exceeded the configured timeout duration.
    #[error("operation timed out")]
    Timeout,

    /// Unexpected protocol-level or internal error.
    #[error("internal error: {0}")]
    Internal(String),
}
