//! LDAP Identity Provider Plugin — [`IdentityProvider`] Implementation for LDAP v3.
//!
//! Implements [`IdentityProvider`](super::super::provider::IdentityProvider) trait
//! for authenticating users against LDAP v3 directory servers (OpenLDAP, AD, etc.).
//!
//! # Architecture
//!
//! ```text
//! AuthRequest::Credentials        LDAP Server (AD / OpenLDAP)
//!        |                             ^
//!        v                             |
//!  LdapIdentityProvider   1. Service Bind      ┌──────────────┐
//!  (this module)         2. Search User       │  LDAP Server  │
//!                       3. User Bind Verify    │              │
//!                       4. Query Groups        │              │
//!                       → MisogiIdentity       └──────────────┘
//! ```
//!
//! # Japanese Government Quirks
//!
//! - **Shift-JIS Fallback**: Auto-transcodes non-UTF-8 attributes via encoding_rs.
//! - **Legacy Schema**: Configurable attribute mappings via [`LdapAttributeMappings`](config::LdapAttributeMappings).
//! - **G-Cloud Compatible**: Tested against 総務省 G-Cloud LDAP endpoints.

pub mod config;
#[cfg(test)]
mod tests;

pub use config::{LdapAttributeMappings, LdapPluginConfig};

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, error, info, instrument, warn};

use crate::provider::{
    AuthRequest, IdentityError, IdentityProvider, MisogiIdentity,
};

// ---------------------------------------------------------------------------
// Provider Implementation
// ---------------------------------------------------------------------------

/// LDAP v3 Identity Provider — implements [`IdentityProvider`] for directory auth.
///
/// Thread-safe: wraps configuration in an atomic round-robin URL selector.
/// Designed for `Arc<>` sharing across async tasks in multi-tenant deployments.
///
/// # Lifecycle
///
/// 1. **Construction**: Created with [`LdapPluginConfig`]; no connections opened yet.
/// 2. **Health Check**: Call [`IdentityProvider::health_check`] to verify connectivity.
/// 3. **Authentication**: Call [`IdentityProvider::authenticate`] with
///    [`AuthRequest::Credentials`].
/// 4. **Result**: Returns [`MisogiIdentity`] with `idp_source = "ldap"` on success.
pub struct LdapIdentityProvider {
    config: LdapPluginConfig,
    url_index: AtomicUsize,
}

impl LdapIdentityProvider {
    /// Construct a new LDAP identity provider from the given configuration.
    ///
    /// No LDAP connections are established at construction time.
    /// Call [`Self::health_check`] after construction to verify connectivity.
    #[instrument(skip(config), fields(urls = ?config.urls))]
    pub fn new(config: LdapPluginConfig) -> Self {
        info!(
            urls_count = config.urls.len(),
            pool_size = config.pool_size,
            shift_jis = config.shift_jis_fallback,
            "LdapIdentityProvider initialized"
        );
        Self { config, url_index: AtomicUsize::new(0) }
    }

    /// Get a read-only reference to the provider configuration.
    pub fn config(&self) -> &LdapPluginConfig {
        &self.config
    }

    // ---- Internal helpers ----

    fn next_url(&self) -> &str {
        if self.config.urls.is_empty() {
            return "ldap://localhost:389";
        }
        let idx = self.url_index.fetch_add(1, Ordering::Relaxed)
            % self.config.urls.len();
        &self.config.urls[idx]
    }

    fn build_user_filter(&self, username: &str) -> String {
        self.config.user_filter.replace("{username}", username)
    }

    fn build_group_filter(&self, user_dn: &str) -> String {
        match &self.config.group_filter {
            Some(f) => f.replace("{user_dn}", user_dn),
            None => format!("(member={user_dn})"),
        }
    }

    /// Decode LDAP attribute value with optional Shift-JIS fallback.
    ///
    /// When `shift_jis_fallback` is enabled and raw bytes are not valid UTF-8,
    /// attempts decoding as Windows-31J before falling back to lossy replacement.
    #[inline]
    pub fn decode_attribute_value(&self, raw: &[u8]) -> String {
        match std::str::from_utf8(raw) {
            Ok(s) => s.to_string(),
            Err(_) if self.config.shift_jis_fallback => {
                let (s, _, _) = encoding_rs::SHIFT_JIS.decode(raw);
                s.to_string()
            }
            Err(_) => String::from_utf8_lossy(raw).into_owned(),
        }
    }

    fn extract_attribute(
        &self,
        entry: &ldap3::SearchEntry,
        attr_name: &str,
    ) -> Option<String> {
        entry.attrs.get(attr_name).and_then(|v| {
            v.first().map(|raw| self.decode_attribute_value(raw.as_bytes()))
        })
    }

    // ---- Core authentication flow ----

    async fn do_authenticate(
        &self,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<MisogiIdentity, IdentityError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);

        // Step 1: Connect to LDAP server
        debug!(url = %url, "Establishing LDAP connection");
        let (conn, mut ldap) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await.map_err(|_| IdentityError::ProviderUnavailable(
                "LDAP connection timed out".into()))?
            .map_err(|e| IdentityError::ProviderUnavailable(
                format!("Failed to connect to {url}: {e}")))?;

        // Step 2: Bind as service account
        let bind_result = tokio::time::timeout(
            timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password),
        ).await.map_err(|_| IdentityError::ProviderUnavailable(
            "Service account bind timed out".into()))?;

        if let Err(e) = bind_result {
            error!(bind_dn = %self.config.bind_dn, error = %e, "Service bind rejected");
            return Err(IdentityError::ConfigurationError(format!("Bind failed: {e}")));
        }

        // Step 3: Search for user entry
        let filter = self.build_user_filter(username);
        let attrs = vec![
            "dn",
            &self.config.attribute_mappings.uid_attribute,
            &self.config.attribute_mappings.display_name_attribute,
            &self.config.attribute_mappings.email_attribute,
        ];

        let search_result = tokio::time::timeout(
            timeout,
            ldap.search(&self.config.user_search_base, Scope::Subtree, &filter, attrs),
        ).await.map_err(|_| IdentityError::ProviderUnavailable("User search timed out".into()))?
         .map_err(|e| IdentityError::ProviderUnavailable(format!("Search failed: {e}")))?;

        let (entries, _result) = search_result.success()
            .map_err(|e| IdentityError::InternalError(format!("Search result error: {e}")))?;

        if entries.is_empty() {
            warn!(username = %username, "User not found in LDAP");
            return Err(IdentityError::UserNotFound);
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        let user_dn = entry.dn.clone();
        debug!(user_dn = %user_dn, "Found user entry");

        // Step 4: Verify credentials via user DN bind on new connection
        let (_uc, mut ul) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await.map_err(|_| IdentityError::ProviderUnavailable(
                "Credential connect timed out".into()))?
            .map_err(|e| IdentityError::ProviderUnavailable(format!("Connect failed: {e}")))?;

        match tokio::time::timeout(timeout, ul.simple_bind(&user_dn, password)).await {
            Ok(Ok(_)) => debug!("User credential verified"),
            Ok(Err(e)) => {
                warn!(error = %e, "Credential bind rejected");
                return Err(IdentityError::InvalidCredentials);
            }
            Err(_) => return Err(IdentityError::ProviderUnavailable(
                "Credential bind timed out".into())),
        };
        drop(ul); drop(_uc);

        // Step 5: Resolve group memberships
        let roles = self.resolve_groups(&mut ldap, &user_dn).await?;
        drop(ldap); drop(conn);

        // Step 6: Build MisogiIdentity
        let applicant_id = self.extract_attribute(&entry, &self.config.attribute_mappings.uid_attribute)
            .unwrap_or_else(|| username.to_string());
        let display_name = self.extract_attribute(&entry, &self.config.attribute_mappings.display_name_attribute);
        let email = self.extract_attribute(&entry, &self.config.attribute_mappings.email_attribute);

        let mut extra = HashMap::new();
        extra.insert("ldap_dn".to_string(), serde_json::Value::String(user_dn.clone()));
        if let Some(ref mail) = email {
            extra.insert("ldap_mail".to_string(), serde_json::Value::String(mail.clone()));
        }

        info!(applicant_id = %applicant_id, roles = roles.len(), "LDAP auth success");
        Ok(MisogiIdentity {
            applicant_id, display_name, roles,
            idp_source: "ldap".to_string(),
            original_subject: Some(user_dn),
            extra,
        })
    }

    async fn resolve_groups(
        &self,
        ldap: &mut ldap3::Ldap,
        user_dn: &str,
    ) -> Result<Vec<String>, IdentityError> {
        let Some(base) = &self.config.group_search_base else {
            return Ok(Vec::new());
        };
        use ldap3::Scope;
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        let filter = self.build_group_filter(user_dn);
        let gattrs = vec![&self.config.attribute_mappings.group_name_attribute];

        let sr = tokio::time::timeout(
            timeout, ldap.search(base, Scope::Subtree, &filter, gattrs),
        ).await.map_err(|_| IdentityError::ProviderUnavailable("Group query timed out".into()))?
         .map_err(|e| IdentityError::ProviderUnavailable(format!("Group query failed: {e}")))?;

        let (entries, _r) = sr.success()
            .map_err(|e| IdentityError::InternalError(format!("Group result error: {e}")))?;

        let roles: Vec<String> = entries.into_iter().flat_map(|e| {
            let se = ldap3::SearchEntry::construct(e);
            se.attrs.get(&self.config.attribute_mappings.group_name_attribute)
                .cloned().unwrap_or_default()
        }).collect();

        debug!(roles = ?roles, "Resolved groups");
        Ok(roles)
    }

    async fn do_health_check(&self, url: &str) -> Result<(), IdentityError> {
        use ldap3::LdapConnAsync;
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        let (_c, mut l) = tokio::time::timeout(timeout, LdapConnAsync::new(url))
            .await.map_err(|_| IdentityError::ProviderUnavailable(format!("{url}: connect timed out")))?
            .map_err(|e| IdentityError::ProviderUnavailable(format!("{url}: {e}")))?;
        tokio::time::timeout(timeout, l.simple_bind(&self.config.bind_dn, &self.config.bind_password))
            .await.map_err(|_| IdentityError::ProviderUnavailable(format!("{url}: bind timed out")))?
            .map_err(|e| IdentityError::ConfigurationError(format!("{url}: {e}")))?;
        info!(url = %url, "LDAP health check passed");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IdentityProvider Trait Implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl IdentityProvider for LdapIdentityProvider {
    fn provider_id(&self) -> &str { "ldap" }

    fn provider_name(&self) -> &str { "LDAP / Active Directory Identity Provider" }

    #[instrument(skip(self, input))]
    async fn authenticate(&self, input: AuthRequest) -> Result<MisogiIdentity, IdentityError> {
        let (username, password) = match input {
            AuthRequest::Credentials { username, password } => (username, password),
            _ => return Err(IdentityError::AuthenticationFailed(
                "LDAP provider only supports Credentials auth request".into())),
        };
        self.do_authenticate(self.next_url(), &username, &password).await
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), IdentityError> {
        if self.config.urls.is_empty() {
            return Err(IdentityError::ConfigurationError("No LDAP URLs configured".into()));
        }
        let mut last = None;
        for url in &self.config.urls {
            match self.do_health_check(url).await {
                Ok(()) => return Ok(()),
                Err(e) => { last = Some(e); }
            }
        }
        Err(last.unwrap_or_else(|| IdentityError::InternalError("No servers available".into())))
    }
}
