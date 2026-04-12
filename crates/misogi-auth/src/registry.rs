//! Identity Registry — Thread-Safe Identity Provider Manager
//!
//! Provides centralized, concurrent-safe management of [`IdentityProvider`] instances.
//! This component serves as the provider routing layer for Misogi's Ultimate Pluggable
//! Architecture (終極可插拔架構), enabling dynamic registration, lookup, and dispatch
//! of authentication backends at runtime.
//!
//! # Design Principles
//!
//! - **Thread Safety**: All operations use `RwLock` for safe concurrent access from
//!   multiple async tasks without blocking reads.
//! - **Zero-Cost Read**: Multiple readers can access provider metadata simultaneously;
//!   only mutations acquire exclusive write locks.
//! - **Graceful Degradation**: Missing providers return structured errors rather than
//!   panicking, enabling fallback logic in [`crate::middleware::AuthEngine`].
//! - **Audit Trail**: Every registration/deregistration is logged with provider identity.
//!
//! # Architecture
//!
//! ```text
//!                    ┌──────────────────────┐
//!                    │   IdentityRegistry    │
//!                    │  (RwLock<HashMap>)   │
//!                    └──────────┬───────────┘
//!                               │
//!              ┌────────────────┼────────────────┐
//!              ▼                ▼                ▼
//!       ┌──────────┐    ┌──────────┐    ┌──────────┐
//!       │  ldap-1  │    │ oidc-v2  │    │ api-key  │
//!       │ (Arc<IdP>)│   │(Arc<IdP>)│   │(Arc<IdP>)│
//!       └──────────┘    └──────────┘    └──────────┘
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tracing::{info, instrument, warn};

use crate::provider::{
    AuthRequest, IdentityError, IdentityProvider, MisogiIdentity,
};

// ---------------------------------------------------------------------------
// Provider Metadata
// ---------------------------------------------------------------------------

/// Lightweight metadata snapshot of a registered identity provider.
///
/// Returned by [`IdentityRegistry::list`] to provide operator-visible information
/// about each registered provider without exposing the underlying implementation.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Stable unique identifier for this provider instance.
    pub provider_id: String,

    /// Human-readable display name for logs, UI, and error messages.
    pub provider_name: String,
}

impl ProviderInfo {
    /// Create a new [`ProviderInfo`] from an [`IdentityProvider`] trait object.
    pub fn from_provider(provider: &dyn IdentityProvider) -> Self {
        Self {
            provider_id: provider.provider_id().to_string(),
            provider_name: provider.provider_name().to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Identity Registry
// ---------------------------------------------------------------------------

/// Thread-safe registry for managing [`IdentityProvider`] instances.
///
/// Stores providers in a `RwLock<HashMap<String, Arc<dyn IdentityProvider>>>`,
/// enabling:
/// - **Concurrent reads**: Multiple tasks call `get()`, `list()`, `authenticate()` freely.
/// - **Exclusive writes**: `register()` / `remove()` acquire write locks briefly.
/// - **Async-safe dispatch**: `Arc<dyn>` allows cloning handles before `.await` points,
///   avoiding lock-holding-across-await deadlocks that plague `Box<dyn>` designs.
///
/// # Panic Safety
///
/// This struct will never panic on API calls. All error conditions return
/// [`IdentityError`] variants. Poisoned locks are recovered automatically.
pub struct IdentityRegistry {
    /// Internal store: provider_id → provider instance (Arc for async-safe cloning).
    providers: RwLock<HashMap<String, Arc<dyn IdentityProvider>>>,
}

impl IdentityRegistry {
    /// Create a new empty [`IdentityRegistry`].
    #[inline]
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
        }
    }

    /// Register an identity provider into the registry.
    ///
    /// The provider's `provider_id` is used as the map key. Duplicate IDs
    /// replace the existing entry (last-write-wins) with a warning log.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::ConfigurationError`] if `provider_id` is empty.
    #[instrument(skip(self, provider), fields(provider_id = %provider.provider_id()))]
    pub fn register(&self, provider: Arc<dyn IdentityProvider>) -> Result<(), IdentityError> {
        let id = provider.provider_id().to_string();

        if id.is_empty() {
            return Err(IdentityError::ConfigurationError(
                "provider_id must not be empty".to_string(),
            ));
        }

        let name = provider.provider_name().to_string();

        match self.providers.write() {
            Ok(mut guard) => {
                let is_duplicate = guard.contains_key(&id);
                guard.insert(id.clone(), provider);

                if is_duplicate {
                    warn!(provider_id = %id, "Provider re-registered (replaced)");
                } else {
                    info!(provider_id = %id, provider_name = %name, "Provider registered");
                }
                Ok(())
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.insert(id.clone(), provider);
                warn!(provider_id = %id, "Registry lock poisoned, recovered");
                Ok(())
            }
        }
    }

    /// Retrieve a registered provider by its unique identifier.
    ///
    /// Returns a cloned `Arc<>` handle that outlives the registry lock,
    /// making it safe to use across `.await` points.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::ConfigurationError`] if not found.
    #[instrument(skip(self), fields(provider_id))]
    pub fn get(&self, provider_id: &str) -> Result<Arc<dyn IdentityProvider>, IdentityError> {
        match self.providers.read() {
            Ok(guard) => guard
                .get(provider_id)
                .cloned()
                .ok_or_else(|| IdentityError::ConfigurationError(format!(
                    "provider '{provider_id}' not found in registry"
                ))),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                guard
                    .get(provider_id)
                    .cloned()
                    .ok_or_else(|| IdentityError::InternalError(format!(
                        "registry lock poisoned during get('{provider_id}')"
                    )))
            }
        }
    }

    /// Remove a provider from the registry by its unique identifier.
    ///
    /// Existing `Arc<>` handles remain valid until dropped (refcount semantics).
    ///
    /// # Returns
    ///
    /// `true` if found and removed, `false` otherwise.
    #[instrument(skip(self), fields(provider_id))]
    pub fn remove(&self, provider_id: &str) -> bool {
        let write_result = self.providers.write();

        match write_result {
            Ok(mut guard) => {
                let existed = guard.remove(provider_id).is_some();
                if existed {
                    info!(provider_id = %provider_id, "Provider removed");
                }
                existed
            }
            Err(poison_error) => {
                let mut guard = poison_error.into_inner();
                let existed = guard.remove(provider_id).is_some();
                warn!(provider_id = %provider_id, "Lock poisoned during remove");
                existed
            }
        }
    }

    /// List all currently registered providers as lightweight metadata.
    pub fn list(&self) -> Vec<ProviderInfo> {
        match self.providers.read() {
            Ok(guard) => guard
                .values()
                .map(|p| ProviderInfo::from_provider(p.as_ref()))
                .collect(),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                guard
                    .values()
                    .map(|p| ProviderInfo::from_provider(p.as_ref()))
                    .collect()
            }
        }
    }

    /// Return the number of currently registered providers.
    pub fn len(&self) -> usize {
        match self.providers.read() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Check whether the registry contains no providers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Authenticate a request against a specific named provider.
    ///
    /// Clones the `Arc<>` handle under a brief read lock, releases the lock,
    /// then calls the provider's async `authenticate()` without holding any
    /// registry lock during the await.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::ConfigurationError`] — Provider not found
    /// - Propagated errors from the underlying IdP adapter
    #[instrument(skip(self, request), fields(provider_id))]
    pub async fn authenticate(
        &self,
        provider_id: &str,
        request: &AuthRequest,
    ) -> Result<MisogiIdentity, IdentityError> {
        let provider = self.get(provider_id)?;
        provider.authenticate(request.clone()).await
    }

    /// Run health checks against all registered providers concurrently.
    ///
    /// Snapshots provider list (brief read lock), clones each `Arc<>`, releases
    /// the lock, then runs all checks via `futures::future::join_all`.
    ///
    /// Returns per-provider `(id, Result)` pairs; one unhealthy provider does
    /// not abort the others.
    pub async fn health_check_all(&self) -> Vec<(String, Result<(), IdentityError>)> {
        let provider_ids: Vec<String>;
        let providers: Vec<Arc<dyn IdentityProvider>>;

        {
            match self.providers.read() {
                Ok(guard) => {
                    provider_ids = guard.keys().cloned().collect();
                    providers = guard.values().cloned().collect();
                }
                Err(poisoned) => {
                    let guard = poisoned.into_inner();
                    provider_ids = guard.keys().cloned().collect();
                    providers = guard.values().cloned().collect();
                }
            }
        }

        let futures: Vec<_> = providers
            .into_iter()
            .map(|p| async move { p.health_check().await })
            .collect();

        let results = futures::future::join_all(futures).await;

        provider_ids
            .into_iter()
            .zip(results.into_iter())
            .collect()
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests (separated file to satisfy line-limit policy)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
