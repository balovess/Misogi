//! Attribute resolution layer for ABAC policy evaluation.
//!
//! Provides [`AttributeResolver`], which normalizes raw access-request parameters
//! (subject identity, resource metadata, environmental context) into a unified
//! `HashMap<String, AbacValue>` suitable for policy condition evaluation.
//!
//! # Resolution Categories
//!
//! | Category | Method | Output Keys |
//! |----------|--------|-------------|
//! | Subject | [`resolve_subject_attributes`] | user_id, role, department, clearance_level, group_membership |
//! | Resource | [`resolve_resource_attributes`] | data_classification, file_type, file_size_bytes, destination_zone, contains_pii |
//! | Environment | [`resolve_environment_attributes`] | time_of_day, day_of_week, business_day, source_network |
//! | Custom | [`resolve_custom_attributes`] | Caller-supplied key-value pairs |
//!
//! # Caching
//!
//! Internal TTL-based cache (`RwLock<HashMap>`) avoids redundant resolution.
//! Entries are lazily evicted on access; use [`clear_cache`] or [`invalidate_key`]
//! for explicit invalidation.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::RwLock;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use chrono::{Datelike, Timelike};

use super::attribute::AbacValue;

// ===========================================================================
// AttributeResolver
// ===========================================================================

/// Resolves raw access-request parameters into a normalized attribute map.
///
/// Performs three functions:
/// 1. **Normalization** — converts heterogeneous input into uniform `HashMap<String, AbacValue>`.
/// 2. **Enrichment** — derives computed attributes (e.g., `time_of_day` from system clock).
/// 3. **Caching** — stores resolved values with TTL-based expiration.
///
/// Thread safety: internal cache protected by `std::sync::RwLock`.
pub struct AttributeResolver {
    cache: RwLock<HashMap<String, (AbacValue, Instant)>>,
    #[cfg(test)]
    cache_ttl: Duration,
}

impl AttributeResolver {
    /// Constructs a new resolver with the specified cache TTL in seconds.
    /// Pass `0` to disable caching entirely.
    pub fn new(_cache_ttl_secs: u64) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            #[cfg(test)]
            cache_ttl: Duration::from_secs(_cache_ttl_secs),
        }
    }

    // -------------------------------------------------------------------
    // Subject Attributes
    // -------------------------------------------------------------------

    /// Resolves subject (who) attributes.
    ///
    /// Standard keys produced: `user_id`, `role`, `department`,
    /// `clearance_level` (derived from role), `group_membership`.
    /// Extra keys from caller override defaults.
    pub fn resolve_subject_attributes(
        &self,
        user_id: &str,
        role: &str,
        department: &str,
        extra: HashMap<String, AbacValue>,
    ) -> HashMap<String, AbacValue> {
        let mut attrs = HashMap::with_capacity(9 + extra.len());
        attrs.insert(
            "user_id".to_string(),
            AbacValue::String(user_id.to_string()),
        );
        attrs.insert("role".to_string(), AbacValue::String(role.to_string()));
        attrs.insert(
            "department".to_string(),
            AbacValue::String(department.to_string()),
        );
        attrs.insert(
            "clearance_level".to_string(),
            AbacValue::Integer(self.derive_clearance_level(role)),
        );
        attrs.insert(
            "group_membership".to_string(),
            AbacValue::List(vec![AbacValue::String(format!("{}/{}", department, role))]),
        );
        for (key, value) in extra {
            attrs.insert(key, value);
        }
        attrs
    }

    // -------------------------------------------------------------------
    // Resource Attributes
    // -------------------------------------------------------------------

    /// Resolves resource (what) attributes.
    ///
    /// Standard keys: `data_classification`, `file_type`, `file_size_bytes`,
    /// `destination_zone`, `contains_pii`.
    pub fn resolve_resource_attributes(
        &self,
        classification: &str,
        file_type: &str,
        file_size: u64,
        destination_zone: &str,
        contains_pii: bool,
        extra: HashMap<String, AbacValue>,
    ) -> HashMap<String, AbacValue> {
        let mut attrs = HashMap::with_capacity(5 + extra.len());
        attrs.insert(
            "data_classification".to_string(),
            AbacValue::String(classification.to_string()),
        );
        attrs.insert(
            "file_type".to_string(),
            AbacValue::String(file_type.to_string()),
        );
        attrs.insert(
            "file_size_bytes".to_string(),
            AbacValue::Integer(file_size as i64),
        );
        attrs.insert(
            "destination_zone".to_string(),
            AbacValue::String(destination_zone.to_string()),
        );
        attrs.insert("contains_pii".to_string(), AbacValue::Boolean(contains_pii));
        for (key, value) in extra {
            attrs.insert(key, value);
        }
        attrs
    }

    // -------------------------------------------------------------------
    // Environment Attributes
    // -------------------------------------------------------------------

    /// Resolves environmental (context) attributes.
    ///
    /// Standard keys: `time_of_day` (`"HH:MM"`), `day_of_week` (ISO 1=Mon..7=Sun),
    /// `business_day` (bool), `source_network` (derived from IP).
    /// Also passes through: `ip_address`, `geographic_region`, `mfa_verified`, `device_compliant`.
    pub fn resolve_environment_attributes(
        &self,
        ip_address: &str,
        geographic_region: &str,
        mfa_verified: bool,
        device_compliant: bool,
        extra: HashMap<String, AbacValue>,
    ) -> HashMap<String, AbacValue> {
        let mut attrs = HashMap::with_capacity(10 + extra.len());
        let now = chrono::Local::now();
        attrs.insert(
            "time_of_day".to_string(),
            AbacValue::String(format!("{:02}:{:02}", now.hour(), now.minute())),
        );
        let iso_weekday = (now.weekday().num_days_from_monday() + 1) as i64;
        attrs.insert("day_of_week".to_string(), AbacValue::Integer(iso_weekday));
        attrs.insert(
            "business_day".to_string(),
            AbacValue::Boolean((1..=5).contains(&iso_weekday)),
        );
        attrs.insert(
            "source_network".to_string(),
            AbacValue::String(self.classify_source_network(ip_address)),
        );
        attrs.insert(
            "ip_address".to_string(),
            AbacValue::String(ip_address.to_string()),
        );
        attrs.insert(
            "geographic_region".to_string(),
            AbacValue::String(geographic_region.to_string()),
        );
        attrs.insert("mfa_verified".to_string(), AbacValue::Boolean(mfa_verified));
        attrs.insert(
            "device_compliant".to_string(),
            AbacValue::Boolean(device_compliant),
        );
        for (key, value) in extra {
            attrs.insert(key, value);
        }
        attrs
    }

    // -------------------------------------------------------------------
    // Custom Attributes
    // -------------------------------------------------------------------

    /// Passes through caller-supplied custom attributes unchanged.
    /// No caching is performed on custom attributes.
    pub fn resolve_custom_attributes(
        &self,
        attributes: HashMap<String, AbacValue>,
    ) -> HashMap<String, AbacValue> {
        attributes
    }

    // -------------------------------------------------------------------
    // Cache Operations
    // -------------------------------------------------------------------

    /// Retrieves a cached value if present and within TTL. Returns `None` on miss or expiry.
    #[cfg(test)]
    fn cache_get(&self, key: &str) -> Option<AbacValue> {
        let cache = self.cache.read().ok()?;
        let (value, inserted_at) = cache.get(key)?;
        if inserted_at.elapsed() < self.cache_ttl {
            Some(value.clone())
        } else {
            None
        }
    }

    /// Inserts or updates a cache entry with the current timestamp.
    #[cfg(test)]
    fn cache_set(&self, key: &str, value: AbacValue) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(key.to_string(), (value, Instant::now()));
        }
    }

    /// Removes all entries from the internal cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Invalidates a single cache entry by key. No-op if key does not exist.
    pub fn invalidate_key(&self, key: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(key);
        }
    }

    // -------------------------------------------------------------------
    // Private Helpers
    // -------------------------------------------------------------------

    /// Derives numeric clearance level from role name via keyword matching.
    ///
    /// | Role Pattern | Level |
    /// |-------------|-------|
    /// | admin/administrator | 5 |
    /// | security/security_officer | 4 |
    /// | manager/director | 3 |
    /// | operator/staff | 2 |
    /// | other | 1 |
    fn derive_clearance_level(&self, role: &str) -> i64 {
        let lower = role.to_lowercase();
        if lower.contains("admin") || lower.contains("administrator") {
            5
        } else if lower.contains("security") {
            4
        } else if lower.contains("manager") || lower.contains("director") {
            3
        } else if lower.contains("operator") || lower.contains("staff") {
            2
        } else {
            1
        }
    }

    /// Classifies an IP address into a coarse network category using RFC 1918 prefix heuristics.
    ///
    /// | Prefix Range | Classification |
    /// |-------------|---------------|
    /// | `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12` | `"corporate-lan"` |
    /// | other | `"unknown"` |
    fn classify_source_network(&self, ip_address: &str) -> String {
        if ip_address.starts_with("10.")
            || ip_address.starts_with("192.168.")
            || Self::is_rfc1918_class_b(ip_address)
        {
            "corporate-lan".to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// Checks whether an IP falls within RFC 1918 Class B range (`172.16.0.0/12`).
    fn is_rfc1918_class_b(ip: &str) -> bool {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 2
            && let (Ok(first), Ok(second)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>())
        {
            return first == 172 && (16..=31).contains(&second);
        }
        false
    }
}
