//! Vendor Permission Isolation Module — Multi-tenant security boundary enforcement.
//!
//! This module provides strict access control and resource isolation for external
//! vendor accounts (取引先) interacting with the Misogi file transfer system.
//!
//! # Security Architecture
//!
//! Japanese government systems require **vendor isolation** (ベンダー分離) to prevent
//! cross-contamination between different contractor/vendor data flows:
//!
//! - **IP Whitelist Enforcement**: Each vendor account is bound to specific CIDR ranges.
//! - **Per-Vendor Rate Limiting**: Independent sliding-window rate limiters prevent abuse.
//! - **Dual Approval Gate**: Sensitive operations require two-person authorization.
//! - **CDR Policy Override**: Administrators can force stricter sanitization policies per vendor.
//! - **File Size & Extension Controls**: Prevent oversized uploads and executable injection.
//!
//! # Thread Safety
//!
//! All state is protected by [`std::sync::RwLock`] for concurrent read access with
//! exclusive write serialization. Safe for use in async Tokio contexts.
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_core::contrib::jp::vendor::{VendorIsolationManager, VendorAccount};
//! use ipnetwork::IpNetwork;
//! use std::net::IpAddr;
//!
//! let manager = VendorIsolationManager::new(true);
//! let account = VendorAccount {
//!     user_id: "vendor_acme".to_string(),
//!     display_name: "ACME Corporation".to_string(),
//!     ip_whitelist: vec!["203.0.113.0/24".parse().unwrap()],
//!     ..Default::default()
//! };
//! manager.register_account(account)?;
//!
//! let allowed = manager.validate_access("vendor_acme", "203.0.113.50")?;
//! assert!(allowed);
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Instant;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;

use crate::error::{MisogiError, Result};

// =============================================================================
// VendorAccount
// =============================================================================

/// Complete security profile for a single vendor (取引先) account.
///
/// Each vendor account represents an external organization or contractor that is
/// granted limited access to the file transfer system. All permissions are
/// explicitly defined — there are no implicit grants.
///
/// # Lifecycle
///
/// Accounts are registered via [`VendorIsolationManager::register_account()`] and
/// remain active until explicitly removed (not implemented in this version).
///
/// # Immutable Fields
///
/// Once created, a `VendorAccount` should be treated as immutable. To modify
/// settings, create a new instance and re-register it (replaces the old one).
#[derive(Debug, Clone)]
pub struct VendorAccount {
    /// Unique identifier for this vendor account (e.g., "vendor_acme_corp").
    ///
    /// Used as the primary key in all lookups. Must be non-empty and unique
    /// across all registered accounts.
    pub user_id: String,

    /// Human-readable display name for audit logs and UI presentation.
    ///
    /// Examples: "ACME Corporation", "東京建設株式会社"
    pub display_name: String,

    /// List of IP CIDR networks from which this vendor is permitted to connect.
    ///
    /// An empty whitelist means **no IP addresses are allowed** (deny-by-default).
    /// Use `["0.0.0.0/0", "::/0"]` to allow all addresses (not recommended).
    ///
    /// # Matching Logic
    /// Access is granted if the client IP matches **any** entry in this list.
    pub ip_whitelist: Vec<IpNetwork>,

    /// Forced CDR (Content Disarm & Reconstruction) policy override.
    ///
    /// If `Some(policy_name)`, all files uploaded by this vendor MUST undergo
    /// the specified CDR policy regardless of the file's normal classification.
    ///
    /// Common values:
    /// - `"convert_to_flat"` — Convert Office documents to flattened PDF
    /// - `"strip_macros"` — Remove all macros/scripts from Office files
    /// - `"deep_sanitize"` — Full content reconstruction (slowest, safest)
    pub force_max_cdr_policy: Option<String>,

    /// Whether this vendor's uploads require dual-person approval before processing.
    ///
    /// When `true`, the approval workflow must collect approvals from **two distinct**
    /// authorized reviewers before the file transfer can proceed to the destination network.
    pub require_dual_approval: bool,

    /// Maximum number of file uploads allowed per hour for this vendor.
    ///
    /// A value of `0` means unlimited (no rate limiting). Recommended range:
    /// - Low-trust vendors: 10–50/hour
    /// - Standard vendors: 100–500/hour
    /// - High-trust internal: 0 (unlimited)
    pub upload_rate_limit_per_hour: u32,

    /// Maximum allowed file size in megabytes for uploads by this vendor.
    ///
    /// Files exceeding this size will be rejected at the API boundary before
    /// any processing occurs. A value of `0` means no size limit.
    ///
    /// Typical values:
    /// - Document-only vendors: 50 MB
    /// - CAD/design vendors: 500 MB
    /// - Media production: 2048 MB (2 GB)
    pub max_file_size_mb: u64,

    /// Allowed file extensions for upload (case-insensitive matching).
    ///
    /// An empty list means **all extensions are allowed** (not recommended).
    /// Include the leading dot: `.pdf`, `.xlsx`, `.dwg`
    pub allowed_extensions: Vec<String>,

    /// Timestamp when this account was created (immutable after creation).
    pub created_at: DateTime<Utc>,
}

impl Default for VendorAccount {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            display_name: String::new(),
            ip_whitelist: Vec::new(),
            force_max_cdr_policy: None,
            require_dual_approval: false,
            upload_rate_limit_per_hour: 0, // Unlimited by default
            max_file_size_mb: 0,           // No limit by default
            allowed_extensions: Vec::new(), // Allow all by default
            created_at: Utc::now(),
        }
    }
}

// =============================================================================
// Rate Limiter (Sliding Window)
// =============================================================================

/// Per-vendor sliding window rate limiter using wall-clock timestamps.
///
/// Implements a simple but effective sliding window algorithm:
/// - Track timestamps of each request within the current window
/// - On each new request, prune entries older than 1 hour
/// - Reject if count exceeds the configured limit
///
/// # Thread Safety
///
/// Not inherently thread-safe; must be used within a [`RwLock`] as part of
/// [`VendorIsolationManager`].
#[derive(Debug)]
struct RateLimiter {
    /// Maximum requests allowed within the sliding window (1 hour).
    max_requests: u32,

    /// Chronologically sorted request timestamps within the current window.
    request_timestamps: Vec<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified hourly limit.
    ///
    /// # Arguments
    /// * `max_per_hour` - Maximum requests allowed per hour. Pass `0` for unlimited.
    fn new(max_per_hour: u32) -> Self {
        Self {
            max_requests: max_per_hour,
            request_timestamps: Vec::new(),
        }
    }

    /// Check if a new request is allowed under the rate limit, and record it.
    ///
    /// # Returns
    /// - `Ok(true)` if the request is within limits (and has been recorded).
    /// - `Ok(false)` if the request would exceed the limit (not recorded).
    fn check_and_record(&mut self) -> bool {
        // Unlimited mode
        if self.max_requests == 0 {
            return true;
        }

        let now = Instant::now();
        let one_hour_ago = now - std::time::Duration::from_secs(3600);

        // Prune expired entries (older than 1 hour)
        self.request_timestamps.retain(|&ts| ts > one_hour_ago);

        // Check if we're within limit
        if self.request_timestamps.len() >= self.max_requests as usize {
            return false; // Rate limit exceeded
        }

        // Record this request
        self.request_timestamps.push(now);
        true
    }

    /// Get the number of requests recorded in the current window.
    #[cfg(test)]
    fn current_count(&self) -> usize {
        self.request_timestamps.len()
    }
}

// =============================================================================
// VendorIsolationManager
// =============================================================================

/// Central authority for vendor access control and permission enforcement.
///
/// Manages the lifecycle of [`VendorAccount`] instances and enforces security
/// policies at runtime for every vendor-initiated operation.
///
/// # Design Principles
///
/// 1. **Deny by Default**: Unknown user IDs are always denied.
/// 2. **Explicit Grants**: Every permission must be explicitly configured.
/// 3. **Audit Trail**: All access decisions are logged (via tracing crate).
/// 4. **Graceful Degradation**: If isolation is disabled, all checks pass (dev mode).
///
/// # Concurrency Model
///
/// Uses [`RwLock`] for fine-grained concurrency:
/// - Multiple concurrent reads (validation checks) proceed without blocking.
/// - Exclusive write lock held only during account registration/modification.
pub struct VendorIsolationManager {
    /// Map of user_id → VendorAccount for O(1) lookups.
    accounts: RwLock<HashMap<String, VendorAccount>>,

    /// Per-vendor rate limiters, keyed by user_id.
    rate_limiters: RwLock<HashMap<String, RateLimiter>>,

    /// Master switch for the entire isolation system.
    ///
    /// When `false`, all validation methods return `Ok(true)` (allow-all mode).
    /// Intended for development/testing environments only.
    enabled: bool,
}

impl VendorIsolationManager {
    /// Create a new VendorIsolationManager with the specified enablement state.
    ///
    /// # Arguments
    /// * `enabled` - `true` to enforce all isolation rules; `false` for allow-all dev mode.
    ///
    /// # Security Warning
    /// **Never** set `enabled = false` in production environments. Doing so
    /// bypasses all IP whitelist, rate limiting, and policy enforcement checks.
    pub fn new(enabled: bool) -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            rate_limiters: RwLock::new(HashMap::new()),
            enabled,
        }
    }

    /// Register (or update) a vendor account in the isolation manager.
    ///
    /// If an account with the same `user_id` already exists, it will be **replaced**
    /// entirely with the new account data. The associated rate limiter is also reset.
    ///
    /// # Arguments
    /// * `account` - Complete [`VendorAccount`] configuration to register.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if `user_id` is empty.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.register_account(VendorAccount {
    ///     user_id: "vendor_tokyo_build".to_string(),
    ///     display_name: "東京建設".to_string(),
    ///     ip_whitelist: vec!["192.168.100.0/24".parse().unwrap()],
    ///     require_dual_approval: true,
    ///     ..Default::default()
    /// })?;
    /// ```
    pub fn register_account(&self, account: VendorAccount) -> Result<()> {
        if account.user_id.is_empty() {
            return Err(MisogiError::Protocol(
                "VendorAccount user_id must not be empty".to_string(),
            ));
        }

        let mut accounts = self.accounts.write().unwrap();
        let mut rate_limiters = self.rate_limiters.write().unwrap();

        // Initialize rate limiter for this account
        rate_limiters.insert(
            account.user_id.clone(),
            RateLimiter::new(account.upload_rate_limit_per_hour),
        );

        // Store/replace account
        let log_user_id = account.user_id.clone();
        let log_display_name = account.display_name.clone();
        accounts.insert(account.user_id.clone(), account);

        tracing::info!(
            user_id = %log_user_id,
            display_name = %log_display_name,
            "Vendor account registered in isolation manager"
        );

        Ok(())
    }

    /// Validate whether a vendor is permitted to connect from the given IP address.
    ///
    /// Performs three-level checking:
    /// 1. Isolation enabled check (bypass if disabled).
    /// 2. Account existence verification.
    /// 3. IP address CIDR matching against the account's whitelist.
    ///
    /// # Arguments
    /// * `user_id` - The vendor's unique identifier.
    /// * `ip_addr` - Client IP address as a string (e.g., "203.0.113.50").
    ///
    /// # Returns
    /// - `Ok(true)` if access is permitted.
    /// - `Ok(false)` if access is denied (IP not in whitelist).
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if the user_id does not exist.
    /// - [`MisogiError::Protocol`] if the IP address string cannot be parsed.
    ///
    /// # CIDR Matching Examples
    ///
    /// | Whitelist Entry   | Client IP       | Result |
    /// |-------------------|-----------------|--------|
    /// | `10.0.0.0/8`      | `10.1.2.3`      | Allow  |
    /// | `192.168.1.0/24`  | `192.168.2.1`   | Deny   |
    /// | `203.0.113.5/32`  | `203.0.113.5`   | Allow  |
    pub fn validate_access(&self, user_id: &str, ip_addr: &str) -> Result<bool> {
        // Bypass if isolation is disabled
        if !self.enabled {
            return Ok(true);
        }

        // Look up account
        let accounts = self.accounts.read().unwrap();
        let account = accounts.get(user_id).ok_or_else(|| {
            MisogiError::NotFound(format!("Vendor account '{}' not found", user_id))
        })?;

        // Parse client IP
        let client_ip: IpAddr = ip_addr.parse().map_err(|e| {
            MisogiError::Protocol(format!("Invalid IP address '{}': {}", ip_addr, e))
        })?;

        // Check CIDR membership
        let allowed = account.ip_whitelist.iter().any(|network| network.contains(client_ip));

        tracing::debug!(
            user_id = %user_id,
            ip = %ip_addr,
            allowed = allowed,
            "Vendor access validation result"
        );

        Ok(allowed)
    }

    /// Check whether a vendor has remaining upload capacity under their hourly rate limit.
    ///
    /// Records the request attempt regardless of outcome (for accurate tracking).
    ///
    /// # Arguments
    /// * `user_id` - The vendor's unique identifier.
    ///
    /// # Returns
    /// - `Ok(true)` if the vendor is within their rate limit.
    /// - `Ok(false)` if the rate limit has been exceeded.
    ///
    /// # Errors
    /// - [`MisogiError::NotFound`] if the user_id does not exist.
    pub fn check_rate_limit(&self, user_id: &str) -> Result<bool> {
        // Bypass if isolation is disabled
        if !self.enabled {
            return Ok(true);
        }

        // Verify account exists
        {
            let accounts = self.accounts.read().unwrap();
            if !accounts.contains_key(user_id) {
                return Err(MisogiError::NotFound(format!(
                    "Vendor account '{}' not found",
                    user_id
                )));
            }
        }

        // Check and record in rate limiter
        let mut rate_limiters = self.rate_limiters.write().unwrap();
        let limiter = rate_limiters.get_mut(user_id).ok_or_else(|| {
            MisogiError::NotFound(format!(
                "Rate limiter for '{}' not initialized",
                user_id
            ))
        })?;

        let allowed = limiter.check_and_record();

        if !allowed {
            tracing::warn!(
                user_id = %user_id,
                "Vendor rate limit exceeded"
            );
        }

        Ok(allowed)
    }

    /// Retrieve the forced CDR policy name for a vendor account (if configured).
    ///
    /// When a forced policy exists, the CDR engine MUST apply this policy to all
    /// files uploaded by this vendor, overriding any file-type-specific defaults.
    ///
    /// # Arguments
    /// * `user_id` - The vendor's unique identifier.
    ///
    /// # Returns
    /// - `Some(policy_name)` if a forced policy is configured.
    /// - `None` if no override is set (use default CDR behavior).
    pub fn get_required_cdr_policy(&self, user_id: &str) -> Option<String> {
        let accounts = self.accounts.read().unwrap();
        accounts.get(user_id).and_then(|a| a.force_max_cdr_policy.clone())
    }

    /// Check whether a vendor requires dual-person approval for uploads.
    ///
    /// Dual approval (二人承認) is a mandatory control for high-risk vendors
    /// handling sensitive government data. When this returns `true`, the approval
    /// workflow system must collect signatures from **two independent** reviewers.
    ///
    /// # Arguments
    /// * `user_id` - The vendor's unique identifier.
    ///
    /// # Returns
    /// `true` if dual approval is required; `false` otherwise (including if the
    /// account doesn't exist).
    pub fn requires_dual_approval(&self, user_id: &str) -> bool {
        let accounts = self.accounts.read().unwrap();
        accounts
            .get(user_id)
            .map(|a| a.require_dual_approval)
            .unwrap_or(false)
    }

    /// Get the maximum allowed file upload size (in MB) for a vendor.
    ///
    /// # Arguments
    /// * `user_id` - The vendor's unique identifier.
    ///
    /// # Returns
    /// - `Some(max_size_mb)` if a size limit is configured.
    /// - `None` if no limit is set (unlimited), or if the account doesn't exist.
    pub fn get_max_file_size(&self, user_id: &str) -> Option<u64> {
        let accounts = self.accounts.read().unwrap();
        accounts.get(user_id).and_then(|a| {
            if a.max_file_size_mb > 0 {
                Some(a.max_file_size_mb)
            } else {
                None
            }
        })
    }

    /// Check whether a given user ID corresponds to a registered vendor account.
    ///
    /// Unlike other methods, this does **not** enforce the `enabled` flag — it
    /// simply checks registration status. Useful for routing decisions.
    ///
    /// # Arguments
    /// * `user_id` - The user identifier to check.
    ///
    /// # Returns
    /// `true` if the user_id is registered as a vendor; `false` otherwise.
    pub fn is_vendor_account(&self, user_id: &str) -> bool {
        let accounts = self.accounts.read().unwrap();
        accounts.contains_key(user_id)
    }

    /// Get the total number of currently registered vendor accounts.
    ///
    /// Useful for monitoring and administrative dashboards.
    #[cfg(test)]
    fn account_count(&self) -> usize {
        let accounts = self.accounts.read().unwrap();
        accounts.len()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Helper: Create Test Account
    // =========================================================================

    fn create_test_account(user_id: &str, whitelist: &[&str]) -> VendorAccount {
        VendorAccount {
            user_id: user_id.to_string(),
            display_name: format!("Test Vendor {}", user_id),
            ip_whitelist: whitelist
                .iter()
                .map(|s| s.parse().unwrap())
                .collect(),
            force_max_cdr_policy: None,
            require_dual_approval: false,
            upload_rate_limit_per_hour: 100,
            max_file_size_mb: 100,
            allowed_extensions: vec![
                String::from(".pdf"),
                String::from(".xlsx"),
                String::from(".docx"),
            ],
            created_at: Utc::now(),
        }
    }

    // =========================================================================
    // Test: IP Whitelist — Allow Correct Subnet
    // =========================================================================

    #[test]
    fn test_ip_whitelist_allow_correct_subnet() {
        let manager = VendorIsolationManager::new(true);

        let account = create_test_account(
            "vendor_allow_test",
            &["10.0.0.0/8"], // Private class A network
        );
        manager.register_account(account).unwrap();

        // 10.1.2.3 should be within 10.0.0.0/8
        let result = manager.validate_access("vendor_allow_test", "10.1.2.3");
        assert!(result.is_ok());
        assert!(result.unwrap(), "10.1.2.3 should be allowed in 10.0.0.0/8");
    }

    #[test]
    fn test_ip_whitelist_allow_exact_match() {
        let manager = VendorIsolationManager::new(true);

        let account = create_test_account(
            "vendor_exact_test",
            &["203.0.113.50/32"], // Single host
        );
        manager.register_account(account).unwrap();

        let result = manager.validate_access("vendor_exact_test", "203.0.113.50");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // =========================================================================
    // Test: IP Whitelist — Deny Wrong Subnet
    // =========================================================================

    #[test]
    fn test_ip_whitelist_deny_wrong_subnet() {
        let manager = VendorIsolationManager::new(true);

        let account = create_test_account(
            "vendor_deny_test",
            &["192.168.1.0/24"], // Only /24 subnet
        );
        manager.register_account(account).unwrap();

        // 192.168.2.1 is NOT in 192.168.1.0/24
        let result = manager.validate_access("vendor_deny_test", "192.168.2.1");
        assert!(result.is_ok());
        assert!(!result.unwrap(), "192.168.2.1 should NOT be allowed in 192.168.1.0/24");
    }

    #[test]
    fn test_ip_whitelist_empty_denies_all() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_empty_test", &[]);
        account.ip_whitelist = Vec::new(); // Explicitly empty
        manager.register_account(account).unwrap();

        // Any IP should be denied when whitelist is empty
        let result = manager.validate_access("vendor_empty_test", "10.0.0.1");
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Empty whitelist should deny all IPs");
    }

    // =========================================================================
    // Test: Account Not Found
    // =========================================================================

    #[test]
    fn test_validate_access_unknown_user() {
        let manager = VendorIsolationManager::new(true);

        let result = manager.validate_access("nonexistent_vendor", "10.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_is_vendor_account_false_for_unknown() {
        let manager = VendorIsolationManager::new(true);
        assert!(!manager.is_vendor_account("ghost_vendor"));
    }

    // =========================================================================
    // Test: Rate Limiting
    // =========================================================================

    #[test]
    fn test_rate_limiting_enforcement() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_rate_test", &["10.0.0.0/8"]);
        account.upload_rate_limit_per_hour = 3; // Very low limit for testing
        manager.register_account(account).unwrap();

        // First 3 requests should succeed
        for i in 0..3 {
            let result = manager.check_rate_limit("vendor_rate_test");
            assert!(
                result.is_ok() && result.unwrap(),
                "Request {} should be allowed",
                i + 1
            );
        }

        // 4th request should be denied
        let result = manager.check_rate_limit("vendor_rate_test");
        assert!(result.is_ok());
        assert!(!result.unwrap(), "4th request should exceed rate limit");
    }

    #[test]
    fn test_rate_limit_unlimited() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_unlimited_test", &["10.0.0.0/8"]);
        account.upload_rate_limit_per_hour = 0; // Unlimited
        manager.register_account(account).unwrap();

        // Should never deny
        for _ in 0..100 {
            let result = manager.check_rate_limit("vendor_unlimited_test");
            assert!(result.is_ok());
            assert!(result.unwrap(), "Unlimited mode should never deny");
        }
    }

    #[test]
    fn test_rate_limit_unknown_vendor_error() {
        let manager = VendorIsolationManager::new(true);

        let result = manager.check_rate_limit("ghost_vendor");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // =========================================================================
    // Test: Dual Approval Requirement
    // =========================================================================

    #[test]
    fn test_dual_approval_required() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_dual_test", &["10.0.0.0/8"]);
        account.require_dual_approval = true;
        manager.register_account(account).unwrap();

        assert!(manager.requires_dual_approval("vendor_dual_test"));
    }

    #[test]
    fn test_dual_approval_not_required_by_default() {
        let manager = VendorIsolationManager::new(true);

        let account = create_test_account("vendor_no_dual_test", &["10.0.0.0/8"]);
        manager.register_account(account).unwrap();

        assert!(!manager.requires_dual_approval("vendor_no_dual_test"));
    }

    // =========================================================================
    // Test: Forced CDR Policy
    // =========================================================================

    #[test]
    fn test_forced_cdr_policy_lookup() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_cdr_test", &["10.0.0.0/8"]);
        account.force_max_cdr_policy = Some(String::from("convert_to_flat"));
        manager.register_account(account).unwrap();

        let policy = manager.get_required_cdr_policy("vendor_cdr_test");
        assert!(policy.is_some());
        assert_eq!(policy.unwrap(), "convert_to_flat");
    }

    #[test]
    fn test_no_forced_cdr_policy() {
        let manager = VendorIsolationManager::new(true);

        let account = create_test_account("vendor_no_cdr_test", &["10.0.0.0/8"]);
        manager.register_account(account).unwrap();

        let policy = manager.get_required_cdr_policy("vendor_no_cdr_test");
        assert!(policy.is_none());
    }

    // =========================================================================
    // Test: Max File Size
    // =========================================================================

    #[test]
    fn test_get_max_file_size_configured() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_size_test", &["10.0.0.0/8"]);
        account.max_file_size_mb = 256;
        manager.register_account(account).unwrap();

        let size = manager.get_max_file_size("vendor_size_test");
        assert!(size.is_some());
        assert_eq!(size.unwrap(), 256);
    }

    #[test]
    fn test_get_max_file_size_unlimited() {
        let manager = VendorIsolationManager::new(true);

        let mut account = create_test_account("vendor_nolimit_test", &["10.0.0.0/8"]);
        account.max_file_size_mb = 0; // No limit
        manager.register_account(account).unwrap();

        let size = manager.get_max_file_size("vendor_nolimit_test");
        assert!(size.is_none()); // None means unlimited
    }

    // =========================================================================
    // Test: Disabled Mode (Allow-All)
    // =========================================================================

    #[test]
    fn test_disabled_mode_allows_everything() {
        let manager = VendorIsolationManager::new(false); // DISABLED

        // Even without registering any account...
        let result = manager.validate_access("anyone", "1.2.3.4");
        assert!(result.is_ok());
        assert!(result.unwrap(), "Disabled mode should allow all");

        let rate_result = manager.check_rate_limit("anyone");
        assert!(rate_result.is_ok());
        assert!(rate_result.unwrap(), "Disabled mode should not rate-limit");
    }

    // =========================================================================
    // Test: Registration Validation
    // =========================================================================

    #[test]
    fn test_register_empty_user_id_fails() {
        let manager = VendorIsolationManager::new(true);

        let account = create_test_account("", &["10.0.0.0/8"]);
        let result = manager.register_account(account);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must not be empty"));
    }

    #[test]
    fn test_register_replaces_existing() {
        let manager = VendorIsolationManager::new(true);

        // First registration
        let account1 = create_test_account("vendor_replace_test", &["10.0.0.0/8"]);
        manager.register_account(account1).unwrap();
        assert_eq!(manager.account_count(), 1);

        // Second registration with same user_id (should replace)
        let account2 = create_test_account("vendor_replace_test", &["192.168.1.0/24"]);
        manager.register_account(account2).unwrap();
        assert_eq!(manager.account_count(), 1); // Still 1, not 2

        // New IP whitelist should be in effect
        let result = manager.validate_access("vendor_replace_test", "192.168.1.50");
        assert!(result.unwrap());

        let result = manager.validate_access("vendor_replace_test", "10.0.0.1");
        assert!(!result.unwrap()); // Old whitelist no longer applies
    }

    // =========================================================================
    // Test: IPv6 Support
    // =========================================================================

    #[test]
    fn test_ipv6_whitelist() {
        let manager = VendorIsolationManager::new(true);

        let account = VendorAccount {
            user_id: "vendor_ipv6_test".to_string(),
            display_name: "IPv6 Test".to_string(),
            ip_whitelist: vec!["fd00::/32".parse().unwrap()],
            ..Default::default()
        };
        manager.register_account(account).unwrap();

        let result = manager.validate_access("vendor_ipv6_test", "fd00::1");
        assert!(result.is_ok());
        assert!(result.unwrap(), "fd00::1 should be in fd00::/32");

        let result = manager.validate_access("vendor_ipv6_test", "fe80::1");
        assert!(result.is_ok());
        assert!(!result.unwrap(), "fe80::1 should NOT be in fd00::/32");
    }
}
