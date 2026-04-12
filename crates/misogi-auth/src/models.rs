use serde::{Deserialize, Serialize};
use super::role::UserRole;
use chrono::{DateTime, Utc};

/// Represents an authenticated user within the Misogi system.
/// Designed for integration with external identity providers (LDAP, Active Directory, SAML).
/// Local storage is file-backed JSON; production deployments should replace with IDP integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier (e.g., employee number, UPN, or UUID)
    pub user_id: String,
    /// Display name in Japanese format (e.g., "田中 太郎")
    pub display_name: String,
    /// Email address (optional, used for notifications)
    pub email: Option<String>,
    /// Department/section affiliation (e.g., "総務課")
    pub department: Option<String>,
    /// Assigned role determining permissions
    pub role: UserRole,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Whether account is active
    pub is_active: bool,
}

impl User {
    pub fn new(user_id: String, display_name: String, role: UserRole) -> Self {
        Self {
            user_id,
            display_name,
            email: None,
            department: None,
            role,
            created_at: Utc::now(),
            is_active: true,
        }
    }

    pub fn staff(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id.into(), name.into(), UserRole::Staff)
    }

    pub fn approver(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id.into(), name.into(), UserRole::Approver)
    }

    pub fn admin(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id.into(), name.into(), UserRole::Admin)
    }
}

/// Lightweight session token for API authentication.
/// In production, replace with JWT/OIDC tokens from enterprise IDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub token_id: String,
    pub user_id: String,
    pub user_name: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SessionToken {
    pub fn new(user: &User, ttl_hours: i64) -> Self {
        let now = Utc::now();
        Self {
            token_id: uuid::Uuid::new_v4().to_string(),
            user_id: user.user_id.clone(),
            user_name: user.display_name.clone(),
            role: user.role.clone(),
            created_at: now.clone(),
            expires_at: now + chrono::Duration::hours(ttl_hours),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}
