use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use super::models::{User, SessionToken};
use super::role::UserRole;
use misogi_core::Result;

/// In-memory user store backed by optional JSON file persistence.
/// Thread-safe via Arc<RwLock<>> pattern.
///
/// ## Storage Format
/// ```json
/// [
///   {"user_id":"001","display_name":"田中太郎","role":"staff","department":"総務課","is_active":true,"created_at":"..."},
///   ...
/// ]
/// ```
pub struct UserStore {
    users: RwLock<HashMap<String, User>>,
    sessions: RwLock<HashMap<String, SessionToken>>,
    storage_path: Option<PathBuf>,
}

impl UserStore {
    /// Create new in-memory store (no file backing)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            storage_path: None,
        })
    }

    /// Create store with JSON file backing (load existing users on creation)
    pub async fn with_file(path: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let path = path.into();
        let store = Arc::new(Self {
            users: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            storage_path: Some(path.clone()),
        });

        if path.exists() {
            store.load_from_file().await?;
        } else {
            store.seed_default_users().await?;
        }

        Ok(store)
    }

    /// Load users from JSON file
    async fn load_from_file(&self) -> Result<()> {
        let path = self.storage_path.as_ref().ok_or_else(|| {
            misogi_core::MisogiError::Protocol("No storage path configured".to_string())
        })?;

        let content = tokio::fs::read_to_string(path).await?;
        let users: Vec<User> = serde_json::from_str(&content)?;

        let mut user_map = self.users.write().await;
        user_map.clear();
        for user in users {
            user_map.insert(user.user_id.clone(), user);
        }

        info!("Loaded {} users from {}", user_map.len(), path.display());
        Ok(())
    }

    /// Seed default demo users for first-time setup
    async fn seed_default_users(&self) -> Result<()> {
        let mut users = self.users.write().await;

        let staff_user = User {
            user_id: "staff001".to_string(),
            display_name: "田中太郎".to_string(),
            email: None,
            department: Some("総務課".to_string()),
            role: UserRole::Staff,
            created_at: chrono::Utc::now(),
            is_active: true,
        };

        let approver_user = User {
            user_id: "approver001".to_string(),
            display_name: "山本一郎".to_string(),
            email: None,
            department: Some("総務課長".to_string()),
            role: UserRole::Approver,
            created_at: chrono::Utc::now(),
            is_active: true,
        };

        let admin_user = User {
            user_id: "admin001".to_string(),
            display_name: "管理者".to_string(),
            email: None,
            department: None,
            role: UserRole::Admin,
            created_at: chrono::Utc::now(),
            is_active: true,
        };

        users.insert(staff_user.user_id.clone(), staff_user);
        users.insert(approver_user.user_id.clone(), approver_user);
        users.insert(admin_user.user_id.clone(), admin_user);

        info!("Seeded 3 default users (staff, approver, admin)");
        drop(users);

        self.save_to_file().await
    }

    /// Persist current state to file
    pub async fn save_to_file(&self) -> Result<()> {
        let path = self.storage_path.as_ref().ok_or_else(|| {
            misogi_core::MisogiError::Protocol("No storage path configured".to_string())
        })?;

        let users = self.users.read().await;
        let user_vec: Vec<User> = users.values().cloned().collect();
        drop(users);

        let content = serde_json::to_string_pretty(&user_vec)?;

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(path, content).await?;

        info!("Saved {} users to disk", user_vec.len());
        Ok(())
    }

    // --- Query operations ---

    pub async fn get_user(&self, user_id: &str) -> Option<User> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    pub async fn list_users(&self) -> Vec<User> {
        let users = self.users.read().await;
        users.values().cloned().collect()
    }

    pub async fn list_by_role(&self, role: &UserRole) -> Vec<User> {
        let users = self.users.read().await;
        users.values()
            .filter(|u| &u.role == role)
            .cloned()
            .collect()
    }

    pub async fn find_approvers(&self) -> Vec<User> {
        self.list_by_role(&UserRole::Approver).await
    }

    // --- Mutation operations ---

    pub async fn add_user(&self, user: User) -> Result<()> {
        let mut users = self.users.write().await;
        if users.contains_key(&user.user_id) {
            return Err(misogi_core::MisogiError::AlreadyExists(format!(
                "User {} already exists",
                user.user_id
            )));
        }
        users.insert(user.user_id.clone(), user);
        drop(users);

        if self.storage_path.is_some() {
            self.save_to_file().await?;
        }

        info!("Added new user");
        Ok(())
    }

    pub async fn update_role(&self, user_id: &str, role: UserRole) -> Result<bool> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(user_id) {
            user.role = role;
            drop(users);

            if self.storage_path.is_some() {
                self.save_to_file().await?;
            }

            info!("Updated role for user {}", user_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn deactivate_user(&self, user_id: &str) -> Result<bool> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(user_id) {
            user.is_active = false;
            drop(users);

            if self.storage_path.is_some() {
                self.save_to_file().await?;
            }

            info!("Deactivated user {}", user_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // --- Session operations ---

    pub async fn create_session(&self, user: &User) -> SessionToken {
        let token = SessionToken::new(user, 24);
        let mut sessions = self.sessions.write().await;
        sessions.insert(token.token_id.clone(), token.clone());
        drop(sessions);

        info!("Created session for user {}", user.user_id);
        token
    }

    pub async fn validate_session(&self, token_id: &str) -> Option<SessionToken> {
        let sessions = self.sessions.read().await;
        let token = sessions.get(token_id)?;

        if token.is_expired() {
            warn!("Session expired for token {}", token_id);
            return None;
        }

        Some(token.clone())
    }

    pub async fn revoke_session(&self, token_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(token_id).is_some() {
            info!("Revoked session {}", token_id);
            true
        } else {
            false
        }
    }

    // --- Auth check helpers ---

    pub async fn can_approve(&self, user_id: &str) -> bool {
        self.get_user(user_id)
            .await
            .map(|u| u.role.can_approve())
            .unwrap_or(false)
    }
}
