use serde::{Deserialize, Serialize};

/// User role classification aligned with Japanese organizational hierarchy for LGWAN (Local Government Wide Area Network) compliance.
///
/// # Role Hierarchy (lowest → highest privilege)
/// 1. **Staff**: Can upload files and request transfers. Cannot approve others' requests.
/// 2. **Approver**: Can upload AND approve/reject transfer requests from Staff members.
/// 3. **Admin**: Full administrative access including user management and system configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    /// 一般職員 (General Staff): File upload and transfer request creation only.
    /// Cannot access approval endpoints.
    Staff,

    /// 上長承認者 (Approver): Transfer request approval/rejection authority.
    /// Required for LGWAN-compliant file transfer workflows.
    Approver,

    /// 管理者 (Administrator): Full system access including user management,
    /// audit log export, and configuration changes.
    Admin,
}

impl UserRole {
    /// Check if this role can upload files to the system.
    pub fn can_upload(&self) -> bool {
        true
    }

    /// Check if this role can approve or reject transfer requests.
    pub fn can_approve(&self) -> bool {
        matches!(self, Self::Approver | Self::Admin)
    }

    /// Check if this role has full administrative privileges.
    pub fn can_administer(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Return the Japanese display name for this role (for UI/logging).
    pub fn display_name_jp(&self) -> &'static str {
        match self {
            Self::Staff => "一般職員",
            Self::Approver => "上長承認者",
            Self::Admin => "管理者",
        }
    }

    /// Compute the full permission set for this role.
    ///
    /// Returns a [`Permissions`] struct with all individual capability flags
    /// resolved according to the role's privilege level.
    ///
    /// # Permission Matrix
    ///
    /// | Permission       | Staff | Approver | Admin |
    /// |------------------|:-----:|:--------:|:-----:|
    /// | `file_upload`    |   ✅   |    ✅     |  ✅   |
    /// | `file_download`  |   ✅   |    ✅     |  ✅   |
    /// | `transfer_approve`|   ❌   |    ✅     |  ✅   |
    /// | `user_manage`    |   ❌   |    ❌     |  ✅   |
    /// | `policy_manage`  |   ❌   |    ❌     |  ✅   |
    /// | `audit_view`     |   ❌   |    ✅     |  ✅   |
    /// | `audit_export`   |   ❌   |    ❌     |  ✅   |
    /// | `system_config`  |   ❌   |    ❌     |  ✅   |
    /// | `api_key_manage` |   ❌   |    ❌     |  ✅   |
    pub fn permissions(&self) -> Permissions {
        match self {
            Self::Staff => Permissions {
                file_upload: true,
                file_download: true,
                transfer_approve: false,
                user_manage: false,
                policy_manage: false,
                audit_view: false,
                audit_export: false,
                system_config: false,
                api_key_manage: false,
            },
            Self::Approver => Permissions {
                file_upload: true,
                file_download: true,
                transfer_approve: true,
                user_manage: false,
                policy_manage: false,
                audit_view: true,
                audit_export: false,
                system_config: false,
                api_key_manage: false,
            },
            Self::Admin => Permissions {
                file_upload: true,
                file_download: true,
                transfer_approve: true,
                user_manage: true,
                policy_manage: true,
                audit_view: true,
                audit_export: true,
                system_config: true,
                api_key_manage: true,
            },
        }
    }
}

impl Default for UserRole {
    fn default() -> Self {
        Self::Staff
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Fine-Grained Permissions
// ---------------------------------------------------------------------------

/// Individual action that can be authorized within the Misogi system.
///
/// Used with [`Permissions::can`] for runtime authorization checks that are
/// more granular than the basic role-level methods on [`UserRole`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    /// Upload files into the system (ファイルアップロード).
    FileUpload,

    /// Download files from the system (ファイルダウンロード).
    FileDownload,

    /// Approve or reject pending transfer requests (転送承認・却下).
    TransferApprove,

    /// Create, modify, or deactivate user accounts (ユーザ管理).
    UserManage,

    /// Create or modify transfer policies and rules (ポリシー管理).
    PolicyManage,

    /// View audit logs (監査ログ閲覧).
    AuditView,

    /// Export audit logs to external format (監査ログエクスポート).
    AuditExport,

    /// Modify system-wide configuration settings (システム設定変更).
    SystemConfig,

    /// Create, rotate, or revoke API keys (API鍵管理).
    ApiKeyManage,
}

impl PermissionAction {
    /// Return the Japanese display name for this permission action.
    ///
    /// Useful for audit logging and admin UI display.
    pub fn display_name_jp(&self) -> &'static str {
        match self {
            Self::FileUpload => "ファイルアップロード",
            Self::FileDownload => "ファイルダウンロード",
            Self::TransferApprove => "転送承認・却下",
            Self::UserManage => "ユーザ管理",
            Self::PolicyManage => "ポリシー管理",
            Self::AuditView => "監査ログ閲覧",
            Self::AuditExport => "監査ログエクスポート",
            Self::SystemConfig => "システム設定変更",
            Self::ApiKeyManage => "API鍵管理",
        }
    }
}

impl std::fmt::Display for PermissionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name_jp())
    }
}

/// Fine-grained permission set derived from a [`UserRole`].
///
/// Each field represents an independent capability within the Misogi system.
/// Use [`can`](Self::can) for runtime checks against specific actions.
///
/// # Design Rationale
///
/// Boolean fields are preferred over bitflags for:
/// - **Clarity**: Each permission has a named field with documentation
/// - **Extensibility**: New permissions can be added without migration
/// - **Serialization**: Directly serializable to JSON for frontend consumption
/// - **Auditability**: Individual fields appear in structured logs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Permissions {
    // --- File Operations ---

    /// Permission to upload files into the Misogi system.
    /// Japanese: ファイルアップロード権限
    #[serde(default = "default_false")]
    pub file_upload: bool,

    /// Permission to download files from the Misogi system.
    /// Japanese: ファイルダウンロード権限
    #[serde(default = "default_false")]
    pub file_download: bool,

    // --- Workflow Operations ---

    /// Permission to approve or reject file transfer requests.
    /// Japanese: 転送承認権限
    #[serde(default = "default_false")]
    pub transfer_approve: bool,

    // --- Administration ---

    /// Permission to manage user accounts (create, edit, deactivate).
    /// Japanese: ユーザ管理権限
    #[serde(default = "default_false")]
    pub user_manage: bool,

    /// Permission to create and modify transfer policies and rules.
    /// Japanese: ポリシー管理権限
    #[serde(default = "default_false")]
    pub policy_manage: bool,

    // --- Audit & Compliance ---

    /// Permission to view audit logs.
    /// Japanese: 監査ログ閲覧権限
    #[serde(default = "default_false")]
    pub audit_view: bool,

    /// Permission to export audit logs to external formats (CSV, etc.).
    /// Required for compliance reporting under Japanese local government regulations.
    /// Japanese: 監査ログエクスポート権限
    #[serde(default = "default_false")]
    pub audit_export: bool,

    // --- System Administration ---

    /// Permission to modify global system configuration.
    /// Japanese: システム設定変更権限
    #[serde(default = "default_false")]
    pub system_config: bool,

    /// Permission to create, rotate, and revoke API keys for service accounts.
    /// Japanese: API鍵管理権限
    #[serde(default = "default_false")]
    pub api_key_manage: bool,
}

/// Default value for serde `#[serde(default)]` — always returns `false`.
const fn default_false() -> bool {
    false
}

impl Permissions {
    /// Check whether this permission set grants the specified action.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let perms = UserRole::Admin.permissions();
    /// assert!(perms.can(PermissionAction::SystemConfig));
    /// assert!(!perms.can(PermissionAction::NonExistentAction)); // compile error
    /// ```
    pub fn can(&self, action: PermissionAction) -> bool {
        match action {
            PermissionAction::FileUpload => self.file_upload,
            PermissionAction::FileDownload => self.file_download,
            PermissionAction::TransferApprove => self.transfer_approve,
            PermissionAction::UserManage => self.user_manage,
            PermissionAction::PolicyManage => self.policy_manage,
            PermissionAction::AuditView => self.audit_view,
            PermissionAction::AuditExport => self.audit_export,
            PermissionAction::SystemConfig => self.system_config,
            PermissionAction::ApiKeyManage => self.api_key_manage,
        }
    }

    /// Return a list of all granted actions in this permission set.
    ///
    /// Useful for displaying available capabilities in admin interfaces.
    pub fn granted_actions(&self) -> Vec<PermissionAction> {
        use PermissionAction::*;
        let mut actions = Vec::new();

        if self.file_upload { actions.push(FileUpload); }
        if self.file_download { actions.push(FileDownload); }
        if self.transfer_approve { actions.push(TransferApprove); }
        if self.user_manage { actions.push(UserManage); }
        if self.policy_manage { actions.push(PolicyManage); }
        if self.audit_view { actions.push(AuditView); }
        if self.audit_export { actions.push(AuditExport); }
        if self.system_config { actions.push(SystemConfig); }
        if self.api_key_manage { actions.push(ApiKeyManage); }

        actions
    }

    /// Return a fully permissive permission set (all flags set to `true`).
    ///
    /// Used internally for testing and superuser scenarios.
    pub fn all() -> Self {
        Self {
            file_upload: true,
            file_download: true,
            transfer_approve: true,
            user_manage: true,
            policy_manage: true,
            audit_view: true,
            audit_export: true,
            system_config: true,
            api_key_manage: true,
        }
    }

    /// Return a fully restrictive permission set (all flags set to `false`).
    ///
    /// Used as the base for building custom permission sets via explicit grants.
    pub fn none() -> Self {
        Self {
            file_upload: false,
            file_download: false,
            transfer_approve: false,
            user_manage: false,
            policy_manage: false,
            audit_view: false,
            audit_export: false,
            system_config: false,
            api_key_manage: false,
        }
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Self::none()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staff_permissions() {
        let perms = UserRole::Staff.permissions();

        assert!(perms.can(PermissionAction::FileUpload));
        assert!(perms.can(PermissionAction::FileDownload));
        assert!(!perms.can(PermissionAction::TransferApprove));
        assert!(!perms.can(PermissionAction::UserManage));
        assert!(!perms.can(PermissionAction::PolicyManage));
        assert!(!perms.can(PermissionAction::AuditView));
        assert!(!perms.can(PermissionAction::AuditExport));
        assert!(!perms.can(PermissionAction::SystemConfig));
        assert!(!perms.can(PermissionAction::ApiKeyManage));
    }

    #[test]
    fn test_approver_permissions() {
        let perms = UserRole::Approver.permissions();

        assert!(perms.can(PermissionAction::FileUpload));
        assert!(perms.can(PermissionAction::FileDownload));
        assert!(perms.can(PermissionAction::TransferApprove));
        assert!(!perms.can(PermissionAction::UserManage));
        assert!(!perms.can(PermissionAction::PolicyManage));
        assert!(perms.can(PermissionAction::AuditView));
        assert!(!perms.can(PermissionAction::AuditExport));
        assert!(!perms.can(PermissionAction::SystemConfig));
        assert!(!perms.can(PermissionAction::ApiKeyManage));
    }

    #[test]
    fn test_admin_permissions() {
        let perms = UserRole::Admin.permissions();

        assert!(perms.can(PermissionAction::FileUpload));
        assert!(perms.can(PermissionAction::FileDownload));
        assert!(perms.can(PermissionAction::TransferApprove));
        assert!(perms.can(PermissionAction::UserManage));
        assert!(perms.can(PermissionAction::PolicyManage));
        assert!(perms.can(PermissionAction::AuditView));
        assert!(perms.can(PermissionAction::AuditExport));
        assert!(perms.can(PermissionAction::SystemConfig));
        assert!(perms.can(PermissionAction::ApiKeyManage));
    }

    #[test]
    fn test_permission_action_display_names() {
        assert_eq!(
            PermissionAction::FileUpload.display_name_jp(),
            "ファイルアップロード"
        );
        assert_eq!(
            PermissionAction::AuditExport.display_name_jp(),
            "監査ログエクスポート"
        );
    }

    #[test]
    fn test_granted_actions_count() {
        let staff_perms = UserRole::Staff.permissions();
        assert_eq!(staff_perms.granted_actions().len(), 2);

        let admin_perms = UserRole::Admin.permissions();
        assert_eq!(admin_perms.granted_actions().len(), 9);
    }

    #[test]
    fn test_role_compatibility_with_legacy_methods() {
        // Ensure new permission model is consistent with legacy role methods
        let staff = UserRole::Staff;
        assert_eq!(staff.can_upload(), staff.permissions().file_upload);
        assert_eq!(
            staff.can_approve(),
            staff.permissions().transfer_approve
        );
        assert_eq!(
            staff.can_administer(),
            staff.permissions().system_config
                && staff.permissions().user_manage
        );

        let approver = UserRole::Approver;
        assert_eq!(approver.can_upload(), approver.permissions().file_upload);
        assert_eq!(
            approver.can_approve(),
            approver.permissions().transfer_approve
        );

        let admin = UserRole::Admin;
        assert_eq!(admin.can_upload(), admin.permissions().file_upload);
        assert_eq!(
            admin.can_administer(),
            admin.permissions().system_config
                && admin.permissions().user_manage
        );
    }
}
