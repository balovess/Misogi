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
    pub fn can_upload(&self) -> bool {
        true
    }

    pub fn can_approve(&self) -> bool {
        matches!(self, Self::Approver | Self::Admin)
    }

    pub fn can_administer(&self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn display_name_jp(&self) -> &'static str {
        match self {
            Self::Staff => "一般職員",
            Self::Approver => "上長承認者",
            Self::Admin => "管理者",
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
