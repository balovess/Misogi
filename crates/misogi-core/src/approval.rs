use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::error::{MisogiError, Result};

/// Approval status enum matching Japanese government workflow terminology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    PendingApproval,
    Approved,
    Rejected,
    Transferring,
    Completed,
    Failed,
    Expired,
}

impl Default for ApprovalStatus {
    fn default() -> Self {
        Self::PendingApproval
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingApproval => write!(f, "pending_approval"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Transferring => write!(f, "transferring"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Valid state transitions for approval workflow.
/// Returns true if transition is valid according to LGWAN compliance rules.
impl ApprovalStatus {
    pub fn can_transition_to(&self, target: &ApprovalStatus) -> bool {
        match (self, target) {
            (Self::PendingApproval, Self::Approved) => true,
            (Self::PendingApproval, Self::Rejected) => true,
            (Self::PendingApproval, Self::Expired) => true,
            (Self::Approved, Self::Transferring) => true,
            (Self::Transferring, Self::Completed) => true,
            (Self::Transferring, Self::Failed) => true,
            _ => false,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Rejected | Self::Failed | Self::Expired)
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::PendingApproval | Self::Approved | Self::Transferring)
    }
}

/// Transfer request representing a cross-network file transfer pending approval.
/// This is the core business entity for LGWAN-compliant workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub request_id: String,
    pub file_id: String,
    pub applicant_id: String,
    pub applicant_name: String,
    pub approver_id: Option<String>,
    pub approver_name: Option<String>,
    pub transfer_reason: String,
    pub original_filename: String,
    pub file_size: u64,
    pub original_hash: String,
    pub sanitized_hash: Option<String>,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl TransferRequest {
    pub fn new(
        file_id: String,
        applicant_id: String,
        applicant_name: String,
        transfer_reason: String,
    ) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            file_id,
            applicant_id,
            applicant_name,
            approver_id: None,
            approver_name: None,
            transfer_reason,
            original_filename: String::new(),
            file_size: 0,
            original_hash: String::new(),
            sanitized_hash: None,
            status: ApprovalStatus::PendingApproval,
            created_at: Utc::now(),
            approved_at: None,
            rejection_reason: None,
            expires_at: None,
        }
    }

    pub fn with_file_info(mut self, filename: String, size: u64, hash: String) -> Self {
        self.original_filename = filename;
        self.file_size = size;
        self.original_hash = hash;
        self
    }

    pub fn with_sanitized_hash(mut self, hash: String) -> Self {
        self.sanitized_hash = Some(hash);
        self
    }

    pub fn with_approver(mut self, approver_id: String, approver_name: String) -> Self {
        self.approver_id = Some(approver_id);
        self.approver_name = Some(approver_name);
        self
    }

    pub fn with_expiry(mut self, hours: i64) -> Self {
        self.expires_at = Some(Utc::now() + chrono::Duration::hours(hours));
        self
    }

    pub fn approve(&mut self, approver_id: &str) -> Result<()> {
        if !self.status.can_transition_to(&ApprovalStatus::Approved) {
            return Err(MisogiError::Protocol(format!(
                "Cannot approve request in status {:?}",
                self.status
            )));
        }

        if let Some(ref assigned_approver) = self.approver_id {
            if assigned_approver != approver_id {
                return Err(MisogiError::Protocol(
                    "Approver ID mismatch: only the assigned approver can approve this request".to_string(),
                ));
            }
        } else {
            return Err(MisogiError::Protocol(
                "No approver assigned to this request".to_string(),
            ));
        }

        self.status = ApprovalStatus::Approved;
        self.approved_at = Some(Utc::now());
        Ok(())
    }

    pub fn reject(&mut self, approver_id: &str, reason: String) -> Result<()> {
        if !self.status.can_transition_to(&ApprovalStatus::Rejected) {
            return Err(MisogiError::Protocol(format!(
                "Cannot reject request in status {:?}",
                self.status
            )));
        }

        if let Some(ref assigned_approver) = self.approver_id {
            if assigned_approver != approver_id {
                return Err(MisogiError::Protocol(
                    "Approver ID mismatch: only the assigned approver can reject this request"
                        .to_string(),
                ));
            }
        } else {
            return Err(MisogiError::Protocol(
                "No approver assigned to this request".to_string(),
            ));
        }

        self.status = ApprovalStatus::Rejected;
        self.rejection_reason = Some(reason);
        Ok(())
    }

    pub fn start_transfer(&mut self) -> Result<()> {
        if !self.status.can_transition_to(&ApprovalStatus::Transferring) {
            return Err(MisogiError::Protocol(format!(
                "Cannot start transfer in status {:?}",
                self.status
            )));
        }

        self.status = ApprovalStatus::Transferring;
        Ok(())
    }

    pub fn complete_transfer(&mut self) -> Result<()> {
        if !self.status.can_transition_to(&ApprovalStatus::Completed) {
            return Err(MisogiError::Protocol(format!(
                "Cannot complete transfer in status {:?}",
                self.status
            )));
        }

        self.status = ApprovalStatus::Completed;
        Ok(())
    }

    pub fn fail_transfer(&mut self) -> Result<()> {
        if !self.status.can_transition_to(&ApprovalStatus::Failed) {
            return Err(MisogiError::Protocol(format!(
                "Cannot mark as failed in status {:?}",
                self.status
            )));
        }

        self.status = ApprovalStatus::Failed;
        Ok(())
    }

    pub fn expire(&mut self) -> Result<()> {
        if !self.status.can_transition_to(&ApprovalStatus::Expired) {
            return Err(MisogiError::Protocol(format!(
                "Cannot expire request in status {:?}",
                self.status
            )));
        }

        self.status = ApprovalStatus::Expired;
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at && self.status == ApprovalStatus::PendingApproval
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_status_transitions() {
        assert!(ApprovalStatus::PendingApproval.can_transition_to(&ApprovalStatus::Approved));
        assert!(ApprovalStatus::PendingApproval.can_transition_to(&ApprovalStatus::Rejected));
        assert!(ApprovalStatus::PendingApproval.can_transition_to(&ApprovalStatus::Expired));
        assert!(!ApprovalStatus::PendingApproval.can_transition_to(&ApprovalStatus::Transferring));
        assert!(!ApprovalStatus::PendingApproval.can_transition_to(&ApprovalStatus::Completed));

        assert!(ApprovalStatus::Approved.can_transition_to(&ApprovalStatus::Transferring));
        assert!(!ApprovalStatus::Approved.can_transition_to(&ApprovalStatus::Completed));

        assert!(ApprovalStatus::Transferring.can_transition_to(&ApprovalStatus::Completed));
        assert!(ApprovalStatus::Transferring.can_transition_to(&ApprovalStatus::Failed));
        assert!(!ApprovalStatus::Transferring.can_transition_to(&ApprovalStatus::Approved));
    }

    #[test]
    fn test_terminal_states() {
        assert!(ApprovalStatus::Completed.is_terminal());
        assert!(ApprovalStatus::Rejected.is_terminal());
        assert!(ApprovalStatus::Failed.is_terminal());
        assert!(ApprovalStatus::Expired.is_terminal());
        assert!(!ApprovalStatus::PendingApproval.is_terminal());
        assert!(!ApprovalStatus::Approved.is_terminal());
        assert!(!ApprovalStatus::Transferring.is_terminal());
    }

    #[test]
    fn test_transfer_request_lifecycle() {
        let mut req = TransferRequest::new(
            "file-001".to_string(),
            "user-001".to_string(),
            "田中 太郎".to_string(),
            "緊急書類送付".to_string(),
        );

        assert_eq!(req.status, ApprovalStatus::PendingApproval);

        let result = req.approve("unknown");
        assert!(result.is_err());

        req = req.with_approver("approver-001".to_string(), "佐藤 部長".to_string());

        req.approve("approver-001").unwrap();
        assert_eq!(req.status, ApprovalStatus::Approved);
        assert!(req.approved_at.is_some());

        req.start_transfer().unwrap();
        assert_eq!(req.status, ApprovalStatus::Transferring);

        req.complete_transfer().unwrap();
        assert_eq!(req.status, ApprovalStatus::Completed);
    }

    #[test]
    fn test_rejection_flow() {
        let mut req = TransferRequest::new(
            "file-002".to_string(),
            "user-002".to_string(),
            "鈴木 次郎".to_string(),
            "機密文書転送".to_string(),
        )
        .with_approver("approver-002".to_string(), "高橋 課長".to_string());

        req.reject("approver-002", "不適切な内容が含まれています".to_string())
            .unwrap();

        assert_eq!(req.status, ApprovalStatus::Rejected);
        assert_eq!(req.rejection_reason.as_deref(), Some("不適切な内容が含まれています"));
    }

    #[test]
    fn test_invalid_transitions() {
        let mut req = TransferRequest::new(
            "file-003".to_string(),
            "user-003".to_string(),
            "伊藤 美咲".to_string(),
            "通常転送".to_string(),
        )
        .with_approver("approver-003".to_string(), "渡辺 係長".to_string());

        let result = req.start_transfer();
        assert!(result.is_err());

        req.approve("approver-003").unwrap();

        let result = req.complete_transfer();
        assert!(result.is_err());
    }
}
