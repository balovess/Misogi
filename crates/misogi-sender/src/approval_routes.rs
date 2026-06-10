use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use misogi_core::{
    FileStatus,
    approval::{ApprovalStatus, TransferRequest},
    audit_log::{AuditEventType, AuditLogEntry},
};
use serde::{Deserialize, Serialize};
// ABAC integration imports (Task 6.28)
use misogi_core::abac::{
    AbacDecision, AbacValue, Obligation, PolicyEffect,
    policy::ApprovalTemplate,
};

// ============================================================================
// Request / Response DTOs
// ============================================================================

#[derive(Deserialize)]
pub struct CreateTransferRequest {
    pub file_id: String,
    pub applicant_id: String,
    pub approver_id: String,
    pub transfer_reason: String,
}

#[derive(Deserialize)]
pub struct ApproveBody {
    pub approver_id: String,
}

#[derive(Deserialize)]
pub struct RejectBody {
    pub approver_id: String,
    pub rejection_reason: String,
}

#[derive(Deserialize)]
pub struct ListPendingQuery {
    pub approver_id: Option<String>,
}

#[derive(Deserialize)]
pub struct ListTransfersQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct ListTransfersResponse {
    pub transfers: Vec<TransferRequest>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
    #[serde(skip)]
    #[allow(dead_code)]
    pub code: StatusCode,
}

impl ApiError {
    fn new(msg: impl Into<String>, code: StatusCode) -> (StatusCode, Json<Self>) {
        (
            code,
            Json(Self {
                error: msg.into(),
                code,
            }),
        )
    }
}

// ============================================================================
// POST /api/v1/transfers — Create transfer request
// ============================================================================

pub async fn create_transfer_request(
    State(state): State<SharedState>,
    Json(body): Json<CreateTransferRequest>,
) -> Result<(StatusCode, Json<TransferRequest>), (StatusCode, Json<ApiError>)> {
    // Validation: transfer_reason must not be empty (Ministry of Internal Affairs compliance)
    if body.transfer_reason.trim().is_empty() {
        return Err(ApiError::new(
            "transfer_reason is required and cannot be empty",
            StatusCode::BAD_REQUEST,
        ));
    }

    // Validation: applicant_id != approver_id (self-approval is prohibited)
    if body.applicant_id == body.approver_id {
        return Err(ApiError::new(
            "applicant_id must differ from approver_id; self-approval is prohibited",
            StatusCode::BAD_REQUEST,
        ));
    }

    // Validation: file_id must exist and status must be Ready
    let file_info = state.get_file(&body.file_id).await.ok_or_else(|| {
        ApiError::new(
            format!("File not found: {}", body.file_id),
            StatusCode::NOT_FOUND,
        )
    })?;

    if file_info.status != FileStatus::Ready {
        return Err(ApiError::new(
            format!(
                "File {} is not ready for transfer (current status: {:?})",
                body.file_id, file_info.status
            ),
            StatusCode::CONFLICT,
        ));
    }

    // ========================================================================
    // ABAC Policy Evaluation (Task 6.28)
    // ========================================================================
    // Evaluate access request against ABAC policy rules before proceeding.
    // This step is optional and skipped when ABAC is not configured.
    let abac_decision = if let (Some(engine), Some(resolver)) =
        (&state.abac_engine, &state.attribute_resolver)
    {
        // Build attribute map for policy evaluation
        let mut attributes = std::collections::HashMap::new();

        // Subject attributes (who is requesting)
        let subject_attrs = resolver.resolve_subject_attributes(
            &body.applicant_id,
            "staff", // Default role; should be resolved from user store
            "default", // Default department; should be resolved from user store
            std::collections::HashMap::new(),
        );
        for (k, v) in subject_attrs {
            attributes.insert(k, v);
        }

        // Resource attributes (what is being transferred)
        let resource_attrs = resolver.resolve_resource_attributes(
            "internal", // Default classification; should be from file metadata
            &file_info.filename,
            file_info.total_size,
            "default", // Destination zone
            false,      // Contains PII; should be from PII scan results
            std::collections::HashMap::new(),
        );
        for (k, v) in resource_attrs {
            attributes.insert(k, v);
        }

        // Environment attributes (context of the request)
        let env_attrs = resolver.resolve_environment_attributes(
            "127.0.0.1", // Source IP; should be from request context
            "JP",        // Geographic region; should be from IP geolocation
            false,       // MFA verified; should be from session state
            true,        // Device compliant; should be from device attestation
            std::collections::HashMap::new(),
        );
        for (k, v) in env_attrs {
            attributes.insert(k, v);
        }

        // Evaluate policy against resolved attributes
        let decision = engine.evaluate(&attributes).await;

        // Record ABAC decision in audit log
        let abac_audit = AuditLogEntry::new(AuditEventType::Custom(
            "abac_policy_evaluated".to_string(),
        ))
        .with_actor(&body.applicant_id, &body.applicant_id, "applicant")
        .with_file(&body.file_id, &file_info.filename)
        .with_custom_field("abac_effect", &format!("{:?}", decision.effect))
        .with_custom_field("abac_matched_rule", decision.matched_rule_id.as_deref().unwrap_or("none"))
        .with_custom_field("abac_evaluated_rules", &decision.evaluated_rules.to_string())
        .with_custom_field("abac_cache_hit", &decision.cache_hit.to_string());
        let _ = state.audit_log.record(abac_audit).await;

        tracing::info!(
            file_id = %body.file_id,
            applicant_id = %body.applicant_id,
            effect = ?decision.effect,
            matched_rule = ?decision.matched_rule_id,
            evaluated_rules = decision.evaluated_rules,
            cache_hit = decision.cache_hit,
            "ABAC policy evaluation completed"
        );

        Some(decision)
    } else {
        // ABAC not configured; proceed without policy evaluation
        tracing::debug!("ABAC not configured; skipping policy evaluation");
        None
    };

    // Enforce ABAC decision: Deny access if policy denies
    if let Some(ref decision) = abac_decision {
        if decision.is_denied() {
            return Err(ApiError::new(
                "Access denied by ABAC policy. The transfer request does not meet the required security conditions.",
                StatusCode::FORBIDDEN,
            ));
        }
    }

    // ========================================================================
    // Handle ABAC Obligations (Task 6.28)
    // ========================================================================
    // Process obligations from ABAC decision (approval, MFA, justification, etc.)
    let obligation_result = if let Some(ref decision) = abac_decision {
        handle_abac_obligation(&state, decision, &body).await?
    } else {
        ObligationResult::Proceed
    };

    // Resolve applicant name from user store
    let applicant_name = state
        .user_store
        .get_user(&body.applicant_id)
        .await
        .map(|u| u.display_name)
        .unwrap_or_else(|| body.applicant_id.clone());

    // Resolve approver name from user store
    let approver_name = state
        .user_store
        .get_user(&body.approver_id)
        .await
        .map(|u| u.display_name)
        .unwrap_or_else(|| body.approver_id.clone());

    // Build TransferRequest entity
    let request = TransferRequest::new(
        body.file_id.clone(),
        body.applicant_id.clone(),
        applicant_name,
        body.transfer_reason.clone(),
    )
    .with_approver(body.approver_id.clone(), approver_name)
    .with_file_info(
        file_info.filename.clone(),
        file_info.total_size,
        file_info.file_md5.clone(),
    )
    .with_expiry(24);

    // Store request in shared state
    let request_id = request.request_id.clone();
    state.add_transfer_request(request.clone()).await;

    // Record audit log: TransferRequested
    let audit_entry = AuditLogEntry::new(AuditEventType::TransferRequested)
        .with_actor(&body.applicant_id, &request.applicant_name, "staff")
        .with_file(&body.file_id, &file_info.filename)
        .with_file_size(file_info.total_size)
        .with_hashes(&file_info.file_md5, "")
        .with_transfer_request(&request_id, &body.transfer_reason);
    let _ = state.audit_log.record(audit_entry).await;

    tracing::info!(
        request_id = %request_id,
        file_id = %body.file_id,
        applicant_id = %body.applicant_id,
        approver_id = %body.approver_id,
        "Transfer request created"
    );

    Ok((StatusCode::CREATED, Json(request)))
}

// ============================================================================
// GET /api/v1/transfers/pending — List pending approval requests
// ============================================================================

pub async fn list_pending_requests(
    State(state): State<SharedState>,
    Query(query): Query<ListPendingQuery>,
) -> Json<Vec<TransferRequest>> {
    let pending = state
        .list_pending_requests(query.approver_id.as_deref())
        .await;
    Json(pending)
}

// ============================================================================
// POST /api/v1/transfers/{request_id}/approve — Approve a transfer request
// ============================================================================

pub async fn approve_request(
    State(state): State<SharedState>,
    Path(request_id): Path<String>,
    Json(body): Json<ApproveBody>,
) -> Result<(StatusCode, Json<TransferRequest>), (StatusCode, Json<ApiError>)> {
    let mut request = state
        .get_transfer_request(&request_id)
        .await
        .ok_or_else(|| {
            ApiError::new(
                format!("Transfer request not found: {}", request_id),
                StatusCode::NOT_FOUND,
            )
        })?;

    // Validation: current status must be PendingApproval
    if request.status != ApprovalStatus::PendingApproval {
        return Err(ApiError::new(
            format!(
                "Cannot approve request in status '{}'. Only PendingApproval can be approved.",
                request.status
            ),
            StatusCode::CONFLICT,
        ));
    }

    // Validation: approver_id must match the assigned approver
    if request.approver_id.as_deref() != Some(&body.approver_id) {
        return Err(ApiError::new(
            "Approver ID mismatch: only the assigned approver can approve this request",
            StatusCode::FORBIDDEN,
        ));
    }

    // Validation: approver role must be Approver or Admin
    let can_approve = state.user_store.can_approve(&body.approver_id).await;
    if !can_approve {
        return Err(ApiError::new(
            "User does not have approval privileges (role must be Approver or Admin)",
            StatusCode::FORBIDDEN,
        ));
    }

    // Execute approval on the domain entity (legacy approach, backward compatible)
    //
    // Task 5.14 Note: This currently uses direct request.approve().
    // Future enhancement: Integrate StateMachine<ApprovalStatus> for validated
    // state transitions (PendingApproval → Approved via machine.transition()).
    // Blocking issue: ApprovalStatus does not implement Hash trait required by
    // StateMachine. Resolution pending enum derivation update.
    request
        .approve(&body.approver_id)
        .map_err(|e| ApiError::new(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    // Persist updated request back to state
    state
        .update_transfer_request(&request_id, request.clone())
        .await;

    // Record audit log: TransferApproved
    let audit_entry = AuditLogEntry::new(AuditEventType::TransferApproved)
        .with_actor(
            &body.approver_id,
            request.approver_name.as_deref().unwrap_or(""),
            "approver",
        )
        .with_file(&request.file_id, &request.original_filename)
        .with_approver(&body.approver_id)
        .with_transfer_request(&request_id, &request.transfer_reason);
    let _ = state.audit_log.record(audit_entry).await;

    // Auto-trigger tunnel transfer after approval
    let trigger_result = crate::http_routes::trigger_transfer(
        axum::extract::Path(request.file_id.clone()),
        State(state.clone()),
    )
    .await;

    match trigger_result {
        Ok(_) => {
            tracing::info!(
                request_id = %request_id,
                file_id = %request.file_id,
                "Transfer request approved and tunnel transfer triggered"
            );
        }
        Err((status, msg)) => {
            tracing::warn!(
                request_id = %request_id,
                file_id = %request.file_id,
                error = %msg,
                status = ?status,
                "Transfer approved but auto-trigger failed"
            );
        }
    }

    Ok((StatusCode::OK, Json(request)))
}

// ============================================================================
// POST /api/v1/transfers/{request_id}/reject — Reject a transfer request
// ============================================================================

pub async fn reject_request(
    State(state): State<SharedState>,
    Path(request_id): Path<String>,
    Json(body): Json<RejectBody>,
) -> Result<(StatusCode, Json<TransferRequest>), (StatusCode, Json<ApiError>)> {
    // Validation: rejection_reason is mandatory
    if body.rejection_reason.trim().is_empty() {
        return Err(ApiError::new(
            "rejection_reason is required and cannot be empty",
            StatusCode::BAD_REQUEST,
        ));
    }

    let mut request = state
        .get_transfer_request(&request_id)
        .await
        .ok_or_else(|| {
            ApiError::new(
                format!("Transfer request not found: {}", request_id),
                StatusCode::NOT_FOUND,
            )
        })?;

    // Validation: current status must be PendingApproval
    if request.status != ApprovalStatus::PendingApproval {
        return Err(ApiError::new(
            format!(
                "Cannot reject request in status '{}'. Only PendingApproval can be rejected.",
                request.status
            ),
            StatusCode::CONFLICT,
        ));
    }

    // Validation: approver_id must match the assigned approver
    if request.approver_id.as_deref() != Some(&body.approver_id) {
        return Err(ApiError::new(
            "Approver ID mismatch: only the assigned approver can reject this request",
            StatusCode::FORBIDDEN,
        ));
    }

    // Execute rejection on the domain entity (legacy approach, backward compatible)
    //
    // Task 5.14 Note: See approve_request() above regarding StateMachine integration.
    request
        .reject(&body.approver_id, body.rejection_reason.clone())
        .map_err(|e| ApiError::new(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    // Persist updated request back to state
    state
        .update_transfer_request(&request_id, request.clone())
        .await;

    // Record audit log: TransferRejected
    let audit_entry = AuditLogEntry::new(AuditEventType::TransferRejected)
        .with_actor(
            &body.approver_id,
            request.approver_name.as_deref().unwrap_or(""),
            "approver",
        )
        .with_file(&request.file_id, &request.original_filename)
        .with_rejection_reason(&body.rejection_reason)
        .with_approver(&body.approver_id)
        .with_transfer_request(&request_id, &request.transfer_reason);
    let _ = state.audit_log.record(audit_entry).await;

    tracing::info!(
        request_id = %request_id,
        file_id = %request.file_id,
        reason = %body.rejection_reason,
        "Transfer request rejected"
    );

    Ok((StatusCode::OK, Json(request)))
}

// ============================================================================
// GET /api/v1/transfers — List all transfer requests (paginated)
// ============================================================================

pub async fn list_transfers(
    State(state): State<SharedState>,
    Query(query): Query<ListTransfersQuery>,
) -> Json<ListTransfersResponse> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    let status_filter = query.status.and_then(|s| match s.to_lowercase().as_str() {
        "pending" | "pending_approval" => Some(ApprovalStatus::PendingApproval),
        "approved" => Some(ApprovalStatus::Approved),
        "rejected" => Some(ApprovalStatus::Rejected),
        "transferring" => Some(ApprovalStatus::Transferring),
        "completed" => Some(ApprovalStatus::Completed),
        "failed" => Some(ApprovalStatus::Failed),
        "expired" => Some(ApprovalStatus::Expired),
        _ => None,
    });

    let (transfers, total) = state
        .list_transfer_requests(page, per_page, status_filter.as_ref())
        .await;

    Json(ListTransfersResponse {
        transfers,
        total,
        page,
        per_page,
    })
}

// ============================================================================
// GET /api/v1/transfers/{request_id} — Get single transfer request detail
// ============================================================================

pub async fn get_transfer(
    State(state): State<SharedState>,
    Path(request_id): Path<String>,
) -> Result<(StatusCode, Json<TransferRequest>), (StatusCode, Json<ApiError>)> {
    let request = state
        .get_transfer_request(&request_id)
        .await
        .ok_or_else(|| {
            ApiError::new(
                format!("Transfer request not found: {}", request_id),
                StatusCode::NOT_FOUND,
            )
        })?;

    Ok((StatusCode::OK, Json(request)))
}

// ============================================================================
// ABAC Integration Helpers (Task 6.28)
// ============================================================================

/// Result of processing ABAC obligation.
///
/// Indicates whether the transfer should proceed immediately or
/// requires additional steps (approval, MFA, justification, etc.).
#[derive(Debug, Clone)]
enum ObligationResult {
    /// Transfer may proceed immediately without additional steps.
    Proceed,
    /// Transfer requires approval before proceeding.
    /// Contains the approval request ID for tracking.
    RequiresApproval(String),
    /// Transfer requires MFA re-authentication.
    RequiresMfa,
    /// Transfer requires business justification.
    RequiresJustification,
}

/// Process ABAC obligation from policy decision.
///
/// Examines the obligation attached to the ABAC decision and takes
/// appropriate action (trigger approval, require MFA, etc.).
///
/// # Arguments
/// * `state` - Application state containing ABAC components.
/// * `decision` - ABAC decision with optional obligation.
/// * `body` - Original transfer request body.
///
/// # Returns
/// * `Ok(ObligationResult::Proceed)` - No obligation or obligation fulfilled.
/// * `Ok(ObligationResult::RequiresApproval(id))` - Approval request created.
/// * `Err(...)` - Failed to process obligation.
async fn handle_abac_obligation(
    state: &SharedState,
    decision: &AbacDecision,
    body: &CreateTransferRequest,
) -> Result<ObligationResult, (StatusCode, Json<ApiError>)> {
    // Extract obligation from decision
    let obligation = match &decision.obligation {
        Some(obl) => obl,
        None => return Ok(ObligationResult::Proceed),
    };

    match obligation {
        Obligation::None => {
            // No obligation; proceed immediately
            Ok(ObligationResult::Proceed)
        }

        Obligation::RequireApproval(template) => {
            // Trigger approval workflow via ApprovalExecutor
            if let Some(executor) = &state.approval_executor {
                // Build attribute map for approver selection
                let mut attr_map = std::collections::HashMap::new();
                attr_map.insert(
                    "user_id".to_string(),
                    AbacValue::String(body.applicant_id.clone()),
                );

                // Execute approval template
                match executor.execute_template(
                    &template.template_id,
                    decision.matched_rule_id.as_deref().unwrap_or("unknown"),
                    &body.applicant_id,
                    &format!("Transfer request for file {}", body.file_id),
                    &attr_map,
                ) {
                    Ok(approval_request) => {
                        // Record approval request creation in audit log
                        let audit_entry = AuditLogEntry::new(AuditEventType::Custom(
                            "abac_approval_triggered".to_string(),
                        ))
                        .with_actor(&body.applicant_id, &body.applicant_id, "applicant")
                        .with_file(&body.file_id, "")
                        .with_custom_field("approval_request_id", &approval_request.request_id)
                        .with_custom_field("template_id", &template.template_id)
                        .with_custom_field("required_approvers", &template.required_approvers.to_string());
                        let _ = state.audit_log.record(audit_entry).await;

                        tracing::info!(
                            approval_request_id = %approval_request.request_id,
                            template_id = %template.template_id,
                            file_id = %body.file_id,
                            applicant_id = %body.applicant_id,
                            "ABAC obligation triggered: approval required"
                        );

                        Ok(ObligationResult::RequiresApproval(approval_request.request_id))
                    }
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            template_id = %template.template_id,
                            "Failed to execute approval template"
                        );
                        Err(ApiError::new(
                            format!("Failed to create approval request: {}", e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                }
            } else {
                // No approval executor configured; cannot fulfill obligation
                tracing::warn!(
                    "ABAC requires approval but no ApprovalExecutor configured"
                );
                Err(ApiError::new(
                    "Approval required by policy but approval system is not configured",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }

        Obligation::RequireMfa => {
            // Record MFA requirement in audit log
            let audit_entry = AuditLogEntry::new(AuditEventType::Custom(
                "abac_mfa_required".to_string(),
            ))
            .with_actor(&body.applicant_id, &body.applicant_id, "applicant")
            .with_file(&body.file_id, "");
            let _ = state.audit_log.record(audit_entry).await;

            tracing::info!(
                file_id = %body.file_id,
                applicant_id = %body.applicant_id,
                "ABAC obligation triggered: MFA required"
            );

            Ok(ObligationResult::RequiresMfa)
        }

        Obligation::RequireJustification => {
            // Record justification requirement in audit log
            let audit_entry = AuditLogEntry::new(AuditEventType::Custom(
                "abac_justification_required".to_string(),
            ))
            .with_actor(&body.applicant_id, &body.applicant_id, "applicant")
            .with_file(&body.file_id, "");
            let _ = state.audit_log.record(audit_entry).await;

            tracing::info!(
                file_id = %body.file_id,
                applicant_id = %body.applicant_id,
                "ABAC obligation triggered: justification required"
            );

            Ok(ObligationResult::RequiresJustification)
        }

        Obligation::NotifyAdmins(admin_ids) => {
            // Record admin notification in audit log
            let audit_entry = AuditLogEntry::new(AuditEventType::Custom(
                "abac_admin_notification".to_string(),
            ))
            .with_actor(&body.applicant_id, &body.applicant_id, "applicant")
            .with_file(&body.file_id, "")
            .with_custom_field("admin_ids", &admin_ids.join(","));
            let _ = state.audit_log.record(audit_entry).await;

            tracing::info!(
                file_id = %body.file_id,
                applicant_id = %body.applicant_id,
                admin_ids = ?admin_ids,
                "ABAC obligation triggered: notify admins"
            );

            // Notification is non-blocking; proceed immediately
            Ok(ObligationResult::Proceed)
        }

        Obligation::LogOnly => {
            // Already logged during evaluation; proceed immediately
            Ok(ObligationResult::Proceed)
        }
    }
}

// ============================================================================
// Integration Tests (Task 6.28)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use misogi_core::abac::{
        AbacEngine, AttributeResolver, ApprovalExecutor,
        policy::{AbacPolicyRule, ApprovalTemplate, ApproverPool, PolicyEffect, PolicyTarget},
    };

    /// Test: ABAC decision with Permit effect allows transfer.
    #[tokio::test]
    async fn test_abac_permit_allows_transfer() {
        // Create ABAC engine with permit-all rule
        let rule = AbacPolicyRule {
            rule_id: "permit-all".to_string(),
            effect: PolicyEffect::Permit,
            conditions: vec![], // No conditions = always matches
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 100,
            enabled: true,
        };

        let engine = Arc::new(AbacEngine::new(
            vec![rule],
            PolicyEffect::Deny,
            300,
        ));

        let resolver = Arc::new(AttributeResolver::new(300));

        // Evaluate with empty attributes (should match permit-all rule)
        let attributes = std::collections::HashMap::new();
        let decision = engine.evaluate(&attributes).await;

        // Verify decision is Permit
        assert!(decision.is_permitted());
        assert_eq!(decision.matched_rule_id, Some("permit-all".to_string()));
    }

    /// Test: ABAC decision with Deny effect blocks transfer.
    #[tokio::test]
    async fn test_abac_deny_blocks_transfer() {
        // Create ABAC engine with deny-all rule
        let rule = AbacPolicyRule {
            rule_id: "deny-all".to_string(),
            effect: PolicyEffect::Deny,
            conditions: vec![], // No conditions = always matches
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 100,
            enabled: true,
        };

        let engine = Arc::new(AbacEngine::new(
            vec![rule],
            PolicyEffect::Deny,
            300,
        ));

        // Evaluate with empty attributes (should match deny-all rule)
        let attributes = std::collections::HashMap::new();
        let decision = engine.evaluate(&attributes).await;

        // Verify decision is Deny
        assert!(decision.is_denied());
        assert_eq!(decision.matched_rule_id, Some("deny-all".to_string()));
    }

    /// Test: ABAC obligation triggers approval workflow.
    #[tokio::test]
    async fn test_abac_obligation_triggers_approval() {
        // Create approval template
        let template = ApprovalTemplate {
            template_id: "default-approval".to_string(),
            required_approvers: 2,
            approver_pool: ApproverPool::CustomList {
                user_ids: vec!["approver1".to_string(), "approver2".to_string()],
            },
            timeout_hours: 24,
            escalation_on_timeout: true,
        };

        // Create ABAC engine with rule requiring approval
        let rule = AbacPolicyRule {
            rule_id: "require-approval-rule".to_string(),
            effect: PolicyEffect::Permit,
            conditions: vec![],
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: Some(Obligation::RequireApproval(template.clone())),
            priority: 100,
            enabled: true,
        };

        let engine = Arc::new(AbacEngine::new(
            vec![rule],
            PolicyEffect::Deny,
            300,
        ));

        // Create approval executor
        let executor = Arc::new(ApprovalExecutor::new(vec![template]));

        // Evaluate decision
        let attributes = std::collections::HashMap::new();
        let decision = engine.evaluate(&attributes).await;

        // Verify decision has approval obligation
        assert!(decision.is_permitted());
        assert!(decision.obligation.is_some());

        // Execute approval template
        let result = executor.execute_template(
            "default-approval",
            "require-approval-rule",
            "applicant1",
            "Test transfer request",
            &attributes,
        );

        // Verify approval request was created
        assert!(result.is_ok());
        let approval_request = result.unwrap();
        assert_eq!(approval_request.required_approvers, 2);
        assert!(approval_request.selected_approvers.contains(&"approver1".to_string()));
        assert!(approval_request.selected_approvers.contains(&"approver2".to_string()));
    }

    /// Test: ABAC deny precedence over permit.
    #[tokio::test]
    async fn test_abac_deny_precedence() {
        // Create rules: permit-all (low priority) and deny-specific (high priority)
        let permit_rule = AbacPolicyRule {
            rule_id: "permit-all".to_string(),
            effect: PolicyEffect::Permit,
            conditions: vec![],
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 10, // Lower priority
            enabled: true,
        };

        let deny_rule = AbacPolicyRule {
            rule_id: "deny-specific".to_string(),
            effect: PolicyEffect::Deny,
            conditions: vec![], // Matches all
            target: PolicyTarget {
                action: "file_transfer".to_string(),
                resource_type: None,
            },
            obligation: None,
            priority: 100, // Higher priority
            enabled: true,
        };

        let engine = Arc::new(AbacEngine::new(
            vec![permit_rule, deny_rule],
            PolicyEffect::Permit,
            300,
        ));

        // Evaluate: deny should win due to higher priority
        let attributes = std::collections::HashMap::new();
        let decision = engine.evaluate(&attributes).await;

        assert!(decision.is_denied());
        assert_eq!(decision.matched_rule_id, Some("deny-specific".to_string()));
    }

    /// Test: Attribute resolver produces correct subject attributes.
    #[test]
    fn test_attribute_resolver_subject() {
        let resolver = AttributeResolver::new(300);

        let attrs = resolver.resolve_subject_attributes(
            "user123",
            "admin",
            "IT",
            std::collections::HashMap::new(),
        );

        // Verify subject attributes
        assert_eq!(attrs.get("user_id"), Some(&AbacValue::String("user123".to_string())));
        assert_eq!(attrs.get("role"), Some(&AbacValue::String("admin".to_string())));
        assert_eq!(attrs.get("department"), Some(&AbacValue::String("IT".to_string())));
        assert_eq!(attrs.get("clearance_level"), Some(&AbacValue::Integer(5))); // Admin = level 5
    }

    /// Test: Attribute resolver produces correct resource attributes.
    #[test]
    fn test_attribute_resolver_resource() {
        let resolver = AttributeResolver::new(300);

        let attrs = resolver.resolve_resource_attributes(
            "confidential",
            "document.pdf",
            1024000,
            "external",
            true,
            std::collections::HashMap::new(),
        );

        // Verify resource attributes
        assert_eq!(attrs.get("data_classification"), Some(&AbacValue::String("confidential".to_string())));
        assert_eq!(attrs.get("file_type"), Some(&AbacValue::String("document.pdf".to_string())));
        assert_eq!(attrs.get("file_size_bytes"), Some(&AbacValue::Integer(1024000)));
        assert_eq!(attrs.get("destination_zone"), Some(&AbacValue::String("external".to_string())));
        assert_eq!(attrs.get("contains_pii"), Some(&AbacValue::Boolean(true)));
    }

    /// Test: Attribute resolver produces correct environment attributes.
    #[test]
    fn test_attribute_resolver_environment() {
        let resolver = AttributeResolver::new(300);

        let attrs = resolver.resolve_environment_attributes(
            "10.0.0.1",
            "JP",
            true,
            true,
            std::collections::HashMap::new(),
        );

        // Verify environment attributes
        assert_eq!(attrs.get("ip_address"), Some(&AbacValue::String("10.0.0.1".to_string())));
        assert_eq!(attrs.get("geographic_region"), Some(&AbacValue::String("JP".to_string())));
        assert_eq!(attrs.get("mfa_verified"), Some(&AbacValue::Boolean(true)));
        assert_eq!(attrs.get("device_compliant"), Some(&AbacValue::Boolean(true)));
        assert_eq!(attrs.get("source_network"), Some(&AbacValue::String("corporate-lan".to_string())));
    }

    /// Test: Approval executor handles timeout correctly.
    #[tokio::test]
    async fn test_approval_executor_timeout() {
        let template = ApprovalTemplate {
            template_id: "timeout-test".to_string(),
            required_approvers: 1,
            approver_pool: ApproverPool::CustomList {
                user_ids: vec!["approver1".to_string()],
            },
            timeout_hours: 1,
            escalation_on_timeout: false,
        };

        let executor = Arc::new(ApprovalExecutor::new(vec![template]));

        // Create approval request
        let request = executor.execute_template(
            "timeout-test",
            "test-rule",
            "applicant1",
            "Test request",
            &std::collections::HashMap::new(),
        ).unwrap();

        // Handle timeout
        let result = executor.handle_timeout(&request.request_id).await;

        // Verify timeout was handled
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(matches!(status, misogi_core::abac::AbacApprovalStatus::TimedOut));
    }
}
