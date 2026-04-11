use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use misogi_core::{
    approval::{ApprovalStatus, TransferRequest},
    audit_log::{AuditLogEntry, AuditEventType},
    FileStatus,
};
use crate::state::SharedState;

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
        (code, Json(Self { error: msg.into(), code }))
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
    .with_file_info(file_info.filename.clone(), file_info.total_size, file_info.file_md5.clone())
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
    let pending = state.list_pending_requests(query.approver_id.as_deref()).await;
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
    let mut request = state.get_transfer_request(&request_id).await.ok_or_else(|| {
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
    request.approve(&body.approver_id).map_err(|e| {
        ApiError::new(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    // Persist updated request back to state
    state.update_transfer_request(&request_id, request.clone()).await;

    // Record audit log: TransferApproved
    let audit_entry = AuditLogEntry::new(AuditEventType::TransferApproved)
        .with_actor(&body.approver_id, request.approver_name.as_deref().unwrap_or(""), "approver")
        .with_file(&request.file_id, &request.original_filename)
        .with_approver(&body.approver_id)
        .with_transfer_request(&request_id, &request.transfer_reason);
    let _ = state.audit_log.record(audit_entry).await;

    // Auto-trigger tunnel transfer after approval
    let trigger_result = crate::http_routes::trigger_transfer(
        axum::extract::Path(request.file_id.clone()),
        State(state.clone()),
    ).await;

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

    let mut request = state.get_transfer_request(&request_id).await.ok_or_else(|| {
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
    request.reject(&body.approver_id, body.rejection_reason.clone()).map_err(|e| {
        ApiError::new(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    // Persist updated request back to state
    state.update_transfer_request(&request_id, request.clone()).await;

    // Record audit log: TransferRejected
    let audit_entry = AuditLogEntry::new(AuditEventType::TransferRejected)
        .with_actor(&body.approver_id, request.approver_name.as_deref().unwrap_or(""), "approver")
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
    let request = state.get_transfer_request(&request_id).await.ok_or_else(|| {
        ApiError::new(
            format!("Transfer request not found: {}", request_id),
            StatusCode::NOT_FOUND,
        )
    })?;

    Ok((StatusCode::OK, Json(request)))
}
