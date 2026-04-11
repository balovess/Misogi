use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use crate::state::SharedState;
use misogi_cdr::{SanitizationReport};

#[derive(Serialize)]
pub struct UploadResponse {
    pub file_id: String,
    pub status: String,
    pub filename: String,
    pub total_size: u64,
    pub chunk_count: u32,
}

#[derive(Deserialize)]
pub struct ListFilesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct ListFilesResponse {
    pub files: Vec<misogi_core::FileInfo>,
    pub total: usize,
}

#[derive(Serialize)]
pub struct TransferResponse {
    pub file_id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct SanitizeResponse {
    pub file_id: String,
    pub success: bool,
    pub original_filename: String,
    pub original_hash: String,
    pub sanitized_hash: String,
    pub policy: String,
    pub actions_taken: Vec<String>,
    pub warnings: Vec<String>,
    pub processing_time_ms: u64,
}

impl From<SanitizationReport> for SanitizeResponse {
    fn from(report: SanitizationReport) -> Self {
        Self {
            file_id: report.file_id,
            success: report.success,
            original_filename: report.original_filename,
            original_hash: report.original_hash,
            sanitized_hash: report.sanitized_hash,
            policy: format!("{:?}", report.policy),
            actions_taken: report.actions_taken.iter().map(|a| format!("{:?}", a)).collect(),
            warnings: report.warnings,
            processing_time_ms: report.processing_time_ms,
        }
    }
}

#[derive(Serialize)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    pub description: String,
}

pub async fn upload(
    State(state): State<SharedState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), (StatusCode, String)> {
    let mut field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => return Err((StatusCode::BAD_REQUEST, "No file uploaded".to_string())),
        Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string())),
    };

    let filename = field.file_name()
        .unwrap_or("unknown")
        .to_string();

    let (file_id, _) = state.uploader
        .create_session(filename.clone(), &state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut chunk_index = 0u32;
    let mut total_size = 0u64;

    while let Some(chunk) = field.chunk().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        if !chunk.is_empty() {
            state.uploader
                .write_chunk(&file_id, chunk_index, &chunk)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            total_size += chunk.len() as u64;
            chunk_index += 1;
        }
    }

    let manifest = state.uploader
        .complete_upload(&file_id, &state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if state.config.auto_sanitize {
        let sanitize_file_id = file_id.clone();
        let sanitize_state = state.clone();
        tokio::spawn(async move {
            // Use legacy sanitizer (backward compatible)
            // Task 5.14 Note: PII detection and CDR strategy chain integration
            // is pending API alignment work. Currently delegates to direct sanitizers.
            match sanitize_state.uploader.sanitize_file(
                &sanitize_file_id,
                &sanitize_state.sanitization_policy,
                &sanitize_state.pdf_sanitizer,
                &sanitize_state.office_sanitizer,
                &sanitize_state.zip_scanner,
            ).await {
                Ok(report) => {
                    tracing::info!(
                        file_id = %sanitize_file_id,
                        actions = report.actions_taken.len(),
                        "File sanitized successfully"
                    );
                    if !report.warnings.is_empty() {
                        for warning in &report.warnings {
                            tracing::warn!(file_id = %sanitize_file_id, %warning, "Sanitization warning");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(file_id = %sanitize_file_id, error = %e, "Sanitization failed");
                }
            }
        });
    }

    Ok((
        StatusCode::OK,
        Json(UploadResponse {
            file_id,
            status: format!("{:?}", manifest.status).to_lowercase(),
            filename,
            total_size,
            chunk_count: manifest.chunk_count,
        }),
    ))
}

pub async fn get_file(
    Path(file_id): Path<String>,
    State(state): State<SharedState>,
) -> Result<(StatusCode, Json<misogi_core::FileInfo>), (StatusCode, String)> {
    let info = state.uploader
        .get_file_info(&file_id)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok((StatusCode::OK, Json(info)))
}

pub async fn list_files(
    State(state): State<SharedState>,
    Query(query): Query<ListFilesQuery>,
) -> Result<(StatusCode, Json<ListFilesResponse>), (StatusCode, String)> {
    let all_files = state.uploader
        .list_files()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let filtered = if let Some(status_str) = query.status {
        let status = match status_str.as_str() {
            "uploading" => Some(misogi_core::FileStatus::Uploading),
            "transferring" => Some(misogi_core::FileStatus::Transferring),
            "ready" => Some(misogi_core::FileStatus::Ready),
            "failed" => Some(misogi_core::FileStatus::Failed),
            _ => None,
        };

        if let Some(s) = status {
            state.list_files(Some(&s)).await
        } else {
            all_files.into_iter().collect()
        }
    } else {
        all_files
    };

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    let start = ((page - 1) as usize * per_page as usize).min(filtered.len());
    let end = (start + per_page as usize).min(filtered.len());
    let paginated: Vec<_> = filtered[start..end].to_vec();

    Ok((
        StatusCode::OK,
        Json(ListFilesResponse {
            files: paginated,
            total: filtered.len(),
        }),
    ))
}

pub async fn trigger_transfer(
    Path(file_id): Path<String>,
    State(state): State<SharedState>,
) -> Result<(StatusCode, Json<TransferResponse>), (StatusCode, String)> {
    let exists = state.get_file(&file_id).await.ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("File not found: {}", file_id))
    })?;

    if exists.status != misogi_core::FileStatus::Ready {
        return Err((
            StatusCode::CONFLICT,
            format!("File is not ready for transfer. Current status: {:?}", exists.status),
        ));
    }

    state.update_file_status(&file_id, misogi_core::FileStatus::Transferring).await;

    tracing::info!(file_id = %file_id, "Transfer triggered");

    // Task 5.14: Use tunnel_remote_addr for TCP mode (backward compatible)
    if let Some(ref receiver_addr) = state.config.tunnel_remote_addr {
        let task_state = state.clone();
        let task_file_id = file_id.clone();
        let task_receiver_addr = receiver_addr.clone();

        tokio::spawn(async move {
            if let Err(e) = crate::tunnel_task::execute_transfer(
                task_state,
                task_file_id,
                task_receiver_addr,
            )
            .await
            {
                tracing::error!(error = %e, "Transfer task failed");
            }
        });
    }

    Ok((
        StatusCode::OK,
        Json(TransferResponse {
            file_id,
            status: "transferring".to_string(),
        }),
    ))
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        role: "sender".to_string(),
    })
}

pub async fn sanitize_file(
    Path(file_id): Path<String>,
    State(state): State<SharedState>,
) -> Result<(StatusCode, Json<SanitizeResponse>), (StatusCode, String)> {
    let exists = state.get_file(&file_id).await.ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("File not found: {}", file_id))
    })?;

    if exists.status != misogi_core::FileStatus::Ready {
        return Err((
            StatusCode::CONFLICT,
            format!("File is not ready for sanitization. Current status: {:?}", exists.status),
        ));
    }

    let report = state.uploader
        .sanitize_file(
            &file_id,
            &state.sanitization_policy,
            &state.pdf_sanitizer,
            &state.office_sanitizer,
            &state.zip_scanner,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(
        file_id = %file_id,
        actions = report.actions_taken.len(),
        "Manual sanitization completed"
    );

    Ok((StatusCode::OK, Json(SanitizeResponse::from(report))))
}

pub async fn list_policies(State(_state): State<SharedState>) -> Json<Vec<PolicyInfo>> {
    Json(vec![
        PolicyInfo {
            id: "stripActiveContent".to_string(),
            name: "Strip Active Content".to_string(),
            description: "Remove JavaScript, VBA macros, and embedded scripts while preserving document editability. This is the default mode compatible with VOTIRO's standard behavior.".to_string(),
        },
        PolicyInfo {
            id: "convertToFlat".to_string(),
            name: "Convert to Flat".to_string(),
            description: "Convert document to flat/read-only format, destroying all interactive elements including form fields, annotations, hyperlinks, bookmarks, and embedded fonts.".to_string(),
        },
        PolicyInfo {
            id: "textOnly".to_string(),
            name: "Text Only".to_string(),
            description: "Extract text content only, discarding all formatting, images, tables, and layout information.".to_string(),
        },
    ])
}
