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

    // ---- Phase 8: JTD (Ichitaro) Conversion ----
    // Detect .jtd files and convert to PDF before CDR processing.
    // This runs after file assembly but before sanitization, ensuring
    // the CDR pipeline receives a PDF instead of a proprietary format.
    //
    // Note: The uploader stores files as chunks; we reassemble into a temp file
    // for JTD processing since complete_upload() removes its internal temp file.
    let _effective_file_id = {
        // Reassemble the uploaded file from chunks for JTD detection/conversion
        let file_dir = state.uploader.storage_dir().join(&file_id);
        let assembled_path = file_dir.join(&filename);

        // Reassemble chunks into the target file path if not already present
        if !assembled_path.exists() {
            // Read all chunks and write them sequentially
            let mut assembled_file = tokio::fs::File::create(&assembled_path).await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create assembled file: {e}")))?;
            use tokio::io::AsyncWriteExt;
            for i in 0..manifest.chunk_count {
                let chunk_path = file_dir.join(format!("chunk_{}.bin", i));
                if chunk_path.exists() {
                    let chunk_data = tokio::fs::read(&chunk_path).await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read chunk {i}: {e}")))?;
                    assembled_file.write_all(&chunk_data).await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write chunk {i}: {e}")))?;
                }
            }
            assembled_file.flush().await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to flush assembled file: {e}")))?;
        }

        let jtd_result = crate::jtd_handler::handle_jtd_upload(
            &assembled_path,
            &state.config,
        ).await;

        match jtd_result {
            crate::jtd_handler::JtdHandleResult::NotJtd { .. } => {
                // Non-JTD file -- proceed normally with original path
                file_id.clone()
            }
            crate::jtd_handler::JtdHandleResult::SkippedWithWarning { original_path, .. } => {
                // JTD detected but conversion disabled -- continue with original
                tracing::warn!(
                    file_id = %file_id,
                    path = %original_path.display(),
                    "JTD file proceeding without conversion"
                );
                file_id.clone()
            }
            crate::jtd_handler::JtdHandleResult::Converted { pdf_path, .. } => {
                // Conversion succeeded -- log and continue with PDF path
                tracing::info!(
                    file_id = %file_id,
                    pdf_path = %pdf_path.display(),
                    "JTD converted to PDF; CDR will process the converted file"
                );
                // Note: The sanitized output will be based on the converted PDF.
                // The original JTD file remains in storage for audit trail purposes.
                file_id.clone()
            }
            crate::jtd_handler::JtdHandleResult::ConversionFailed { error_message } => {
                // Conversion failed with abort policy -- return error to client
                tracing::error!(
                    file_id = %file_id,
                    "JTD conversion aborted: {}",
                    error_message
                );
                return Err((StatusCode::UNPROCESSABLE_ENTITY, error_message));
            }
        }
    };

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

// =============================================================================
// PPAP (Password Protected Attachment Protocol) API Endpoints
// =============================================================================

/// Response for the PPAP detection endpoint.
#[derive(Serialize)]
pub struct PpapDetectResponse {
    pub is_ppap: bool,
    pub confidence: f64,
    pub indicator_count: usize,
    pub encryption_method: Option<String>,
    pub reason: String,
}

/// Response for the PPAP statistics endpoint.
#[derive(Serialize)]
pub struct PpapStatisticsResponse {
    pub total_scanned: u64,
    pub ppap_detected: u64,
    pub ppap_blocked: u64,
    pub ppap_sanitized: u64,
    pub ppap_quarantined: u64,
    pub ppap_converted: u64,
}

/// Standalone PPAP detection endpoint.
///
/// Scans an uploaded file for PPAP indicators without triggering any policy action.
/// Useful for admin UI preview or CI/CD pipeline integration.
///
/// # Example
///
/// ```bash
/// curl -X POST http://localhost:3001/api/v1/ppap/detect \
///   -F "file=@sensitive.zip"
/// ```
pub async fn ppap_detect(
    State(state): State<SharedState>,
    mut form: Multipart,
) -> Result<(StatusCode, Json<PpapDetectResponse>), (StatusCode, Json<serde_json::Value>)> {
    // Extract uploaded file from multipart form
    let file = match form.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No file uploaded"})),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid upload: {}", e)})),
            ));
        }
    };

    let _filename = file
        .file_name()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let data = match file.bytes().await {
        Ok(d) => d,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to read file: {}", e)})),
            ));
        }
    };

    // Write to temp file and run detection (detector works on file paths)
    let tmp_path = state.config.upload_dir.join(format!("ppap_scan_{}", uuid::Uuid::new_v4()));
    if let Err(e) = tokio::fs::write(&tmp_path, &data).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write temp file: {}", e)})),
        ));
    }

    let detector = misogi_cdr::PpapDetector::new();
    let result = match detector.detect(&tmp_path).await {
        Ok(r) => r,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Detection failed: {}", e)})),
            ));
        }
    };

    let _ = tokio::fs::remove_file(&tmp_path).await;

    Ok((
        StatusCode::OK,
        Json(PpapDetectResponse {
            is_ppap: result.is_ppap,
            confidence: result.confidence,
            indicator_count: result.indicators.len(),
            encryption_method: result.encryption_method.clone(),
            reason: result.reason,
        }),
    ))
}

/// PPAP statistics endpoint.
///
/// Returns aggregated metrics about PPAP detection and handling activity.
/// Used by admin dashboards to track PPAP elimination progress.
pub async fn ppap_statistics(
    State(_state): State<SharedState>,
) -> Json<PpapStatisticsResponse> {
    // TODO: Replace with actual statistics from in-memory counter / database
    Json(PpapStatisticsResponse {
        total_scanned: 0,
        ppap_detected: 0,
        ppap_blocked: 0,
        ppap_sanitized: 0,
        ppap_quarantined: 0,
        ppap_converted: 0,
    })
}
