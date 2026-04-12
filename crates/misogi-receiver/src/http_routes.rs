use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use crate::state::SharedState;

pub async fn list_files(
    State(state): State<SharedState>,
) -> axum::response::Response {
    match state.storage.list_ready_files().await {
        Ok(files) => Json(json!({
            "files": files,
            "total": files.len(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn download_file(
    Path(file_id): Path<String>,
    State(state): State<SharedState>,
    range_header: Option<axum::http::HeaderMap>,
) -> axum::response::Response {
    let file_info = match state.storage.get_file_info(&file_id).await {
        Ok(Some(info)) => info,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "File not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let download_path = state.storage.get_download_path(&file_id, &file_info.filename);

    if !download_path.exists() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "File not ready for download"}))).into_response();
    }

    let file = match tokio::fs::File::open(&download_path).await {
        Ok(f) => f,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let metadata = match tokio::fs::metadata(&download_path).await {
        Ok(m) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let file_len = metadata.len();

    use tokio_util::io::ReaderStream;
    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        file_len.to_string().parse().unwrap(),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", file_info.filename)
            .parse()
            .unwrap(),
    );

    if let Some(headers) = range_header {
        if let Some(range) = headers.get("range") {
            if let Ok(range_str) = range.to_str() {
                if let Some((start, end)) = parse_range(range_str, file_len) {
                    *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                    response.headers_mut().insert(
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", start, end, file_len)
                            .parse()
                            .unwrap(),
                    );
                    response.headers_mut().insert(
                        header::CONTENT_LENGTH,
                        (end - start + 1).to_string().parse().unwrap(),
                    );
                }
            }
        }
    }

    response
}

fn parse_range(range: &str, file_len: u64) -> Option<(u64, u64)> {
    if !range.starts_with("bytes=") {
        return None;
    }

    let range_part = &range[6..];
    let parts: Vec<&str> = range_part.split('-').collect();

    if parts.len() != 2 {
        return None;
    }

    let start: u64 = if parts[0].is_empty() {
        0
    } else {
        parts[0].trim().parse().ok()?
    };

    let end: u64 = if parts[1].is_empty() {
        file_len.saturating_sub(1)
    } else {
        parts[1].trim().parse().ok()?
    };

    if start > end || end >= file_len {
        return None;
    }

    Some((start, end))
}

pub async fn get_file_status(
    Path(file_id): Path<String>,
    State(state): State<SharedState>,
) -> axum::response::Response {
    match state.storage.get_file_info(&file_id).await {
        Ok(Some(info)) => Json(info).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "File not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn health_check() -> impl axum::response::IntoResponse {
    Json(json!({
        "status": "ok",
        "role": "receiver"
    }))
}

pub async fn reassemble(
    Path(file_id): Path<String>,
    State(state): State<SharedState>,
) -> axum::response::Response {
    let manifest = match state.storage.get_manifest(&file_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": format!("Manifest not found for file: {}", file_id)}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let is_complete = match state.storage.check_complete(&file_id, manifest.chunk_count).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    if !is_complete {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Not all chunks received yet",
                "file_id": file_id,
                "expected_chunks": manifest.chunk_count,
            })),
        )
            .into_response();
    }

    match state.storage
        .reassemble_file(&file_id, &manifest.filename, &manifest.file_md5)
        .await
    {
        Ok(output_path) => {
            if let Err(e) = state.storage.update_manifest_status(&file_id, misogi_core::FileStatus::Ready).await {
                tracing::error!(error = %e, file_id = %file_id, "Failed to update manifest status after reassembly");
            }
            (
                StatusCode::OK,
                Json(json!({
                    "status": "success",
                    "file_id": file_id,
                    "output_path": output_path,
                    "filename": manifest.filename,
                })),
            )
                .into_response()
        }
        Err(e) => {
            if let Err(status_err) = state.storage.update_manifest_status(&file_id, misogi_core::FileStatus::Failed).await {
                tracing::error!(error = %status_err, file_id = %file_id, "Failed to update manifest status after reassembly failure");
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": e.to_string(),
                    "file_id": file_id,
                })),
            )
                .into_response()
        }
    }
}
