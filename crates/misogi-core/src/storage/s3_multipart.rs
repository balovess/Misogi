//! S3 Multipart Upload Support
//!
//! Provides large-file upload capability for [`S3Storage`] by splitting data
//! into multiple parts that are uploaded concurrently. This avoids memory pressure
//! from loading entire large objects (e.g., 200MB+ scanned PDFs) into a single
//! `PutObject` call.
//!
//! # Threshold Strategy
//!
//! | Data Size | Upload Method | Reason |
//! |-----------|--------------|--------|
//! | ≤ threshold | Single `PutObject` | Fast path, no overhead |
//! | > threshold | `CreateMultipartUpload` → `UploadPart` × N → `CompleteMultipartUpload` | Memory-efficient, concurrent |
//!
//! # Concurrency Model
//!
//! Parts are uploaded using bounded concurrency (`tokio::sync::Semaphore`).
//! Default: 4 concurrent uploads. Failed parts trigger `AbortMultipartUpload`
//! to clean up partial uploads on S3.
//!
//! # Error Recovery
//!
//! - **Single part failure**: Abort entire upload, return error.
//! - **Network timeout**: Retry individual part (up to 3 times with exponential backoff).
//! - **Abort failure**: Log warning; S3 cleans up abandoned multipart uploads after 7 days.

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::{
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    Client,
};
use bytes::Bytes;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, instrument, warn};

use crate::traits::storage::{StorageError, StorageInfo};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Controls when and how [`S3Storage`] switches to multipart upload mode.
///
/// S3 requires each part to be at least 5 MB (except the last part).
/// The default configuration is tuned for Japanese government file sizes
/// where scanned documents commonly range from 10–500 MB.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3MultipartConfig {
    /// Minimum data size (in bytes) that triggers multipart upload.
    ///
    /// Data smaller than this uses single `PutObject` for lower latency.
    /// Default: 5 MB (5 * 1024 * 1024). Must be ≥ 5 MB per S3 requirements.
    pub threshold_bytes: usize,

    /// Target size of each upload part.
    ///
    /// Actual last part may be smaller. Each part must be ≥ 5 MB
    /// except the final one. Default: 8 MB.
    pub part_size_bytes: usize,

    /// Maximum number of parts uploading concurrently.
    ///
    /// Higher values increase throughput but also memory usage
    /// (each in-flight part holds `part_size_bytes` in memory).
    /// Default: 4.
    pub max_concurrent_parts: usize,
}

impl Default for S3MultipartConfig {
    fn default() -> Self {
        Self {
            threshold_bytes: 5 * 1024 * 1024,
            part_size_bytes: 8 * 1024 * 1024,
            max_concurrent_parts: 4,
        }
    }
}

impl S3MultipartConfig {
    #[must_use]
    pub fn with_threshold(mut self, bytes: usize) -> Self {
        self.threshold_bytes = bytes.max(5 * 1024 * 1024);
        self
    }

    #[must_use]
    pub fn with_part_size(mut self, bytes: usize) -> Self {
        self.part_size_bytes = bytes.max(5 * 1024 * 1024);
        self
    }

    #[must_use]
    pub fn with_max_concurrency(mut self, n: usize) -> Self {
        self.max_concurrent_parts = n.max(1);
        self
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        if self.threshold_bytes < 5 * 1024 * 1024 {
            return Err(StorageError::ConfigurationError(format!(
                "threshold_bytes must be >= 5MB (got {})",
                self.threshold_bytes
            )));
        }
        if self.part_size_bytes < 5 * 1024 * 1024 {
            return Err(StorageError::ConfigurationError(format!(
                "part_size_bytes must be >= 5MB (got {})",
                self.part_size_bytes
            )));
        }
        if self.part_size_bytes > 5 * 1024 * 1024 * 1024 {
            return Err(StorageError::ConfigurationError(
                "part_size_bytes must be <= 5 GB".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Execute a multipart upload of `data` to S3 under `key`.
#[instrument(skip(client, data), fields(key, bucket, data_len = data.len()))]
pub async fn execute_multipart_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    data: Bytes,
    config: &S3MultipartConfig,
) -> Result<StorageInfo, StorageError> {
    let total_len = data.len();

    info!(
        key = %key,
        bucket = %bucket,
        total_bytes = total_len,
        part_size_mb = config.part_size_bytes / (1024 * 1024),
        concurrent = config.max_concurrent_parts,
        "Starting multipart upload"
    );

    // Step 1: Initiate
    let upload_id = initiate_upload(client, bucket, key).await?;

    // Step 2: Upload parts concurrently
    let result =
        upload_parts_concurrent(client, bucket, key, &upload_id, data, config).await;

    match result {
        Ok(parts) => complete_upload(client, bucket, key, &upload_id, &parts, total_len as u64).await,
        Err(e) => {
            if let Err(abort_err) = abort_upload(client, bucket, key, &upload_id).await {
                warn!(key = %key, error = %abort_err, "Failed to abort after upload failure");
            }
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Internal: Step 1 — Initiate
// ---------------------------------------------------------------------------

async fn initiate_upload(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<String, StorageError> {
    debug!(key = %key, "Creating multipart upload");

    let response = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| map_sdk_error(&e, key))?;

    let upload_id = response
        .upload_id()
        .ok_or_else(|| {
            StorageError::InternalError("CreateMultipartUpload returned no upload_id".into())
        })?
        .to_string();

    debug!(key = %key, upload_id = %upload_id, "Multipart initiated");
    Ok(upload_id)
}

// ---------------------------------------------------------------------------
// Internal: Step 2 — Concurrent Parts
// ---------------------------------------------------------------------------

struct UploadedPart {
    part_number: i32,
    etag: String,
}

async fn upload_parts_concurrent(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    data: Bytes,
    config: &S3MultipartConfig,
) -> Result<Vec<UploadedPart>, StorageError> {
    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_parts));
    let mut handles = Vec::new();
    let total_len = data.len();
    let part_size = config.part_size_bytes;

    for part_idx in 0.. {
        let offset = part_idx * part_size;
        if offset >= total_len {
            break;
        }
        let end = (offset + part_size).min(total_len);
        let part_data = data.slice(offset..end);
        let part_number = (part_idx + 1) as i32;

        let sem = Arc::clone(&semaphore);
        let handle = tokio::spawn({
            let client_ref = client.clone();
            let bkt = bucket.to_string();
            let k = key.to_string();
            let uid = upload_id.to_string();
            async move {
                let _permit = sem.acquire().await.unwrap();
                upload_single_part_with_retry(
                    &client_ref, &bkt, &k, &uid, part_number, part_data,
                )
                .await
            }
        });

        handles.push(handle);
    }

    let mut parts = Vec::with_capacity(handles.len());
    let mut errors = Vec::new();

    for handle in handles {
        match handle.await {
            Ok(Ok(part)) => parts.push(part),
            Ok(Err(e)) => errors.push(e),
            Err(join_err) => errors.push(StorageError::InternalError(format!(
                "multipart task panicked: {join_err}"
            ))),
        }
    }

    if !errors.is_empty() {
        let msg = format!("{} of {} parts failed", errors.len(), parts.len() + errors.len());
        error!(key = %key, "{}", msg);
        return Err(StorageError::InternalError(msg));
    }

    parts.sort_by_key(|p| p.part_number);
    debug!(key = %key, total_parts = parts.len(), "All parts uploaded");
    Ok(parts)
}

async fn upload_single_part_with_retry(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: i32,
    data: Bytes,
) -> Result<UploadedPart, StorageError> {
    const MAX_RETRIES: u32 = 3;

    for attempt in 1..=MAX_RETRIES {
        debug!(key = %key, part = part_number, attempt, size = data.len(), "Uploading part");

        let body = ByteStream::from(data.clone());

        match client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body)
            .content_length(data.len() as i64)
            .send()
            .await
        {
            Ok(response) => {
                let etag = response.e_tag().ok_or_else(|| {
                    StorageError::InternalError(format!(
                        "UploadPart {part_number} returned no etag"
                    ))
                })?;

                debug!(key = %key, part = part_number, etag = ?etag, "Part done");
                return Ok(UploadedPart {
                    part_number,
                    etag: etag.to_string(),
                });
            }
            Err(e) if attempt < MAX_RETRIES => {
                let backoff = Duration::from_millis(200u64 * (2u64.pow(attempt)));
                warn!(key = %key, part = part_number, attempt, error = %e, "Retrying");
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(map_sdk_error(&e, key)),
        }
    }

    unreachable!()
}

// ---------------------------------------------------------------------------
// Internal: Step 3 — Complete
// ---------------------------------------------------------------------------

async fn complete_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[UploadedPart],
    total_size: u64,
) -> Result<StorageInfo, StorageError> {
    debug!(key = %key, num_parts = parts.len(), "Completing multipart");

    let completed_parts: Vec<_> = parts
        .iter()
        .map(|p| {
            aws_sdk_s3::types::CompletedPart::builder()
                .part_number(p.part_number)
                .e_tag(&p.etag)
                .build()
        })
        .collect();

    let response = client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .set_parts(Some(completed_parts))
                .build(),
        )
        .send()
        .await
        .map_err(|e| map_sdk_error(&e, key))?;

    let etag = response.e_tag().map(|s| s.to_string());

    info!(key = %key, total_size, etag = ?etag, "Multipart completed");
    Ok(StorageInfo {
        key: key.to_string(),
        size: total_size,
        content_type: None,
        created_at: Some(chrono::Utc::now()),
        etag,
    })
}

// ---------------------------------------------------------------------------
// Internal: Cleanup — Abort
// ---------------------------------------------------------------------------

async fn abort_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<(), StorageError> {
    warn!(key = %key, upload_id = %upload_id, "Aborting multipart");

    client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| map_sdk_error(&e, key))
}

// ---------------------------------------------------------------------------
// Error Mapping
// ---------------------------------------------------------------------------

fn map_sdk_error<E: ProvideErrorMetadata + std::fmt::Debug>(
    error: &SdkError<E>,
    key: &str,
) -> StorageError {
    match error {
        SdkError::ServiceError(se) => {
            let status = se.raw().status().as_u16();
            let code = se.err().code().unwrap_or("UNKNOWN");
            match status {
                404 => StorageError::NotFound(key.into()),
                403 => StorageError::PermissionDenied(format!(
                    "Access denied for '{key}': {code}"
                )),
                400 => StorageError::ConfigurationError(format!(
                    "Bad request for '{key}': {code}"
                )),
                _ => StorageError::NetworkError(format!(
                    "S3 error ({status}) for '{key}': {code}"
                )),
            }
        }
        SdkError::DispatchFailure(dfe) => {
            StorageError::NetworkError(format!("Dispatch failure for '{key}': {:?}", dfe))
        }
        SdkError::TimeoutError(te) => {
            StorageError::NetworkError(format!("Timeout for '{key}': {:?}", te))
        }
        other => StorageError::InternalError(format!(
            "Unexpected S3 error for '{key}': {:?}",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let cfg = S3MultipartConfig::default();
        assert_eq!(cfg.threshold_bytes, 5 * 1024 * 1024);
        assert_eq!(cfg.part_size_bytes, 8 * 1024 * 1024);
        assert_eq!(cfg.max_concurrent_parts, 4);
    }

    #[test]
    fn test_builder_methods() {
        let cfg = S3MultipartConfig::default()
            .with_threshold(10 * 1024 * 1024)
            .with_part_size(16 * 1024 * 1024)
            .with_max_concurrency(8);

        assert_eq!(cfg.threshold_bytes, 10 * 1024 * 1024);
        assert_eq!(cfg.part_size_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.max_concurrent_parts, 8);
    }

    #[test]
    fn test_minimum_threshold_enforced() {
        let cfg = S3MultipartConfig::default().with_threshold(1);
        assert_eq!(cfg.threshold_bytes, 5 * 1024 * 1024);
    }

    #[test]
    fn test_minimum_part_size_enforced() {
        let cfg = S3MultipartConfig::default().with_part_size(100);
        assert_eq!(cfg.part_size_bytes, 5 * 1024 * 1024);
    }

    #[test]
    fn test_validate_good_config() {
        assert!(S3MultipartConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_small_threshold() {
        let cfg = S3MultipartConfig {
            threshold_bytes: 1,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_small_part() {
        let cfg = S3MultipartConfig {
            part_size_bytes: 100,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_oversized_part() {
        let cfg = S3MultipartConfig {
            part_size_bytes: 6 * 1024 * 1024 * 1024,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_part_count_math() {
        let ps = 10 * 1024 * 1024;
        // 25 MB / 10 MB = 3 parts
        assert_eq!((25 * 1024 * 1024 + ps - 1) / ps, 3);
        // Exactly 10 MB = 1 part
        assert_eq!((ps + ps - 1) / ps, 1);
        // 0 bytes = 0 parts
        assert_eq!((0 + ps - 1) / ps, 0);
    }
}
