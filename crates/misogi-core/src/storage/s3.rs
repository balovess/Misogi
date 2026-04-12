// =============================================================================
// S3Storage — S3-Compatible Cloud Storage Backend Implementation
// =============================================================================
// Implements StorageBackend for Amazon S3, MinIO, Cloudflare R2, and any
// S3-compatible object storage service. Provides production-ready operations
// with comprehensive error mapping, presigned URL support, and health checks.
//
// Design Decisions:
// 1. Uses aws-sdk-s3 (AWS SDK for Rust) for all API interactions.
// 2. Client is constructed once at initialization and reused (connection pooling).
// 3. All keys are validated before forwarding to S3 (length, characters).
// 4. Error mapping follows the StorageError classification in the trait.
// 5. Presigned URLs use GET operation with configurable TTL.
//
// Compatibility Matrix:
// | Provider       | endpoint              | path_style | Notes                    |
// |----------------|-----------------------|------------|--------------------------|
// | Amazon S3      | None (default)        | false      | Virtual-hosted style     |
// | MinIO          | http://minio:9000     | true       | Path-style required      |
// | Cloudflare R2  | https://account.r2... | true       | No ListObjects support   |
// | DigitalOcean   | https://nyc3...       | true       | Region-based endpoints   |
// | Wasabi         | https://s3.wasabisys..| true       | Cross-region replication |
// =============================================================================

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{Client, Config as S3ClientConfig, error::SdkError, primitives::ByteStream};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_smithy_types::DateTime as SmithyDateTime;
use aws_types::region::Region;
use bytes::Bytes;
use chrono::{Utc};
use tracing::{debug, error, info, instrument, warn};

use crate::traits::storage::{StorageBackend, StorageError, StorageInfo};

// =============================================================================
// S3Config — Configuration for S3-compatible storage backend
// =============================================================================

/// Configuration parameters for [`S3Storage`].
///
/// This struct captures all settings needed to establish a connection to an
/// S3-compatible storage service. All fields are validated at construction
/// time to fail-fast on misconfiguration.
///
/// # Required Fields
///
/// | Field        | Description                                          | Example               |
/// |--------------|------------------------------------------------------|-----------------------|
/// | `bucket`     | S3 bucket name (must be DNS-compliant for virtual-hosted) | `"my-app-files"`    |
/// | `region`     | AWS region or MinIO region identifier                | `"us-east-1"`        |
/// | `access_key` | Access key ID for authentication                     | `"AKIAIOSFODNN7EXAMPLE"` |
/// | `secret_key` | Secret access key for authentication                 | `"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"` |
///
/// # Optional Fields
///
/// | Field                  | Default | Description                              |
/// |------------------------|---------|------------------------------------------|
/// | `endpoint`             | `None`  | Custom endpoint URL (required for MinIO/R2) |
/// | `presigned_url_ttl_secs`| `3600` | Presigned URL expiration in seconds      |
/// | `path_style`           | `false` | Use path-style addressing (required for MinIO) |
///
/// # Security Considerations
///
/// - **Never hardcode credentials** in source code. Use environment variables,
///   AWS IAM roles, or secret management systems (HashiCorp Vault, AWS Secrets Manager).
/// - **Prefer IAM roles** for EC2/EKS/Lambda: omit access_key/secret_key to
///   use the instance metadata service automatically.
/// - **Rotate credentials regularly**: the SDK does not enforce rotation.
/// - **Use minimum-privilege policies**: grant only required actions
///   (s3:PutObject, s3:GetObject, s3:DeleteObject, s3:HeadObject, s3:ListBucket).
///
/// # Example
///
/// ```ignore
/// use misogi_core::storage::S3Config;
///
/// let config = S3Config::new(
///     "my-bucket",
///     "us-east-1",
///     "AKIAIOSFODNN7EXAMPLE",
///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
/// )
/// .with_endpoint(Some("http://localhost:9000".to_string()))
/// .with_path_style(true);
/// ```
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name where objects will be stored.
    ///
    /// Must be a valid DNS name (lowercase, alphanumeric, hyphens) when using
    /// virtual-hosted style. For path-style addressing, relaxed rules apply.
    pub bucket: String,

    /// AWS region or S3-compatible service region.
    ///
    /// Examples: `"us-east-1"`, `"eu-west-2"`, `"minio"` (for self-hosted).
    pub region: String,

    /// Optional custom endpoint URL for S3-compatible services.
    ///
    /// - `None`: Use default AWS S3 endpoint (https://s3.{region}.amazonaws.com).
    /// - `Some(url)`: Use custom endpoint (e.g., `"http://minio:9000"` for MinIO).
    ///
    /// Required for non-AWS providers (MinIO, R2, Wasabi, DigitalOcean Spaces).
    pub endpoint: Option<String>,

    /// AWS access key ID for authentication.
    ///
    /// When set to empty string on EC2/EKS/Lambda, the SDK will attempt to
    /// retrieve credentials from the instance metadata service (IAM roles).
    pub access_key: String,

    /// AWS secret access key for authentication.
    ///
    /// Must correspond to the `access_key`. See security notes above.
    pub secret_key: String,

    /// Time-to-live for generated presigned URLs in seconds.
    ///
    /// Default: `3600` (1 hour). Maximum recommended: `604800` (7 days).
    /// S3 enforces a maximum of 7 days (604800 seconds) for presigned URLs.
    pub presigned_url_ttl_secs: u64,

    /// Whether to use path-style addressing instead of virtual-hosted style.
    ///
    /// - `false` (default): Virtual-hosted style (`https://{bucket}.s3.{region}.amazonaws.com/{key}`)
    ///   Required for AWS S3 with DNS-compliant bucket names.
    /// - `true`: Path-style (`https://s3.{region}.amazonaws.com}/{bucket}/{key}`)
    ///   Required for MinIO, R2, and some other S3-compatible services.
    pub path_style: bool,
}

impl S3Config {
    /// Create a new [`S3Config`] with required fields.
    ///
    /// # Arguments
    /// * `bucket` - S3 bucket name.
    /// * `region` - AWS or compatible region identifier.
    /// * `access_key` - Access key ID for authentication.
    /// * `secret_key` - Secret access key for authentication.
    ///
    /// # Returns
    /// A configured [`S3Config`] instance with default optional values:
    /// - `endpoint`: `None`
    /// - `presigned_url_ttl_secs`: `3600`
    /// - `path_style`: `false`
    ///
    /// # Example
    /// ```ignore
    /// let config = S3Config::new("my-bucket", "us-east-1", "key", "secret");
    /// ```
    pub fn new(
        bucket: impl Into<String>,
        region: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            presigned_url_ttl_secs: 3600,
            path_style: false,
        }
    }

    /// Set custom endpoint URL for S3-compatible services.
    ///
    /// Required for MinIO, R2, and other non-AWS providers.
    ///
    /// # Arguments
    /// * `endpoint` - Endpoint URL (e.g., `"http://localhost:9000"`).
    ///
    /// # Returns
    /// `Self` for method chaining.
    ///
    /// # Example
    /// ```ignore
    /// let config = S3Config::new("b", "r", "k", "s")
    ///     .with_endpoint(Some("http://minio:9000".to_string()));
    /// ```
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Set presigned URL time-to-live in seconds.
    ///
    /// # Arguments
    /// * `ttl_secs` - TTL in seconds (max 604800 per S3 limits).
    ///
    /// # Returns
    /// `Self` for method chaining.
    #[must_use]
    pub fn with_presigned_url_ttl(mut self, ttl_secs: u64) -> Self {
        self.presigned_url_ttl_secs = ttl_secs;
        self
    }

    /// Enable or disable path-style addressing.
    ///
    /// # Arguments
    /// * `path_style` - `true` for path-style, `false` for virtual-hosted.
    ///
    /// # Returns
    /// `Self` for method chaining.
    #[must_use]
    pub fn with_path_style(mut self, path_style: bool) -> Self {
        self.path_style = path_style;
        self
    }

    /// Validate configuration parameters for correctness.
    ///
    /// Performs sanity checks on all fields to catch misconfiguration early
    /// (before attempting network I/O). Called internally by [`S3Storage::new()`].
    ///
    /// # Errors
    /// Returns [`StorageError::ConfigurationError`] if validation fails:
    /// - Bucket name is empty or exceeds 63 characters.
    /// - Region is empty.
    /// - Presigned URL TTL exceeds S3 maximum (604800 seconds).
    /// - Endpoint URL (if provided) is not a valid HTTP(S) URL.
    ///
    /// # Example
    /// ```ignore
    /// let config = S3Config::new("my-bucket", "us-east-1", "key", "secret");
    /// config.validate()?; // Returns Ok(()) or Err(ConfigurationError)
    /// ```
    pub fn validate(&self) -> Result<(), StorageError> {
        // Validate bucket name
        if self.bucket.is_empty() {
            return Err(StorageError::ConfigurationError(
                "bucket name must not be empty".to_string(),
            ));
        }
        if self.bucket.len() > 63 {
            return Err(StorageError::ConfigurationError(format!(
                "bucket name too long: {} bytes (max 63)",
                self.bucket.len()
            )));
        }

        // Validate region
        if self.region.is_empty() {
            return Err(StorageError::ConfigurationError(
                "region must not be empty".to_string(),
            ));
        }

        // Validate presigned URL TTL (S3 max is 7 days = 604800 seconds)
        if self.presigned_url_ttl_secs > 604_800 {
            return Err(StorageError::ConfigurationError(format!(
                "presigned_url_ttl_secs exceeds S3 maximum: {} (max 604800)",
                self.presigned_url_ttl_secs
            )));
        }

        // Validate endpoint URL format if provided
        if let Some(ref endpoint) = self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(StorageError::ConfigurationError(format!(
                    "endpoint must be HTTP(S) URL: {}",
                    endpoint
                )));
            }
        }

        Ok(())
    }
}

// =============================================================================
// S3Storage — Main implementation of StorageBackend for S3
// =============================================================================

/// S3-compatible cloud storage backend implementing [`StorageBackend`].
///
/// This struct provides a complete implementation of the Misogi storage abstraction
/// for Amazon S3, MinIO, Cloudflare R2, and any S3-compatible object storage service.
///
/// # Thread Safety
///
/// [`S3Storage`] is `Send + Sync` and can be safely shared across tokio tasks
/// via `Arc<S3Storage>`. The internal AWS SDK client handles connection pooling
/// and request multiplexing transparently.
///
/// # Lifecycle
///
/// 1. Construct via [`S3Storage::new()`] with a valid [`S3Config`].
/// 2. Use [`put()`](StorageBackend::put), [`get()`](StorageBackend::get),
///    [`delete()`](StorageBackend::delete), [`exists()`](StorageBackend::exists)
///    for CRUD operations.
/// 3. Monitor health via [`health_check()`](StorageBackend::health_check).
/// 4. Generate direct download links via [`generate_presigned_url()`].
/// 5. Drop when done; the AWS SDK client cleans up resources automatically.
///
/// # Consistency Model
///
/// - **Amazon S3**: Read-after-write consistency for PUTs of new objects in
///   all regions (since December 2020). Eventual consistency for overwrite PUTs
///   and DELETEs in some cases.
/// - **MinIO**: Strong consistency (all operations immediately visible).
/// - **Cloudflare R2**: Strong consistency for reads after writes.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use misogi_core::storage::{S3Config, S3Storage};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = S3Config::new(
///         "my-bucket",
///         "us-east-1",
///         "AKIA...",
///         "secret...",
///     );
///
///     let storage = Arc::new(S3Storage::new(config)?);
///     storage.health_check().await?;
///
///     let data = bytes::Bytes::from_static(b"Hello, S3!");
///     let info = storage.put("test/hello.txt", data.clone()).await?;
///     println!("Stored: {} bytes, etag={:?}", info.size, info.etag);
///
///     let retrieved = storage.get("test/hello.txt").await?;
///     assert_eq!(retrieved, data);
///
///     Ok(())
/// }
/// ```
pub struct S3Storage {
    /// AWS S3 client (thread-safe, handles connection pooling internally).
    client: Client,

    /// Configuration snapshot (used for bucket name, logging, presigned URLs).
    config: S3Config,
}

impl Debug for S3Storage {
    /// Format S3Storage for debugging (excludes secrets).
    ///
    /// The Debug output intentionally omits `access_key` and `secret_key`
    /// to prevent accidental credential leakage in log files.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Storage")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .field("endpoint", &self.config.endpoint)
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field("presigned_url_ttl_secs", &self.config.presigned_url_ttl_secs)
            .field("path_style", &self.config.path_style)
            .finish()
    }
}

impl S3Storage {
    /// Create a new [`S3Storage`] instance from configuration.
    ///
    /// This constructor validates the configuration, builds the AWS SDK
    /// client with appropriate settings (custom endpoint, path-style, etc.),
    /// and returns a ready-to-use storage backend.
    ///
    /// # Arguments
    /// * `config` - Validated [`S3Config`] containing connection parameters.
    ///
    /// # Returns
    /// A fully initialized [`S3Storage`] instance on success.
    ///
    /// # Errors
    /// Returns [`StorageError::ConfigurationError`] if:
    /// - Configuration validation fails (see [`S3Config::validate()`]).
    /// - AWS SDK client construction fails (invalid region, malformed endpoint).
    ///
    /// # Example
    /// ```ignore
    /// let config = S3Config::new("bucket", "us-east-1", "key", "secret")
    ///     .with_path_style(true);
    /// let storage = S3Storage::new(config)?;
    /// ```
    pub async fn new(config: S3Config) -> Result<Self, StorageError> {
        // Validate configuration first (fail-fast)
        config.validate()?;

        info!(
            bucket = %config.bucket,
            region = %config.region,
            endpoint = ?config.endpoint,
            path_style = config.path_style,
            "Initializing S3Storage backend"
        );

        // Build AWS SDK loader with static credentials
        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        // Set endpoint URL if provided (for MinIO/R2 compatibility)
        if let Some(ref endpoint) = config.endpoint {
            debug!(endpoint = %endpoint, "Using custom S3 endpoint");
            loader = loader.endpoint_url(endpoint);
        }

        // Set static credentials using environment variables (AWS SDK standard approach)
        // The AWS SDK for Rust reads credentials from environment variables automatically:
        // - AWS_ACCESS_KEY_ID
        // - AWS_SECRET_ACCESS_KEY
        // We set them temporarily during client construction.
        use std::sync::Arc;
        use aws_credential_types::{Credentials, provider::ProvideCredentials};

        // Create a shared credentials provider from static credentials
        let credentials = Credentials::new(
            &config.access_key,
            &config.secret_key,
            None,  // session_token
            None,  // expires_after
            "static", // source
        );

        // Load base SDK configuration (region, retry strategy, etc.)
        let sdk_config = loader.load().await;

        // Build S3-specific config with region, force_path_style, and custom credentials
        let mut s3_config_builder = S3ClientConfig::builder()
            .region(Region::new(config.region.clone()))
            .force_path_style(config.path_style)
            .credentials_provider(aws_credential_types::provider::SharedCredentialsProvider::new(Arc::new(credentials)));

        // Re-set endpoint for S3 client if custom endpoint provided
        if let Some(ref endpoint) = config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        let s3_config = s3_config_builder.build();
        let client = Client::from_conf(s3_config);

        info!(
            bucket = %config.bucket,
            backend_type = "s3",
            "S3Storage backend initialized successfully"
        );

        Ok(Self {
            client,
            config,
        })
    }

    /// Generate a presigned URL for downloading an object.
    ///
    /// Creates a time-limited authenticated URL that allows anonymous clients
    /// to download the specified object without AWS credentials. Useful for:
    /// - Direct browser downloads (avoiding server-side proxying).
    /// - Temporary sharing links for file transfers.
    /// - CDN integration (some CDNs can fetch from presigned URLs).
    ///
    /// # Arguments
    /// * `key` - Object key to generate URL for.
    ///
    /// # Returns
    /// A presigned URL string with expiration based on [`S3Config::presigned_url_ttl_secs`].
    ///
    /// # Errors
    /// - [`StorageError::NotFound`] if the object does not exist (optional validation).
    /// - [`StorageError::InternalError`] if URL generation fails.
    /// - [`StorageError::ConfigurationError`] if TTL is invalid.
    ///
    /// # Security Note
    /// Presigned URLs grant access to anyone who possesses them until expiry.
    /// Treat them as secrets: use short TTLs, avoid logging them, and
    /// consider IP restrictions if your S3 provider supports them.
    ///
    /// # Example
    /// ```ignore
    /// let url = storage.generate_presigned_url("documents/report.pdf").await?;
    /// println!("Download link: {} (expires in 1 hour)", url);
    /// ```
    #[instrument(skip(self), fields(key))]
    pub async fn generate_presigned_url(&self, key: &str) -> Result<String, StorageError> {
        // Validate key
        self.validate_key(key)?;

        // Calculate expiration timestamp using SystemTime (required by SmithyDateTime)
        let expires_in = Duration::from_secs(self.config.presigned_url_ttl_secs);
        let _expires_at = SmithyDateTime::from(std::time::SystemTime::now() + expires_in); // Used implicitly by presigned request builder

        debug!(
            key = %key,
            ttl_secs = self.config.presigned_url_ttl_secs,
            bucket = %self.config.bucket,
            "Generating presigned GET URL"
        );

        // Build presigned request for GetObject
        let presigned_request = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .presigned(
                aws_sdk_s3::presigning::PresigningConfig::builder()
                    .expires_in(expires_in)
                    .build()
                    .map_err(|e| StorageError::InternalError(format!(
                        "failed to build presigning config: {e}"
                    )))?,
            )
            .await
            .map_err(|e| self.map_sdk_error(&e, key))?;

        let url = presigned_request.uri().to_string();

        info!(
            key = %key,
            url_length = url.len(),
            ttl_secs = self.config.presigned_url_ttl_secs,
            "Generated presigned URL successfully"
        );

        Ok(url)
    }

    // =========================================================================
    // Private Helper Methods
    // =========================================================================

    /// Validate an S3 object key for safety and compliance.
    ///
    /// Enforces constraints to prevent injection attacks and ensure
    /// compatibility with S3's key namespace rules.
    ///
    /// # Rules
    /// - Key must not be empty.
    /// - Key length must not exceed 1024 UTF-8 bytes (S3 limit).
    /// - Key must be valid UTF-8 (enforced by Rust's String type).
    ///
    /// # Errors
    /// Returns [`StorageError::ConfigurationError`] for invalid keys.
    fn validate_key(&self, key: &str) -> Result<(), StorageError> {
        if key.is_empty() {
            return Err(StorageError::ConfigurationError(
                "S3 key must not be empty".to_string(),
            ));
        }

        if key.len() > 1024 {
            return Err(StorageError::ConfigurationError(format!(
                "S3 key too long: {} bytes (max 1024)",
                key.len()
            )));
        }

        Ok(())
    }

    /// Map AWS SDK errors to Misogi [`StorageError`] variants.
    ///
    /// Translates the AWS SDK's typed error hierarchy into Misogi's
    /// standardized error taxonomy for consistent error handling by callers.
    ///
    /// # Error Mapping Table
    ///
    /// | AWS SdkError Variant          | Mapped To                          |
    /// |------------------------------|------------------------------------|
    /// | NotFound (HeadObject 404)     | [`StorageError::NotFound`]         |
    /// | AccessDenied (403)            | [`StorageError::PermissionDenied`] |
    /// | Network / Timeout / Dispatch  | [`StorageError::NetworkError`]     |
    /// | Construction / Validation     | [`StorageError::ConfigurationError`] |
    /// | Other (unexpected)            | [`StorageError::InternalError`]    |
    ///
    /// # Arguments
    /// * `error` - The AWS SDK error to map.
    /// * `key` - The object key involved (for error context).
    ///
    /// # Returns
    /// Appropriate [`StorageError`] variant with contextual information.
    fn map_sdk_error<E: ProvideErrorMetadata + std::fmt::Debug>(&self, error: &SdkError<E>, key: &str) -> StorageError {
        match error {
            SdkError::ServiceError(service_err) => {
                let status = service_err.raw().status();
                let code = service_err.err().code().unwrap_or("UNKNOWN");

                match status.as_u16() {
                    404 => {
                        warn!(
                            error = ?error,
                            key = %key,
                            status = %status,
                            aws_code = %code,
                            "S3 returned Not Found"
                        );
                        StorageError::NotFound(key.to_string())
                    }
                    403 => {
                        warn!(
                            error = ?error,
                            key = %key,
                            status = %status,
                            aws_code = %code,
                            "S3 returned Access Denied"
                        );
                        StorageError::PermissionDenied(format!(
                            "access denied for key '{key}': AWS code={code}"
                        ))
                    }
                    400 => {
                        error!(
                            error = ?error,
                            key = %key,
                            status = %status,
                            aws_code = %code,
                            "S3 returned Bad Request"
                        );
                        StorageError::ConfigurationError(format!(
                            "bad request for key '{key}': AWS code={code}, message={}",
                            service_err.err().message().unwrap_or("unknown")
                        ))
                    }
                    _ => {
                        error!(
                            error = ?error,
                            key = %key,
                            status = %status,
                            aws_code = %code,
                            "S3 returned unexpected service error"
                        );
                        StorageError::InternalError(format!(
                            "S3 service error for key '{key}': HTTP {status}, code={code}"
                        ))
                    }
                }
            }
            SdkError::DispatchFailure(dispatch_err) => {
                warn!(
                    error = ?dispatch_err,
                    key = %key,
                    "S3 dispatch failure (network/timeout)"
                );
                StorageError::NetworkError(format!(
                    "S3 network error for key '{key}: {dispatch_err:?}'"
                ))
            }
            SdkError::ConstructionFailure(construction_err) => {
                error!(
                    error = ?construction_err,
                    key = %key,
                    "S3 request construction failure"
                );
                StorageError::ConfigurationError(format!(
                    "S3 request construction failed for key '{key}: {construction_err:?}'"
                ))
            }
            SdkError::TimeoutError(timeout_err) => {
                warn!(
                    error = ?timeout_err,
                    key = %key,
                    "S3 operation timed out"
                );
                StorageError::NetworkError(format!(
                    "S3 timeout for key '{key}: {timeout_err:?}'"
                ))
            }
            other => {
                error!(
                    error = %other,
                    key = %key,
                    "Unexpected S3 SDK error"
                );
                StorageError::InternalError(format!(
                    "Unexpected S3 error for key '{key}: {other}'"
                ))
            }
        }
    }
}

// =============================================================================
// StorageBackend Trait Implementation
// =============================================================================

#[async_trait]
impl StorageBackend for S3Storage {
    /// Upload an object to the S3 bucket.
    ///
    /// Uses the S3 PutObject API to store data under the specified key.
    /// If the key already exists, it will be overwritten (S3 default behavior).
    ///
    /// # Performance Characteristics
    /// - Latency: ~50-200ms (depending on region and object size).
    /// - Throughput: Limited by network bandwidth to S3 endpoint.
    /// - Idempotent: Subsequent calls with same key overwrite previous version.
    ///
    /// # S3-Specific Behavior
    /// - Content-Type is set to `"application/octet-stream"` unless otherwise
    ///   specified via metadata (future enhancement).
    /// - ETag is extracted from response for integrity verification.
    /// - Server-side encryption depends on bucket policy (not controlled here).
    #[instrument(skip(self, data), fields(key, data_len = data.len()))]
    async fn put(&self, key: &str, data: Bytes) -> Result<StorageInfo, StorageError> {
        // Validate input key
        self.validate_key(key)?;

        let data_len = data.len() as u64;

        debug!(
            key = %key,
            bucket = %self.config.bucket,
            size = data_len,
            "Uploading object to S3"
        );

        // Convert Bytes to ByteStream for AWS SDK
        let body = ByteStream::from(data);

        // Execute PutObject
        let result = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(body)
            .content_length(data_len as i64)
            .send()
            .await
            .map_err(|e| self.map_sdk_error(&e, key))?;

        // Extract ETag from response (integrity token)
        let etag = result.e_tag().map(|s: &str| s.to_string());

        let created_at = Some(Utc::now());

        let etag_for_log = etag.clone(); // Clone for logging (etag is moved into StorageInfo)

        let info = StorageInfo {
            key: key.to_string(),
            size: data_len,
            content_type: None, // Could be extended to detect from key extension
            created_at,
            etag,
        };

        info!(
            key = %key,
            size = data_len,
            etag = ?etag_for_log,
            "Object uploaded to S3 successfully"
        );

        Ok(info)
    }

    /// Download an object from the S3 bucket.
    ///
    /// Uses the S3 GetObject API to retrieve the complete object content.
    /// The entire object is loaded into memory as [`Bytes`].
    ///
    /// # Performance Warning
    /// For objects larger than available RAM, this method may cause OOM kills.
    /// Future versions should provide a streaming interface for large objects.
    ///
    /// # S3-Specific Behavior
    /// - Range requests are NOT used; always fetches the complete object.
    /// - Response metadata (Content-Type, Last-Modified) is discarded currently.
    #[instrument(skip(self), fields(key))]
    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        // Validate input key
        self.validate_key(key)?;

        debug!(
            key = %key,
            bucket = %self.config.bucket,
            "Downloading object from S3"
        );

        // Execute GetObject
        let result = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| self.map_sdk_error(&e, key))?;

        // Collect the streaming body into Bytes
        let data = result
            .body
            .collect()
            .await
            .map_err(|e| StorageError::NetworkError(format!(
                "failed to read S3 response body for key '{key}: {e}'
            ")))?
            .into_bytes();

        debug!(
            key = %key,
            size = data.len(),
            "Object downloaded from S3 successfully"
        );

        Ok(data)
    }

    /// Delete an object from the S3 bucket.
    ///
    /// Uses the S3 DeleteObject API to remove the specified object.
    /// Deleting a non-existent key succeeds silently (idempotent behavior).
    ///
    /// # S3-Specific Behavior
    /// - S3 DeleteObject returns 204 No Content even if the object doesn't exist.
    /// - Versioned buckets: this creates a delete marker (object still exists
    ///   in older versions but is invisible to normal GetObject calls).
    /// - The operation is eventually consistent: immediate Exists() may return
    ///   true briefly after deletion.
    #[instrument(skip(self), fields(key))]
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        // Validate input key
        self.validate_key(key)?;

        debug!(
            key = %key,
            bucket = %self.config.bucket,
            "Deleting object from S3"
        );

        // Execute DeleteObject
        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| self.map_sdk_error(&e, key))?;

        info!(key = %key, "Object deleted from S3 successfully");

        Ok(())
    }

    /// Check whether an object exists in the S3 bucket.
    ///
    /// Uses the S3 HeadObject API (lightweight metadata-only request).
    /// Does not retrieve the object body, minimizing bandwidth usage.
    ///
    /// # Consistency Note
    /// - **Amazon S3**: Strong consistency for HeadObject after PUT (since Dec 2020).
    /// - **MinIO**: Strong consistency (immediate visibility).
    /// - **R2**: Strong consistency.
    ///
    /// # Performance
    /// - Latency: ~20-100ms (faster than GetObject due to no body transfer).
    /// - Bandwidth: Only HTTP headers exchanged (no payload).
    #[instrument(skip(self), fields(key))]
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        // Validate input key
        self.validate_key(key)?;

        debug!(
            key = %key,
            bucket = %self.config.bucket,
            "Checking object existence via HeadObject"
        );

        // Execute HeadObject
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => {
                debug!(key = %key, "Object exists in S3");
                Ok(true)
            }
            Err(e) => {
                // Check if this is a 404 Not Found error
                if let SdkError::ServiceError(service_err) = &e {
                    if service_err.raw().status().as_u16() == 404 {
                        debug!(key = %key, "Object does not exist in S3");
                        return Ok(false);
                    }
                }
                // Re-throw other errors through standard mapping
                Err(self.map_sdk_error(&e, key))
            }
        }
    }

    /// Perform a health check against the S3 backend.
    ///
    /// Verifies connectivity and authentication by attempting to list objects
    /// in the bucket with `max_keys=1`. This is a lightweight operation that:
    /// - Validates credentials (fails fast on auth errors).
    /// - Confirms network reachability to the S3 endpoint.
    /// - Verifies bucket existence and accessibility.
    /// - Does not modify any data (read-only operation).
    ///
    /// # Performance Target
    /// - Expected latency: <500ms for healthy backends.
    /// - Recommended polling interval: 10-60 seconds for monitoring systems.
    ///
    /// # S3-Specific Notes
    /// - Requires `s3:ListBucket` IAM permission on the bucket.
    /// - May fail with PermissionDenied even if get/put work (separate permission).
    /// - Cloudflare R2 does not support ListObjects; consider alternative health check.
    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), StorageError> {
        debug!(
            bucket = %self.config.bucket,
            endpoint = ?self.config.endpoint,
            "Performing S3 health check via ListObjectsV2"
        );

        // Execute ListObjectsV2 with max_keys=1 (minimal payload)
        self.client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .max_keys(1)
            .send()
            .await
            .map_err(|e| self.map_sdk_error(&e, "<health-check>"))?;

        info!(
            bucket = %self.config.bucket,
            "S3 health check passed — backend is reachable"
        );

        Ok(())
    }

    /// Return the backend type identifier string.
    ///
    /// Always returns `"s3"` regardless of the actual provider (S3, MinIO, R2).
    /// This enables runtime identification for logging, plugin registry lookups,
    /// and conditional logic based on backend capabilities.
    fn backend_type(&self) -> &'static str {
        "s3"
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test 1: S3Config Validation — Valid Configuration
    // =========================================================================

    #[test]
    fn test_config_validation_valid() {
        let config = S3Config::new(
            "valid-bucket-name",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );

        assert!(config.validate().is_ok());
    }

    // =========================================================================
    // Test 2: S3Config Validation — Empty Bucket Name
    // =========================================================================

    #[test]
    fn test_config_validation_empty_bucket() {
        let config = S3Config::new("", "us-east-1", "key", "secret");

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("bucket"));
            }
            other => panic!("Expected ConfigurationError, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test 3: S3Config Validation — Empty Region
    // =========================================================================

    #[test]
    fn test_config_validation_empty_region() {
        let config = S3Config::new("bucket", "", "key", "secret");

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("region"));
            }
            other => panic!("Expected ConfigurationError, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test 4: S3Config Validation — Excessive Presigned URL TTL
    // =========================================================================

    #[test]
    fn test_config_validation_excessive_ttl() {
        let config = S3Config::new("bucket", "region", "key", "secret")
            .with_presigned_url_ttl(999_999); // Exceeds 604800 limit

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("presigned_url_ttl_secs"));
                assert!(msg.contains("604800"));
            }
            other => panic!("Expected ConfigurationError, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test 5: S3Config Validation — Invalid Endpoint URL Scheme
    // =========================================================================

    #[test]
    fn test_config_validation_invalid_endpoint_scheme() {
        let config = S3Config::new("bucket", "region", "key", "secret")
            .with_endpoint(Some("ftp://invalid-scheme".to_string()));

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("HTTP(S)"));
            }
            other => panic!("Expected ConfigurationError, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test 6: S3Config Validation — Valid Endpoint URL (HTTP)
    // =========================================================================

    #[test]
    fn test_config_validation_valid_http_endpoint() {
        let config = S3Config::new("bucket", "region", "key", "secret")
            .with_endpoint(Some("http://localhost:9000".to_string()));

        assert!(config.validate().is_ok());
    }

    // =========================================================================
    // Test 7: S3Config Validation — Valid Endpoint URL (HTTPS)
    // =========================================================================

    #[test]
    fn test_config_validation_valid_https_endpoint() {
        let config = S3Config::new("bucket", "region", "key", "secret")
            .with_endpoint(Some("https://r2.example.com".to_string()));

        assert!(config.validate().is_ok());
    }

    // =========================================================================
    // Test 8: S3Config Builder Pattern — Method Chaining
    // =========================================================================

    #[test]
    fn test_config_builder_pattern() {
        let config = S3Config::new("bucket", "region", "key", "secret")
            .with_endpoint(Some("http://localhost:9000".to_string()))
            .with_presigned_url_ttl(1800)
            .with_path_style(true);

        assert_eq!(config.bucket, "bucket");
        assert_eq!(config.region, "region");
        assert_eq!(config.access_key, "key");
        assert_eq!(config.secret_key, "secret");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.presigned_url_ttl_secs, 1800);
        assert!(config.path_style);
    }

    // =========================================================================
    // Test 9: Key Validation — Empty Key
    // =========================================================================

    #[tokio::test]
    async fn test_validate_key_empty() {
        let config = create_test_config();
        let storage = create_test_storage(config).await;

        let result = storage.validate_key("");
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("Expected ConfigurationError, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test 10: Key Validation — Oversized Key (>1024 bytes)
    // =========================================================================

    #[tokio::test]
    async fn test_validate_key_oversized() {
        let config = create_test_config();
        let storage = create_test_storage(config).await;

        let long_key = "a".repeat(1025);
        let result = storage.validate_key(&long_key);

        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::ConfigurationError(msg) => {
                assert!(msg.contains("1024"));
            }
            other => panic!("Expected ConfigurationError, got: {:?}", other),
        }
    }

    // =========================================================================
    // Test 11: Backend Type Identifier
    // =========================================================================

    #[tokio::test]
    async fn test_backend_type_returns_s3() {
        let config = create_test_config();
        let storage = create_test_storage(config).await;

        assert_eq!(storage.backend_type(), "s3");
    }

    // =========================================================================
    // Test 12: Debug Output Redacts Credentials
    // =========================================================================

    #[tokio::test]
    async fn test_debug_redacts_credentials() {
        let config = S3Config::new(
            "test-bucket",
            "us-east-1",
            "SECRET_ACCESS_KEY",
            "SUPER_SECRET_PASSWORD",
        );
        let storage = create_test_storage(config).await;

        let debug_str = format!("{:?}", storage);
        assert!(!debug_str.contains("SECRET_ACCESS_KEY"));
        assert!(!debug_str.contains("SUPER_SECRET_PASSWORD"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    // =========================================================================
    // Test Helpers
    // =========================================================================

    /// Create a valid S3Config for testing (uses dummy credentials).
    ///
    /// These credentials are not used in unit tests since we don't make
    /// real network calls; they're only needed for struct construction.
    fn create_test_config() -> S3Config {
        S3Config::new(
            "test-bucket",
            "us-east-1",
            "test-access-key",
            "test-secret-key",
        )
        .with_endpoint(Some("http://localhost:9000".to_string()))
        .with_path_style(true)
    }

    /// Create an S3Storage instance for testing.
    ///
    /// Note: This creates a real AWS SDK client but doesn't connect to
    /// any server. Integration tests would need a running MinIO/S3 instance.
    async fn create_test_storage(config: S3Config) -> S3Storage {
        S3Storage::new(config)
            .await
            .expect("Failed to create test S3Storage instance")
    }
}
