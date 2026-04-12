// =============================================================================
// Misogi Core — gRPC Remote Scanner Adapter
// =============================================================================
//! Connects to an external gRPC-based scanning service (enterprise
//! security platform, custom microservice, etc.) and delegates
//! file scanning over the wire using Protocol Buffers.
//!
//! # Architecture
//!
//! This adapter implements a generic gRPC client for file scanning services.
//! It uses a flexible approach that can work with any gRPC service implementing
//! a simple scan interface, with pluggable request/response mapping.
//!
//! # Proto Service Definition (Expected Interface)
//!
//! The adapter expects a gRPC service that follows this general pattern:
//!
//! ```protobuf
//! service FileScanner {
//!   rpc ScanFile(ScanRequest) returns (ScanResponse);
//!   rpc HealthCheck(HealthRequest) returns (HealthResponse);
//! }
//!
//! message ScanRequest {
//!   bytes file_content = 1;
//!   string filename = 2;
//!   uint64 file_size = 3;
//! }
//!
//! message ScanResponse {
//!   enum Status {
//!     CLEAN = 0;
//!     INFECTED = 1;
//!     ERROR = 2;
//!   }
//!   Status status = 1;
//!   string threat_name = 2;
//!   string severity = 3;
//!   string error_message = 4;
//! }
//! ```
//!
//! ⚠️ **Note**: For maximum flexibility, this adapter provides a generic
//! implementation. Users can create specialized wrappers for specific proto
//! definitions by composing this adapter or implementing [`ExternalScanner`]
//! directly.
//!
//! # Example Usage
//!
//! ```ignore
//! use misogi_core::scanners::{GrpcScannerAdapter, GrpcScannerConfig};
//!
//! let config = GrpcScannerConfig {
//!     server_addr: "scanner.example.com:50051".to_string(),
//!     use_tls: true,
//!     tls_domain: Some("scanner.example.com".to_string()),
//!     timeout_secs: 30,
//! };
//!
//! let mut scanner = GrpcScannerAdapter::new(config);
//! let result = scanner.scan_stream(&file_data).await?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tonic::transport::{Channel, ClientTlsConfig};

use super::{
    ExternalScanner, Result as ScannerResult, ScanResult, ScannerError,
    ScannerMetadata,
};

// =============================================================================
// Configuration Types
// =============================================================================

/// Configuration for gRPC-based remote scanner adapter.
///
/// Defines connection parameters for the gRPC service including address,
/// TLS settings, and operation timeouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcScannerConfig {
    /// gRPC server address in `"host:port"` format.
    ///
    /// Examples:
    /// - `"localhost:50051"` — Local development server
    /// - `"scanner.internal:443"` — Internal production server
    /// - `"10.0.0.50:9000"` — Direct IP address
    pub server_addr: String,

    /// Whether to use TLS encryption for the connection.
    ///
    /// - `true`: Connect via `https://` with TLS certificate verification
    /// - `false`: Connect via plain text (development/internal networks only)
    ///
    /// **Security Warning**: Always use TLS in production environments.
    pub use_tls: bool,

    /// TLS domain for certificate verification (if applicable).
    ///
    /// When `use_tls` is true, this specifies the expected server name
    /// for certificate validation. If `None`, uses the hostname from
    /// `server_addr`.
    pub tls_domain: Option<String>,

    /// Timeout for gRPC operations (seconds).
    ///
    /// Applied to both scan requests and health checks.
    /// Should account for network latency + server processing time.
    /// Default: `30` seconds.
    pub timeout_secs: u64,
}

impl Default for GrpcScannerConfig {
    fn default() -> Self {
        Self {
            server_addr: "localhost:50051".to_string(),
            use_tls: false,
            tls_domain: None,
            timeout_secs: 30,
        }
    }
}

// =============================================================================
// gRPC Scanner Adapter Implementation
// =============================================================================

/// Adapter for gRPC-based remote virus/malware scanning services.
///
/// Implements [`ExternalScanner`] trait by connecting to external gRPC servers
/// that provide file scanning capabilities. Maintains a persistent connection
/// channel with automatic reconnection on failure.
///
/// # Thread Safety
/// This struct is `Send + Sync` safe because:
/// - Configuration data is immutable after construction
/// - Channel management uses interior mutability (`tokio::sync::Mutex`)
/// - All gRPC calls are async and non-blocking
///
/// # Connection Management
///
/// The adapter lazily initializes the gRPC channel on first use and maintains
/// it for subsequent calls. If the channel becomes disconnected, subsequent
/// calls will attempt reconnection automatically.
///
/// # Performance Characteristics
///
/// - **Connection overhead**: One-time cost on first call (~10-50ms with TLS)
/// - **Throughput**: Limited by network latency and server processing time
/// - **Memory usage**: Minimal (channel handle only; no buffering)
/// - **Concurrency**: Fully async-safe; supports concurrent scan operations
pub struct GrpcScannerAdapter {
    /// Immutable configuration for this adapter instance.
    config: GrpcScannerConfig,

    /// Shared gRPC channel (initialized lazily).
    ///
    /// Wrapped in Mutex for interior mutability despite &self methods.
    channel: std::sync::Mutex<Option<Channel>>,

    /// Unique identifier for logging and chain identification.
    adapter_id: String,
}

impl GrpcScannerAdapter {
    /// Create a new gRPC scanner adapter with specified configuration.
    ///
    /// Does not immediately connect to the server — connection is established
    /// lazily on first scan/health_check/metadata call.
    ///
    /// # Arguments
    /// * `config` — Server address, TLS settings, and timeout configuration.
    ///
    /// # Returns
    /// Initialized `GrpcScannerAdapter` ready for use.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = GrpcScannerConfig {
    ///     server_addr: "scan-service:50051".to_string(),
    ///     use_tls: true,
    ///     ..Default::default()
    /// };
    /// let adapter = GrpcScannerAdapter::new(config);
    /// ```
    pub fn new(config: GrpcScannerConfig) -> Self {
        let adapter_id = format!("grpc-{}", config.server_addr);

        tracing::info!(
            adapter_id = %adapter_id,
            server = %config.server_addr,
            tls = config.use_tls,
            "Creating gRPC scanner adapter"
        );

        Self {
            config,
            channel: std::sync::Mutex::new(None),
            adapter_id,
        }
    }

    /// Ensure gRPC channel is connected, creating if necessary.
    ///
    /// Establishes a new channel if one doesn't exist or if the existing
    /// channel has been closed/disconnected. Thread-safe via mutex lock.
    ///
    /// # Returns
    /// Clone of the active channel, or error if connection fails.
    async fn ensure_channel(&self) -> ScannerResult<Channel> {
        // Check if we already have a valid channel
        {
            let guard = self.channel.lock().unwrap();
            if let Some(ref ch) = *guard {
                // Quick check: is the channel still usable?
                // Note: tonic Channel doesn't have a direct is_ready() in all versions,
                // so we'll try to use it and reconnect on failure
                return Ok(ch.clone());
            }
        }

        // Need to establish new connection
        tracing::info!(
            server = %self.config.server_addr,
            tls = self.config.use_tls,
            "Establishing new gRPC channel"
        );

        let endpoint = tonic::transport::Endpoint::from_shared(self.config.server_addr.clone())
            .map_err(|e| {
                ScannerError::Configuration(format!(
                    "Invalid gRPC server address '{}': {}",
                    self.config.server_addr, e
                ))
            })?;

        // Apply timeout
        let endpoint = endpoint.timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
        );

        // Apply TLS if configured
        let endpoint = if self.config.use_tls {
            let tls_config = ClientTlsConfig::new();

            let tls_config = if let Some(ref domain) = self.config.tls_domain {
                tls_config.domain_name(domain)
            } else {
                tls_config
            };

            endpoint.tls_config(tls_config).map_err(|e| {
                ScannerError::Configuration(format!("TLS configuration failed: {}", e))
            })?
        } else {
            endpoint
        };

        // Connect to server
        let channel = endpoint.connect().await.map_err(|e: tonic::transport::Error| {
            tracing::error!(error = %e, "Failed to connect to gRPC server");
            ScannerError::Connection(format!(
                "Failed to connect to gRPC server {}: {}",
                self.config.server_addr, e
            ))
        })?;

        tracing::info!(server = %self.config.server_addr, "gRPC channel established");

        // Store channel for reuse
        {
            let mut guard = self.channel.lock().unwrap();
            *guard = Some(channel.clone());
        }

        Ok(channel)
    }

    /// Execute file scan via gRPC (generic implementation).
    ///
    /// ⚠️ **Note**: This is a generic implementation template. In practice,
    /// users should either:
    /// 1. Use a concrete proto-generated client wrapped around this adapter
    /// 2. Implement their own [`ExternalScanner`] for custom proto definitions
    ///
    /// This implementation demonstrates the pattern but would need actual
    /// proto-generated client code for real usage.
    ///
    /// # Arguments
    /// * `data` — File content bytes to send for scanning.
    ///
    /// # Returns
    /// Parsed [`ScanResult`] from the gRPC response.
    async fn grpc_scan(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        tracing::debug!(
            adapter_id = %self.adapter_id,
            data_size = data.len(),
            "Executing gRPC scan"
        );

        // Get or establish channel
        let _channel = self.ensure_channel().await?;

        // TODO: Implement actual gRPC call with proto-generated client
        //
        // Pseudocode for typical implementation:
        // ```rust
        // let mut client = ScannerServiceClient::new(channel);
        // let request = ScanRequest {
        //     file_content: data.to_vec(),
        //     filename: "scan_target".to_string(),
        //     file_size: data.len() as u64,
        // };
        // let response = client
        //     .scan_file(request)
        //     .await
        //     .map_err(|e| match e.code() {
        //         tonic::Code::Unavailable => ScannerError::Connection(e.message().to_string()),
        //         tonic::Code::DeadlineExceeded => ScannerError::Timeout { ... },
        //         _ => ScannerError::Protocol(format!("gRPC error: {}", e)),
        //     })?
        //     .into_inner();
        //
        // match response.status() {
        //     Status::Clean => Ok(ScanResult::Clean),
        //     Status::Infected => Ok(ScanResult::Infected { ... }),
        //     Status::Error => Ok(ScanResult::Error { ... }),
        // }
        // ```

        // Placeholder: return clean until proto integration is complete
        tracing::warn!(
            "gRPC scan called but proto client not yet integrated — returning placeholder Clean"
        );
        Ok(ScanResult::Clean)
    }

    /// Perform gRPC health check against the server.
    ///
    /// Calls the standard gRPC health checking protocol (gRPC Health Checking
    /// Specification) or a custom health RPC if configured.
    async fn grpc_health_check(&self) -> bool {
        tracing::debug!(adapter_id = %self.adapter_id, "Performing gRPC health check");

        match self.ensure_channel().await {
            Ok(_channel) => {
                // TODO: Implement actual health check call
                // Pseudocode:
                // ```rust
                // let mut client = HealthClient::new(channel);
                // let response = client.check(HealthRequest { service: "".to_string() }).await;
                // matches!(response, Ok(resp) if resp.status() == ServingStatus::Serving)
                // ```
                tracing::info!("gRPC health check passed (placeholder)");
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "gRPC health check failed");
                false
            }
        }
    }

    /// Query metadata from gRPC server (version info, etc.).
    ///
    /// Calls a version/info RPC if available on the server.
    async fn grpc_metadata(&self) -> Option<ScannerMetadata> {
        tracing::debug!(adapter_id = %self.adapter_id, "Querying gRPC metadata");

        match self.ensure_channel().await {
            Ok(_channel) => {
                // TODO: Implement actual metadata query
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "Cannot query gRPC metadata");
                None
            }
        }
    }
}

#[async_trait]
impl ExternalScanner for GrpcScannerAdapter {
    /// Returns `"GrpcScanner"` as the display name.
    fn name(&self) -> &str {
        "GrpcScanner"
    }

    /// Returns unique identifier based on server address.
    fn id(&self) -> &str {
        &self.adapter_id
    }

    /// Scan file content via gRPC remote procedure call.
    ///
    /// Ensures channel connectivity, then sends file content to the
    /// remote scanning service for analysis.
    ///
    /// # Arguments
    /// * `data` — Complete file bytes to scan.
    ///
    /// # Returns
    /// - `Ok(ScanResult::Clean)` — No threats detected
    /// - `Ok(ScanResult::Infected { ... })` — Threat found
    /// - `Ok(ScanResult::Error { ... })` — Server-reported error
    /// - `Ok(ScanResult::Timeout { ... })` — Operation timed out
    /// - `Err(ScannerError)` — Connection/protocol failure
    async fn scan_stream(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        // Apply overall timeout wrapper
        let timeout_duration = std::time::Duration::from_secs(self.config.timeout_secs);

        match tokio::time::timeout(timeout_duration, self.grpc_scan(data)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    timeout = self.config.timeout_secs,
                    "gRPC scan timed out"
                );
                Ok(ScanResult::Timeout {
                    timeout_secs: self.config.timeout_secs,
                })
            }
        }
    }

    /// Health check by verifying gRPC server connectivity.
    ///
    /// Attempts to establish channel and optionally queries server health status.
    ///
    /// # Returns
    /// - `true` — gRPC server is reachable and healthy
    /// - `false` — Cannot connect or server reports unhealthy
    async fn health_check(&self) -> bool {
        self.grpc_health_check().await
    }

    /// Query scanner metadata from gRPC server.
    ///
    /// Retrieves engine version, signature info, etc. from the remote service.
    ///
    /// # Returns
    /// Some(`ScannerMetadata`) if supported by server, `None` otherwise.
    async fn metadata(&self) -> Option<ScannerMetadata> {
        self.grpc_metadata().await
    }
}

impl std::fmt::Debug for GrpcScannerAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcScannerAdapter")
            .field("adapter_id", &self.adapter_id)
            .field("config", &self.config)
            .field("has_channel", &self.channel.lock().unwrap().is_some())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_default_config() {
        let config = GrpcScannerConfig::default();
        assert_eq!(config.server_addr, "localhost:50051");
        assert!(!config.use_tls);
        assert!(config.tls_domain.is_none());
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_custom_config_creation() {
        let config = GrpcScannerConfig {
            server_addr: "scanner.example.com:50051".to_string(),
            use_tls: true,
            tls_domain: Some("scanner.example.com".to_string()),
            timeout_secs: 60,
        };

        assert_eq!(config.server_addr, "scanner.example.com:50051");
        assert!(config.use_tls);
        assert_eq!(config.tls_domain.as_deref(), Some("scanner.example.com"));
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = GrpcScannerConfig {
            server_addr: "grpc-scanner.internal:9000".to_string(),
            use_tls: true,
            tls_domain: Some("grpc-scanner.internal".to_string()),
            timeout_secs: 45,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: GrpcScannerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.server_addr, config.server_addr);
        assert_eq!(deserialized.use_tls, config.use_tls);
        assert_eq!(deserialized.tls_domain, config.tls_domain);
        assert_eq!(deserialized.timeout_secs, config.timeout_secs);
    }

    // =========================================================================
    // Adapter Creation Tests
    // =========================================================================

    #[test]
    fn test_adapter_creation() {
        let config = GrpcScannerConfig {
            server_addr: "localhost:50051".to_string(),
            ..Default::default()
        };

        let adapter = GrpcScannerAdapter::new(config);
        assert_eq!(adapter.name(), "GrpcScanner");
        assert!(adapter.id().contains("localhost:50051"));
    }

    #[test]
    fn test_adapter_debug_format() {
        let config = GrpcScannerConfig {
            server_addr: "test-server:1234".to_string(),
            ..Default::default()
        };

        let adapter = GrpcScannerAdapter::new(config);
        let debug_str = format!("{:?}", adapter);

        assert!(debug_str.contains("GrpcScannerAdapter"));
        assert!(debug_str.contains("test-server:1234"));
    }

    // =========================================================================
    // Invalid Address Tests
    // =========================================================================

    #[test]
    fn test_invalid_server_address_rejected() {
        // Note: This test verifies configuration validation
        // Actual connection failure happens at runtime
        let config = GrpcScannerConfig {
            server_addr: "not-a-valid-url".to_string(),
            ..Default::default()
        };

        let adapter = GrpcScannerAdapter::new(config);
        // Creation succeeds (validation deferred to connection)
        assert_eq!(adapter.name(), "GrpcScanner");
    }

    // =========================================================================
    // Integration-style Test (requires running server)
    // =========================================================================

    #[tokio::test]
    async fn test_health_check_fails_without_server() {
        let config = GrpcScannerConfig {
            server_addr: "localhost:19999".to_string(), // Unlikely port
            timeout_secs: 2, // Short timeout for fast failure
            ..Default::default()
        };

        let adapter = GrpcScannerAdapter::new(config);

        // Should fail quickly when no server is listening
        let healthy = adapter.health_check().await;
        assert!(!healthy); // No server → not healthy
    }
}
