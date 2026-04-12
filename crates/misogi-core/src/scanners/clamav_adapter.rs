// =============================================================================
// Misogi Core — ClamAV Daemon (clamd) Adapter
// =============================================================================
//! Connects to a running ClamAV daemon (clamd) instance via TCP socket or
//! UNIX domain socket using the INSTREAM protocol for streaming file scanning.
//!
//! # Protocol Reference
//!
//! This adapter implements ClamAV's **INSTREAM** protocol for sending file
//! content to clamd over a network connection without writing to disk.
//!
//! ## INSTREAM Protocol Flow
//!
//! ```text
//! 1. Client → Server: "zINSTREAM\0" (command initiation)
//! 2. Client → Server: [4-byte big-endian length][chunk data] (repeat)
//! 3. Client → Server: [0x00000000] (zero-length chunk = EOF marker)
//! 4. Server → Client: "<filepath>: <result>\0" (scan result)
//! ```
//!
//! ## Response Format
//!
//! - `stream: OK` — File is clean, no threats detected
//! - `stream: <signature> FOUND` — Threat detected with signature name
//! - `stream: <error message>` — Error condition (parse error, etc.)
//!
//! # Configuration
//!
//! Supports both TCP and UNIX socket connections:
//!
//! - **TCP**: `ClamAvConnection::Tcp { host: "localhost", port: 3310 }`
//! - **UNIX**: `ClamAvConnection::Unix { path: "/var/run/clamd.sock" }`
//!
//! # Example Usage
//!
//! ```ignore
//! use misogi_core::scanners::{ClamAvAdapter, ClamAvConfig, ClamAvConnection};
//!
//! let config = ClamAvConfig {
//!     connection: ClamAvConnection::Tcp {
//!         host: "localhost".to_string(),
//!         port: 3310,
//!     },
//!     scan_timeout_secs: 30,
//!     connect_timeout_secs: 10,
//!     stream_chunk_size: 131072, // 128KB chunks
//! };
//!
//! let scanner = ClamAvAdapter::new(config);
//! let result = scanner.scan_stream(&file_data).await?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{
    ExternalScanner, Result as ScannerResult, ScanResult, ScannerError,
    ScannerMetadata, ThreatSeverity,
};

// =============================================================================
// Configuration Types
// =============================================================================

/// ClamAV daemon connection configuration.
///
/// Defines how to connect to the ClamAV daemon and parameters for scan operations.
/// All timeouts are in seconds; chunk size controls INSTREAM protocol behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamAvConfig {
    /// Connection type: TCP socket or UNIX domain socket.
    pub connection: ClamAvConnection,

    /// Timeout for each scan operation (seconds).
    ///
    /// Includes time for sending data AND receiving response.
    /// For large files (>100MB), increase this value accordingly.
    /// Default: `30` seconds.
    pub scan_timeout_secs: u64,

    /// Connection timeout (seconds).
    ///
    /// Maximum time to wait for TCP/UNIX socket connection establishment.
    /// Default: `10` seconds.
    pub connect_timeout_secs: u64,

    /// Maximum stream chunk size for INSTREAM protocol (bytes).
    ///
    /// Data is sent to clamd in chunks of this size. Larger values reduce
    /// round-trips but increase memory usage per chunk.
    /// - Minimum: `1024` (1 KB)
    /// - Maximum: `1048576` (1 MB)
    /// - Recommended: `131072` (128 KB) — balances throughput and latency
    /// - Default: `131072`
    pub stream_chunk_size: usize,
}

impl Default for ClamAvConfig {
    fn default() -> Self {
        Self {
            connection: ClamAvConnection::Tcp {
                host: "localhost".to_string(),
                port: 3310,
            },
            scan_timeout_secs: 30,
            connect_timeout_secs: 10,
            stream_chunk_size: 131072, // 128 KB
        }
    }
}

/// Connection type for communicating with ClamAV daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ClamAvConnection {
    /// Connect via TCP socket to remote or local clamd instance.
    ///
    /// # Fields
    /// * `host` — Hostname or IP address (e.g., `"localhost"`, `"192.168.1.100"`).
    /// * `port` — TCP port number (default: `3310`).
    Tcp {
        /// Hostname or IP address of clamd server.
        host: String,

        /// TCP port number (standard ClamAV port is 3310).
        port: u16,
    },

    /// Connect via UNIX domain socket (local only).
    ///
    /// # Fields
    /// * `path` — Path to UNIX socket file (e.g., `"/var/run/clamd.sock"`).
    #[cfg(unix)]
    Unix {
        /// Filesystem path to clamd UNIX socket.
        path: String,
    },
}

// =============================================================================
// ClamAV Adapter Implementation
// =============================================================================

/// Adapter for ClamAV daemon (clamd) using INSTREAM protocol.
///
/// Implements [`ExternalScanner`] trait to integrate Misogi with ClamAV's
/// streaming scan capability. Maintains no persistent connections — each
/// scan operation opens a new socket, sends data, and closes.
///
/// # Thread Safety
/// This struct is `Send + Sync` safe because it holds only configuration
/// data (`ClamAvConfig`) and an identifier string. All I/O is performed
/// within async methods using Tokio runtime.
///
/// # Resource Management
/// No persistent state is maintained between scans. Socket connections
/// are created and dropped per-scan operation, ensuring clean resource
/// cleanup even if scans fail or timeout.
///
/// # Performance Characteristics
/// - **Connection overhead**: ~1-5ms per scan (TCP handshake)
/// - **Throughput**: Limited by network latency and chunk size
/// - **Memory usage**: O(chunk_size) during transmission (default 128 KB)
/// - **Concurrency**: Fully async-safe; multiple scans can run concurrently
pub struct ClamAvAdapter {
    /// Immutable configuration for this adapter instance.
    config: ClamAvConfig,

    /// Unique identifier for this scanner instance (for logging/chaining).
    client_id: String,
}

impl ClamAvAdapter {
    /// Create a new ClamAV adapter with the specified configuration.
    ///
    /// # Arguments
    /// * `config` — Connection and operational parameters.
    ///
    /// # Returns
    /// Initialized `ClamAvAdapter` ready for scanning operations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = ClamAvConfig {
    ///     connection: ClamAvConnection::Tcp {
    ///         host: "clamav-server".to_string(),
    ///         port: 3310,
    ///     },
    ///     ..Default::default()
    /// };
    /// let adapter = ClamAvAdapter::new(config);
    /// ```
    pub fn new(config: ClamAvConfig) -> Self {
        let id = match &config.connection {
            ClamAvConnection::Tcp { host, port } => format!("clamav-tcp-{}:{}", host, port),
            #[cfg(unix)]
            ClamAvConnection::Unix { path } => format!("clamav-unix-{}", path),
        };

        tracing::info!(
            adapter_id = %id,
            connection = ?config.connection,
            "Creating ClamAV adapter"
        );

        Self {
            config,
            client_id: id,
        }
    }

    /// Execute INSTREAM scan against clamd.
    ///
    /// Implements the complete INSTREAM protocol:
    /// 1. Open TCP/UNIX connection to clamd
    /// 2. Send INSTREAM command header
    /// 3. Stream file data in configured chunk sizes
    /// 4. Send zero-length EOF marker
    /// 5. Read and parse response
    /// 6. Close connection
    ///
    /// # Protocol Details
    ///
    /// ```text
    /// Client → Server: zINSTREAM\0
    /// Client → Server: <chunk_size (4BE)><chunk_data>  (repeated)
    /// Client → Server: \x00\x00\x00\x00              (EOF)
    /// Server → Client: stream: <result>\0
    /// ```
    ///
    /// # Arguments
    /// * `data` — Complete file content bytes to scan.
    ///
    /// # Errors
    /// - [`ScannerError::Connection`] — Cannot connect to clamd
    /// - [`ScannerError::Protocol`] — Invalid response from clamd
    /// - [`ScannerError::Timeout`] — Operation exceeded configured timeout
    ///
    /// # Returns
    /// Parsed [`ScanResult`] indicating clean, infected, or error status.
    async fn instream_scan(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        tracing::debug!(
            data_size = data.len(),
            chunk_size = self.config.stream_chunk_size,
            timeout = self.config.scan_timeout_secs,
            "Starting INSTREAM scan"
        );

        // Establish connection based on configuration
        let mut stream = match &self.config.connection {
            ClamAvConnection::Tcp { host, port } => {
                self.connect_tcp(host, *port).await?
            }
            #[cfg(unix)]
            ClamAvConnection::Unix { path } => {
                self.connect_unix(path).await?
            }
        };

        // Send INSTREAM command
        self.send_instream_command(&mut stream).await?;

        // Stream file data in chunks
        self.stream_data(&mut stream, data).await?;

        // Send EOF marker (zero-length chunk)
        self.send_eof_marker(&mut stream).await?;

        // Read response
        let response = self.read_response(&mut stream).await?;

        // Parse response into ScanResult
        Self::parse_response(&response)
    }

    /// Establish TCP connection to clamd with timeout.
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> ScannerResult<TcpStream> {
        let addr = format!("{}:{}", host, port);

        tracing::debug!(
            addr = %addr,
            timeout = self.config.connect_timeout_secs,
            "Connecting to clamd via TCP"
        );

        let connect_duration = std::time::Duration::from_secs(self.config.connect_timeout_secs);

        match timeout(connect_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                tracing::debug!(addr = %addr, "TCP connection established");
                Ok(stream)
            }
            Ok(Err(e)) => {
                Err(ScannerError::Connection(format!(
                    "Failed to connect to {}: {}",
                    addr, e
                )))
            }
            Err(_) => Err(ScannerError::Timeout {
                timeout_secs: self.config.connect_timeout_secs,
            }),
        }
    }

    /// Establish UNIX socket connection to clamd (platform-specific).
    #[cfg(unix)]
    async fn connect_unix(&self, path: &str) -> ScannerResult<tokio::net::UnixStream> {
        use tokio::net::UnixStream;

        tracing::debug!(
            socket_path = path,
            timeout = self.config.connect_timeout_secs,
            "Connecting to clamd via UNIX socket"
        );

        let connect_duration = std::time::Duration::from_secs(self.config.connect_timeout_secs);

        match timeout(connect_duration, UnixStream::connect(path)).await {
            Ok(Ok(stream)) => {
                tracing::debug!(socket_path = path, "UNIX socket connected");
                Ok(stream)
            }
            Ok(Err(e)) => {
                Err(ScannerError::Connection(format!(
                    "Failed to connect to UNIX socket {}: {}",
                    path, e
                )))
            }
            Err(_) => Err(ScannerError::Timeout {
                timeout_secs: self.config.connect_timeout_secs,
            }),
        }
    }

    /// Send INSTREAM command to initiate streaming scan.
    async fn send_instream_command<T: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut T,
    ) -> ScannerResult<()> {
        const INSTREAM_COMMAND: &[u8] = b"zINSTREAM\0";

        tracing::trace!("Sending INSTREAM command");

        stream
            .write_all(INSTREAM_COMMAND)
            .await
            .map_err(|e| ScannerError::Protocol(format!("Failed to send INSTREAM command: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| ScannerError::Protocol(format!("Failed to flush INSTREAM command: {}", e)))?;

        Ok(())
    }

    /// Stream file data to clamd in chunks.
    ///
    /// Splits input data into chunks of `stream_chunk_size` bytes and sends
    /// each chunk with a 4-byte big-endian length prefix per INSTREAM spec.
    async fn stream_data<T: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut T,
        data: &[u8],
    ) -> ScannerResult<()> {
        let chunk_size = self.config.stream_chunk_size;
        let total_chunks = (data.len() + chunk_size - 1) / chunk_size;

        tracing::debug!(
            total_data = data.len(),
            chunk_size = chunk_size,
            total_chunks = total_chunks,
            "Streaming data to clamd"
        );

        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            // Send 4-byte big-endian length prefix
            let len_bytes = (chunk.len() as u32).to_be_bytes();
            stream
                .write_all(&len_bytes)
                .await
                .map_err(|e| {
                    ScannerError::Protocol(format!(
                        "Failed to send chunk {} length: {}",
                        i, e
                    ))
                })?;

            // Send chunk data
            stream
                .write_all(chunk)
                .await
                .map_err(|e| {
                    ScannerError::Protocol(format!("Failed to send chunk {} data: {}", i, e))
                })?;

            if (i + 1) % 100 == 0 || i == total_chunks - 1 {
                tracing::trace!(
                    chunk_index = i,
                    total_chunks = total_chunks,
                    bytes_sent = (i + 1) * chunk_size.min(data.len()),
                    "Streaming progress"
                );
            }
        }

        stream
            .flush()
            .await
            .map_err(|e| ScannerError::Protocol(format!("Failed to flush data: {}", e)))?;

        tracing::debug!(total_bytes = data.len(), "Data streaming complete");
        Ok(())
    }

    /// Send zero-length chunk as EOF marker.
    async fn send_eof_marker<T: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut T,
    ) -> ScannerResult<()> {
        const EOF_MARKER: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        tracing::trace!("Sending EOF marker");

        stream
            .write_all(&EOF_MARKER)
            .await
            .map_err(|e| ScannerError::Protocol(format!("Failed to send EOF marker: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| ScannerError::Protocol(format!("Failed to flush EOF marker: {}", e)))?;

        Ok(())
    }

    /// Read scan response from clamd.
    ///
    /// Reads until null terminator (`\0`) or connection close.
    /// Applies scan timeout to prevent hanging on unresponsive daemons.
    async fn read_response<T: AsyncReadExt + Unpin>(
        &self,
        stream: &mut T,
    ) -> ScannerResult<String> {
        let scan_duration = std::time::Duration::from_secs(self.config.scan_timeout_secs);

        tracing::trace!(timeout_secs = self.config.scan_timeout_secs, "Reading response");

        let read_result = timeout(scan_duration, async {
            let mut buffer = Vec::new();
            let mut temp_buf = [0u8; 1024];

            loop {
                match stream.read(&mut temp_buf).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        buffer.extend_from_slice(&temp_buf[..n]);
                        // Check for null terminator
                        if temp_buf[..n].contains(&0x00) {
                            break;
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            Ok(buffer)
        })
        .await;

        match read_result {
            Ok(Ok(buffer)) => {
                let response = String::from_utf8_lossy(&buffer)
                    .trim_end_matches('\0')
                    .to_string();

                tracing::debug!(response = %response, "Received scan response");
                Ok(response)
            }
            Ok(Err(e)) => Err(ScannerError::Protocol(format!(
                "Failed to read response: {}",
                e
            ))),
            Err(_) => Err(ScannerError::Timeout {
                timeout_secs: self.config.scan_timeout_secs,
            }),
        }
    }

    /// Parse clamd response line into structured ScanResult.
    ///
    /// # Response Format
    ///
    /// ClamAV returns responses in these formats:
    /// - `stream: OK` — Clean
    /// - `stream: <signature> FOUND` — Infected
    /// - `stream: <error message>` — Error
    ///
    /// # Arguments
    /// * `response` — Raw response string from clamd.
    ///
    /// # Returns
    /// Parsed [`ScanResult`] or protocol error if unparseable.
    fn parse_response(response: &str) -> ScannerResult<ScanResult> {
        tracing::debug!(raw_response = response, "Parsing clamd response");

        // Normalize whitespace
        let response = response.trim();

        if response.is_empty() {
            return Err(ScannerError::Protocol(
                "Empty response from clamd".to_string(),
            ));
        }

        // Extract the part after "stream: " (or whatever filepath was used)
        let result_part = if let Some(colon_pos) = response.find(':') {
            response[colon_pos + 1..].trim()
        } else {
            response
        };

        match result_part {
            "OK" => {
                tracing::info!("ClamAV reports: CLEAN");
                Ok(ScanResult::Clean)
            }
            s if s.ends_with(" FOUND") => {
                // Extract threat name (everything before " FOUND")
                let threat_name = s[..s.len() - 6].trim().to_string();

                tracing::warn!(
                    threat_name = %threat_name,
                    "ClamAV reports: INFECTED"
                );

                Ok(ScanResult::Infected {
                    threat_name,
                    severity: ThreatSeverity::Medium, // Default severity; could be enhanced with mapping
                })
            }
            s if s.contains("Access denied") => {
                tracing::error!("ClamAV reports: ACCESS DENIED");
                Err(ScannerError::Auth(format!(
                    "ClamAV access denied: {}",
                    s
                )))
            }
            s if s.contains("ERROR") => {
                let error_msg = s.to_string();
                tracing::error!(error = %error_msg, "ClamAV reports: ERROR");
                Ok(ScanResult::Error {
                    message: error_msg,
                    transient: false,
                })
            }
            other => {
                // Unknown response format — treat as error
                tracing::warn!(response = other, "Unknown clamd response format");
                Ok(ScanResult::Error {
                    message: format!("Unknown clamd response: {}", other),
                    transient: false,
                })
            }
        }
    }

    /// Send VERSION command to get engine version information.
    async fn query_version<T: AsyncReadExt + AsyncWriteExt + Unpin>(
        &self,
        mut stream: T,
    ) -> ScannerResult<String> {
        const VERSION_CMD: &[u8] = b"zVERSION\0";

        tracing::trace!("Sending VERSION command");

        stream
            .write_all(VERSION_CMD)
            .await
            .map_err(|e| ScannerError::Protocol(format!("Failed to send VERSION: {}", e)))?;

        stream.flush().await.map_err(|e| {
            ScannerError::Protocol(format!("Failed to flush VERSION: {}", e))
        })?;

        let mut buffer = Vec::new();
        let mut temp_buf = [0u8; 256];

        loop {
            match stream.read(&mut temp_buf).await {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    if temp_buf[..n].contains(&0x00) {
                        break;
                    }
                }
                Err(e) => return Err(ScannerError::Protocol(format!("VERSION read failed: {}", e))),
            }
        }

        let version = String::from_utf8_lossy(&buffer)
            .trim_end_matches('\0')
            .to_string();

        tracing::debug!(version = %version, "Received VERSION response");
        Ok(version)
    }
}

#[async_trait]
impl ExternalScanner for ClamAvAdapter {
    /// Returns `"ClamAV"` as the display name.
    fn name(&self) -> &str {
        "ClamAV"
    }

    /// Returns unique identifier derived from connection configuration.
    fn id(&self) -> &str {
        &self.client_id
    }

    /// Scan file content via ClamAV INSTREAM protocol.
    ///
    /// Opens a new connection to clamd for each scan, streams the file content,
    /// and parses the response. All I/O is bounded by configured timeouts.
    ///
    /// # Arguments
    /// * `data` — Complete file bytes to scan.
    ///
    /// # Returns
    /// - `Ok(ScanResult::Clean)` — No threats detected
    /// - `Ok(ScanResult::Infected { ... })` — Threat found with signature name
    /// - `Ok(ScanResult::Error { ... })` — ClamAV-reported error
    /// - `Err(ScannerError)` — Transport/protocol failure
    async fn scan_stream(&self, data: &[u8]) -> ScannerResult<ScanResult> {
        // Apply overall scan timeout
        let scan_duration = std::time::Duration::from_secs(self.config.scan_timeout_secs);

        match timeout(scan_duration, self.instream_scan(data)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    timeout = self.config.scan_timeout_secs,
                    "Scan timed out"
                );
                Ok(ScanResult::Timeout {
                    timeout_secs: self.config.scan_timeout_secs,
                })
            }
        }
    }

    /// Health check by attempting connection and VERSION command.
    ///
    /// Verifies that clamd is reachable and responding by opening a connection
    /// and querying engine version. This is a lightweight check suitable for
    /// periodic monitoring (every 30-60 seconds recommended).
    ///
    /// # Returns
    /// - `true` — ClamAV daemon is reachable and responding
    /// - `false` — Cannot connect or daemon not responding
    async fn health_check(&self) -> bool {
        tracing::debug!(adapter_id = %self.client_id, "Performing health check");

        let result = match &self.config.connection {
            ClamAvConnection::Tcp { host, port } => {
                self.connect_tcp(host, *port).await
            }
            #[cfg(unix)]
            ClamAvConnection::Unix { path } => {
                self.connect_unix(path).await
            }
        };

        match result {
            Ok(stream) => {
                // Try to get version as additional health validation
                let version_result = self.query_version(stream).await;
                match version_result {
                    Ok(version) => {
                        tracing::info!(version = %version, "Health check passed");
                        true
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Connected but VERSION failed");
                        false
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Health check failed — cannot connect");
                false
            }
        }
    }

    /// Query ClamAV metadata (engine version, signature info).
    ///
    /// Sends VERSION command to retrieve engine and signature database versions.
    /// Note that ClamAV does not provide exact signature count via standard
    /// commands — this field will be estimated or left as 0.
    ///
    /// # Returns
    /// Some(`ScannerMetadata`) if successful, `None` on failure.
    async fn metadata(&self) -> Option<ScannerMetadata> {
        tracing::debug!(adapter_id = %self.client_id, "Querying scanner metadata");

        let stream_result = match &self.config.connection {
            ClamAvConnection::Tcp { host, port } => self.connect_tcp(host, *port).await,
            #[cfg(unix)]
            ClamAvConnection::Unix { path } => self.connect_unix(path).await,
        };

        match stream_result {
            Ok(stream) => match self.query_version(stream).await {
                Ok(version_str) => {
                    // Parse version string: "ClamAV 0.103.8/27387/Wed Mar 15 08:23:02 2024"
                    let parts: Vec<&str> = version_str.split('/').collect();

                    let engine_version = parts
                        .get(0)
                        .and_then(|s| s.split_whitespace().nth(1))
                        .unwrap_or("unknown")
                        .to_string();

                    let signature_version = parts.get(1).unwrap_or(&"unknown").to_string();

                    let last_updated = parts
                        .get(2)
                        .and_then(|s| {
                            chrono::DateTime::parse_from_rfc2822(s)
                                .ok()
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                        })
                        .unwrap_or_else(chrono::Utc::now);

                    let meta = ScannerMetadata {
                        engine_name: "ClamAV".to_string(),
                        engine_version,
                        signature_version,
                        signatures_count: 0, // Not available via VERSION command
                        last_updated,
                    };

                    tracing::info!(metadata = ?meta, "Retrieved scanner metadata");
                    Some(meta)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to query metadata");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "Cannot connect for metadata query");
                None
            }
        }
    }
}

impl std::fmt::Debug for ClamAvAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClamAvAdapter")
            .field("client_id", &self.client_id)
            .field("config", &self.config)
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
    // parse_response Tests
    // =========================================================================

    #[test]
    fn test_parse_clean_response() {
        let result = ClamAvAdapter::parse_response("stream: OK").unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[test]
    fn test_parse_infected_response() {
        let result =
            ClamAvAdapter::parse_response("stream: Eicar-Test-Signature FOUND").unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threat_name(), Some("Eicar-Test-Signature"));
        assert_eq!(result.severity(), Some(ThreatSeverity::Medium));
    }

    #[test]
    fn test_parse_error_response() {
        let result = ClamAvAdapter::parse_response("stream: ERROR: Database load failed").unwrap();
        assert!(result.is_error());
        match result {
            ScanResult::Error { message, .. } => {
                assert!(message.contains("Database load failed"));
            }
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_parse_empty_response() {
        let result = ClamAvAdapter::parse_response("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_response() {
        let result = ClamAvAdapter::parse_response("stream: SOMETHING_UNEXPECTED").unwrap();
        assert!(result.is_error());
    }

    #[test]
    fn test_parse_access_denied() {
        let result = ClamAvAdapter::parse_response("stream: Access denied. ERROR level set to ForbiddenPath.");
        assert!(result.is_err());
        match result.unwrap_err() {
            ScannerError::Auth(msg) => {
                assert!(msg.contains("Access denied"));
            }
            _ => panic!("Expected Auth error"),
        }
    }

    #[test]
    fn test_parse_whitespace_handling() {
        // Response with extra whitespace should still parse
        let result = ClamAvAdapter::parse_response("  stream: OK  ").unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_default_config() {
        let config = ClamAvConfig::default();
        assert_eq!(config.scan_timeout_secs, 30);
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.stream_chunk_size, 131072); // 128 KB
    }

    #[test]
    fn test_adapter_creation() {
        let config = ClamAvConfig {
            connection: ClamAvConnection::Tcp {
                host: "localhost".to_string(),
                port: 3310,
            },
            ..Default::default()
        };
        let adapter = ClamAvAdapter::new(config);
        assert_eq!(adapter.name(), "ClamAV");
        assert!(adapter.id().contains("localhost"));
        assert!(adapter.id().contains("3310"));
    }

    #[test]
    fn test_config_serialization() {
        let config = ClamAvConfig {
            connection: ClamAvConnection::Tcp {
                host: "192.168.1.50".to_string(),
                port: 3310,
            },
            scan_timeout_secs: 60,
            connect_timeout_secs: 15,
            stream_chunk_size: 65536,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ClamAvConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.scan_timeout_secs, deserialized.scan_timeout_secs);
        assert_eq!(config.stream_chunk_size, deserialized.stream_chunk_size);
    }
}
