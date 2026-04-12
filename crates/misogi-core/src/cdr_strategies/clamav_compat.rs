// =============================================================================
// Misogi Core — CDR Strategy: ClamAV Backward Compatibility Alias
// =============================================================================
// Provides [`ClamAvIntegrationStrategy`] as a deprecated alias for
// [`ExternalScannerStrategy`] to prevent breakage of existing configurations
// and code that reference the old name.
//
// **DEPRECATED**: Use [`ExternalScannerStrategy`] instead. New code should
// use the pluggable adapter architecture directly.

#![cfg_attr(not(feature = "clamav"), allow(unexpected_cfgs))]
#![allow(deprecated)] // Allow usage of deprecated APIs within this compatibility layer

use crate::scanners::ChainMode;
use crate::traits::{PIIAction, StrategyDecision};

use super::external_scanner::ExternalScannerStrategy;

/// Type alias for backward compatibility with existing code using `ClamAvIntegrationStrategy`.
///
/// **DEPRECATED**: Use [`ExternalScannerStrategy`] instead. This alias exists
/// solely to prevent breakage of existing configurations and code that references
/// `ClamAvIntegrationStrategy`. New code should use `ExternalScannerStrategy`
/// which provides the full pluggable adapter architecture.
///
/// # Migration Guide
///
/// Old code:
/// ```ignore
/// let strategy = ClamAvIntegrationStrategy::new(socket_path, 100, action_virus, action_clean);
/// ```
///
/// New code:
/// ```ignore
/// let mut strategy = ExternalScannerStrategy::new(
///     100, // max_scan_size_mb
///     action_virus,
///     action_clean,
///     ChainMode::AnyInfectedBlocks,
///     true, // fail_open
/// );
/// strategy.add_scanner(Box::new(ClamAvAdapter::new(clamav_config)));
/// ```
#[cfg(not(feature = "clamav"))]
#[allow(dead_code)]
pub type ClamAvIntegrationStrategy = ExternalScannerStrategy;

#[cfg(not(feature = "clamav"))]
#[allow(dead_code)]
impl ClamAvIntegrationStrategy {
    /// Backward-compatible constructor that creates a single-ClamAV configuration.
    ///
    /// **DEPRECATED**: Use [`ExternalScannerStrategy::new()`] plus
    /// [`add_scanner()`](ExternalScannerStrategy::add_scanner) instead.
    ///
    /// # Arguments
    /// * `socket_path` — ClamAV daemon address (`"host:port"` or UNIX socket path).
    /// * `max_scan_size_mb` — Maximum file size to scan (MB).
    /// * `action_on_virus` — Action when malware detected.
    /// * `action_on_clean` — Decision when file is clean.
    #[deprecated(note = "Use ExternalScannerStrategy with add_scanner()")]
    pub fn with_socket(
        socket_path: String,
        max_scan_size_mb: u64,
        action_on_virus: PIIAction,
        action_on_clean: StrategyDecision,
    ) -> ExternalScannerStrategy {
        tracing::warn!(
            "ClamAvIntegrationStrategy::new() is DEPRECATED — migrate to ExternalScannerStrategy"
        );

        let clamav_config = if socket_path.contains(':') && !socket_path.contains('/') {
            let parts: Vec<&str> = socket_path.splitn(2, ':').collect();
            let host = parts[0].to_string();
            let port = parts[1].parse::<u16>().unwrap_or(3310);

            crate::scanners::ClamAvConfig {
                connection: crate::scanners::ClamAvConnection::Tcp { host, port },
                ..Default::default()
            }
        } else {
            #[cfg(unix)]
            {
                crate::scanners::ClamAvConfig {
                    connection: crate::scanners::ClamAvConnection::Unix {
                        path: socket_path,
                    },
                    ..Default::default()
                }
            }
            #[cfg(not(unix))]
            {
                crate::scanners::ClamAvConfig {
                    connection: crate::scanners::ClamAvConnection::Tcp {
                        host: socket_path,
                        port: 3310,
                    },
                    ..Default::default()
                }
            }
        };

        let mut strategy = ExternalScannerStrategy::new(
            max_scan_size_mb,
            action_on_virus,
            action_on_clean,
            ChainMode::AnyInfectedBlocks,
            true, // fail-open for backward compat
        );

        let adapter = crate::scanners::ClamAvAdapter::new(clamav_config);
        strategy.add_scanner(Box::new(adapter));

        strategy
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    

    #[cfg(not(feature = "clamav"))]
    use super::*;

    #[cfg(not(feature = "clamav"))]
    use crate::traits::CDRStrategy;

    #[cfg(not(feature = "clamav"))]
    #[test]
    fn test_clamav_stub_name() {
        let strategy = ClamAvIntegrationStrategy::with_socket(
            "/var/run/clamd.sock".to_string(),
            100,
            PIIAction::Block,
            StrategyDecision::Skip,
        );
        assert_eq!(strategy.name(), "external-scanner-integration");
    }

    #[cfg(not(feature = "clamav"))]
    #[test]
    fn test_clamav_stub_empty_extensions() {
        let strategy = ClamAvIntegrationStrategy::with_socket(
            "localhost:3310".to_string(),
            50,
            PIIAction::Block,
            StrategyDecision::Skip,
        );
        assert!(strategy.supported_extensions().is_empty());
    }

    #[cfg(not(feature = "clamav"))]
    #[tokio::test]
    async fn test_clamav_stub_evaluate_returns_clean_decision() {
        let strategy = ClamAvIntegrationStrategy::with_socket(
            "localhost:3310".to_string(),
            50,
            PIIAction::Block,
            StrategyDecision::Skip,
        );

        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let tmp_file = tmp_dir.path().join("test.docx");
        std::fs::write(&tmp_file, b"test content").expect("Failed to write test file");

        let context = crate::traits::SanitizeContext {
            filename: "test.docx".to_string(),
            mime_type: String::new(),
            file_size: 1024,
            original_hash: "hash".to_string(),
            source_zone: "a".to_string(),
            destination_zone: "b".to_string(),
            uploader_id: "u1".to_string(),
            file_path: tmp_file.clone(),
            output_path: tmp_dir.path().join("out.docx"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        // When scanner is unreachable (stub mode), falls back to default_decision
        assert_eq!(decision, StrategyDecision::Skip);
    }

    #[cfg(not(feature = "clamav"))]
    #[tokio::test]
    async fn test_clamav_stub_apply_returns_success() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let strategy = ClamAvIntegrationStrategy::with_socket(
            "localhost:3310".to_string(),
            50,
            PIIAction::Block,
            StrategyDecision::Skip,
        );

        let input_path = tmp_dir.path().join("input.txt");
        tokio::fs::write(&input_path, b"test content").await.unwrap();

        let context = crate::traits::SanitizeContext {
            filename: "input.txt".to_string(),
            mime_type: String::new(),
            file_size: 12,
            original_hash: "h123".to_string(),
            source_zone: "a".to_string(),
            destination_zone: "b".to_string(),
            uploader_id: "u1".to_string(),
            file_path: input_path.clone(),
            output_path: tmp_dir.path().join("output.txt"),
        };

        let report = strategy
            .apply(&context, &StrategyDecision::Skip)
            .await
            .unwrap();

        assert!(report.success);
        assert_eq!(report.actions_performed, 0);
    }
}
