// =============================================================================
// Misogi Core 鈥?CDR Strategy: External Scanner Integration
// =============================================================================
// Implements [`ExternalScannerStrategy`] that integrates external virus/malware
// scanners via the pluggable adapter architecture defined in [`crate::scanners`].
//
// ## Architecture
//
// ```text
// File Upload → [ExternalScannerStrategy] → [ScannerChain] → [Adapters] → Decision
//                                          │
//                                    ClamAV / HTTP API / CLI / gRPC
// ```
//
// # Design Principles
// 1. **Zero bundled engines**: All scanning delegated to external adapters.
// 2. **Chain composition**: Multiple scanners combined with aggregation modes.
// 3. **Fail-safe operation**: Configurable fail-open/fail-close on scanner errors.
// 4. **Audit trail**: Comprehensive logging of all scan decisions.

use std::time::Instant;

use async_trait::async_trait;

use crate::error::{MisogiError, Result};
use crate::hash::compute_file_md5;
use crate::scanners::{
    ChainMode, ExternalScanner, ScanResult, ScannerChain,
};
use crate::traits::{
    CDRStrategy, PIIAction, SanitizeContext, SanitizationReport, StrategyDecision,
};

// =============================================================================
// ExternalScannerStrategy
// =============================================================================

/// CDR strategy for external virus/malware scanner integration.
///
/// Implements the [`CDRStrategy`] trait to integrate Misogi's CDR pipeline with
/// external scanning solutions via the pluggable adapter architecture.
///
/// # Thread Safety
/// This struct is `Send + Sync` safe; the internal `ScannerChain` supports
/// concurrent async operations.
pub struct ExternalScannerStrategy {
    /// Scanner chain that orchestrates all configured scanner adapters.
    chain: ScannerChain,

    /// Maximum file size to scan (bytes). Larger files are skipped.
    max_scan_size_bytes: u64,

    /// Action to take when a virus is detected (for reporting/logging).
    action_on_virus: PIIAction,

    /// Decision to return when file is clean (passes scanning).
    action_on_clean: StrategyDecision,
}

impl ExternalScannerStrategy {
    /// Construct a new external scanner integration strategy.
    ///
    /// Creates an empty scanner chain ready for adapters to be added.
    /// Use [`add_scanner()`](Self::add_scanner) to configure specific scanners,
    /// or use [`ScannerRegistry`](crate::scanners::ScannerRegistry) to build
    /// from TOML configuration.
    ///
    /// # Arguments
    /// * `max_scan_size_mb` — Maximum file size to scan (megabytes).
    /// * `action_on_virus` — Action to record when malware detected.
    /// * `action_on_clean` — Decision to return when file passes all scans.
    /// * `chain_mode` — Aggregation mode for combining multiple scanner results.
    /// * `fail_open_on_error` — If true, scanner errors allow files through.
    pub fn new(
        max_scan_size_mb: u64,
        action_on_virus: PIIAction,
        action_on_clean: StrategyDecision,
        chain_mode: ChainMode,
        fail_open_on_error: bool,
    ) -> Self {
        tracing::info!(
            max_size_mb = max_scan_size_mb,
            mode = %chain_mode,
            fail_open = fail_open_on_error,
            "Creating ExternalScannerStrategy"
        );

        Self {
            chain: ScannerChain::new(chain_mode, fail_open_on_error),
            max_scan_size_bytes: max_scan_size_mb * 1024 * 1024,
            action_on_virus,
            action_on_clean,
        }
    }

    /// Add a scanner adapter to the internal chain.
    ///
    /// Delegates to [`ScannerChain::add_scanner()`]. Order matters for
    /// [`ChainMode::FirstResponder`] mode — earlier scanners have priority.
    pub fn add_scanner(&mut self, scanner: Box<dyn ExternalScanner>) -> &mut Self {
        self.chain.add_scanner(scanner);
        self
    }

    /// Get reference to the internal scanner chain (for advanced configuration).
    pub fn chain(&self) -> &ScannerChain {
        &self.chain
    }

    /// Get mutable reference to the internal scanner chain.
    pub fn chain_mut(&mut self) -> &mut ScannerChain {
        &mut self.chain
    }
}

#[async_trait]
impl CDRStrategy for ExternalScannerStrategy {
    /// Returns `"external-scanner-integration"`.
    fn name(&self) -> &str {
        "external-scanner-integration"
    }

    /// Returns empty vector — this strategy applies to ALL file types.
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![] // Empty = applies to all files
    }

    /// Evaluate file by running it through the scanner chain.
    ///
    /// Reads the file content from disk, checks size limits, executes all
    /// configured scanners via the internal [`ScannerChain`], and maps the
    /// result to a CDR pipeline decision.
    ///
    /// # Decision Mapping
    ///
    /// | Scan Result | StrategyDecision | Rationale |
    /// |-------------|-------------------|-----------|
    /// | `Clean` | `action_on_clean` | No threats found |
    /// | `Infected` | `Block { reason }` | Threat detected |
    /// | `Error` (fail-open) | `action_on_clean` | Scanner failed; policy allows continuation |
    /// | `Error` (fail-close) | `Block { reason }` | Scanner failed; conservative blocking |
    /// | `Timeout` | Per fail-open/fail-close | Similar to Error handling |
    /// | Oversized file | `action_on_clean` | Skip scan; warn in logs |
    async fn evaluate(&self, context: &SanitizeContext) -> Result<StrategyDecision> {
        tracing::info!(
            strategy = self.name(),
            file_id = %context.original_hash,
            filename = %context.filename,
            file_size = context.file_size,
            scanner_count = self.chain.len(),
            "Evaluating file with external scanner chain"
        );

        if context.file_size > self.max_scan_size_bytes {
            tracing::warn!(
                file_size = context.file_size,
                max_size = self.max_scan_size_bytes,
                filename = %context.filename,
                "File exceeds maximum scan size — skipping external scan (fail-open)"
            );
            return Ok(self.action_on_clean.clone());
        }

        let file_data = match tokio::fs::read(&context.file_path).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %context.file_path.display(),
                    "Failed to read file for scanning"
                );
                return Ok(StrategyDecision::Block {
                    reason: format!("Cannot read file for scanning: {}", e),
                });
            }
        };

        let scan_result = self.chain.scan(&file_data).await.map_err(|e| {
            MisogiError::Protocol(format!("Scanner chain execution failed: {}", e))
        })?;

        match scan_result {
            ScanResult::Clean => {
                tracing::info!(
                    file_id = %context.original_hash,
                    "External scanner chain reports CLEAN — allowing file"
                );
                Ok(self.action_on_clean.clone())
            }
            ScanResult::Infected {
                threat_name,
                severity,
            } => {
                tracing::error!(
                    file_id = %context.original_hash,
                    threat_name = %threat_name,
                    severity = %severity,
                    action = ?self.action_on_virus,
                    "External scanner chain reports INFECTED — BLOCKING file"
                );
                Ok(StrategyDecision::Block {
                    reason: format!(
                        "Threat detected by external scanner: {} (severity: {})",
                        threat_name, severity
                    ),
                })
            }
            ScanResult::Error {
                message,
                transient,
            } => {
                if self.chain.len() == 0 {
                    tracing::warn!(
                        message = %message,
                        "No scanners configured — treating as clean"
                    );
                    Ok(self.action_on_clean.clone())
                } else {
                    tracing::error!(
                        message = %message,
                        transient = transient,
                        "External scanner chain reported ERROR"
                    );
                    Ok(StrategyDecision::Block {
                        reason: format!(
                            "Scanner error (transient: {}): {}",
                            transient, message
                        ),
                    })
                }
            }
            ScanResult::Timeout { timeout_secs } => {
                tracing::error!(
                    timeout_secs = timeout_secs,
                    "External scanner chain timed out"
                );
                Ok(StrategyDecision::Block {
                    reason: format!("Scanner timed out after {}s", timeout_secs),
                })
            }
        }
    }

    /// Apply strategy decision (record audit trail).
    ///
    /// For the external scanner strategy, `apply()` primarily serves as an
    /// audit checkpoint. The actual scanning work happens in `evaluate()`.
    /// This method records the decision in the sanitization report for the
    /// immutable audit chain of custody.
    async fn apply(
        &self,
        context: &SanitizeContext,
        decision: &StrategyDecision,
    ) -> Result<SanitizationReport> {
        let start_time = Instant::now();

        tracing::info!(
            strategy = self.name(),
            file_id = %context.original_hash,
            decision = ?decision,
            scanner_count = self.chain.len(),
            "Applying external scanner strategy (audit recording)"
        );

        tokio::fs::copy(&context.file_path, &context.output_path).await?;

        let sanitized_hash = compute_file_md5(&context.output_path).await?;
        let sanitized_meta = tokio::fs::metadata(&context.output_path).await?;
        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        let (success, details, actions_performed) = match decision {
            StrategyDecision::Block { reason } => (
                true,
                format!("File blocked: {}", reason),
                1u32,
            ),
            _ => (
                true,
                format!(
                    "Scanned by {} scanner(s); no threats detected",
                    self.chain.len()
                ),
                0,
            ),
        };

        let report = SanitizationReport {
            file_id: context.original_hash.clone(),
            strategy_name: self.name().to_string(),
            success,
            actions_performed,
            details,
            sanitized_hash,
            sanitized_size: sanitized_meta.len(),
            processing_time_ms: elapsed_ms,
            error: None,
        };

        tracing::info!(
            file_id = %context.original_hash,
            success = report.success,
            actions = report.actions_performed,
            elapsed_ms = report.processing_time_ms,
            "External scanner strategy application complete"
        );

        Ok(report)
    }
}
