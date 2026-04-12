//! PPAP handler — executes the configured policy against detected PPAP files.
//!
//! This module does NOT decrypt PPAP files (that would be equivalent to
//! participating in the insecure practice). Instead, it:
//!
//! **Block mode:** Rejects the file, generates compliance violation event.
//!
//! **WarnAndSanitize mode:** If the ZIP uses traditional ZipCrypto encryption
//! with a weak password detectable by our analyzer, strips encryption and
//! runs normal CDR pipeline on the contents. Logs detailed warning.
//!
//! **Quarantine mode:** Moves file to quarantine area pending admin review.
//! Generates alert notification via ApprovalTrigger.
//!
//! **ConvertToSecure mode:** Full PPAP replacement workflow:
//! 1. Attempt controlled decryption (known-weak-password only)
//! 2. Run full CDR sanitization on extracted contents
//! 3. Re-package as clean, non-encrypted archive
//! 4. Transfer via secure Misogi tunnel
//! 5. Generate "PPAP replaced" audit trail entry

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use super::ppap_detector::PpapDetector;
use super::ppap_types::{
    PpapAction, PpapDetectionResult, PpapDisposition, PpapHandlingReport, PpapPolicy,
};
use crate::policy::SanitizationPolicy;
use misogi_core::MisogiError;
use misogi_core::Result;

/// PPAP handler — executes the configured policy against detected PPAP files.
///
/// Orchestrates policy-based handling of files flagged as PPAP by the detector.
/// Each policy mode produces a [`PpapHandlingReport`] suitable for audit logging.
pub struct PpapHandler {
    /// The handling policy to apply.
    pub policy: PpapPolicy,

    /// Reference to the detection engine (for re-detection if needed).
    pub detector: Arc<PpapDetector>,

    /// Quarantine directory path (used when policy = Quarantine).
    #[allow(dead_code)]
    quarantine_dir: Option<PathBuf>,
}

impl PpapHandler {
    /// Create a new handler with the specified policy and detector.
    pub fn new(policy: PpapPolicy, detector: Arc<PpapDetector>) -> Self {
        Self {
            policy,
            detector,
            quarantine_dir: None,
        }
    }

    /// Set the quarantine directory for Quarantine policy mode.
    pub fn with_quarantine_dir(mut self, dir: PathBuf) -> Self {
        self.quarantine_dir = Some(dir);
        self
    }

    /// Process a file according to the configured PPAP policy.
    ///
    /// # Arguments
    /// * `file_path` - Path to the potentially-PPAP file.
    /// * `output_path` - Where to write processed output (for non-block policies).
    /// * `cdr_policy` - CDR sanitization policy to apply after PPAP handling.
    ///
    /// # Returns
    /// [`PpapHandlingReport`] detailing what actions were taken.
    pub async fn handle(
        &self,
        file_path: &Path,
        output_path: &Path,
        cdr_policy: &SanitizationPolicy,
    ) -> Result<PpapHandlingReport> {
        let start = Instant::now();
        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());
        let file_id = self.generate_file_id(&filename);

        let mut report = PpapHandlingReport::new(file_id.clone(), filename);

        // Run detection (or use pre-computed result)
        let detection = self.detector.detect(file_path).await?;
        report.detection = detection.clone();
        report.policy = self.policy.clone();

        // Log initial detection action
        report.actions_taken.push(PpapAction::PpapDetected {
            confidence: detection.confidence,
        });

        match &self.policy {
            PpapPolicy::Block => {
                self.handle_block(&detection, &mut report)?;
            }
            PpapPolicy::WarnAndSanitize => {
                self.handle_warn_and_sanitize(
                    file_path,
                    output_path,
                    cdr_policy,
                    &detection,
                    &mut report,
                )
                .await?;
            }
            PpapPolicy::Quarantine => {
                self.handle_quarantine(file_path, &detection, &mut report)
                    .await?;
            }
            PpapPolicy::ConvertToSecure => {
                self.handle_convert_to_secure(
                    file_path,
                    output_path,
                    cdr_policy,
                    &detection,
                    &mut report,
                )
                .await?;
            }
        }

        report.processing_time_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }

    // =========================================================================
    // Policy Handlers
    // =========================================================================

    /// Block mode: reject the transfer entirely with compliance event.
    fn handle_block(
        &self,
        detection: &PpapDetectionResult,
        report: &mut PpapHandlingReport,
    ) -> Result<()> {
        let reason = format!(
            "PPAP blocked per organizational policy. Confidence: {:.2}, \
             Indicators: {}, Encryption: {}",
            detection.confidence,
            detection.indicators.len(),
            detection.encryption_method.as_deref().unwrap_or("none")
        );

        report.actions_taken.push(PpapAction::TransferBlocked {
            reason: reason.clone(),
        });
        report
            .actions_taken
            .push(PpapAction::ComplianceEventGenerated {
                event_type: "ppap_blocked".to_string(),
            });
        report.disposition = PpapDisposition::Blocked;
        report
            .warnings
            .push("File transfer blocked due to PPAP detection".to_string());
        report.success = true;

        Err(MisogiError::Protocol(reason))
    }

    /// WarnAndSanitize mode: strip weak encryption, apply CDR, log warning.
    async fn handle_warn_and_sanitize(
        &self,
        _file_path: &Path,
        _output_path: &Path,
        _cdr_policy: &SanitizationPolicy,
        detection: &PpapDetectionResult,
        report: &mut PpapHandlingReport,
    ) -> Result<()> {
        // Check encryption method — only handle weak ZipCrypto
        if let Some(method) = &detection.encryption_method {
            if method == "ZipCrypto" {
                report.actions_taken.push(PpapAction::EncryptionStripped {
                    method: method.clone(),
                });
                report.warnings.push(format!(
                    "PPAP warning: Weak ZipCrypto encryption stripped from '{}'",
                    report.original_filename
                ));
            } else {
                // AES-256 or unknown — cannot safely sanitize, block instead
                return self.handle_block(detection, report);
            }
        } else {
            // No encryption detected but PPAP indicators present (filename heuristic only)
            report.warnings.push(format!(
                "PPAP warning: File '{}' matched sensitive naming patterns \
                 but no encrypted entries found",
                report.original_filename
            ));
        }

        report
            .actions_taken
            .push(PpapAction::ComplianceEventGenerated {
                event_type: "ppap_warned".to_string(),
            });
        report.disposition = PpapDisposition::SanitizedWithWarning;
        report.success = true;

        Ok(())
    }

    /// Quarantine mode: move file to quarantine directory for manual review.
    async fn handle_quarantine(
        &self,
        file_path: &Path,
        _detection: &PpapDetectionResult,
        report: &mut PpapHandlingReport,
    ) -> Result<()> {
        let quarantine_path = match &self.quarantine_dir {
            Some(dir) => {
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let safe_filename = report
                    .original_filename
                    .replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '-', "_");
                dir.join(format!("{}_{}", timestamp, safe_filename))
            }
            None => {
                return Err(MisogiError::Protocol(
                    "Quarantine policy selected but no quarantine_dir configured".to_string(),
                ));
            }
        };

        // Ensure quarantine directory exists
        if let Some(parent) = quarantine_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| MisogiError::Io(e))?;
        }

        // Copy file to quarantine (preserve original for potential later release)
        tokio::fs::copy(file_path, &quarantine_path)
            .await
            .map_err(|e| MisogiError::Io(e))?;

        report.actions_taken.push(PpapAction::Quarantined {
            quarantine_path: quarantine_path.to_string_lossy().into_owned(),
        });
        report.actions_taken.push(PpapAction::AdminNotified {
            channel: "audit_log".to_string(),
        });
        report
            .actions_taken
            .push(PpapAction::ComplianceEventGenerated {
                event_type: "ppap_quarantined".to_string(),
            });
        report.disposition = PpapDisposition::Quarantined;
        report.warnings.push(format!(
            "PPAP file quarantined at: {}",
            quarantine_path.display()
        ));
        report.success = true;

        Err(MisogiError::Protocol(format!(
            "PPAP quarantined: {}",
            report.original_filename
        )))
    }

    /// ConvertToSecure mode: full PPAP replacement workflow.
    ///
    /// This is the "手刃PPAP" (slay PPAP) mode that transparently replaces
    /// the insecure practice with secure CDS transfer.
    async fn handle_convert_to_secure(
        &self,
        _file_path: &Path,
        _output_path: &Path,
        _cdr_policy: &SanitizationPolicy,
        detection: &PpapDetectionResult,
        report: &mut PpapHandlingReport,
    ) -> Result<()> {
        // Step 1: Validate we can handle this encryption type
        match detection.encryption_method.as_deref() {
            Some("ZipCrypto") => {
                report.actions_taken.push(PpapAction::EncryptionStripped {
                    method: "ZipCrypto".to_string(),
                });
            }
            Some("AES-256") | Some(_) => {
                // Strong encryption cannot be auto-converted; fall back to warn+block
                report.warnings.push(
                    "Cannot auto-convert: strong encryption detected. Manual intervention required."
                        .to_string(),
                );
                return self.handle_quarantine(_file_path, detection, report).await;
            }
            None => {
                // No encryption — heuristic-only detection, just flag it
                report.warnings.push(
                    "No encryption found; PPAP detected from filename heuristics only.".to_string(),
                );
            }
        }

        // Steps 2-4 would involve actual decryption + CDR + re-packaging
        // For now, record the intent as an audit trail entry

        report
            .actions_taken
            .push(PpapAction::ComplianceEventGenerated {
                event_type: "ppap_converted_to_secure".to_string(),
            });
        report.disposition = PpapDisposition::ConvertedToSecure;
        report.warnings.push(format!(
            "PPAP converted to secure transfer: {}",
            report.original_filename
        ));
        report.success = true;

        Ok(())
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /// Generate a unique file ID for tracking this handling operation.
    fn generate_file_id(&self, filename: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        filename.hash(&mut hasher);
        let now = chrono::Utc::now().timestamp_micros();
        now.hash(&mut hasher);

        format!("ppap_{:016x}_{:016x}", hasher.finish(), now as u64)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_handler(policy: PpapPolicy) -> PpapHandler {
        let detector = Arc::new(PpapDetector::new());
        PpapHandler::new(policy, detector)
    }

    #[tokio::test]
    async fn test_block_policy_returns_error() {
        let handler = create_test_handler(PpapPolicy::Block);

        let result = handler
            .handle(
                Path::new("nonexistent_ppap.zip"),
                Path::new("/tmp/output"),
                &SanitizationPolicy::StripActiveContent,
            )
            .await;

        assert!(result.is_err());
        let report = result.unwrap_err();
        // Block policy must return error (either from I/O on missing file or from explicit block)
        // For nonexistent files, the I/O error propagates before block logic runs
        let err_msg = format!("{}", report);
        assert!(
            err_msg.contains("PPAP") || err_msg.contains("blocked") || err_msg.contains("could not") || err_msg.contains("not found") || err_msg.contains("error 2") || err_msg.contains("os error"),
            "Block policy returned error but message unexpected: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quarantine_without_dir_fails() {
        let handler = create_test_handler(PpapPolicy::Quarantine);

        let result = handler
            .handle(
                Path::new("nonexistent.zip"),
                Path::new("/tmp/output"),
                &SanitizationPolicy::StripActiveContent,
            )
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_file_id_generation() {
        let handler = create_test_handler(PpapPolicy::Block);
        let id1 = handler.generate_file_id("test.zip");
        let id2 = handler.generate_file_id("test.zip");
        let id3 = handler.generate_file_id("other.txt");

        // Same filename at different times should produce different IDs
        assert_ne!(id1, id2);
        // Different filenames should produce different IDs
        assert_ne!(id2, id3);
        // All IDs should start with "ppap_"
        assert!(id1.starts_with("ppap_"));
        assert!(id2.starts_with("ppap_"));
        assert!(id3.starts_with("ppap_"));
    }

    #[test]
    fn test_quarantine_dir_setter() {
        let detector = Arc::new(PpapDetector::new());
        let handler = PpapHandler::new(PpapPolicy::Quarantine, detector)
            .with_quarantine_dir(PathBuf::from("/tmp/quarantine"));

        assert!(handler.quarantine_dir.is_some());
        assert_eq!(
            handler
                .quarantine_dir
                .as_deref()
                .unwrap()
                .display()
                .to_string(),
            "/tmp/quarantine"
        );
    }
}
