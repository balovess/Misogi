//! Core Posture Evaluation Engine
//!
//! Evaluates device posture reports against organizational policies and
//! produces allow/block/warn decisions with detailed scoring.

use tracing::{debug, info, warn};

use super::types::{
    CheckSeverity,
    DevicePosture,
    FailureAction,
    OsPlatform,
    OsRequirement,
    PostureCheckResult,
    PosturePolicy,
};

/// Result of a posture evaluation with decision metadata.
#[derive(Debug, Clone)]
pub struct PostureEvaluationResult {
    /// Whether the device passed posture evaluation.
    pub allowed: bool,

    /// The evaluated posture data (with computed score).
    pub posture: DevicePosture,

    /// The action taken based on evaluation result.
    pub action: FailureAction,

    /// Human-readable reason for the decision.
    pub reason: String,

    /// List of failed critical checks (if any).
    pub failed_critical_checks: Vec<String>,
}

/// Posture evaluation engine.
///
/// Thread-safe (stateless after construction). Safe to share via `Arc<>`.
pub struct PostureChecker {
    policy: PosturePolicy,
}

impl PostureChecker {
    /// Create a new posture checker with the given policy.
    pub fn new(policy: PosturePolicy) -> Self {
        Self { policy }
    }

    /// Evaluate a device posture report against the configured policy.
    ///
    /// # Arguments
    ///
    /// * `posture` — The device posture data to evaluate
    ///
    /// # Returns
    ///
    /// A [`PostureEvaluationResult`] containing the decision and reasoning.
    pub fn evaluate(&self, mut posture: DevicePosture) -> PostureEvaluationResult {
        let mut checks = Vec::new();
        let mut score: i32 = 100;
        let mut failed_critical = Vec::new();

        // Check 1: OS version compliance
        let os_check = self.check_os_version(&posture.os_info);
        if !os_check.passed {
            match os_check.severity {
                CheckSeverity::Critical => {
                    score -= 30;
                    failed_critical.push(os_check.check_id.clone());
                }
                CheckSeverity::Warning => score -= 15,
                CheckSeverity::Info => score -= 0,
            }
        }
        checks.push(os_check);

        // Check 2: Antivirus status
        let av_check = self.check_antivirus(&posture.security_software);
        if !av_check.passed {
            match av_check.severity {
                CheckSeverity::Critical => {
                    score -= 25;
                    failed_critical.push(av_check.check_id.clone());
                }
                CheckSeverity::Warning => score -= 10,
                CheckSeverity::Info => score -= 0,
            }
        }
        checks.push(av_check);

        // Check 3: Patch compliance
        let patch_check = self.check_patch_compliance(&posture.patch_status);
        if !patch_check.passed {
            match patch_check.severity {
                CheckSeverity::Critical => {
                    score -= 20;
                    failed_critical.push(patch_check.check_id.clone());
                }
                CheckSeverity::Warning => score -= 10,
                CheckSeverity::Info => score -= 0,
            }
        }
        checks.push(patch_check);

        // Check 4: EDR presence (if required)
        let edr_check = self.check_edr(&posture.security_software);
        if !edr_check.passed {
            match edr_check.severity {
                CheckSeverity::Critical => {
                    score -= 15;
                    failed_critical.push(edr_check.check_id.clone());
                }
                CheckSeverity::Warning => score -= 5,
                CheckSeverity::Info => score -= 0,
            }
        }
        checks.push(edr_check);

        // Clamp score to [0, 100]
        let final_score = score.max(0).min(100) as u8;
        posture.posture_score = final_score;
        posture.checks = checks;

        // Determine outcome
        let has_critical_failures = !failed_critical.is_empty();
        let below_threshold = final_score < self.policy.min_posture_score;

        let (allowed, action, reason) = if has_critical_failures {
            (
                false,
                FailureAction::Block,
                format!(
                    "Critical checks failed: {}",
                    failed_critical.join(", ")
                ),
            )
        } else if below_threshold {
            match self.policy.failure_action {
                FailureAction::Block => (
                    false,
                    FailureAction::Block,
                    format!(
                        "Posture score {final_score} below minimum {}",
                        self.policy.min_posture_score
                    ),
                ),
                FailureAction::Warn => (
                    true,
                    FailureAction::Warn,
                    format!(
                        "Posture score {final_score} below minimum {} (warn mode)",
                        self.policy.min_posture_score
                    ),
                ),
                FailureAction::Allow => (
                    true,
                    FailureAction::Allow,
                    format!(
                        "Posture score {final_score} below minimum {} (allow mode)",
                        self.policy.min_posture_score
                    ),
                ),
            }
        } else {
            (
                true,
                FailureAction::Allow,
                format!("Posture evaluation passed (score: {final_score})"),
            )
        };

        debug!(
            score = final_score,
            allowed,
            action = %action,
            failures = failed_critical.len(),
            "Posture evaluation complete"
        );

        PostureEvaluationResult {
            allowed,
            posture,
            action,
            reason,
            failed_critical_checks: failed_critical,
        }
    }

    fn check_os_version(&self, os_info: &super::types::OsPosture) -> PostureCheckResult {
        let requirement = self.policy.os_requirements.get(&os_info.platform);

        match requirement {
            Some(req) if os_info.is_supported => PostureCheckResult {
                check_id: "os_supported".to_string(),
                check_name: "OS Version Supported".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: format!(
                    "{} {} meets minimum requirement ({})",
                    req.display_name, os_info.version, req.min_version
                ),
            },
            Some(req) => PostureCheckResult {
                check_id: "os_supported".to_string(),
                check_name: "OS Version Supported".to_string(),
                passed: false,
                severity: CheckSeverity::Critical,
                details: format!(
                    "{} {} does not meet minimum requirement ({})",
                    req.display_name, os_info.version, req.min_version
                ),
            },
            None => PostureCheckResult {
                check_id: "os_supported".to_string(),
                check_name: "OS Version Supported".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: "No specific OS requirement for this platform".to_string(),
            },
        }
    }

    fn check_antivirus(
        &self,
        sw: &super::types::SecuritySoftwarePosture,
    ) -> PostureCheckResult {
        if !self.policy.require_antivirus {
            return PostureCheckResult {
                check_id: "antivirus_enabled".to_string(),
                check_name: "Antivirus Enabled".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: "Antivirus not required by policy".to_string(),
            };
        }

        if sw.antivirus_enabled {
            let sig_age_note = sw
                .antivirus_signature_age_days
                .map(|d| format!(", signature age: {d} days"))
                .unwrap_or_default();

            PostureCheckResult {
                check_id: "antivirus_enabled".to_string(),
                check_name: "Antivirus Enabled".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: format!(
                    "AV enabled ({:?}){}",
                    sw.antivirus_name.as_deref().unwrap_or("unknown"),
                    sig_age_note
                ),
            }
        } else {
            PostureCheckResult {
                check_id: "antivirus_enabled".to_string(),
                check_name: "Antivirus Enabled".to_string(),
                passed: false,
                severity: CheckSeverity::Critical,
                details: "Antivirus is disabled or not present".to_string(),
            }
        }
    }

    fn check_patch_compliance(
        &self,
        patch: &super::types::PatchStatus,
    ) -> PostureCheckResult {
        if patch.is_compliant && patch.critical_patches_missing == 0 {
            PostureCheckResult {
                check_id: "patch_compliant".to_string(),
                check_name: "Patch Compliance".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: "Device is patch compliant".to_string(),
            }
        } else {
            let age_note = patch
                .days_since_last_patch
                .map(|d| format!(", days since last patch: {d}"))
                .unwrap_or_default();

            let severity = if patch.critical_patches_missing > 0 {
                CheckSeverity::Critical
            } else {
                CheckSeverity::Warning
            };

            PostureCheckResult {
                check_id: "patch_compliant".to_string(),
                check_name: "Patch Compliance".to_string(),
                passed: false,
                severity,
                details: format!(
                    "{} critical patches missing{}",
                    patch.critical_patches_missing, age_note
                ),
            }
        }
    }

    fn check_edr(
        &self,
        sw: &super::types::SecuritySoftwarePosture,
    ) -> PostureCheckResult {
        if !self.policy.require_edr {
            return PostureCheckResult {
                check_id: "edr_present".to_string(),
                check_name: "EDR Present".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: "EDR not required by policy".to_string(),
            };
        }

        if sw.edr_present {
            PostureCheckResult {
                check_id: "edr_present".to_string(),
                check_name: "EDR Present".to_string(),
                passed: true,
                severity: CheckSeverity::Info,
                details: format!(
                    "EDR detected ({:?})",
                    sw.edr_name.as_deref().unwrap_or("unknown")
                ),
            }
        } else {
            PostureCheckResult {
                check_id: "edr_present".to_string(),
                check_name: "EDR Present".to_string(),
                passed: false,
                severity: CheckSeverity::Warning,
                details: "EDR agent not detected on device".to_string(),
            }
        }
    }

    /// Get a reference to the current policy.
    pub fn policy(&self) -> &PosturePolicy {
        &self.policy
    }
}

#[cfg(test)]
mod tests;
