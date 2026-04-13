//! EDR Provider Trait Definition
//!
//! Abstract interface for querying device security posture from any
//! EDR (Endpoint Detection and Response) solution.

use async_trait::async_trait;

use super::models::{
    EdrDevicePosture,
    EdrError,
    EdrRiskScore,
};

/// EDR (Endpoint Detection and Response) provider trait.
///
/// Abstraction over vendor-specific APIs for real-time device security
/// posture queries. Implementations exist for:
///
/// - Microsoft Defender for Endpoint ([`defender`])
/// - CrowdStrike Falcon ([`falcon`])
///
/// # Thread Safety
///
/// All implementations MUST be `Send + Sync` safe for sharing across async tasks.
#[async_trait]
pub trait EdrProvider: Send + Sync {
    /// Query comprehensive device posture by device ID.
    ///
    /// Returns aggregated security status including threat state,
    /// sensor health, and basic OS information.
    ///
    /// # Arguments
    ///
    /// * `device_id` — Identifier of the device in the EDR system
    async fn get_device_posture(
        &self,
        device_id: &str,
    ) -> Result<EdrDevicePosture, EdrError>;

    /// Check if the device currently has active threats or detections.
    ///
    /// A lightweight alternative to [`get_device_posture`] when only
    /// threat presence is needed (e.g., for fast auth decisions).
    ///
    /// # Arguments
    ///
    /// * `device_id` — Identifier of the device in the EDR system
    async fn has_active_threats(
        &self,
        device_id: &str,
    ) -> Result<bool, EdrError>;

    /// Get the current risk score for a device from EDR analytics.
    ///
    /// Risk scores incorporate detection history, vulnerability exposure,
    /// configuration assessments, and behavioral analytics.
    ///
    /// # Arguments
    ///
    /// * `device_id` — Identifier of the device in the EDR system
    async fn get_risk_score(
        &self,
        device_id: &str,
    ) -> Result<EdrRiskScore, EdrError>;
}
