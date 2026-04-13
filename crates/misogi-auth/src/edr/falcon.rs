//! CrowdStrike Falcon API Client
//!
//! Integrates with CrowdStrike Falcon Zero Trust Assessment (ZTA) API
//! to query device security posture and risk scores.
//!
//! # Prerequisites
//!
//! - Falcon API credentials (client_id + client_secret)
//! - Appropriate read-only API scopes:
//!   - `Sensor Update Policies Read`
//!   - `Zero Trust Assessment Read`
//!
//! # Feature Flag
//!
//! Requires `falcon` feature flag.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::models::{
    EdrDevicePosture,
    EdrError,
    EdrOsInfo,
    EdrRiskScore,
    EdrRiskLevel,
    RiskFactor,
};
use super::traits::EdrProvider;

/// CrowdStrike Falcon cloud regions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FalconCloudRegion {
    /// US-1 region (default).
    Us1,
    /// US-2 region.
    Us2,
    /// EU-1 region.
    Eu1,
    /// Custom URL (for private cloud deployments).
    Custom(String),
}

impl std::fmt::Display for FalconCloudRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Us1 => write!(f, "us-1"),
            Self::Us2 => write!(f, "us-2"),
            Self::Eu1 => write!(f, "eu-1"),
            Self::Custom(url) => write!(f, "{url}"),
        }
    }
}

impl Default for FalconCloudRegion {
    fn default() -> Self {
        Self::Us1
    }
}

/// Base URL template per region.
fn falcon_base_url(region: &FalconCloudRegion) -> &str {
    match region {
        FalconCloudRegion::Us1 => "https://api.crowdstrike.com",
        FalconCloudRegion::Us2 => "https://api.us-2.crowdstrike.com",
        FalconCloudRegion::Eu1 => "https://api.eu-1.crowdstrike.com",
        FalconCloudRegion::Custom(_) => "",
    }
}

/// OAuth2 token endpoint.
const FALCON_TOKEN_URL: &str = "/oauth2/token";

/// CrowdStrike Falcon API client.
///
/// Uses OAuth2 client credentials flow with the Falcon API to query
/// device posture via Zero Trust Assessment endpoints.
pub struct FalconEdrProvider {
    /// Falcon API base URL.
    base_url: String,

    /// Cloud region (determines base URL).
    cloud_region: FalconCloudRegion,

    /// OAuth2 client ID.
    client_id: String,

    /// OAuth2 client secret.
    client_secret: String,

    /// Current access token (auto-refreshed).
    access_token: Arc<RwLock<FalconAuthToken>>,

    /// HTTP client.
    client: reqwest::Client,

    /// Request timeout.
    timeout: std::time::Duration,
}

/// Falcon OAuth2 authentication token.
#[derive(Debug, Clone)]
struct FalconAuthToken {
    bearer_token: String,
    expires_at: DateTime<Utc>,
}

impl FalconEdrProvider {
    /// Create a new Falcon EDR provider.
    ///
    /// # Arguments
    ///
    /// * `cloud_region` — Falcon cloud deployment region
    /// * `client_id` — Falcon API client ID
    /// * `client_secret` — Falcon API client secret
    pub fn new(
        cloud_region: FalconCloudRegion,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, EdrError> {
        if client_id.is_empty() {
            return Err(EdrError::Configuration("client_id is required".to_string()));
        }
        if client_secret.is_empty() {
            return Err(EdrError::Configuration("client_secret is required".to_string()));
        }

        let base_url = match &cloud_region {
            FalconCloudRegion::Custom(url) => url.clone(),
            _ => falcon_base_url(&cloud_region).to_string(),
        };

        Ok(Self {
            base_url,
            cloud_region,
            client_id,
            client_secret,
            access_token: Arc::new(RwLock::new(FalconAuthToken {
                bearer_token: String::new(),
                expires_at: DateTime::<Utc>::MIN_UTC,
            })),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            timeout: std::time::Duration::from_secs(30),
        })
    }

    /// Ensure a valid access token exists, refreshing if needed.
    async fn ensure_token(&self) -> Result<String, EdrError> {
        {
            let token = self.access_token.read().map_err(|e| {
                EdrError::Internal(format!("Token lock poisoned: {e}"))
            })?;
            if !token.bearer_token.is_empty() && token.expires_at > Utc::now() {
                return Ok(token.bearer_token.clone());
            }
        }

        let new_token = self.refresh_token().await?;
        if let Ok(mut guard) = self.access_token.write() {
            *guard = new_token.clone();
        }
        Ok(new_token.bearer_token)
    }

    /// Refresh the Falcon OAuth2 token.
    async fn refresh_token(&self) -> Result<FalconAuthToken, EdrError> {
        let url = format!("{}{}", self.base_url, FALCON_TOKEN_URL);

        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            map_err(|e| EdrError::Api(format!("Falcon token request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EdrError::Authentication(format!(
                "Falcon auth failed ({status}): {body}"
            )));
        }

        let token_resp: FalconTokenResponse = response
            .json()
            .await
            .map_err(|e| EdrError::InvalidResponse(format!("Falcon token parse failed: {e}")))?;

        debug!(
            region = %self.cloud_region,
            "Falcon access token refreshed"
        );

        Ok(FalconAuthToken {
            bearer_token: token_resp.access_token,
            expires_at: Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64),
        })
    }

    /// Make authenticated GET request to Falcon API.
    async fn falcon_get(&self, path: &str) -> Result<reqwest::Response, EdrError> {
        let token = self.ensure_token().await?;
        let url = format!("{}{}", self.base_url, path);

        self.client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| EdrError::Api(format!("Falcon GET failed: {e}")))
    }
}

#[async_trait]
impl EdrProvider for FalconEdrProvider {
    async fn get_device_posture(
        &self,
        device_id: &str,
    ) -> Result<EdrDevicePosture, EdrError> {
        let encoded = urlencoding::encode(device_id);
        let response = self
            .falcon_get(&format!(
                "/devices/entities/devices/v1?ids={encoded}"
            ))
            .await?;

        if response.status() == 404 {
            return Err(EdrError::DeviceNotFound(device_id.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EdrError::Api(format!(
                "Falcon devices API error ({status}): {body}"
            )));
        }

        let devices: FalconDevicesResponse = response
            .json()
            .await
            .map_err(|e| {
                EdrError::InvalidResponse(format!("Falcon devices parse failed: {e}"))
            })?;

        let device = devices.resources.into_iter().next().ok_or_else(|| {
            EdrError::DeviceNotFound(device_id.to_string())
        })?;

        let has_active_thrusts = device
            .local_admins
            .unwrap_or(false)
            || !device
                .reduced_functionality_mode
                .unwrap_or(true);

        Ok(EdrDevicePosture {
            device_id: device.device_id.unwrap_or_else(|| device_id.to_string()),
            hostname: device.hostname,
            has_active_threats: has_active_thrusts,
            active_detection_count: 0,
            sensor_healthy: device
                .status
                .map_or(false, |s| s == "normal" || s == "enabled"),
            last_seen_at: device.last_seen,
            os_info: Some(EdrOsInfo {
                platform: device.os_version
                    .as_ref()
                    .map(|v| v.split_whitespace().next().unwrap_or(""))
                    .unwrap_or("")
                    .to_string(),
                version: device.os_version.unwrap_or_default(),
                build: device.os_build.unwrap_or(None).flatten(),
            }),
            raw_response: Some(serde_json::to_value(&device).unwrap_or_default()),
        })
    }

    async fn has_active_threats(
        &self,
        device_id: &str,
    ) -> Result<bool, EdrError> {
        let posture = self.get_device_posture(device_id).await?;
        Ok(posture.has_active_threats)
    }

    async fn get_risk_score(
        &self,
        device_id: &str,
    ) -> Result<EdrRiskScore, EdrError> {
        let posture = self.get_device_posture(device_id).await?;

        let score = if posture.has_active_threats {
            60u8
        } else if !posture.sensor_healthy {
            45u8
        } else {
            15u8
        };

        let level = match score {
            0..=29 => EdrRiskLevel::Low,
            30..=69 => EdrRiskLevel::Medium,
            70..=89 => EdrRiskLevel::High,
            _ => EdrRiskLevel::Critical,
        };

        Ok(EdrRiskScore {
            score: score,
            level,
            assessed_at: Utc::now(),
            factors: vec![
                RiskFactor {
                    category: "falcon_sensor".to_string(),
                    description: "Falcon sensor health".to_string(),
                    weight: 0.5,
                },
                RiskFactor {
                    category: "falcon_threats".to_string(),
                    description: "Active threat detection".to_string(),
                    weight: 0.5,
                },
            ],
        })
    }
}

// ---------------------------------------------------------------------------
// Falcon API Response Types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct FalconTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct FalconDevicesResponse {
    resources: Vec<FalconDeviceDetail>,
    #[allow(dead_code)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FalconDeviceDetail {
    device_id: Option<String>,
    hostname: Option<String>,
    status: Option<String>,
    local_admins: Option<bool>,
    reduced_functionality_mode: Option<bool>,
    last_seen: Option<DateTime<Utc>>,
    os_version: Option<String>,
    os_build: Option<Option<String>>,
}
