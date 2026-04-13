//! Microsoft Defender for Endpoint API Client
//!
//! Integrates with Microsoft Graph Security API to query device posture
//! from Defender for Endpoint (formerly Microsoft Defender ATP).
//!
//! # Prerequisites
//!
//! - Azure AD app registration with `SecurityEvents.Read.All` scope
//! - Valid OAuth2 credentials (client_id, client_secret, tenant_id)
//!
//! # API Endpoints Used
//!
//! - `GET /security/machines/{machineId}` — Machine health status
//! - `GET /security/machines/{machineId}/logins` — Login history
//!
//! # Feature Flag
//!
//! Requires `defender` feature flag.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::models::{
    EdrDevicePosture,
    EdrError,
    EdrOsInfo,
    EdrRiskScore,
    EdrRiskLevel,
    RiskFactor,
};
use super::traits::EdrProvider;

/// Microsoft Graph API base URL.
const GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";
const GRAPH_BETA_URL: &str = "https://graph.microsoft.com/beta";

/// OAuth2 token endpoint for Azure AD.
const AZURE_TOKEN_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";

/// Microsoft Defender for Endpoint client.
///
/// Uses OAuth2 client credentials flow to authenticate with Azure AD and
/// query the Microsoft Graph Security API for device posture data.
pub struct DefenderEdrProvider {
    /// Azure AD tenant ID.
    tenant_id: String,

    /// Application (client) ID.
    client_id: String,

    /// Client secret for OAuth2.
    client_secret: String,

    /// Current OAuth2 access token (auto-refreshed).
    access_token: Arc<RwLock<String>>,

    /// HTTP client with default configuration.
    client: reqwest::Client,

    /// Request timeout.
    timeout: std::time::Duration,

    /// Whether to use beta Graph API endpoints.
    use_beta_api: bool,
}

impl DefenderEdrProvider {
    /// Create a new Defender EDR provider.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` — Azure AD directory (tenant) ID
    /// * `client_id` — Registered application client ID
    /// * `client_secret` — Application client secret
    ///
    /// # Errors
    ///
    /// Returns [`EdrError::Configuration`] if any required parameter is empty.
    pub fn new(
        tenant_id: String,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, EdrError> {
        if tenant_id.is_empty() {
            return Err(EdrError::Configuration("tenant_id is required".to_string()));
        }
        if client_id.is_empty() {
            return Err(EdrError::Configuration("client_id is required".to_string()));
        }
        if client_secret.is_empty() {
            return Err(EdrError::Configuration("client_secret is required".to_string()));
        }

        Ok(Self {
            tenant_id,
            client_id,
            client_secret,
            access_token: Arc::new(RwLock::new(String::new())),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            timeout: std::time::Duration::from_secs(30),
            use_beta_api: false,
        })
    }

    /// Set whether to use beta Graph API endpoints.
    pub fn with_beta_api(mut self, use_beta: bool) -> Self {
        self.use_beta_api = use_beta;
        self
    }

    /// Get the base URL for Graph API calls.
    fn base_url(&self) -> &str {
        if self.use_beta_api {
            GRAPH_BETA_URL
        } else {
            GRAPH_URL
        }
    }

    /// Ensure a valid access token is available, refreshing if necessary.
    async fn ensure_token(&self) -> Result<String, EdrError> {
        {
            let token = self.access_token.read().map_err(|e| {
                EdrError::Internal(format!("Token lock poisoned: {e}"))
            })?;
            if !token.is_empty() {
                return Ok(token.clone());
            }
        }

        // Token is empty or expired — refresh it
        let token = self.refresh_token().await?;

        if let Ok(mut guard) = self.access_token.write() {
            *guard = token.clone();
        }

        Ok(token)
    }

    /// Refresh the OAuth2 access token using client credentials flow.
    async fn refresh_token(&self) -> Result<String, EdrError> {
        let token_url = AZURE_TOKEN_URL.replace("{tenant_id}", &self.tenant_id);

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", "https://graph.microsoft.com/.default"),
        ];

        let response = self
            .client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| EdrError::Api(format!("Token request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EdrError::Authentication(format!(
                "Token request failed ({status}): {body}"
            )));
        }

        let token_response: AzureTokenResponse = response
            .json()
            .await
            .map_err(|e| EdrError::InvalidResponse(format!("Token parse failed: {e}")))?;

        debug!(
            token_type = %token_response.token_type,
            expires_in = token_response.expires_in,
            "Defender access token refreshed"
        );

        Ok(token_response.access_token)
    }

    /// Make an authenticated GET request to the Graph API.
    async fn graph_get(&self, path: &str) -> Result<reqwest::Response, EdrError> {
        let token = self.ensure_token().await?;
        let url = format!("{}{}", self.base_url(), path);

        self.client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| EdrError::Api(format!("GET {url} failed: {e}")))
    }
}

#[async_trait]
impl EdrProvider for DefenderEdrProvider {
    async fn get_device_posture(
        &self,
        device_id: &str,
    ) -> Result<EdrDevicePosture, EdrError> {
        let url_encoded = urlencoding::encode(device_id);
        let response = self
            .graph_get(&format!("/security/machines/{url_encoded}"))
            .await?;

        if response.status() == 404 {
            return Err(EdrError::DeviceNotFound(device_id.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EdrError::Api(format!(
                "Defender API error ({status}): {body}"
            )));
        }

        let machine: DefenderMachineResponse = response
            .json()
            .await
            .map_err(|e| EdrError::InvalidResponse(format!("Parse machine failed: {e}")))?;

        let has_active_threats = machine.risk_score.unwrap_or(0) >= 70
            || machine.exposure_level
                .as_deref()
                .map_or(false, |e| e == "High" || e == "Medium");

        Ok(EdrDevicePosture {
            device_id: machine.id.unwrap_or_else(|| device_id.to_string()),
            hostname: machine.computer_dns_name,
            has_active_threats,
            active_detection_count: 0, // Requires separate API call
            sensor_healthy: machine.health_status.as_deref() == Some("Active"),
            last_seen_at: machine.last_seen_time,
            os_info: Some(EdrOsInfo {
                platform: machine.os_platform.unwrap_or_default(),
                version: machine.os_version.unwrap_or_default(),
                build: None,
            }),
            raw_response: Some(serde_json::to_value(&machine).unwrap_or_default()),
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

        let score_raw = posture
            .raw_response
            .and_then(|v| v.get("riskScore").and_then(|v| v.as_u64()))
            .unwrap_or(0) as u8;

        let level = match score_raw {
            0..=29 => EdrRiskLevel::Low,
            30..=69 => EdrRiskLevel::Medium,
            70..=89 => EdrRiskLevel::High,
            90..=100 => EdrRiskLevel::Critical,
            _ => EdrRiskLevel::Low,
        };

        Ok(EdrRiskScore {
            score: score_raw,
            level,
            assessed_at: Utc::now(),
            factors: vec![RiskFactor {
                category: "defender_risk".to_string(),
                description: "Microsoft Defender risk score".to_string(),
                weight: 1.0,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// Azure AD / Graph API Response Types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[allow(dead_code)]
    expires_on: u64,
    #[allow(dead_code)]
    resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderMachineResponse {
    id: Option<String>,
    computer_dns_name: Option<String>,
    #[serde(rename = "riskScore")]
    risk_score: Option<i64>,
    exposure_level: Option<String>,
    health_status: Option<String>,
    last_seen_time: Option<DateTime<Utc>>,
    os_platform: Option<String>,
    os_version: Option<String>,
}
