//! Sunset Policy engine for managing API version lifecycle.
//!
//! Japanese enterprise/government systems require multi-year transition windows.
//! This module provides configurable policies for:
//!
//! - **Warning phase**: Log deprecation notices but serve normally
//! - **Soft sunset**: Add rate limiting + response headers
//! - **Hard sunset**: Return 410 Gone with migration guide
//!
//! # Lifecycle States
//!
//! ```text
//! STABLE ──► DEPRECATED (warning only)
//!           ──► SUNSET_SOFT (rate limit + headers)
//!                  ──► SUNSET_HARD (410 Gone)
//!                        ──► REMOVED (404)
//! ```
//!
//! # Typical Japanese Government Timeline
//!
//! ```text
//! 2025-Q2: Announce V1 deprecation (DEPRECATED phase begins)
//! 2026-Q2: Enter SOFT_SUNSET (rate limit active, SIers notified)
//! 2027-Q3: HARD_SUNSET (410 Gone, migration mandatory)
//! 2028-Q1: REMOVED (404, V1 endpoints deleted)
//! ```

use serde::{Deserialize, Serialize};

/// Lifecycle phase for an API version within the sunset policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SunsetPhase {
    /// Fully supported. No deprecation notice. This is the default for new versions.
    Stable,

    /// Still functional, but emits `[DEPRECATION]` warnings on every request.
    /// SIers should see these logs and begin budget planning.
    Deprecated,

    /// Rate-limited to N req/s. Adds `Sunset` / `Deprecated` HTTP headers per RFC 8594.
    /// Intended as a strong signal that upgrade is imminent.
    SoftSunset {
        /// Maximum requests per second allowed before returning 429 Too Many Requests.
        max_requests_per_sec: u64,
    },

    /// Returns HTTP 410 Gone with JSON body explaining the migration path.
    /// All requests are rejected; no data flows through this version anymore.
    HardSunset {
        /// The successor endpoint clients should migrate to.
        /// Example: `/api/v2/upload`
        successor_endpoint: String,
    },
}

impl Default for SunsetPhase {
    fn default() -> Self {
        Self::Stable
    }
}

/// Per-version lifecycle configuration controlling deprecation behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSunsetPolicy {
    /// API version string (e.g., `"v1"`, `"v2"`).
    pub version: String,

    /// Current lifecycle phase for this version.
    pub phase: SunsetPhase,

    /// ISO 8601 date when hard sunset takes effect (format: `YYYY-MM-DD`).
    ///
    /// Used in log messages and HTTP `Sunset` header value.
    pub hard_sunset_date: Option<String>,

    /// ISO 8601 date when deprecation was first announced.
    pub announced_date: Option<String>,

    /// Human-readable URL pointing to migration documentation.
    pub migration_guide_url: Option<String>,
}

impl VersionSunsetPolicy {
    /// Create a new stable policy for the given version.
    pub fn stable(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            phase: SunsetPhase::Stable,
            hard_sunset_date: None,
            announced_date: None,
            migration_guide_url: None,
        }
    }

    /// Create a deprecated policy with a future hard sunset date.
    pub fn deprecated(
        version: impl Into<String>,
        hard_sunset: impl Into<String>,
        announced: impl Into<String>,
        guide_url: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            phase: SunsetPhase::Deprecated,
            hard_sunset_date: Some(hard_sunset.into()),
            announced_date: Some(announced.into()),
            migration_guide_url: Some(guide_url.into()),
        }
    }

    /// Check whether requests to this version are still accessible.
    pub fn is_accessible(&self) -> bool {
        !matches!(self.phase, SunsetPhase::HardSunset { .. })
    }

    /// Check whether requests to this version should be rate-limited.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self.phase, SunsetPhase::SoftSunset { .. })
    }

    /// Check whether this version emits deprecation warnings (but still serves).
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self.phase,
            SunsetPhase::Deprecated | SunsetPhase::SoftSunset { .. }
        )
    }

    /// Generate an RFC 8594 `Sunset` header value for HTTP responses.
    ///
    /// Returns `None` for Stable/Deprecated phases (no Sunset header needed).
    pub fn sunset_header_value(&self) -> Option<String> {
        match &self.phase {
            SunsetPhase::SoftSunset { .. } | SunsetPhase::HardSunset { .. } => self
                .hard_sunset_date
                .as_ref()
                .map(|d| format!("Sunset=\"{}\"", d)),
            _ => None,
        }
    }

    /// Generate the successor-version Link header value (RFC 8288).
    pub fn successor_link_header(&self, _original_path: &str) -> Option<String> {
        if let SunsetPhase::HardSunset { ref successor_endpoint } = self.phase {
            Some(format!(
                "<{}>; rel=\"successor-version\"; type=\"text/html\"",
                successor_endpoint
            ))
        } else {
            None
        }
    }

    /// Build a JSON body for 410 Gone responses during hard sunset.
    pub fn gone_response_body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": "Gone",
            "code": 410,
            "message": format!("API version '{}' has been retired.", self.version),
            "sunset_date": self.hard_sunset_date,
            "migration_guide": self.migration_guide_url,
            "successor": match &self.phase {
                SunsetPhase::HardSunset { successor_endpoint } => Some(successor_endpoint.as_str()),
                _ => None,
            },
            "documentation": "https://docs.misogi.dev/api/versioning"
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_policy() {
        let p = VersionSunsetPolicy::stable("v1");
        assert!(p.is_accessible());
        assert!(!p.is_rate_limited());
        assert!(!p.is_deprecated());
        assert!(p.sunset_header_value().is_none());
    }

    #[test]
    fn test_deprecated_policy() {
        let p = VersionSunsetPolicy::deprecated(
            "v1",
            "2027-03-31",
            "2025-04-11",
            "https://docs.misogi.dev/migration/v1-to-v2",
        );
        assert!(p.is_accessible());
        assert!(!p.is_rate_limited());
        assert!(p.is_deprecated());
        assert!(p.sunset_header_value().is_none());
        assert_eq!(p.hard_sunset_date.as_deref(), Some("2027-03-31"));
    }

    #[test]
    fn test_soft_sunset_policy() {
        let p = VersionSunsetPolicy {
            version: "v1".to_string(),
            phase: SunsetPhase::SoftSunset {
                max_requests_per_sec: 100,
            },
            hard_sunset_date: Some("2027-06-30".to_string()),
            announced_date: None,
            migration_guide_url: None,
        };
        assert!(p.is_accessible());
        assert!(p.is_rate_limited());
        assert!(p.is_deprecated());
        assert_eq!(
            p.sunset_header_value(),
            Some(r#"Sunset="2027-06-30""#.to_string())
        );
    }

    #[test]
    fn test_hard_sunset_not_accessible() {
        let p = VersionSunsetPolicy {
            version: "v1".to_string(),
            phase: SunsetPhase::HardSunset {
                successor_endpoint: "/api/v2/upload".to_string(),
            },
            hard_sunset_date: Some("2027-03-31".to_string()),
            announced_date: Some("2025-01-15".to_string()),
            migration_guide_url: Some("https://example.com/migrate".to_string()),
        };
        assert!(!p.is_accessible());
        assert!(!p.is_rate_limited());

        let body = p.gone_response_body();
        assert_eq!(body["error"], "Gone");
        assert_eq!(body["code"], 410);

        let link = p.successor_link_header("/api/v1/upload");
        assert!(link.is_some());
        assert!(link.unwrap().contains("/api/v2/upload"));
    }

    #[test]
    fn test_gone_body_contains_migration_info() {
        let p = VersionSunsetPolicy {
            version: "v1".to_string(),
            phase: SunsetPhase::HardSunset {
                successor_endpoint: "/api/v2/sanitize".to_string(),
            },
            hard_sunset_date: Some("2027-12-31".to_string()),
            announced_date: None,
            migration_guide_url: Some("https://docs.example.com".to_string()),
        };
        let body = p.gone_response_body();
        assert!(body.get("sunset_date").is_some());
        assert!(body.get("migration_guide").is_some());
        assert!(body.get("successor").is_some());
    }

    #[test]
    fn test_phase_serialization() {
        let phases = vec![
            SunsetPhase::Stable,
            SunsetPhase::Deprecated,
            SunsetPhase::SoftSunset { max_requests_per_sec: 50 },
            SunsetPhase::HardSunset { successor_endpoint: "/v2".to_string() },
        ];
        for phase in &phases {
            let json = serde_json::to_string(phase).unwrap();
            let decoded: SunsetPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, decoded);
        }
    }
}
