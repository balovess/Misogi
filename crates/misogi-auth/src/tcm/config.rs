//! TCM Provider Configuration
//!
//! Defines configuration options for selecting and parameterizing the
//! TCM/TPM backend implementation.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::traits::QuoteAlgorithm;

/// TCM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcmConfig {
    /// Which TCM backend implementation to use.
    pub provider_type: TcmProviderType,

    /// Whether TCM attestation is required for authentication.
    ///
    /// When `true`, authentication requests without a valid TCM quote
    /// will be rejected.
    pub require_attestation: bool,

    /// Accepted PCR indices for attestation validation.
    ///
    /// Only quotes containing these PCR indices will be accepted.
    /// Common choices:
    /// - PCR 0: BIOS/UEFI code
    /// - PCR 2: EFI/GPT partition table
    /// - PCR 4: MBR/partition table
    /// - PCR 7: Secure Boot state
    pub accepted_pcr_indices: Vec<u8>,

    /// Path to AIK (Attestation Identity Key) certificate for quote verification.
    ///
    /// Required for validating quotes in production. Left as `None`
    /// for mock/testing scenarios.
    pub aik_certificate_path: Option<PathBuf>,

    /// Timeout for TCM operations in milliseconds.
    pub operation_timeout_ms: u64,

    /// Preferred quote algorithm.
    pub preferred_algorithm: QuoteAlgorithm,
}

impl Default for TcmConfig {
    fn default() -> Self {
        Self {
            provider_type: TcmProviderType::Disabled,
            require_attestation: false,
            accepted_pcr_indices: vec![0, 2, 4, 7],
            aik_certificate_path: None,
            operation_timeout_ms: 5000,
            preferred_algorithm: QuoteAlgorithm::Sha256Rsa,
        }
    }
}

/// Available TCM/TPM provider types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TcmProviderType {
    /// Auto-detect available TCM/TPM hardware.
    Auto,

    /// Windows TPM 2.0 via TBS (Trusted Base Services) API.
    WindowsTpm20,

    /// Chinese TCM per GM/T 0012-2012 standard.
    ChineseTcm,

    /// Software-only mock implementation (testing only).
    Mock,

    /// TCM functionality disabled entirely.
    Disabled,
}

impl std::fmt::Display for TcmProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::WindowsTpm20 => write!(f, "windows_tpm20"),
            Self::ChineseTcm => write!(f, "chinese_tcm"),
            Self::Mock => write!(f, "mock"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TcmConfig::default();
        assert_eq!(config.provider_type, TcmProviderType::Disabled);
        assert!(!config.require_attestation);
        assert_eq!(config.operation_timeout_ms, 5000);
        assert!(config.accepted_pcr_indices.contains(&0));
        assert!(config.accepted_pcr_indices.contains(&7));
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(TcmProviderType::Auto.to_string(), "auto");
        assert_eq!(TcmProviderType::Mock.to_string(), "mock");
        assert_eq!(TcmProviderType::Disabled.to_string(), "disabled");
    }
}
