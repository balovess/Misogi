//! Mock TCM Provider for Testing
//!
//! Implements [`TcmProvider`] trait using in-memory cryptographic operations.
//! Suitable for unit tests and development environments without real TPM/TCM hardware.
//!
//! # Security Warning
//!
//! This implementation provides **no real security guarantees**. It uses
//! software-only HMAC-SHA256 for all operations. Never use in production.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::debug;

use super::traits::{
    PcrValue,
    QuoteAlgorithm,
    TcmError,
    TcmProvider,
    TcmQuote,
    TcmSealedData,
};

type HmacSha256 = Hmac<Sha256>;

/// In-memory mock TCM provider for testing.
///
/// Simulates TPM/TCM operations using software cryptography.
/// All keys are derived from a single seed value provided at construction.
pub struct MockTcmProvider {
    /// Seed key for deriving mock TPM keys.
    seed: Vec<u8>,
    /// Whether to simulate hardware availability.
    available: bool,
    /// Simulated PCR values (index → hash).
    pcr_store: std::collections::HashMap<u8, [u8; 32]>,
}

impl MockTcmProvider {
    /// Create a new mock TCM provider.
    ///
    /// # Arguments
    ///
    /// * `seed` — Arbitrary seed for deterministic key derivation
    /// * `available` — Whether to report hardware as available
    pub fn new(seed: Vec<u8>, available: bool) -> Self {
        Self {
            seed,
            available,
            pcr_store: std::collections::HashMap::new(),
        }
    }

    /// Set a simulated PCR value for testing.
    pub fn set_pcr(&mut self, index: u8, value: [u8; 32]) {
        self.pcr_store.insert(index, value);
    }

    /// Generate a mock EK certificate (self-signed X.509).
    ///
    /// Returns a minimal DER-encoded certificate structure suitable for
    /// parsing tests. This is NOT a valid X.509 certificate.
    fn generate_mock_ek_cert(&self) -> Vec<u8> {
        format!("MOCK-EK-CERT-{}", hex::encode(&self.seed)).into_bytes()
    }
}

#[async_trait::async_trait]
impl TcmProvider for MockTcmProvider {
    async fn is_available(&self) -> Result<bool, TcmError> {
        Ok(self.available)
    }

    async fn get_endorsement_key_cert(&self) -> Result<Vec<u8>, TcmError> {
        if !self.available {
            return Err(TcmError::HardwareUnavailable(
                "Mock TCM is configured as unavailable".to_string(),
            ));
        }
        Ok(self.generate_mock_ek_cert())
    }

    async fn quote(&self, nonce: &[u8], pcr_selection: &[u8]) -> Result<TcmQuote, TcmError> {
        if !self.available {
            return Err(TcmError::HardwareUnavailable(
                "Mock TCM is configured as unavailable".to_string(),
            ));
        }

        debug!(
            nonce_len = nonce.len(),
            pcr_count = pcr_selection.len(),
            "Mock TCM: generating quote"
        );

        let mut pcr_values = Vec::new();
        for &idx in pcr_selection {
            let value = self.pcr_store.get(&idx).copied().unwrap_or([0u8; 32]);
            pcr_values.push(PcrValue { index: idx, value });
        }

        // Generate a mock signature (HMAC over pcr values + nonce)
        let mut mac = HmacSha256::new_from_slice(&self.seed)
            .expect("HMAC accepts any key size");
        for pcr in &pcr_values {
            mac.update(&pcr.value);
        }
        mac.update(nonce);
        let signature = mac.finalize().into_bytes().to_vec();

        Ok(TcmQuote {
            pcr_values,
            signature,
            cert_chain: self.generate_mock_ek_cert(),
            algorithm: QuoteAlgorithm::Sha256Rsa,
        })
    }

    async fn seal(
        &self,
        data: &[u8],
        pcr_selection: &[u8],
    ) -> Result<TcmSealedData, TcmError> {
        if !self.available {
            return Err(TcmError::HardwareUnavailable(
                "Mock TCM is configured as unavailable".to_string(),
            ));
        }

        let mut mac = HmacSha256::new_from_slice(&self.seed)
            .expect("HMAC accepts any key size");
        mac.update(data);
        mac.update(pcr_selection);
        let ciphertext = mac.finalize().into_bytes().to_vec();

        Ok(TcmSealedData {
            ciphertext,
            pcr_selection: pcr_selection.to_vec(),
            algorithm: QuoteAlgorithm::Sha256Rsa,
            created_at: Some(Utc::now()),
        })
    }

    async fn unseal(&self, sealed: &TcmSealedData) -> Result<Vec<u8>, TcmError> {
        if !self.available {
            return Err(TcmError::HardwareUnavailable(
                "Mock TCM is configured as unavailable".to_string(),
            ));
        }

        // In mock mode, we can't actually recover the original data from HMAC.
        // Return a placeholder indicating successful unseal.
        //
        // Real TPM unseal would recover the original plaintext here.
        debug!(
            cipher_len = sealed.ciphertext.len(),
            "Mock TCM: unseal operation (returns placeholder)"
        );

        Ok(b"mock-unsealed-data-placeholder".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mock() -> MockTcmProvider {
        MockTcmProvider::new(b"test-seed-mock-tcm".to_vec(), true)
    }

    #[tokio::test]
    async fn test_is_available_when_configured() {
        let mock = make_mock();
        assert!(mock.is_available().await.unwrap());
    }

    #[tokio::test]
    async fn test_is_unavailable_when_disabled() {
        let mock = MockTcmProvider::new(b"seed".to_vec(), false);
        assert!(!mock.is_available().await.unwrap());
    }

    #[tokio::test]
    async fn test_get_ek_cert_succeeds() {
        let mock = make_mock();
        let cert = mock.get_endorsement_key_cert().await.unwrap();
        assert!(!cert.is_empty());
        assert!(cert.starts_with(b"MOCK-EK-CERT-"));
    }

    #[tokio::test]
    async fn test_quote_generates_result() {
        let mock = make_mock();
        let nonce = b"test-nonce-123";
        let pcr_sel = vec![0u8, 2, 4];

        let quote = mock.quote(nonce, &pcr_sel).await.unwrap();
        assert_eq!(quote.pcr_values.len(), 3);
        assert!(!quote.signature.is_empty());
        assert_eq!(quote.algorithm, QuoteAlgorithm::Sha256Rsa);
    }

    #[tokio::test]
    async fn test_quote_with_pcr_values() {
        let mut mock = make_mock();
        mock.set_pcr(0, [0xAA; 32]);
        mock.set_pcr(2, [0xBB; 32]);

        let quote = mock.quote(b"nonce", &[0, 2]).await.unwrap();

        let pcr0 = quote.pcr_values.iter().find(|p| p.index == 0).unwrap();
        assert_eq!(pcr0.value, [0xAA; 32]);

        let pcr2 = quote.pcr_values.iter().find(|p| p.index == 2).unwrap();
        assert_eq!(pcr2.value, [0xBB; 32]);
    }

    #[tokio::test]
    async fn test_seal_roundtrip_structure() {
        let mock = make_mock();
        let data = b"sensitive-secret-data";
        let pcr_sel = vec![7u8];

        let sealed = mock.seal(data, &pcr_sel).await.unwrap();
        assert!(!sealed.ciphertext.is_empty());
        assert_eq!(sealed.pcr_selection, vec![7]);
        assert!(sealed.created_at.is_some());
    }

    #[tokio::test]
    async fn test_unseal_returns_placeholder() {
        let mock = make_mock();
        let sealed = mock.seal(b"data", &[0]).await.unwrap();
        let unsealed = mock.unseal(&sealed).await.unwrap();
        assert_eq!(unsealed, b"mock-unsealed-data-placeholder");
    }

    #[tokio::test]
    async fn test_operations_fail_when_unavailable() {
        let mock = MockTcmProvider::new(b"seed".to_vec(), false);

        assert!(mock.get_endorsement_key_cert().await.is_err());
        assert!(mock.quote(b"nonce", &[0]).await.is_err());
        assert!(mock.seal(b"data", &[0]).await.is_err());
        assert!(mock.unseal(&TcmSealedData {
            ciphertext: vec![],
            pcr_selection: vec![],
            algorithm: QuoteAlgorithm::Sha256Rsa,
            created_at: None,
        }).await.is_err());
    }
}
