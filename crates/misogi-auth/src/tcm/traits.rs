//! TCG TCM / TPM Trait Definitions
//!
//! Defines the abstract interface for trusted computing module operations.
//! Implementations exist for:
//!
//! - Windows TPM 2.0 via TBS API (future)
//! - Chinese TCM GM/T 0012-2012 (future)
//! - Software mock for testing (see [`mock`])

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Error type for TCM/TPM operations.
#[derive(Debug, thiserror::Error)]
pub enum TcmError {
    /// Hardware not available or driver not installed.
    #[error("TCM/TPM hardware not available: {0}")]
    HardwareUnavailable(String),

    /// Operation timed out.
    #[error("TCM operation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    /// Invalid parameters provided to the operation.
    #[error("Invalid TCM parameters: {0}")]
    InvalidParameters(String),

    /// Attestation verification failed (bad signature, wrong nonce, etc.).
    #[error("Attestation verification failed: {0}")]
    AttestationFailed(String),

    /// The TCM is in an error state or needs attention.
    #[error("TCM device error: {0}")]
    DeviceError(String),

    /// I/O error communicating with the TCM device.
    #[error("TCM communication error: {0}")]
    CommunicationError(String),

    /// Feature not supported by this TCM implementation.
    #[error("Feature not supported: {0}")]
    Unsupported(String),

    /// Internal error in the TCM provider implementation.
    #[error("Internal TCM error: {0}")]
    Internal(String),
}

/// TCG TCM (Trusted Cryptography Module) provider trait.
///
/// Abstraction layer over hardware-backed cryptographic operations used
/// for remote attestation and secure key storage.
///
/// # Implementations
///
/// | Platform | Implementation | Crate |
/// |----------|---------------|-------|
/// | Windows 10+ | TPM 2.0 via TBS | `windows-tpm` (future) |
/// | China | TCM GM/T 0012-2012 | vendor SDK (future) |
/// | Testing | In-memory mock | [`MockTcmProvider`] |
///
/// # Thread Safety
///
/// All implementations MUST be `Send + Sync` safe for use across async tasks.
#[async_trait]
pub trait TcmProvider: Send + Sync {
    /// Check if TCM/TPM hardware is available and operational.
    async fn is_available(&self) -> Result<bool, TcmError>;

    /// Get the endorsement key (EK) certificate in DER format.
    ///
    /// The EK certificate is issued by the TPM/TCM manufacturer and uniquely
    /// identifies the physical hardware. Used for remote attestation of
    /// device identity.
    ///
    /// # Returns
    ///
    /// DER-encoded X.509 certificate bytes.
    async fn get_endorsement_key_cert(&self) -> Result<Vec<u8>, TcmError>;

    /// Perform a quote (attestation) operation.
    ///
    /// Signs the current values of selected PCR (Platform Configuration
    /// Registers) together with a server-provided nonce to prove the system's
    /// state at a specific point in time.
    ///
    /// # Arguments
    ///
    /// * `nonce` — Server-provided random value to prevent replay attacks
    /// * `pcr_selection` — Which PCR indices to include in the quote
    ///
    /// # Returns
    ///
    /// A signed [`TcmQuote`] containing PCR values and signature.
    async fn quote(
        &self,
        nonce: &[u8],
        pcr_selection: &[u8],
    ) -> Result<TcmQuote, TcmError>;

    /// Seal data to the current PCR state.
    ///
    /// Encrypts data using a key that is only releasable when PCRs match
    /// the specified values. Useful for protecting secrets that should only
    /// be accessible on verified, uncompromised systems.
    ///
    /// # Arguments
    ///
    /// * `data` — Plaintext data to seal
    /// * `pcr_selection` — PCR indices whose values bind this seal
    async fn seal(
        &self,
        data: &[u8],
        pcr_selection: &[u8],
    ) -> Result<TcmSealedData, TcmError>;

    /// Unseal previously sealed data.
    ///
    /// Recovers the original plaintext only if current PCR values match
    /// those specified when sealing. If PCRs have changed (e.g., due to
    /// firmware update or compromise), unsealing fails.
    ///
    /// # Arguments
    ///
    /// * `sealed` — The sealed data blob from a prior [`seal`](Self::seal) call
    async fn unseal(&self, sealed: &TcmSealedData) -> Result<Vec<u8>, TcmError>;
}

/// Result of a quote (remote attestation) operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcmQuote {
    /// Signed PCR values from the selected registers.
    pub pcr_values: Vec<PcrValue>,

    /// Digital signature over PCR values + nonce.
    pub signature: Vec<u8>,

    /// Attestation identity key certificate chain (DER-encoded).
    pub cert_chain: Vec<u8>,

    /// Cryptographic algorithm used for signing.
    pub algorithm: QuoteAlgorithm,
}

/// Individual PCR (Platform Configuration Register) value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcrValue {
    /// PCR index (0–23 for TPM 2.0).
    pub index: u8,

    /// SHA-256 hash value of the measured data (32 bytes).
    pub value: [u8; 32],
}

/// Supported quote/signing algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuoteAlgorithm {
    /// SHA-256 with RSASSA-PKCS1-v1_5 (TPM 2.0 standard).
    Sha256Rsa,

    /// SM3 with SM2 (Chinese TCM GM/T standard).
    Sm3Sm2,
}

impl std::fmt::Display for QuoteAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256Rsa => write!(f, "sha256_rsa"),
            Self::Sm3Sm2 => write!(f, "sm3_sm2"),
        }
    }
}

/// Sealed data blob produced by [`TcmProvider::seal`].
///
/// Opaque structure containing encrypted data plus PCR binding metadata.
/// The internal format depends on the underlying TCM implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcmSealedData {
    /// Encrypted payload (implementation-specific format).
    pub ciphertext: Vec<u8>,

    /// PCR selection used when sealing (for validation on unseal).
    pub pcr_selection: Vec<u8>,

    /// Algorithm used for sealing.
    pub algorithm: QuoteAlgorithm,

    /// Optional metadata about the seal (for debugging/logging).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}
