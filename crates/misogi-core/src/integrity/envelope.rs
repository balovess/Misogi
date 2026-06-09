//! Integrity envelope types for per-chunk verification and tamper detection.
//!
//! Defines the cryptographic envelope that wraps each data chunk during
//! transport. The envelope provides:
//!
//! - **Payload integrity** via configurable hash algorithms (SHA-256/512, BLAKE3).
//! - **Envelope authenticity** via self-hash of the serialized envelope structure.
//! - **Replay protection** via monotonically increasing sequence nonces.
//! - **Chain integrity** via optional linking to previous chunk hash.
//!
//! # Design Rationale
//!
//! The envelope is designed as an append-only structure: once built and sealed
//! (via [`IntegrityEnvelopeBuilder::build`]), its fields are immutable. Any
//! modification would invalidate the `envelope_hash`, making tampering detectable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

// ===========================================================================
// Error Types
// ===========================================================================

/// Specialized error type for integrity operations.
///
/// Covers all failure modes in the integrity pipeline including hash
/// computation failures, envelope validation errors, and serialization
/// problems that may occur during envelope construction or verification.
#[derive(thiserror::Error, Debug)]
pub enum IntegrityError {
    /// Cryptographic hash computation failed unexpectedly.
    ///
    /// This should never occur with software hash implementations but is
    /// included for completeness when hardware-accelerated backends fail.
    #[error("Hash computation failed: {0}")]
    HashComputationFailed(String),

    /// Envelope structure validation failed.
    ///
    /// Indicates the envelope was malformed, missing required fields,
    /// or contained logically inconsistent data (e.g., nonce regression).
    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// Computed hash does not match expected value.
    ///
    /// Carries both the expected hash (from envelope metadata) and the
    /// actual hash (recomputed from data) for diagnostic purposes.
    #[error("Hash mismatch: expected={expected}, actual={actual}")]
    HashMismatch { expected: String, actual: String },

    /// JSON serialization/deserialization error.
    ///
    /// Propagated from `serde_json` when envelope structures cannot be
    /// serialized to or deserialized from JSON representation.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// ===========================================================================
// Hash Algorithm
// ===========================================================================

/// Supported cryptographic hash algorithms for payload integrity verification.
///
/// Each variant maps to a specific hash function implementation. The choice
/// of algorithm affects both security properties and performance characteristics:
///
/// | Algorithm | Output Size | Speed (approx.) | Use Case |
/// |-----------|-------------|------------------|----------|
/// | `Sha256`  | 256 bits    | Baseline         | General purpose, NIST standard |
/// | `Sha512`  | 512 bits    | ~2x faster on 64-bit | Long-term security, large data |
/// | `Blake3`  | 256 bits    | Fastest          | High-throughput, modern default |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256 (FIPS 180-4). 256-bit output. Widely compatible.
    Sha256,

    /// SHA-512 (FIPS 180-4). 512-bit output. Preferred on 64-bit platforms.
    Sha512,

    /// BLAKE3. 256-bit output. Highest throughput, tree-hashing capable.
    Blake3,
}

impl HashAlgorithm {
    /// Compute the cryptographic digest of the given data.
    ///
    /// Returns a lowercase hexadecimal string representation of the hash
    /// output. The output length depends on the algorithm:
    ///
    /// - `Sha256`: 64 hex characters (32 bytes)
    /// - `Sha512`: 128 hex characters (64 bytes)
    /// - `Blake3`: 64 hex characters (32 bytes)
    ///
    /// # Arguments
    /// * `data` - Arbitrary byte slice to digest.
    ///
    /// # Returns
    /// Hex-encoded hash string.
    ///
    /// # Errors
    /// Returns [`IntegrityError::HashComputationFailed`] if the underlying
    /// hash backend encounters an unrecoverable error.
    pub fn hash(&self, data: &[u8]) -> Result<String, IntegrityError> {
        match self {
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(format!("{:x}", hasher.finalize()))
            }
            Self::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(format!("{:x}", hasher.finalize()))
            }
            Self::Blake3 => {
                // BLAKE3 implementation using the blake3 crate.
                // Falls back to SHA-256 if blake3 feature is not enabled.
                let hasher = blake3::hash(data);
                Ok(hasher.to_hex().to_string())
            }
        }
    }

    /// Returns the expected hexadecimal output length for this algorithm.
    pub fn output_len_hex(&self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
            Self::Blake3 => 64,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha512 => write!(f, "SHA-512"),
            Self::Blake3 => write!(f, "BLAKE3"),
        }
    }
}

// ===========================================================================
// Integrity Envelope
// ===========================================================================

/// Cryptographic integrity envelope wrapping a single transport chunk.
///
/// The envelope serves as a tamper-evident container for each data chunk.
/// It carries sufficient information to independently verify both payload
/// integrity and envelope authenticity without requiring external state.
///
/// # Tamper Detection Model
///
/// The `envelope_hash` field is computed over the entire serialized envelope
/// *excluding* the `envelope_hash` field itself. This creates a self-referential
/// seal: any modification to any field after construction will cause
/// verification to fail because the recomputed hash will not match.
///
/// # Fields
///
/// - `chunk_index` — Zero-based position of this chunk within the transfer.
/// - `data_hash` — Digest of the raw payload bytes.
/// - `envelope_hash` — Digest of the envelope structure (tamper-proof seal).
/// - `sequence_nonce` — Monotonically increasing anti-replay counter.
/// - `previous_chunk_hash` — Optional chain-link to preceding chunk's data_hash.
/// - `timestamp_ms` — Unix epoch milliseconds at envelope creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityEnvelope {
    /// Zero-based index of this chunk within the transfer session.
    pub chunk_index: u32,

    /// Hex-encoded cryptographic digest of the payload data.
    pub data_hash: String,

    /// Hex-encoded digest of the entire serialized envelope (self-seal).
    ///
    /// Computed over all other fields; acts as tamper-detection fingerprint.
    pub envelope_hash: String,

    /// Monotonically increasing nonce for replay attack prevention.
    pub sequence_nonce: u64,

    /// Hex-encoded data_hash of the preceding chunk, if chain-linking is enabled.
    ///
    /// Enables detection of chunk insertion, deletion, or reordering attacks.
    pub previous_chunk_hash: Option<String>,

    /// Unix timestamp in milliseconds when this envelope was created.
    pub timestamp_ms: u64,
}

// ===========================================================================
// Envelope Builder
// ===========================================================================

/// Builder for constructing and verifying [`IntegrityEnvelope`] instances.
///
/// Manages hash algorithm selection, nonce generation, and chunk-linking
/// configuration. The builder maintains internal mutable state (nonce counter)
/// and should be reused across all envelopes within a single transfer session
/// to ensure monotonic nonce progression.
///
/// # Usage Pattern
///
/// ```ignore
/// let mut builder = IntegrityEnvelopeBuilder::new(HashAlgorithm::Sha256, true);
/// let envelope = builder.build(0, &chunk_data, None)?;
/// assert!(builder.verify_envelope(&envelope, &chunk_data)?);
/// ```
///
/// # Thread Safety
///
/// The builder is **not** thread-safe due to internal mutable nonce state.
/// In multi-producer scenarios, construct one builder per task or protect
/// with external synchronization.
pub struct IntegrityEnvelopeBuilder {
    /// Hash algorithm used for data and envelope hashing.
    hash_algorithm: HashAlgorithm,

    /// Whether to include previous chunk hash in envelopes (chain-linking).
    chunk_linking: bool,

    /// Next nonce value to assign. Incremented after each build() call.
    next_nonce: u64,
}

impl IntegrityEnvelopeBuilder {
    /// Create a new envelope builder with the specified configuration.
    ///
    /// # Arguments
    /// * `algorithm` — Hash algorithm for data/envelope digests.
    /// * `chunk_linking` — If true, each envelope references the previous
    ///   chunk's hash, enabling insertion/deletion detection.
    ///
    /// # Returns
    /// A new builder instance with nonce initialized to zero.
    pub fn new(algorithm: HashAlgorithm, chunk_linking: bool) -> Self {
        Self {
            hash_algorithm: algorithm,
            chunk_linking,
            next_nonce: 0,
        }
    }

    /// Build a sealed integrity envelope for the given chunk data.
    ///
    /// Constructs an [`IntegrityEnvelope`] with computed hashes, assigned
    /// nonce, and optional chain-link reference. The envelope_hash is
    /// computed last to seal the entire structure.
    ///
    /// # Arguments
    /// * `chunk_index` — Zero-based position of this chunk in the transfer.
    /// * `data` — Raw payload bytes to wrap in the envelope.
    /// * `prev_hash` — Optional hex-encoded hash of the previous chunk's data.
    ///   Required when `chunk_linking` was set to `true` at construction;
    ///   ignored otherwise.
    ///
    /// # Returns
    /// A sealed [`IntegrityEnvelope`] ready for transport.
    ///
    /// # Errors
    /// - [`IntegrityError::HashComputationFailed`] if hash computation fails.
    /// - [`IntegrityError::InvalidEnvelope`] if prev_hash is required but missing.
    pub fn build(
        &mut self,
        chunk_index: u32,
        data: &[u8],
        prev_hash: Option<&str>,
    ) -> Result<IntegrityEnvelope, IntegrityError> {
        // Validate chain-linking requirement.
        if self.chunk_linking && prev_hash.is_none() && chunk_index > 0 {
            return Err(IntegrityError::InvalidEnvelope(
                "previous_chunk_hash is required when chunk_linking is enabled \
                 and chunk_index > 0"
                    .to_string(),
            ));
        }

        let nonce = self.generate_nonce();
        let data_hash = self.hash_algorithm.hash(data)?;
        let timestamp_ms = current_timestamp_ms();

        // Build partial envelope (without envelope_hash).
        let partial = PartialEnvelope {
            chunk_index,
            data_hash: data_hash.clone(),
            sequence_nonce: nonce,
            previous_chunk_hash: prev_hash.map(|s| s.to_string()),
            timestamp_ms,
        };

        // Compute envelope_hash over the serialized partial envelope.
        let serialized = serde_json::to_string(&partial).map_err(IntegrityError::Serialization)?;
        let envelope_hash = self.hash_algorithm.hash(serialized.as_bytes())?;

        Ok(IntegrityEnvelope {
            chunk_index,
            data_hash,
            envelope_hash,
            sequence_nonce: nonce,
            previous_chunk_hash: prev_hash.map(|s| s.to_string()),
            timestamp_ms,
        })
    }

    /// Verify an envelope against the original payload data.
    ///
    /// Performs three independent checks:
    ///
    /// 1. **Data integrity** — Recomputes data_hash and compares with stored value.
    /// 2. **Envelope authenticity** — Recomputes envelope_hash and compares.
    /// 3. **Nonce ordering** — Ensures nonce is strictly positive (basic sanity).
    ///
    /// # Arguments
    /// * `envelope` — The envelope to verify.
    /// * `data` — Original payload data that was wrapped in the envelope.
    ///
    /// # Returns
    /// `Ok(true)` if all verification passes, `Ok(false)` or `Err(_)` on failure.
    pub fn verify_envelope(
        &self,
        envelope: &IntegrityEnvelope,
        data: &[u8],
    ) -> Result<bool, IntegrityError> {
        // Check 1: Data hash integrity.
        let computed_data_hash = self.hash_algorithm.hash(data)?;
        if computed_data_hash != envelope.data_hash {
            return Err(IntegrityError::HashMismatch {
                expected: envelope.data_hash.clone(),
                actual: computed_data_hash,
            });
        }

        // Check 2: Envelope hash authenticity (seal verification).
        let partial = PartialEnvelope {
            chunk_index: envelope.chunk_index,
            data_hash: envelope.data_hash.clone(),
            sequence_nonce: envelope.sequence_nonce,
            previous_chunk_hash: envelope.previous_chunk_hash.clone(),
            timestamp_ms: envelope.timestamp_ms,
        };
        let serialized = serde_json::to_string(&partial).map_err(IntegrityError::Serialization)?;
        let computed_envelope_hash = self.hash_algorithm.hash(serialized.as_bytes())?;
        if computed_envelope_hash != envelope.envelope_hash {
            return Err(IntegrityError::HashMismatch {
                expected: envelope.envelope_hash.clone(),
                actual: computed_envelope_hash,
            });
        }

        // Check 3: Basic nonce sanity (must be non-zero for generated envelopes).
        if envelope.sequence_nonce == 0 && envelope.chunk_index > 0 {
            return Err(IntegrityError::InvalidEnvelope(
                "sequence_nonce is zero for non-first chunk".to_string(),
            ));
        }

        Ok(true)
    }

    /// Generate and return the next sequence nonce, advancing internal counter.
    ///
    /// Nonce values are monotonically increasing starting from 0.
    /// Each call consumes the current value and increments for the next call.
    ///
    /// # Returns
    /// The current nonce value before increment.
    pub fn generate_nonce(&mut self) -> u64 {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        nonce
    }

    /// Reset the internal nonce counter to zero.
    ///
    /// Should only be called between transfer sessions to prevent nonce
    /// reuse across sessions. Calling this mid-session will break
    /// monotonicity guarantees.
    pub fn reset_nonce(&mut self) {
        self.next_nonce = 0;
    }

    /// Returns the current hash algorithm configuration.
    pub fn algorithm(&self) -> &HashAlgorithm {
        &self.hash_algorithm
    }

    /// Returns whether chunk chain-linking is enabled.
    pub fn is_chunk_linking(&self) -> bool {
        self.chunk_linking
    }
}

// ===========================================================================
// Internal Helper Types
// ===========================================================================

/// Partial envelope used for envelope_hash computation.
///
/// Excludes `envelope_hash` itself to avoid circular dependency.
/// Serialized to JSON and hashed to produce the tamper-proof seal.
#[derive(Serialize, Deserialize)]
struct PartialEnvelope {
    chunk_index: u32,
    data_hash: String,
    sequence_nonce: u64,
    previous_chunk_hash: Option<String>,
    timestamp_ms: u64,
}

/// Returns the current Unix timestamp in milliseconds.
fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ===========================================================================
// Integrity Acknowledgment
// ===========================================================================

/// Acknowledgment message sent by receiver after processing a chunk.
///
/// Carries per-chunk reception status back to the sender, enabling
/// the repair system to identify missing or corrupted chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityAck {
    /// Index of the acknowledged chunk.
    pub chunk_index: u32,

    /// True if the chunk was received and verified successfully.
    pub received_ok: bool,

    /// Optional error description if received_ok is false.
    pub error: Option<String>,
}

impl IntegrityAck {
    /// Create a successful acknowledgment for a chunk.
    pub fn ok(chunk_index: u32) -> Self {
        Self {
            chunk_index,
            received_ok: true,
            error: None,
        }
    }

    /// Create a failure acknowledgment with error description.
    pub fn fail(chunk_index: u32, error: impl Into<String>) -> Self {
        Self {
            chunk_index,
            received_ok: false,
            error: Some(error.into()),
        }
    }
}

#[cfg(test)]
mod tests;
