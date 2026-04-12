//! Reed-Solomon erasure code encoder/decoder using Galois Field GF(2^8).
//!
//! Wraps the [`reed_solomon_erasure`] crate which provides a high-performance
//! implementation of Reed-Solomon erasure coding over GF(256). This module adapts
//! that library's slice-based API for Misogi's streaming shard model.
//!
//! # Performance Characteristics
//!
//! - Encoding: O(n × k) where n = total shards, k = shard size
//! - Decoding: O(n² × k) Gaussian elimination over GF(2^8)
//! - Memory: O(n × k) for working buffers
//!
//! # Recovery Guarantee
//!
//! With `data_shards = D` and `parity_shards = P`, any D of the (D + P)
//! total shards are sufficient to reconstruct all original data.
//! Maximum tolerable loss rate = P / (D + P).
//!
//! Example: 16 data + 4 parity → can lose up to 4/20 = 20% of shards.

use reed_solomon_erasure::{ReedSolomon as RsCodec, galois_8::Field};

use super::FecConfig;
use super::FecEncodedBlock;
use crate::error::{MisogiError, Result};

/// Reed-Solomon erasure code encoder/decoder backed by `reed-solomon-erasure`.
#[derive(Debug)]
pub struct ReedSolomonCodec {
    config: FecConfig,
    rs: RsCodec<Field>,
}

impl ReedSolomonCodec {
    /// Create codec with default configuration (16+4 shards, 1400B each).
    pub fn new() -> Result<Self> {
        Self::with_config(FecConfig::default())
    }

    /// Create codec with custom FEC configuration.
    ///
    /// # Arguments
    /// * `config` - FEC parameters controlling shard count and size.
    ///
    /// # Errors
    /// - [`MisogiError::Configuration`] if total_shards > 255 (GF(2^8) limit)
    ///   or if parity_shards >= data_shards.
    pub fn with_config(config: FecConfig) -> Result<Self> {
        let total = config.total_shards();
        if total > 255 {
            return Err(MisogiError::Configuration(format!(
                "total_shards {} exceeds GF(2^8) maximum of 255",
                total
            )));
        }
        if config.parity_shards >= config.data_shards {
            return Err(MisogiError::Configuration(format!(
                "parity_shards ({}) must be < data_shards ({})",
                config.parity_shards, config.data_shards
            )));
        }
        if config.data_shards == 0 || config.parity_shards == 0 {
            return Err(MisogiError::Configuration(
                "data_shards and parity_shards must both be >= 1".into(),
            ));
        }

        let rs = RsCodec::<Field>::new(config.data_shards, config.parity_shards)
            .map_err(|e| MisogiError::Configuration(format!("RS init failed: {}", e)))?;

        Ok(Self { config, rs })
    }

    /// Returns a reference to the current FEC configuration.
    pub fn config(&self) -> &FecConfig {
        &self.config
    }

    /// Encode raw data into FEC-protected shard set.
    ///
    /// Splits input into `data_shards` equal-sized blocks, pads the last block,
    /// then computes `parity_shards` redundancy vectors via Reed-Solomon encoding.
    ///
    /// # Pipeline
    ///
    /// ```text
    /// [raw bytes] → [split into N data shards] → [RS encode] → [N data + P parity]
    /// ```
    ///
    /// # Arguments
    /// * `data` - Original file content to encode.
    ///
    /// # Returns
    /// [`FecEncodedBlock`] containing all shards plus reconstruction metadata.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if data is empty or RS encoding fails.
    pub fn encode(&self, data: &[u8]) -> Result<FecEncodedBlock> {
        let shard_size = self.config.shard_size;
        let n_data = self.config.data_shards;
        let n_par = self.config.parity_shards;
        let original_len = data.len();

        if data.is_empty() {
            return Err(MisogiError::Protocol(
                "Cannot encode empty data".into(),
            ));
        }

        let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(n_data);
        for i in 0..n_data {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, original_len);
            let mut shard = vec![0u8; shard_size];
            let copy_len = end.saturating_sub(start);
            if copy_len > 0 {
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            data_shards.push(shard);
        }

        let mut parity_shards_raw: Vec<Vec<u8>> =
            vec![vec![0u8; shard_size]; n_par];

        // Build combined shard buffer: [data_shards... | parity_shards...]
        let mut all_shards: Vec<&mut [u8]> = Vec::with_capacity(n_data + n_par);
        for ds in &mut data_shards {
            all_shards.push(ds.as_mut_slice());
        }
        for ps in &mut parity_shards_raw {
            all_shards.push(ps.as_mut_slice());
        }

        self.rs
            .encode(all_shards.as_mut_slice())
            .map_err(|e| MisogiError::Protocol(format!("RS encode failed: {}", e)))?;

        Ok(FecEncodedBlock {
            original_len,
            data_shards,
            parity_shards: parity_shards_raw,
            config: self.config.clone(),
        })
    }

    /// Decode/reconstruct original data from a partial shard collection.
    ///
    /// Uses Gaussian elimination over GF(2^8) to solve for missing data shards
    /// using available parity shards as linear constraints.
    ///
    /// # Arguments
    /// * `received_shards` - Slice of `(shard_index, shard_data)` pairs.
    ///   Indices are logical positions 0..(data_shards + parity_shards - 1).
    /// * `original_len` - Expected original byte length (for padding removal).
    ///
    /// # Returns
    /// Reconstructed original data bytes on success.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if too many shards lost (> parity count),
    ///   or if RS reconstruction fails internally.
    pub fn decode(
        &self,
        received_shards: &[(usize, Vec<u8>)],
        original_len: usize,
    ) -> Result<Vec<u8>> {
        let n_data = self.config.data_shards;
        let _n_par = self.config.parity_shards;
        let total = self.config.total_shards();
        let shard_size = self.config.shard_size;

        if received_shards.is_empty() {
            return Err(MisogiError::Protocol(
                "No shards provided for decode".into(),
            ));
        }

        // Build Option-wrapped shard array: Some(data) = present, None = missing
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];
        for &(idx, ref data) in received_shards {
            if idx < total && data.len() == shard_size {
                shards[idx] = Some(data.clone());
            }
        }

        let present_count = shards.iter().filter(|s| s.is_some()).count();
        if present_count < n_data {
            return Err(MisogiError::Protocol(format!(
                "Insufficient shards: got {}/{} (need at least {})",
                present_count, total, n_data
            )));
        }

        // Reconstruct missing shards in-place
        self.rs
            .reconstruct(shards.as_mut_slice())
            .map_err(|e| MisogiError::Protocol(format!("RS reconstruct failed: {}", e)))?;

        // Concatenate reconstructed data shards into contiguous output buffer
        let mut result = Vec::with_capacity(original_len.max(shard_size * n_data));
        for i in 0..n_data {
            if let Some(ref shard) = shards[i] {
                let start = i * shard_size;
                let end = std::cmp::min(start + original_len, (i + 1) * shard_size);
                if start < original_len {
                    let copy_end = std::cmp::min(end - start, shard.len());
                    result.extend_from_slice(&shard[..copy_end]);
                }
            }
        }

        result.truncate(original_len);
        Ok(result)
    }

    /// Estimate how many shards are missing from a partial collection index set.
    ///
    /// Purely diagnostic — does not attempt decoding.
    pub fn estimate_missing(&self, received_indices: &[usize]) -> usize {
        let total = self.config.total_shards();
        let present: std::collections::HashSet<usize> =
            received_indices.iter().copied().collect();
        total - present.intersection(&(0..total).collect()).count()
    }
}

impl Default for ReedSolomonCodec {
    fn default() -> Self {
        Self::new().expect("default FEC config should always be valid")
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let cfg = FecConfig::default();
        assert_eq!(cfg.data_shards, 16);
        assert_eq!(cfg.parity_shards, 4);
        assert_eq!(cfg.shard_size, 1400);
        assert_eq!(cfg.total_shards(), 20);
        assert_eq!(cfg.recoverable_loss(), 4);
        assert!((cfg.max_loss_rate() - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_codec_creation_valid() {
        assert!(ReedSolomonCodec::new().is_ok());
        assert!(ReedSolomonCodec::with_config(FecConfig::standard()).is_ok());
    }

    #[test]
    fn test_codec_creation_invalid_too_many_shards() {
        let cfg = FecConfig {
            data_shards: 200,
            parity_shards: 60,
            shard_size: 1024,
        };
        assert!(ReedSolomonCodec::with_config(cfg).is_err());
    }

    #[test]
    fn test_codec_creation_invalid_parity_ge_data() {
        let cfg = FecConfig {
            data_shards: 4,
            parity_shards: 10,
            shard_size: 512,
        };
        assert!(ReedSolomonCodec::with_config(cfg).is_err());
    }

    #[test]
    fn test_encode_empty_data_fails() {
        let codec = ReedSolomonCodec::new().unwrap();
        assert!(codec.encode(&[]).is_err());
    }

    #[test]
    fn test_encode_small_file_roundtrip() {
        let codec = ReedSolomonCodec::new().unwrap();
        let original = b"Hello, Misogi UDP Blast!".to_vec();

        let block = codec.encode(&original).unwrap();

        assert_eq!(block.original_len, original.len());
        assert_eq!(block.data_shards.len(), 16);
        assert_eq!(block.parity_shards.len(), 4);

        let mut all_shards: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, shard) in block.data_shards.iter().enumerate() {
            all_shards.push((i, shard.clone()));
        }
        for (i, shard) in block.parity_shards.iter().enumerate() {
            all_shards.push((block.data_shards.len() + i, shard.clone()));
        }

        let decoded = codec.decode(&all_shards, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_with_zero_loss() {
        let codec = ReedSolomonCodec::new().unwrap();
        let original: Vec<u8> = (0..20000).map(|i| (i % 256) as u8).collect();

        let block = codec.encode(&original).unwrap();
        assert_eq!(block.original_len, original.len());

        let mut all_shards: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, shard) in block.data_shards.iter().enumerate() {
            all_shards.push((i, shard.clone()));
        }
        for (i, shard) in block.parity_shards.iter().enumerate() {
            all_shards.push((block.data_shards.len() + i, shard.clone()));
        }

        let decoded = codec.decode(&all_shards, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_with_15_percent_loss() {
        let codec = ReedSolomonCodec::new().unwrap();
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();

        let block = codec.encode(&original).unwrap();

        let mut received: Vec<(usize, Vec<u8>)> = Vec::new();
        let drop_count = 3; // 3/20 = 15%

        for (i, shard) in block.data_shards.iter().enumerate() {
            if i < drop_count {
                continue;
            }
            received.push((i, shard.clone()));
        }
        for (i, shard) in block.parity_shards.iter().enumerate() {
            received.push((block.data_shards.len() + i, shard.clone()));
        }

        let decoded = codec.decode(&received, original.len()).unwrap();
        assert_eq!(decoded, original, "Decoded data must match original after 15% loss");
    }

    #[test]
    fn test_encode_decode_with_20_percent_loss() {
        let codec = ReedSolomonCodec::new().unwrap();
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();

        let block = codec.encode(&original).unwrap();

        let mut received: Vec<(usize, Vec<u8> )> = Vec::new();
        for (i, shard) in block.data_shards.iter().enumerate() {
            if i == 0 || i == 4 || i == 8 || i == 12 {
                continue; // Drop 4 data shards (20% loss within parity capacity)
            }
            received.push((i, shard.clone()));
        }
        for (i, shard) in block.parity_shards.iter().enumerate() {
            received.push((block.data_shards.len() + i, shard.clone()));
        }

        let decoded = codec.decode(&received, original.len()).unwrap();
        assert_eq!(decoded, original, "Should recover at 20% loss (within parity capacity)");
    }

    #[test]
    fn test_encode_decode_exceeds_recovery_capacity() {
        let codec = ReedSolomonCodec::new().unwrap();
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();

        let block = codec.encode(&original).unwrap();

        let mut received: Vec<(usize, Vec<u8> )> = Vec::new();
        for (i, shard) in block.data_shards.iter().enumerate() {
            if i < 7 {
                continue; // Drop 7 data shards (35% > 20% tolerance)
            }
            received.push((i, shard.clone()));
        }
        for (i, shard) in block.parity_shards.iter().enumerate() {
            received.push((block.data_shards.len() + i, shard.clone()));
        }

        let result = codec.decode(&received, original.len());
        assert!(result.is_err(), "Should fail when loss exceeds recovery capacity");
    }

    #[test]
    fn test_get_shard_by_index() {
        let codec = ReedSolomonCodec::new().unwrap();
        let block = codec.encode(b"hello world test").unwrap();

        assert!(block.get_shard(0).is_some());
        assert!(block.get_shard(16).is_some());
        assert!(block.get_shard(99).is_none());
    }

    #[test]
    fn test_estimate_missing_no_loss() {
        let codec = ReedSolomonCodec::new().unwrap();
        let indices: Vec<usize> = (0..20).collect();
        assert_eq!(codec.estimate_missing(&indices), 0);
    }

    #[test]
    fn test_estimate_missing_partial() {
        let codec = ReedSolomonCodec::new().unwrap();
        let indices: Vec<usize> = vec![0, 1, 2, 5, 6, 7, 10, 11, 12, 15, 16, 17, 18, 19];
        assert_eq!(codec.estimate_missing(&indices), 6);
    }
}
