//! BlindSendDecoder — Reconstructs Bytes from received FecPacket slice.
//!
//! The decoder collects whatever packets arrive through the data diode and
//! attempts reconstruction when enough shards are available. It can tolerate
//! packet loss up to the parity shard count configured at encode time.
//!
//! # Decoding Strategy
//!
//! 1. Collect all received packets, filtering out corrupted ones (checksum fail)
//! 2. Extract shard data indexed by `shard_index`
//! 3. Pass collected shards to RS decoder for reconstruction
//! 4. Trim padding to recover exact original length

use crate::error::{MisogiError, Result};
use crate::fec::{
    FecConfig,
    reed_solomon::ReedSolomonCodec,
};
use super::packet::FecPacket;

/// Reconstructs original data from a (possibly incomplete) set of received packets.
pub struct BlindSendDecoder {
    /// Reed-Solomon codec instance matching the encoder's configuration.
    codec: ReedSolomonCodec,

    /// Expected data shard count (must match encoder).
    data_shards: usize,
}

impl BlindSendDecoder {
    /// Create a new decoder with the given FEC configuration.
    ///
    /// **Critical**: The configuration MUST match what was used during encoding,
    /// or reconstruction will produce garbage output.
    ///
    /// # Arguments
    /// * `config` - FEC parameters (must match encoder's config exactly).
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Configuration`] if the FEC config is invalid.
    pub fn new(config: &FecConfig) -> Result<Self> {
        let data_shards = config.data_shards;
        let codec = ReedSolomonCodec::with_config(config.clone())?;
        Ok(Self { codec, data_shards })
    }

    /// Reconstruct original data from a collection of received packets.
    ///
    /// This method is tolerant to packet loss — it will succeed as long as
    /// at least `data_shards` valid (checksum-passing) packets are provided.
    ///
    /// # Arguments
    /// * `packets` - Slice of received [`FecPacket`] instances.
    ///   May be incomplete (missing packets) or contain corrupted entries.
    /// * `original_len` - Expected original data length (for padding removal).
    ///   If unknown, pass 0 and the decoder returns the full padded output.
    ///
    /// # Returns
    ///
    /// Reconstructed original data on success.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Protocol`] if too many packets are lost (> parity capacity)
    ///   or if RS reconstruction fails internally.
    pub fn decode(&self, packets: &[FecPacket], original_len: usize) -> Result<Vec<u8>> {
        // Phase 1: Filter valid packets and extract shard data
        let mut received: Vec<(usize, Vec<u8>)> = Vec::new();
        for pkt in packets {
            if !pkt.verify() {
                tracing::warn!(
                    seq = pkt.sequence,
                    shard_idx = pkt.shard_index,
                    "Dropping corrupted FecPacket (CRC mismatch)"
                );
                continue;
            }
            received.push((
                pkt.shard_index as usize,
                pkt.data.to_vec(),
            ));
        }

        if received.is_empty() {
            return Err(MisogiError::Protocol(
                "No valid packets provided for decode".into(),
            ));
        }

        // Phase 2: Delegate to RS codec for actual reconstruction
        let len = if original_len > 0 { original_len } else { 0 };
        self.codec.decode(&received, len)
    }

    /// Estimate how many more packets are needed for successful decoding.
    ///
    /// Useful for progress reporting on the receiver side.
    ///
    /// # Arguments
    /// * `received_count` - Number of unique valid packets collected so far.
    ///
    /// # Returns
    ///
    /// Additional packets required (0 = ready to decode).
    pub fn packets_needed(&self, received_count: usize) -> usize {
        self.data_shards.saturating_sub(received_count)
    }

    /// Returns the data shard count expected by this decoder.
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }
}

// =============================================================================
// Unit Tests — Decoder creation, loss tolerance, boundary conditions
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::driver::BlindSendConfig;

    // -----------------------------------------------------------------
    // Helper: encode → simulate loss → decode → compare
    // -----------------------------------------------------------------

    fn encode_decode_with_loss(original: &[u8], loss_rate: f32) -> bool {
        let config = BlindSendConfig::default().to_fec_config();
        let enc = super::super::encoder::BlindSendEncoder::new(&config).expect("Encoder");
        let dec = BlindSendDecoder::new(&config).expect("Decoder");

        let packets = enc.encode(original).expect("Encode");
        let total = packets.len();
        let drop_count = (total as f32 * loss_rate).round() as usize;

        // Drop first `drop_count` packets to simulate loss
        let surviving: Vec<FecPacket> = packets.into_iter().skip(drop_count).collect();

        match dec.decode(&surviving, original.len()) {
            Ok(decoded) => decoded == original,
            Err(_) => false,
        }
    }

    #[test]
    fn test_decoder_creation() {
        let config = BlindSendConfig::default().to_fec_config();
        let dec = BlindSendDecoder::new(&config);
        assert!(dec.is_ok());
    }

    #[test]
    fn test_decode_zero_percent_loss() {
        let original: Vec<u8> = (0..8000).map(|i| i as u8).collect();
        assert!(encode_decode_with_loss(&original, 0.0));
    }

    #[test]
    fn test_decode_twenty_percent_loss() {
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        // Default: 16 data + 15 parity = 31 total, 20% loss = ~6 lost, well within 15 parity
        assert!(encode_decode_with_loss(&original, 0.20));
    }

    #[test]
    fn test_decode_forty_percent_loss() {
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        // 40% loss on 31 total = ~12 lost, still within 15 parity capacity
        assert!(encode_decode_with_loss(&original, 0.40));
    }

    #[test]
    fn test_decode_exceeds_recovery_capacity() {
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        // 70% loss on 31 total = ~22 lost > 15 parity capacity -> should fail
        assert!(!encode_decode_with_loss(&original, 0.70));
    }

    #[test]
    fn test_decoder_packets_needed_calculation() {
        let config = BlindSendConfig {
            fec_data_shards: 16,
            ..Default::default()
        }.to_fec_config();
        let dec = BlindSendDecoder::new(&config).unwrap();

        assert_eq!(dec.packets_needed(0), 16); // Need 16, have 0
        assert_eq!(dec.packets_needed(10), 6);  // Need 16, have 10
        assert_eq!(dec.packets_needed(16), 0);  // Need 16, have 16 -> ready
        assert_eq!(dec.packets_needed(20), 0);  // Already have enough
    }

    #[test]
    fn test_encode_single_byte_data() {
        let config = BlindSendConfig::default().to_fec_config();
        let enc = super::super::encoder::BlindSendEncoder::new(&config).unwrap();
        let dec = BlindSendDecoder::new(&config).unwrap();

        let original = vec![0xAB_u8];
        let packets = enc.encode(&original).expect("Encode single byte");
        assert!(!packets.is_empty());

        let decoded = dec.decode(&packets, original.len()).expect("Decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_large_data_multiple_shards() {
        let config = BlindSendConfig {
            packet_size: 256, // Small shard size to force multi-shard
            fec_data_shards: 8,
            redundancy_factor: 1.5, // Low redundancy to keep valid
            ..Default::default()
        }.to_fec_config();
        let enc = super::super::encoder::BlindSendEncoder::new(&config).unwrap();
        let dec = BlindSendDecoder::new(&config).unwrap();

        // Generate 2000 bytes of data (spans multiple 256-byte shards)
        let original: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let packets = enc.encode(&original).expect("Encode large data");
        let decoded = dec.decode(&packets, original.len()).expect("Decode");
        assert_eq!(decoded, original);
    }
}
