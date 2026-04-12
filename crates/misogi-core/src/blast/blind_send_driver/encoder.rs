//! BlindSendEncoder — Encodes Bytes into a sequence of FEC-protected packets.
//!
//! The encoder splits input data into fixed-size chunks, applies Reed-Solomon
//! erasure coding to generate parity shards, then wraps each shard into a
//! [`FecPacket`](super::packet::FecPacket) with sequencing metadata for ordered reconstruction.
//!
//! # Encoding Pipeline
//!
//! ```text
//! [Bytes] → [Split into data_shards chunks] → [RS encode] → [N data + P parity shards]
//!                                                              ↓
//!                                                    [Wrap each in FecPacket]
//!                                                              ↓
//!                                                    [Vec<FecPacket> (sequenced)]
//! ```

use bytes::Bytes;

use crate::error::{MisogiError, Result};
use crate::fec::{
    FecConfig,
    reed_solomon::ReedSolomonCodec,
};
use super::packet::FecPacket;

/// Encodes arbitrary byte data into a sequence of FEC-protected packets.
#[derive(Debug)]
pub struct BlindSendEncoder {
    /// Reed-Solomon codec instance for FEC operations.
    codec: ReedSolomonCodec,

    /// Data shard count (from configuration).
    data_shards: usize,
}

impl BlindSendEncoder {
    /// Create a new encoder with the given FEC configuration.
    ///
    /// # Arguments
    /// * `config` - FEC parameters controlling encoding behavior.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Configuration`] if the FEC config is invalid.
    pub fn new(config: &FecConfig) -> Result<Self> {
        let data_shards = config.data_shards;
        let codec = ReedSolomonCodec::with_config(config.clone())?;
        Ok(Self { codec, data_shards })
    }

    /// Encode raw bytes into a sequence of FEC-protected packets.
    ///
    /// Each returned packet is independently transmittable via UDP broadcast.
    /// The receiver needs any `data_shards` packets out of the total to recover
    /// the original data.
    ///
    /// # Arguments
    /// * `data` - Original data to encode (must be non-empty).
    ///
    /// # Returns
    ///
    /// A vector of [`FecPacket`] instances, each containing one encoded shard.
    /// Packets are ordered by sequence number (0, 1, 2, ...).
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Protocol`] if data is empty or RS encoding fails.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<FecPacket>> {
        if data.is_empty() {
            return Err(MisogiError::Protocol(
                "Cannot encode empty data".into(),
            ));
        }

        // Phase 1: Reed-Solomon encode into data + parity shards
        let block = self.codec.encode(data)?;
        let total_packets = block.total_shards() as u32;
        let total_shards = total_packets;

        // Phase 2: Wrap each shard into a FecPacket with sequence numbers
        let mut packets = Vec::with_capacity(total_packets as usize);

        // Emit data shards first (indices 0..data_shards-1)
        for (idx, shard) in block.data_shards.iter().enumerate() {
            packets.push(FecPacket::new(
                idx as u32,
                total_packets,
                idx as u32,
                total_shards,
                Bytes::copy_from_slice(shard),
            ));
        }

        // Emit parity shards (indices data_shards..total-1)
        for (idx, shard) in block.parity_shards.iter().enumerate() {
            let pidx = (self.data_shards + idx) as u32;
            packets.push(FecPacket::new(
                pidx,
                total_packets,
                pidx,
                total_shards,
                Bytes::copy_from_slice(shard),
            ));
        }

        Ok(packets)
    }

    /// Returns the data shard count used by this encoder.
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }
}

// =============================================================================
// Unit Tests — Encoder creation, encoding, packet count, sequencing
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::driver::BlindSendConfig;

    #[test]
    fn test_encoder_creation() {
        let config = BlindSendConfig::default().to_fec_config();
        let enc = BlindSendEncoder::new(&config);
        assert!(enc.is_ok());
        assert_eq!(enc.unwrap().data_shards(), 16); // Default fec_data_shards
    }

    #[test]
    fn test_encode_small_data_produces_correct_packet_count() {
        let config = BlindSendConfig::default().to_fec_config();
        let enc = BlindSendEncoder::new(&config).unwrap();

        let data = b"Hello, Blind Send!".to_vec();
        let packets = enc.encode(&data).expect("Encode succeeds");

        let expected_total = config.data_shards + config.parity_shards;
        assert_eq!(packets.len(), expected_total);
    }

    #[test]
    fn test_encode_empty_data_fails() {
        let config = BlindSendConfig::default().to_fec_config();
        let enc = BlindSendEncoder::new(&config).unwrap();
        assert!(enc.encode(&[]).is_err());
    }

    #[test]
    fn test_encode_packets_have_monotonic_sequence() {
        let config = BlindSendConfig::default().to_fec_config();
        let enc = BlindSendEncoder::new(&config).unwrap();

        let data: Vec<u8> = (0u32..5000).map(|i| i as u8).collect();
        let packets = enc.encode(&data).expect("Encode");

        for i in 0..packets.len() {
            assert_eq!(packets[i].sequence, i as u32,
                "Packet {} has wrong sequence", i);
        }
    }
}
