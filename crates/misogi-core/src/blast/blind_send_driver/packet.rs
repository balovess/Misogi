//! FecPacket — Wire format for blind send FEC-protected packets.
//!
//! Each packet is an independent unit carrying sequence information,
//! shard identity, payload data, and CRC32 checksum for integrity verification.
//!
//! # Wire Layout (24 + N bytes)
//!
//! ```text
//! Offset  Size   Field           Type
//! ------  ----   -----           ----
//! 0       4      sequence        u32 BE — logical packet sequence number
//! 4       4      total_packets   u32 BE — total packets in this transfer
//! 8       4      shard_index     u32 BE — index within FEC block (0-based)
//! 12      4      total_shards    u32 BE — total shards in this FEC block
//! 16      4      data_len        u32 BE — length of data field
//! 20      4      checksum        u32 BE — CRC32 of data field
//! 24      N      data            [u8; N] — shard payload bytes
//! ```

use bytes::Bytes;

use crate::error::{MisogiError, Result};

/// Single FEC-encoded packet transmitted over UDP broadcast.
///
/// Each packet is an independent unit carrying:
/// - Sequence information for ordered reconstruction at receiver
/// - Shard identity for FEC decoding (which shard of which block this is)
/// - Payload data (raw shard bytes)
/// - CRC32 checksum for integrity verification
#[derive(Debug, Clone, PartialEq)]
pub struct FecPacket {
    /// Logical sequence number for ordering (0-based, monotonically increasing).
    pub sequence: u32,

    /// Total number of packets in this complete transfer session.
    pub total_packets: u32,

    /// Index of this shard within its FEC encoding block.
    ///
    /// Range: 0 .. (data_shards + parity_shards - 1)
    /// Values < data_shards indicate data shards.
    /// Values >= data_shards indicate parity shards.
    pub shard_index: u32,

    /// Total number of shards in this FEC block (data + parity).
    pub total_shards: u32,

    /// Payload data for this shard.
    pub data: Bytes,

    /// CRC32 checksum of the `data` field (IEEE polynomial, big-endian).
    pub checksum: u32,
}

impl FecPacket {
    /// Header size in bytes (fixed portion before variable-length data).
    pub const HEADER_SIZE: usize = 24;

    /// Create a new FecPacket with computed checksum.
    ///
    /// The checksum is automatically calculated from the provided data.
    pub fn new(
        sequence: u32,
        total_packets: u32,
        shard_index: u32,
        total_shards: u32,
        data: Bytes,
    ) -> Self {
        let checksum = crc32fast::hash(&data);
        Self {
            sequence,
            total_packets,
            shard_index,
            total_shards,
            data,
            checksum,
        }
    }

    /// Verify the integrity of this packet's data against its stored checksum.
    ///
    /// Returns `true` if the CRC32 matches (data is intact), `false` otherwise.
    /// Corrupted packets should be discarded by the receiver.
    pub fn verify(&self) -> bool {
        crc32fast::hash(&self.data) == self.checksum
    }

    /// Returns true if this packet is a parity (redundancy) shard.
    ///
    /// Parity shards have `shard_index >= data_shards`, where `data_shards`
    /// can be derived from the relationship between `shard_index` and `total_shards`.
    /// Since we don't store data_shards explicitly, this uses a heuristic:
    /// the caller should know the expected data_shards count from config.
    pub fn is_parity(&self, data_shards: usize) -> bool {
        self.shard_index >= data_shards as u32
    }

    /// Encode this packet into wire-format bytes for UDP transmission.
    ///
    /// Layout: `[header 24B] [data N bytes]`
    /// Note: checksum is embedded in the header, not appended as trailer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.total_packets.to_be_bytes());
        buf.extend_from_slice(&self.shard_index.to_be_bytes());
        buf.extend_from_slice(&self.total_shards.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode a raw byte buffer into a validated [`FecPacket`].
    ///
    /// Performs minimum size validation but does NOT verify the checksum.
    /// Call [`verify()`](Self::verify) separately for integrity checking.
    ///
    /// # Arguments
    /// * `bytes` - Raw packet data received from UDP socket.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Protocol`] if the buffer is too short for the header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(MisogiError::Protocol(format!(
                "FecPacket too short: {} bytes (minimum {})",
                bytes.len(),
                Self::HEADER_SIZE,
            )));
        }

        let sequence = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let total_packets = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let shard_index = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let total_shards = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let data_len = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let checksum = u32::from_be_bytes(bytes[20..24].try_into().unwrap());

        let data_start = Self::HEADER_SIZE;
        let data_end = data_start + data_len;

        if bytes.len() < data_end {
            return Err(MisogiError::Protocol(format!(
                "FecPacket truncated: declared data_len={} but only {} bytes remain",
                data_len,
                bytes.len() - data_start,
            )));
        }

        let data = Bytes::copy_from_slice(&bytes[data_start..data_end]);

        Ok(Self {
            sequence,
            total_packets,
            shard_index,
            total_shards,
            data,
            checksum,
        })
    }
}

// =============================================================================
// Unit Tests — FecPacket wire format roundtrip and integrity
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_packet_new_computes_checksum() {
        let data = Bytes::from_static(b"hello world");
        let pkt = FecPacket::new(0, 10, 3, 20, data.clone());
        assert_eq!(pkt.sequence, 0);
        assert_eq!(pkt.total_packets, 10);
        assert_eq!(pkt.shard_index, 3);
        assert_eq!(pkt.total_shards, 20);
        assert_eq!(pkt.data, data);
        assert_ne!(pkt.checksum, 0); // Non-zero CRC32
    }

    #[test]
    fn test_fec_packet_verify_intact() {
        let pkt = FecPacket::new(0, 10, 0, 8, Bytes::from_static(b"test data"));
        assert!(pkt.verify()); // Freshly created packet must verify
    }

    #[test]
    fn test_fec_packet_to_bytes_roundtrip() {
        let original = FecPacket::new(
            42, 100, 7, 16,
            Bytes::from_static(b"shard payload data here"),
        );
        let bytes = original.to_bytes();
        let decoded = FecPacket::from_bytes(&bytes).expect("Roundtrip decode");

        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.total_packets, 100);
        assert_eq!(decoded.shard_index, 7);
        assert_eq!(decoded.total_shards, 16);
        assert_eq!(decoded.data, original.data);
        assert_eq!(decoded.checksum, original.checksum);
    }

    #[test]
    fn test_fec_packet_too_short_rejected() {
        let result = FecPacket::from_bytes(&[0u8; 10]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_fec_packet_is_parity_detection() {
        let data_pkt = FecPacket::new(0, 20, 3, 20, Bytes::new());
        let parity_pkt = FecPacket::new(8, 20, 11, 20, Bytes::new());

        assert!(!data_pkt.is_parity(8)); // index 3 < 8 data shards
        assert!(parity_pkt.is_parity(8)); // index 11 >= 8 data shards
    }

    #[test]
    fn test_fec_packet_max_size_payload() {
        let large_data = vec![0xFF_u8; 60000];
        let pkt = FecPacket::new(0, 1, 0, 1, Bytes::from(large_data.clone()));
        let bytes = pkt.to_bytes();
        let decoded = FecPacket::from_bytes(&bytes).expect("Large payload roundtrip");
        assert_eq!(decoded.data.len(), 60000);
    }
}
