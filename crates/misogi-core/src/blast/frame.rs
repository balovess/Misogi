//! UDP Blast frame format for air-gap / data-diode transmission.
//!
//! Unlike the TCP-based [`ProtocolFrame`](crate::protocol::ProtocolFrame) which
//! requires bidirectional ACKs, UDP Blast frames are designed for pure one-way
//! transmission:
//!
//! - No handshake required
//! - No ACK expected or possible
//! - No flow control (sender fires at will)
//! - No connection state on either side
//!
//! # Wire Format (per UDP datagram)
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │ Magic: 4 bytes ("MBLT")                                  │
//! │ Version: 1 byte (0x01)                                    │
//! │ Flags: 1 byte                                             │
//! │   Bit 0: IsParityShard (FEC parity vs data)               │
//! │   Bit 1: IsManifest (file metadata, last packet)          │
//! │   Bit 2: IsEofMarker (end of transmission marker)          │
//! │ SessionId: 16 bytes (UUID, big-endian)                   │
//! │ FileId: 16 bytes (UUID, big-endian)                      │
//! │ ShardIndex: 4 bytes (uint32 BE)                          │
//! │ TotalShards: 4 bytes (uint32 BE, 0 if unknown)            │
//! │ ShardData: variable length (up to MTU - header)          │
//! │ CRC32: 4 bytes (covering all above fields)               │
//! └────────────────────────────────────────────────────────────┘
//! Total header: 55 bytes | Payload: ≤ (MTU - 59) | Trailer: 4 bytes
//! ```

use crate::fec::FecConfig;
use crate::error::{MisogiError, Result};

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol magic bytes identifying Misogi Blast packets.
///
/// Chosen to be visually distinct from common protocols and easily
/// identifiable in packet captures (e.g., Wireshark).
pub const BLAST_MAGIC: &[u8; 4] = b"MBLT";

/// Current protocol version.
pub const BLAST_VERSION: u8 = 0x01;

/// Size of the fixed header portion (magic + version + flags + session + file + indices).
///
/// Layout breakdown:
/// - magic:      4 bytes  (offset  0)
/// - version:    1 byte   (offset  4)
/// - flags:      1 byte   (offset  5)
/// - session_id: 16 bytes (offset  6)
/// - file_id:    16 bytes (offset 22)
/// - shard_index:4 bytes  (offset 38)
/// - total_shards:4 bytes (offset 42)
pub const BLAST_HEADER_SIZE: usize = 46;

/// Size of the CRC32 trailer appended after payload.
pub const BLAST_TRAILER_SIZE: usize = 4;

/// Minimum total frame size (header + zero-length payload + CRC trailer).
pub const BLAST_MIN_FRAME_SIZE: usize = BLAST_HEADER_SIZE + BLAST_TRAILER_SIZE;

bitflags! {
    /// Flag bits within the Blast header flags byte.
    ///
    /// Multiple flags can be combined (e.g., a manifest packet may also be EOF).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlastFlags: u8 {
        /// This shard is an FEC parity shard (not original data).
        ///
        /// When clear, the shard is a data shard. The receiver uses this
        /// to classify incoming shards before FEC decoding.
        const IS_PARITY_SHARD = 0x01;

        /// This packet carries a [`BlastManifest`] payload.
        ///
        /// Manifest packets contain file metadata (filename, size, MD5)
        /// needed for the receiver to validate the reconstructed file.
        /// Sent after all data/parity shards.
        const IS_MANIFEST = 0x02;

        /// This packet is an end-of-transmission (EOF) marker.
        ///
        /// Signals to the receiver that no more shards are coming for
        /// this session. The receiver should attempt decode immediately.
        /// Multiple EOF markers are sent for redundancy.
        const IS_EOF_MARKER = 0x04;
    }
}

impl Default for BlastFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// Fixed-size header preceding every UDP Blast datagram.
///
/// Layout (55 bytes total):
/// ```text
/// Offset  Size   Field
/// ------  ----   -----
/// 0       4      magic     ("MBLT")
/// 4       1      version   (0x01)
/// 5       1      flags     (BlastFlags bitmask)
/// 6       16     session_id (UUID big-endian)
/// 22      16     file_id   (UUID big-endian)
/// 38      4      shard_index (uint32 BE)
/// 42      4      total_shards (uint32 BE)
/// ```
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BlastHeader {
    /// Magic bytes: always `b"MBLT"`.
    pub magic: [u8; 4],

    /// Protocol version (must equal [`BLAST_VERSION`]).
    pub version: u8,

    /// Semantic flags for this packet.
    pub flags: BlastFlags,

    /// Unique session identifier (UUID v4, big-endian bytes).
    ///
    /// Groups all packets belonging to a single file transfer.
    /// Different files transferred in sequence use different session IDs.
    pub session_id: [u8; 16],

    /// File identifier within this session (UUID v4, big-endian bytes).
    ///
    /// Allows multiplexing multiple files over a single session.
    pub file_id: [u8; 16],

    /// Index of this shard within the encoding block (0-based).
    ///
    /// For data shards: 0 .. data_shards-1
    /// For parity shards: data_shards .. total_shards-1
    pub shard_index: u32,

    /// Total number of shards in this encoding block.
    ///
    /// Set to 0 if unknown at send time (e.g., first packet sent before
    /// encoding completes). Receiver learns this from the manifest.
    pub total_shards: u32,
}

impl Default for BlastHeader {
    fn default() -> Self {
        Self {
            magic: *BLAST_MAGIC,
            version: BLAST_VERSION,
            flags: BlastFlags::empty(),
            session_id: [0u8; 16],
            file_id: [0u8; 16],
            shard_index: 0,
            total_shards: 0,
        }
    }
}

/// A complete UDP Blast packet: header + variable payload + CRC32 trailer.
///
/// This is the atomic unit of transmission — each `BlastPacket` maps to
/// exactly one UDP datagram on the wire.
#[derive(Debug, Clone)]
pub struct BlastPacket {
    /// Fixed-size header with routing and classification information.
    pub header: BlastHeader,

    /// Variable-length payload (shard data or manifest JSON).
    ///
    /// For data/parity shards: raw FEC-encoded bytes (`shard_size` long).
    /// For manifest packets: serialized [`BlastManifest`] JSON.
    /// For EOF markers: empty.
    pub payload: Vec<u8>,

    /// CRC-32 checksum covering header + payload (4 bytes, big-endian).
    ///
    /// Computed using IEEE polynomial (same as zlib/ethernet FCS).
    /// Validated by the receiver before accepting any packet.
    pub crc32: u32,
}

impl BlastPacket {
    /// Encode this packet into wire-format bytes ready for UDP transmission.
    ///
    /// Layout: `[header 55B] [payload N bytes] [crc32 4B]`
    ///
    /// Total size = `BLAST_HEADER_SIZE + payload.len() + BLAST_TRAILER_SIZE`
    ///
    /// # Returns
    ///
    /// A `BytesMut` buffer containing the complete on-wire representation.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(
            BLAST_HEADER_SIZE + self.payload.len() + BLAST_TRAILER_SIZE,
        );

        // Header
        buf.put_slice(&self.header.magic);
        buf.put_u8(self.header.version);
        buf.put_u8(self.header.flags.bits());
        buf.put_slice(&self.header.session_id);
        buf.put_slice(&self.header.file_id);
        buf.put_u32(self.header.shard_index);
        buf.put_u32(self.header.total_shards);

        // Payload
        buf.put_slice(&self.payload);

        // CRC32 trailer (computed over header + payload only)
        let crc = crc32fast::hash(&buf);
        buf.put_u32(crc);

        buf
    }

    /// Decode a raw UDP datagram into a validated [`BlastPacket`].
    ///
    /// Performs the following validations in order:
    /// 1. Minimum size check (>= `BLAST_MIN_FRAME_SIZE`)
    /// 2. Magic bytes verification (`b"MBLT"`)
    /// 3. Version compatibility check (= `BLAST_VERSION`)
    /// 4. CRC32 integrity check
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes received from a UDP socket.
    ///
    /// # Errors
    ///
    /// - [`MisogiError::Protocol`] if any validation fails.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < BLAST_MIN_FRAME_SIZE {
            return Err(MisogiError::Protocol(format!(
                "Blast packet too short: {} bytes (minimum {})",
                data.len(),
                BLAST_MIN_FRAME_SIZE
            )));
        }

        // Verify magic
        if &data[0..4] != BLAST_MAGIC {
            return Err(MisogiError::Protocol(format!(
                "Invalid magic: {:?} (expected MBLT)",
                &data[0..4]
            )));
        }

        // Verify version
        let version = data[4];
        if version != BLAST_VERSION {
            return Err(MisogiError::Protocol(format!(
                "Unsupported version: {} (expected {})",
                version, BLAST_VERSION
            )));
        }

        // Extract header fields
        let flags = BlastFlags::from_bits_truncate(data[5]);
        let session_id: [u8; 16] = data[6..22].try_into().map_err(|_| {
            MisogiError::Protocol("Failed to extract session_id".to_string())
        })?;
        let file_id: [u8; 16] = data[22..38].try_into().map_err(|_| {
            MisogiError::Protocol("Failed to extract file_id".to_string())
        })?;
        let shard_index = u32::from_be_bytes(data[38..42].try_into().unwrap());
        let total_shards = u32::from_be_bytes(data[42..46].try_into().unwrap());

        let header = BlastHeader {
            magic: *BLAST_MAGIC,
            version,
            flags,
            session_id,
            file_id,
            shard_index,
            total_shards,
        };

        // Extract payload (everything between header and trailing CRC32)
        let payload_start = BLAST_HEADER_SIZE;
        let payload_end = data.len() - BLAST_TRAILER_SIZE;
        let payload = data[payload_start..payload_end].to_vec();

        // Verify CRC32
        let stored_crc = u32::from_be_bytes(
            data[payload_end..].try_into().map_err(|_| {
                MisogiError::Protocol("Failed to extract CRC32".to_string())
            })?,
        );
        let computed_crc = crc32fast::hash(&data[..payload_end]);
        if stored_crc != computed_crc {
            return Err(MisogiError::Protocol(format!(
                "CRC32 mismatch: stored=0x{:08X}, computed=0x{:08X}",
                stored_crc, computed_crc
            )));
        }

        Ok(Self {
            header,
            payload,
            crc32: stored_crc,
        })
    }

    /// Create a data shard packet.
    ///
    /// # Arguments
    /// * `session_id` - Session UUID string (e.g., "a1b2c3d4-...").
    /// * `file_id` - File UUID string.
    /// * `index` - Logical shard index.
    /// * `total` - Total shards in block.
    /// * `data` - Shard payload bytes.
    pub fn data_shard(
        session_id: &str,
        file_id: &str,
        index: u32,
        total: u32,
        data: &[u8],
    ) -> Self {
        Self::build_packet(session_id, file_id, index, total, data, BlastFlags::empty())
    }

    /// Create a parity shard packet.
    ///
    /// Same as [`data_shard`](Self::data_shard) but sets the `IS_PARITY_SHARD` flag.
    pub fn parity_shard(
        session_id: &str,
        file_id: &str,
        index: u32,
        total: u32,
        data: &[u8],
    ) -> Self {
        Self::build_packet(
            session_id,
            file_id,
            index,
            total,
            data,
            BlastFlags::IS_PARITY_SHARD,
        )
    }

    /// Create a manifest packet carrying file metadata.
    ///
    /// The manifest is serialized as JSON into the payload field.
    /// Sent after all data/parity shards, repeated for redundancy.
    pub fn manifest(session_id: &str, file_id: &str, metadata: &BlastManifest) -> Result<Self> {
        let payload =
            serde_json::to_vec(metadata).map_err(|e| MisogiError::Protocol(format!("Manifest serialization failed: {}", e)))?;

        let mut pkt = Self::build_packet(
            session_id,
            file_id,
            0,
            0,
            &payload,
            BlastFlags::IS_MANIFEST,
        );
        pkt.crc32 = crc32fast::hash(&(pkt.encode()[..pkt.encode().len() - 4]));
        Ok(pkt)
    }

    /// Create an EOF (end-of-transmission) marker packet.
    ///
    /// Has empty payload. Sent multiple times to ensure delivery.
    pub fn eof_marker(session_id: &str) -> Self {
        Self::build_packet(
            session_id,
            "",
            0,
            0,
            &[],
            BlastFlags::IS_EOF_MARKER,
        )
    }

    /// Internal builder for all packet types.
    fn build_packet(
        session_id: &str,
        file_id: &str,
        index: u32,
        total: u32,
        data: &[u8],
        flags: BlastFlags,
    ) -> Self {
        let session_uuid = Uuid::parse_str(session_id).unwrap_or(Uuid::nil());
        let file_uuid = Uuid::parse_str(file_id).unwrap_or(Uuid::nil());

        let header = BlastHeader {
            magic: *BLAST_MAGIC,
            version: BLAST_VERSION,
            flags,
            session_id: session_uuid.as_bytes().to_vec().try_into().unwrap(),
            file_id: file_uuid.as_bytes().to_vec().try_into().unwrap(),
            shard_index: index,
            total_shards: total,
        };

        let full = [&header.magic, &[header.version][..], &[header.flags.bits()],
            &header.session_id, &header.file_id,
            &index.to_be_bytes(), &total.to_be_bytes(), data]
            .concat();
        let crc = crc32fast::hash(&full);

        Self {
            header,
            payload: data.to_vec(),
            crc32: crc,
        }
    }

    /// Returns the total on-wire size of this packet in bytes.
    pub fn wire_size(&self) -> usize {
        BLAST_HEADER_SIZE + self.payload.len() + BLAST_TRAILER_SIZE
    }

    /// Returns true if this packet is a parity (redundancy) shard.
    pub fn is_parity(&self) -> bool {
        self.header.flags.contains(BlastFlags::IS_PARITY_SHARD)
    }

    /// Returns true if this packet carries a manifest.
    pub fn is_manifest(&self) -> bool {
        self.header.flags.contains(BlastFlags::IS_MANIFEST)
    }

    /// Returns true if this is an EOF marker.
    pub fn is_eof(&self) -> bool {
        self.header.flags.contains(BlastFlags::IS_EOF_MARKER)
    }
}

/// File metadata carried in manifest packets.
///
/// Serialized as JSON and transmitted after all data/parity shards.
/// The receiver uses this to validate reconstructed file integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastManifest {
    /// Original filename (without path).
    pub filename: String,

    /// Original file size in bytes.
    pub original_size: u64,

    /// MD5 hash of the original (pre-FEC) file content.
    ///
    /// Base16-encoded lowercase string (32 characters).
    pub original_md5: String,

    /// FEC configuration used for encoding (needed for decoding setup).
    pub fec_config: FecConfigInfo,

    /// Unix timestamp (milliseconds) when transmission started.
    pub timestamp_ms: u64,
}

/// Serializable subset of [`FecConfig`] for wire transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecConfigInfo {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
}

impl From<&FecConfig> for FecConfigInfo {
    fn from(config: &FecConfig) -> Self {
        Self {
            data_shards: config.data_shards,
            parity_shards: config.parity_shards,
            shard_size: config.shard_size,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_shard_encode_decode_roundtrip() {
        let original = BlastPacket::data_shard(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "f1e2d3c4-b5a6-7890-1234-567890abcdef",
            5,
            20,
            b"Hello, Blast!",
        );

        assert!(!original.is_parity());
        assert!(!original.is_manifest());
        assert!(!original.is_eof());
        assert_eq!(original.header.shard_index, 5);
        assert_eq!(original.header.total_shards, 20);

        let encoded = original.encode();
        let decoded = BlastPacket::decode(&encoded).expect("Decode should succeed");

        assert_eq!(decoded.header.shard_index, 5);
        assert_eq!(decoded.header.total_shards, 20);
        assert_eq!(decoded.payload, b"Hello, Blast!");
        assert!(!decoded.is_parity());
    }

    #[test]
    fn test_parity_shard_flag_set() {
        let pkt = BlastPacket::parity_shard("sess", "file", 18, 20, b"parity_data");
        assert!(pkt.is_parity());
        assert!(!pkt.is_manifest());
    }

    #[test]
    fn test_eof_marker_has_no_payload() {
        let pkt = BlastPacket::eof_marker("sess-id");
        assert!(pkt.is_eof());
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn test_manifest_serialization() {
        let manifest = BlastManifest {
            filename: "secret_document.pdf".to_string(),
            original_size: 1048576,
            original_md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            fec_config: FecConfigInfo {
                data_shards: 16,
                parity_shards: 4,
                shard_size: 1400,
            },
            timestamp_ms: 1700000000000,
        };

        let pkt = BlastPacket::manifest("sess", "file", &manifest).expect("Manifest encode");
        assert!(pkt.is_manifest());

        let decoded_manifest: BlastManifest =
            serde_json::from_slice(&pkt.payload).expect("Manifest decode");
        assert_eq!(decoded_manifest.filename, "secret_document.pdf");
        assert_eq!(decoded_manifest.original_size, 1048576);
        assert_eq!(decoded_manifest.fec_config.data_shards, 16);
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut bad_data = vec![0u8; BLAST_MIN_FRAME_SIZE];
        bad_data[0..4].copy_from_slice(b"XXXX");
        let result = BlastPacket::decode(&bad_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_version_rejected() {
        let mut bad_data = vec![0u8; BLAST_MIN_FRAME_SIZE];
        bad_data[0..4].copy_from_slice(b"MBLT");
        bad_data[4] = 0xFF;
        let result = BlastPacket::decode(&bad_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_crc_mismatch_rejected() {
        let valid = BlastPacket::data_shard("s", "f", 0, 1, b"test");
        let mut encoded = valid.encode();
        let len = encoded.len();
        encoded[len - 1] ^= 0xFF;

        let result = BlastPacket::decode(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRC"));
    }

    #[test]
    fn test_too_short_rejected() {
        let result = BlastPacket::decode(&[0u8; 10]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_wire_size_calculation() {
        let pkt = BlastPacket::data_shard("s", "f", 0, 1, b"data");
        assert_eq!(
            pkt.wire_size(),
            BLAST_HEADER_SIZE + 4 + BLAST_TRAILER_SIZE
        );
    }

    #[test]
    fn test_empty_payload_packet() {
        let pkt = BlastPacket::eof_marker("session-uuid");
        let encoded = pkt.encode();
        let decoded = BlastPacket::decode(&encoded).expect("EOF roundtrip");
        assert!(decoded.is_eof());
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_large_payload_within_mtu() {
        let large_payload = vec![0xAB; 1400];
        let pkt = BlastPacket::data_shard("s", "f", 10, 20, &large_payload);
        assert_eq!(pkt.payload.len(), 1400);

        let encoded = pkt.encode();
        let decoded = BlastPacket::decode(&encoded).expect("Large payload roundtrip");
        assert_eq!(decoded.payload.len(), 1400);
        assert_eq!(decoded.header.shard_index, 10);
    }

    #[test]
    fn test_fec_config_info_conversion() {
        use crate::fec::FecConfig;
        let config = FecConfig::high_reliability();
        let info = FecConfigInfo::from(&config);
        assert_eq!(info.data_shards, 16);
        assert_eq!(info.parity_shards, 8);
    }

    #[test]
    fn test_blast_flags_combinations() {
        assert!(!BlastFlags::empty().intersects(BlastFlags::IS_PARITY_SHARD));
        assert!(BlastFlags::IS_PARITY_SHARD.contains(BlastFlags::IS_PARITY_SHARD));

        let combined = BlastFlags::IS_MANIFEST | BlastFlags::IS_EOF_MARKER;
        assert!(combined.contains(BlastFlags::IS_MANIFEST));
        assert!(combined.contains(BlastFlags::IS_EOF_MARKER));
        assert!(!combined.contains(BlastFlags::IS_PARITY_SHARD));
    }
}
