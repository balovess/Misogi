use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use crate::error::{MisogiError, Result};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Handshake = 0x01,
    ChunkData = 0x02,
    ChunkAck = 0x03,
    FileComplete = 0x04,
    Heartbeat = 0x05,
    HandshakeAck = 0x06,
}

impl TryFrom<u8> for FrameType {
    type Error = MisogiError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(FrameType::Handshake),
            0x02 => Ok(FrameType::ChunkData),
            0x03 => Ok(FrameType::ChunkAck),
            0x04 => Ok(FrameType::FileComplete),
            0x05 => Ok(FrameType::Heartbeat),
            0x06 => Ok(FrameType::HandshakeAck),
            _ => Err(MisogiError::InvalidFrameType(value)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolFrame {
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

impl ProtocolFrame {
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self { frame_type, payload }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let total_len = 1 + self.payload.len() as u32;
        buf.put_u32(total_len);
        buf.put_u8(self.frame_type as u8);
        buf.put_slice(&self.payload);
        buf
    }

    pub fn decode(data: &Bytes) -> Result<Self> {
        if data.len() < 5 {
            return Err(MisogiError::Protocol(
                "Frame too short".to_string(),
            ));
        }

        let mut cursor = data.clone();
        let total_len = cursor.get_u32() as usize;

        if data.len() < 4 + total_len {
            return Err(MisogiError::Protocol(
                "Incomplete frame".to_string(),
            ));
        }

        let frame_type_byte = cursor.get_u8();
        let frame_type = FrameType::try_from(frame_type_byte)?;
        let payload_len = total_len - 1;
        let payload = cursor.copy_to_bytes(payload_len).to_vec();

        Ok(ProtocolFrame { frame_type, payload })
    }

    pub async fn decode_from_stream<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        len_buf: &[u8; 4],
    ) -> Result<Self> {
        let len = u32::from_be_bytes(*len_buf) as usize;

        if len == 0 {
            return Err(MisogiError::Protocol("Zero length frame".to_string()));
        }

        let mut type_byte = [0u8; 1];
        reader.read_exact(&mut type_byte).await?;
        let frame_type = FrameType::try_from(type_byte[0])?;

        let payload_len = len.saturating_sub(1);
        let mut payload = vec![0u8; payload_len];

        if payload_len > 0 {
            reader.read_exact(&mut payload).await?;
        }

        Ok(Self { frame_type, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode_roundtrip() {
        let original = ProtocolFrame::new(
            FrameType::Handshake,
            b"test_payload".to_vec(),
        );

        let encoded = original.encode();
        let decoded = ProtocolFrame::decode(&encoded.freeze()).unwrap();

        assert_eq!(decoded.frame_type, original.frame_type);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn test_all_frame_types() {
        let frame_types = vec![
            FrameType::Handshake,
            FrameType::ChunkData,
            FrameType::ChunkAck,
            FrameType::FileComplete,
            FrameType::Heartbeat,
            FrameType::HandshakeAck,
        ];

        for frame_type in frame_types {
            let frame = ProtocolFrame::new(frame_type, b"data".to_vec());
            let encoded = frame.encode();
            let decoded = ProtocolFrame::decode(&encoded.freeze()).unwrap();

            assert_eq!(decoded.frame_type, frame_type);
            assert_eq!(decoded.payload, b"data");
        }
    }

    #[test]
    fn test_empty_payload() {
        let frame = ProtocolFrame::new(FrameType::Heartbeat, vec![]);
        let encoded = frame.encode();
        let decoded = ProtocolFrame::decode(&encoded.freeze()).unwrap();

        assert_eq!(decoded.frame_type, FrameType::Heartbeat);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let large_payload = vec![0xAB; 1024 * 1024];
        let frame = ProtocolFrame::new(FrameType::ChunkData, large_payload.clone());
        let encoded = frame.encode();
        let decoded = ProtocolFrame::decode(&encoded.freeze()).unwrap();

        assert_eq!(decoded.frame_type, FrameType::ChunkData);
        assert_eq!(decoded.payload.len(), large_payload.len());
        assert_eq!(decoded.payload, large_payload);
    }

    #[test]
    fn test_invalid_frame_type() {
        let result = FrameType::try_from(0xFF);
        assert!(result.is_err());

        match result.unwrap_err() {
            MisogiError::InvalidFrameType(v) => assert_eq!(v, 0xFF),
            _ => panic!("Expected InvalidFrameType error"),
        }
    }

    #[test]
    fn test_file_info_serialization() {
        use crate::types::{FileInfo, FileStatus};
        
        let info = FileInfo {
            file_id: "file-123".to_string(),
            filename: "test.txt".to_string(),
            total_size: 1024,
            chunk_count: 4,
            file_md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            status: FileStatus::Uploading,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let decoded: FileInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(info.file_id, decoded.file_id);
        assert_eq!(info.filename, decoded.filename);
        assert_eq!(info.status, decoded.status);
    }

    #[test]
    fn test_chunk_meta_serialization() {
        use crate::types::ChunkMeta;
        
        let chunk = ChunkMeta {
            file_id: "file-123".to_string(),
            chunk_index: 0,
            chunk_md5: "abc123".to_string(),
            size: 256,
        };

        let json = serde_json::to_string(&chunk).unwrap();
        let decoded: ChunkMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(chunk.file_id, decoded.file_id);
        assert_eq!(chunk.chunk_index, decoded.chunk_index);
    }

    #[test]
    fn test_manifest_serialization() {
        use crate::types::*;
        
        let manifest = FileManifest {
            file_id: "file-456".to_string(),
            filename: "large_file.bin".to_string(),
            total_size: 1048576,
            chunk_count: 16,
            file_md5: "hash123".to_string(),
            chunks: vec![
                ChunkMeta {
                    file_id: "file-456".to_string(),
                    chunk_index: 0,
                    chunk_md5: "chunk0_hash".to_string(),
                    size: 65536,
                },
                ChunkMeta {
                    file_id: "file-456".to_string(),
                    chunk_index: 1,
                    chunk_md5: "chunk1_hash".to_string(),
                    size: 65536,
                },
            ],
            status: FileStatus::Transferring,
            created_at: "2024-02-15T12:30:00Z".to_string(),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: FileManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.file_id, decoded.file_id);
        assert_eq!(manifest.chunks.len(), decoded.chunks.len());
        assert_eq!(manifest.status, decoded.status);
    }

    #[test]
    fn test_compute_md5() {
        use crate::hash::compute_md5;
        
        let data = b"hello world";
        let hash = compute_md5(data);

        assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }
}
