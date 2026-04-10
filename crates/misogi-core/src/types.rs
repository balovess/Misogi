use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    Uploading,
    Transferring,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub file_id: String,
    pub filename: String,
    pub total_size: u64,
    pub chunk_count: u32,
    pub file_md5: String,
    pub status: FileStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub file_id: String,
    pub chunk_index: u32,
    pub chunk_md5: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub file_id: String,
    pub filename: String,
    pub total_size: u64,
    pub chunk_count: u32,
    pub file_md5: String,
    pub chunks: Vec<ChunkMeta>,
    pub status: FileStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub version: String,
    pub node_id: String,
    pub node_role: String,
}
