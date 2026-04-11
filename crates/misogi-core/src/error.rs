use thiserror::Error;

#[derive(Error, Debug)]
pub enum MisogiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("File not found: {0}")]
    NotFound(String),

    #[error("File already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),

    #[error("Chunk missing: file_id={file_id}, chunk_index={chunk_index}")]
    ChunkMissing {
        file_id: String,
        chunk_index: u32,
    },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Poison error: {0}")]
    PoisonError(String),

    #[error("Configuration error: {0}")]
    Configuration(String),
}

pub type Result<T> = std::result::Result<T, MisogiError>;
