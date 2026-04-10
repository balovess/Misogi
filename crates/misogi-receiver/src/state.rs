use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::ReceiverConfig;
use crate::storage::ChunkStorage;
use misogi_core::FileInfo;

pub struct AppState {
    pub config: ReceiverConfig,
    pub files: RwLock<Vec<FileInfo>>,
    pub storage: ChunkStorage,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(config: ReceiverConfig) -> Self {
        let storage = ChunkStorage::new(&config.storage_dir, &config.download_dir);
        Self {
            config,
            files: RwLock::new(Vec::new()),
            storage,
        }
    }
}
