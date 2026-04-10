use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::SenderConfig;
use crate::upload_engine::FileUploader;
use misogi_core::{FileInfo, FileStatus};

pub struct AppState {
    pub config: SenderConfig,
    pub files: RwLock<Vec<FileInfo>>,
    pub uploader: FileUploader,
}

impl AppState {
    pub fn new(config: SenderConfig) -> Self {
        let uploader = FileUploader::new(&config.storage_dir, config.chunk_size);
        Self {
            config,
            files: RwLock::new(Vec::new()),
            uploader,
        }
    }

    pub async fn add_file(&self, file_info: FileInfo) {
        let mut files = self.files.write().await;
        files.push(file_info);
    }

    pub async fn get_file(&self, file_id: &str) -> Option<FileInfo> {
        let files = self.files.read().await;
        files.iter().find(|f| f.file_id == file_id).cloned()
    }

    pub async fn update_file_status(&self, file_id: &str, status: FileStatus) -> bool {
        let mut files = self.files.write().await;
        if let Some(file) = files.iter_mut().find(|f| f.file_id == file_id) {
            file.status = status;
            true
        } else {
            false
        }
    }

    pub async fn list_files(
        &self,
        status_filter: Option<&FileStatus>,
    ) -> Vec<FileInfo> {
        let files = self.files.read().await;
        if let Some(filter) = status_filter {
            files.iter()
                .filter(|f| &f.status == filter)
                .cloned()
                .collect()
        } else {
            files.clone()
        }
    }
}

pub type SharedState = Arc<AppState>;
