use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use crate::state::SharedState;
use misogi_core::{ChunkMeta, FileManifest, FileInfo, FileStatus, MisogiError, Result};

pub struct FileUploader {
    storage_dir: PathBuf,
    chunk_size: usize,
}

impl FileUploader {
    pub fn new(storage_dir: &str, chunk_size: usize) -> Self {
        Self {
            storage_dir: PathBuf::from(storage_dir),
            chunk_size,
        }
    }

    pub async fn create_session(
        &self,
        filename: String,
        state: &SharedState,
    ) -> Result<(String, FileManifest)> {
        let file_id = uuid::Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().to_rfc3339();

        let file_dir = self.storage_dir.join(&file_id);
        tokio::fs::create_dir_all(&file_dir).await?;

        let manifest = FileManifest {
            file_id: file_id.clone(),
            filename,
            total_size: 0,
            chunk_count: 0,
            file_md5: String::new(),
            chunks: Vec::new(),
            status: FileStatus::Uploading,
            created_at: created_at.clone(),
        };

        self.save_manifest(&file_id, &manifest).await?;

        let file_info = FileInfo {
            file_id: file_id.clone(),
            filename: manifest.filename.clone(),
            total_size: 0,
            chunk_count: 0,
            file_md5: String::new(),
            status: FileStatus::Uploading,
            created_at,
        };

        state.add_file(file_info).await;

        Ok((file_id, manifest))
    }

    pub async fn write_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: &[u8],
    ) -> Result<ChunkMeta> {
        let chunk_md5 = misogi_core::hash::compute_md5(data);

        let chunk_path = self.storage_dir
            .join(file_id)
            .join(format!("chunk_{}.bin", chunk_index));

        let mut file = tokio::fs::File::create(&chunk_path).await?;
        file.write_all(data).await?;
        file.flush().await?;
        drop(file);

        let chunk_meta = ChunkMeta {
            file_id: file_id.to_string(),
            chunk_index,
            chunk_md5,
            size: data.len() as u64,
        };

        let mut manifest = self.load_manifest(file_id).await?;
        manifest.chunks.push(chunk_meta.clone());
        manifest.total_size += data.len() as u64;
        manifest.chunk_count = manifest.chunks.len() as u32;

        self.save_manifest(file_id, &manifest).await?;

        Ok(chunk_meta)
    }

    pub fn storage_dir(&self) -> &std::path::Path {
        &self.storage_dir
    }

    pub async fn complete_upload(
        &self,
        file_id: &str,
        state: &SharedState,
    ) -> Result<FileManifest> {
        let mut manifest = self.load_manifest(file_id).await?;

        use tokio::io::AsyncWriteExt;
        let file_dir = self.storage_dir.join(file_id);
        let temp_file_path = file_dir.join("_complete_temp.bin");
        let mut temp_file = tokio::fs::File::create(&temp_file_path).await?;

        for i in 0..manifest.chunk_count {
            let chunk_path = file_dir.join(format!("chunk_{}.bin", i));
            if !chunk_path.exists() {
                return Err(MisogiError::ChunkMissing {
                    file_id: file_id.to_string(),
                    chunk_index: i,
                });
            }
            let chunk_data = tokio::fs::read(&chunk_path).await?;
            temp_file.write_all(&chunk_data).await?;
        }
        temp_file.flush().await?;
        drop(temp_file);

        let file_md5 = misogi_core::hash::compute_file_md5(&temp_file_path).await?;

        tokio::fs::remove_file(&temp_file_path).await.ok();

        manifest.file_md5 = file_md5;
        manifest.status = FileStatus::Ready;

        self.save_manifest(file_id, &manifest).await?;

        state.update_file_status(file_id, FileStatus::Ready).await;

        Ok(manifest)
    }

    pub async fn check_resume(&self, file_id: &str) -> Result<Vec<u32>> {
        let manifest = self.load_manifest(file_id).await?;

        if manifest.status != FileStatus::Uploading {
            return Ok(Vec::new());
        }

        let mut missing_chunks = Vec::new();
        for i in 0..manifest.chunk_count {
            let chunk_path = self.storage_dir
                .join(file_id)
                .join(format!("chunk_{}.bin", i));

            if !chunk_path.exists() {
                missing_chunks.push(i);
            }
        }

        Ok(missing_chunks)
    }

    pub async fn get_file_info(&self, file_id: &str) -> Result<FileInfo> {
        let manifest = self.load_manifest(file_id).await?;

        let completed_chunks = if manifest.status == FileStatus::Uploading {
            let mut count = 0u32;
            for i in 0..manifest.chunk_count {
                let chunk_path = self.storage_dir
                    .join(file_id)
                    .join(format!("chunk_{}.bin", i));
                if chunk_path.exists() {
                    count += 1;
                }
            }
            count
        } else {
            manifest.chunk_count
        };

        Ok(FileInfo {
            file_id: manifest.file_id,
            filename: manifest.filename,
            total_size: manifest.total_size,
            chunk_count: manifest.chunk_count,
            file_md5: manifest.file_md5,
            status: manifest.status,
            created_at: manifest.created_at,
        })
    }

    pub async fn list_files(&self) -> Result<Vec<FileInfo>> {
        let mut files = Vec::new();

        if !self.storage_dir.exists() {
            return Ok(files);
        }

        let mut entries = tokio::fs::read_dir(&self.storage_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Some(file_id) = path.file_name()
                    .and_then(|n| n.to_str())
                {
                    match self.get_file_info(file_id).await {
                        Ok(info) => files.push(info),
                        Err(_) => continue,
                    }
                }
            }
        }

        Ok(files)
    }

    pub async fn read_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
    ) -> Result<Vec<u8>> {
        let chunk_path = self.storage_dir
            .join(file_id)
            .join(format!("chunk_{}.bin", chunk_index));

        if !chunk_path.exists() {
            return Err(MisogiError::ChunkMissing {
                file_id: file_id.to_string(),
                chunk_index,
            });
        }

        let data = tokio::fs::read(&chunk_path).await?;
        Ok(data)
    }

    async fn load_manifest(&self, file_id: &str) -> Result<FileManifest> {
        let manifest_path = self.storage_dir
            .join(file_id)
            .join("manifest.json");

        if !manifest_path.exists() {
            return Err(MisogiError::NotFound(format!(
                "File not found: {}",
                file_id
            )));
        }

        let content = tokio::fs::read_to_string(&manifest_path).await?;
        let manifest: FileManifest = serde_json::from_str(&content)?;

        Ok(manifest)
    }

    async fn save_manifest(&self, file_id: &str, manifest: &FileManifest) -> Result<()> {
        let manifest_path = self.storage_dir
            .join(file_id)
            .join("manifest.json");

        let content = serde_json::to_string_pretty(manifest)?;
        tokio::fs::write(&manifest_path, content).await?;

        Ok(())
    }

    fn get_file_path(&self, file_id: &str) -> Result<PathBuf> {
        let file_dir = self.storage_dir.join(file_id);
        if !file_dir.exists() {
            return Err(MisogiError::NotFound(format!(
                "File directory not found: {}",
                file_id
            )));
        }
        Ok(file_dir)
    }
}
