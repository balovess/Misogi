use std::path::PathBuf;
use misogi_core::{hash, MisogiError, Result, FileManifest, FileInfo, FileStatus};

pub struct ChunkStorage {
    storage_dir: PathBuf,
    download_dir: PathBuf,
}

impl ChunkStorage {
    pub fn new(storage_dir: &str, download_dir: &str) -> Self {
        let storage_path = PathBuf::from(storage_dir);
        let download_path = PathBuf::from(download_dir);

        std::fs::create_dir_all(&storage_path).expect("Failed to create storage directory");
        std::fs::create_dir_all(&download_path).expect("Failed to create download directory");

        Self {
            storage_dir: storage_path,
            download_dir: download_path,
        }
    }

    pub async fn save_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: &[u8],
        expected_md5: &str,
    ) -> Result<()> {
        let actual_md5 = hash::compute_md5(data);

        if actual_md5 != expected_md5 {
            return Err(MisogiError::HashMismatch {
                expected: expected_md5.to_string(),
                actual: actual_md5,
            });
        }

        let file_dir = self.storage_dir.join(file_id);
        tokio::fs::create_dir_all(&file_dir).await?;

        let chunk_path = file_dir.join(format!("chunk_{}.bin", chunk_index));
        tokio::fs::write(&chunk_path, data).await?;

        Ok(())
    }

    pub async fn check_complete(&self, file_id: &str, total_chunks: u32) -> Result<bool> {
        let file_dir = self.storage_dir.join(file_id);

        if !file_dir.exists() {
            return Ok(false);
        }

        let mut existing_chunks = 0;
        let mut entries = tokio::fs::read_dir(&file_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with("chunk_") && name_str.ends_with(".bin") {
                    existing_chunks += 1;
                }
            }
        }

        Ok(existing_chunks >= total_chunks)
    }

    pub async fn reassemble_file(
        &self,
        file_id: &str,
        filename: &str,
        expected_md5: &str,
    ) -> Result<String> {
        let manifest_path = self.storage_dir.join(file_id).join("manifest.json");
        let manifest_content = tokio::fs::read_to_string(&manifest_path).await?;
        let manifest: FileManifest = serde_json::from_str(&manifest_content)?;

        for i in 0..manifest.chunk_count {
            let chunk_path = self.storage_dir.join(file_id).join(format!("chunk_{}.bin", i));
            if !chunk_path.exists() {
                return Err(MisogiError::ChunkMissing {
                    file_id: file_id.to_string(),
                    chunk_index: i,
                });
            }
        }

        let output_dir = self.download_dir.join(file_id);
        tokio::fs::create_dir_all(&output_dir).await?;

        let output_path = output_dir.join(filename);
        let mut output_file = tokio::fs::File::create(&output_path).await?;

        for i in 0..manifest.chunk_count {
            let chunk_path = self.storage_dir.join(file_id).join(format!("chunk_{}.bin", i));
            let chunk_data = tokio::fs::read(&chunk_path).await?;
            tokio::io::AsyncWriteExt::write_all(&mut output_file, &chunk_data).await?;
        }

        drop(output_file);

        let actual_md5 = hash::compute_file_md5(&output_path).await?;

        if actual_md5 != expected_md5 {
            tokio::fs::remove_file(&output_path).await.ok();
            return Err(MisogiError::HashMismatch {
                expected: expected_md5.to_string(),
                actual: actual_md5,
            });
        }

        let path_str = output_path.to_string_lossy().to_string();
        Ok(path_str)
    }

    pub fn get_download_path(&self, file_id: &str, filename: &str) -> PathBuf {
        self.download_dir.join(file_id).join(filename)
    }

    pub async fn list_ready_files(&self) -> Result<Vec<FileInfo>> {
        let mut files = Vec::new();

        if !self.download_dir.exists() {
            return Ok(files);
        }

        let mut entries = tokio::fs::read_dir(&self.download_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Some(file_id) = path.file_name().and_then(|n| n.to_str()) {
                    let manifest_path = self.storage_dir.join(file_id).join("manifest.json");
                    if manifest_path.exists() {
                        let content = tokio::fs::read_to_string(&manifest_path).await?;
                        if let Ok(manifest) = serde_json::from_str::<FileManifest>(&content) {
                            files.push(FileInfo {
                                file_id: manifest.file_id.clone(),
                                filename: manifest.filename.clone(),
                                total_size: manifest.total_size,
                                chunk_count: manifest.chunk_count,
                                file_md5: manifest.file_md5.clone(),
                                status: FileStatus::Ready,
                                created_at: manifest.created_at.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    pub async fn get_file_info(&self, file_id: &str) -> Result<Option<FileInfo>> {
        let manifest_path = self.storage_dir.join(file_id).join("manifest.json");

        if !manifest_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&manifest_path).await?;
        let manifest: FileManifest = serde_json::from_str(&content)?;

        let is_complete = self.check_complete(file_id, manifest.chunk_count).await?;
        let status = if is_complete {
            let download_path = self.get_download_path(file_id, &manifest.filename);
            if download_path.exists() {
                FileStatus::Ready
            } else {
                FileStatus::Transferring
            }
        } else {
            FileStatus::Transferring
        };

        Ok(Some(FileInfo {
            file_id: manifest.file_id,
            filename: manifest.filename,
            total_size: manifest.total_size,
            chunk_count: manifest.chunk_count,
            file_md5: manifest.file_md5,
            status,
            created_at: manifest.created_at,
        }))
    }

    #[allow(dead_code)]
    pub async fn read_chunk(&self, file_id: &str, chunk_index: u32) -> Result<Vec<u8>> {
        let chunk_path = self.storage_dir.join(file_id).join(format!("chunk_{}.bin", chunk_index));

        if !chunk_path.exists() {
            return Err(MisogiError::ChunkMissing {
                file_id: file_id.to_string(),
                chunk_index,
            });
        }

        let data = tokio::fs::read(&chunk_path).await?;
        Ok(data)
    }

    #[allow(dead_code)]
    pub async fn cleanup(&self, file_id: &str) -> Result<()> {
        let storage_path = self.storage_dir.join(file_id);
        let download_path = self.download_dir.join(file_id);

        if storage_path.exists() {
            tokio::fs::remove_dir_all(&storage_path).await?;
        }

        if download_path.exists() {
            tokio::fs::remove_dir_all(&download_path).await?;
        }

        Ok(())
    }

    pub async fn save_manifest(&self, manifest: &FileManifest) -> Result<()> {
        let file_dir = self.storage_dir.join(&manifest.file_id);
        tokio::fs::create_dir_all(&file_dir).await?;

        let manifest_path = file_dir.join("manifest.json");
        let content = serde_json::to_string_pretty(manifest)?;
        tokio::fs::write(manifest_path, content).await?;

        Ok(())
    }

    pub async fn get_manifest(&self, file_id: &str) -> Result<Option<FileManifest>> {
        let manifest_path = self.storage_dir.join(file_id).join("manifest.json");

        if !manifest_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&manifest_path).await?;
        let manifest: FileManifest = serde_json::from_str(&content)?;
        Ok(Some(manifest))
    }

    pub async fn update_manifest_status(&self, file_id: &str, status: FileStatus) -> Result<()> {
        let manifest = match self.get_manifest(file_id).await? {
            Some(m) => m,
            None => return Err(MisogiError::NotFound(format!("Manifest not found: {}", file_id))),
        };

        let mut updated = manifest;
        updated.status = status;

        self.save_manifest(&updated).await
    }
}
