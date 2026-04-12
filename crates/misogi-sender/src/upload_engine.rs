use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use crate::state::SharedState;
use misogi_core::{ChunkMeta, FileManifest, FileInfo, FileStatus, MisogiError, Result};
use misogi_cdr::{pdf_sanitizer::PdfSanitizer, office_sanitizer::OfficeSanitizer, zip_scanner::ZipScanner, SanitizationPolicy, SanitizationReport, FileSanitizer};

pub struct FileUploader {
    storage_dir: PathBuf,
    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

        let _completed_chunks = if manifest.status == FileStatus::Uploading {
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

    pub fn get_reassembled_path(&self, file_id: &str) -> Result<PathBuf> {
        let file_dir = self.get_file_path(file_id)?;
        Ok(file_dir.join("_reassembled.bin"))
    }

    pub fn get_sanitized_output_path(&self, file_id: &str) -> Result<PathBuf> {
        let file_dir = self.get_file_path(file_id)?;
        Ok(file_dir.join("_sanitized.bin"))
    }

    /// Sanitize an uploaded file using the appropriate CDR engine.
    /// Called automatically after complete_upload() when auto_sanitize is enabled.
    ///
    /// **Task 5.14 Note**: This method currently uses legacy direct sanitizer calls.
    /// The pluggable CDR strategy chain (`state.cdr_strategies`) is available in
    /// AppState but not yet wired into this method due to API alignment work needed
    /// between CDRStrategy trait signatures and existing sanitizer interfaces.
    ///
    /// **Future Enhancement**: Replace legacy match block with iteration over
    /// `state.cdr_strategies`, calling `strategy.evaluate()` then `strategy.apply()`.
    /// See [`sanitize_file_with_state()`](Self::sanitize_file_with_state) for the
    /// intended integration pattern (currently returns NotImplemented).
    pub async fn sanitize_file(
        &self,
        file_id: &str,
        policy: &SanitizationPolicy,
        pdf_sanitizer: &PdfSanitizer,
        office_sanitizer: &OfficeSanitizer,
        zip_scanner: &ZipScanner,
    ) -> Result<SanitizationReport> {
        let manifest = self.load_manifest(file_id).await?;

        let ext = Path::new(&manifest.filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let input_path = self.get_reassembled_path(file_id)?;

        if !input_path.exists() {
            let file_dir = self.storage_dir.join(file_id);
            let _temp_file_path = file_dir.join("_complete_temp.bin");
            let mut output = tokio::fs::File::create(&input_path).await?;

            for i in 0..manifest.chunk_count {
                let chunk_path = file_dir.join(format!("chunk_{}.bin", i));
                if chunk_path.exists() {
                    let chunk_data = tokio::fs::read(&chunk_path).await?;
                    output.write_all(&chunk_data).await?;
                }
            }
            output.flush().await?;
            drop(output);
        }

        let output_path = self.get_sanitized_output_path(file_id)?;

        // Legacy sanitization logic (backward compatible, unchanged)
        let report = match ext.as_str() {
            ".pdf" => pdf_sanitizer.sanitize(&input_path, &output_path, policy).await?,
            ".docx" | ".xlsx" | ".pptx" | ".docm" | ".xlsm" | ".pptm" => {
                office_sanitizer.sanitize(&input_path, &output_path, policy).await?
            }
            ".zip" | ".jar" => zip_scanner.sanitize(&input_path, &output_path, policy).await?,
            _ => {
                SanitizationReport::new(file_id.to_string(), manifest.filename.clone())
            },
        };

        Ok(report)
    }

    /// Sanitize a file using the pluggable CDR strategy chain from AppState (Task 5.14).
    ///
    /// **Status**: Placeholder for future integration.
    ///
    /// This method is intended to replace [`sanitize_file()`](Self::sanitize_file) by
    /// iterating through `state.cdr_strategies` and delegating to matching strategies.
    /// However, integration is pending alignment of CDRStrategy trait signatures with
    /// existing sanitizer interfaces.
    ///
    /// # Arguments
    /// * `file_id` — Unique file identifier
    /// * `policy` — Global sanitization policy controlling strictness
    /// * `state` — Shared application state containing `cdr_strategies`
    ///
    /// # Returns
    /// Currently delegates to legacy [`sanitize_file()`](Self::sanitize_file).
    /// Will return strategy-chain results once CDRStrategy integration is complete.
    #[allow(dead_code)]
    pub async fn sanitize_file_with_state(
        &self,
        file_id: &str,
        policy: &SanitizationPolicy,
        state: &SharedState,
    ) -> Result<SanitizationReport> {
        // TODO (Task 5.14 future): Implement CDR strategy chain iteration here.
        // Intended pattern:
        //   for strategy in &state.cdr_strategies {
        //       if strategy.supports(&ext) {
        //           let decision = strategy.evaluate(&context).await?;
        //           if matches!(decision, StrategyDecision::Sanitize) {
        //               return strategy.apply(&context, &decision).await;
        //           }
        //       }
        //   }
        //
        // Blocking issues to resolve:
        // - CDRStrategy::apply() signature uses (context, decision) not (input, output, context)
        // - SanitizeContext fields differ from assumed (filename/mime_type vs file_id/extension/policy)
        // - evaluate() returns Result<StrategyDecision> requiring ? operator handling
        //
        // For now, delegate to legacy implementation to maintain backward compatibility.

        self.sanitize_file(
            file_id,
            policy,
            &state.pdf_sanitizer,
            &state.office_sanitizer,
            &state.zip_scanner,
        ).await
    }
}
