use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::SenderConfig;
use crate::state::SharedState;

const POLL_INTERVAL_SECS: u64 = 5;

pub async fn run_daemon(config: SenderConfig, state: SharedState) {
    let watch_dir = match &config.watch_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            error!("Watch directory not specified for daemon mode");
            return;
        }
    };

    if !watch_dir.exists() {
        if let Err(e) = tokio::fs::create_dir_all(&watch_dir).await {
            error!(path = %watch_dir.display(), error = %e, "Failed to create watch directory");
            return;
        }
    }

    info!(
        role = "sender",
        mode = "daemon",
        watch_dir = %watch_dir.display(),
        storage_dir = %config.storage_dir,
        chunk_size = config.chunk_size,
        "Sender daemon starting"
    );

    let seen_files: Arc<RwLock<HashSet<PathBuf>>> = Arc::new(RwLock::new(HashSet::new()));

    let watcher_result = spawn_file_watcher(
        watch_dir.clone(),
        state.clone(),
        config.chunk_size,
        seen_files.clone(),
    );

    match watcher_result {
        Ok(_) => {
            info!("File system watcher started successfully");
        }
        Err(e) => {
            warn!(
                error = %e,
                "Failed to create file system watcher, falling back to polling mode"
            );
            run_polling_mode(watch_dir, state, config.chunk_size, seen_files).await;
            return;
        }
    }

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl+c");

    info!(role = "sender", mode = "daemon", "Shutting down daemon");
}

fn spawn_file_watcher(
    watch_dir: PathBuf,
    state: SharedState,
    chunk_size: usize,
    seen_files: Arc<RwLock<HashSet<PathBuf>>>,
) -> Result<RecommendedWatcher, notify::Error> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(100);

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        },
        notify::Config::default(),
    )?;

    watcher.watch(&watch_dir, RecursiveMode::NonRecursive)?;

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            handle_watcher_event(&event, &state, chunk_size, &seen_files).await;
        }
    });

    Ok(watcher)
}

async fn handle_watcher_event(
    event: &Event,
    state: &SharedState,
    chunk_size: usize,
    seen_files: &Arc<RwLock<HashSet<PathBuf>>>,
) {
    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            for path in &event.paths {
                if path.is_file() {
                    let is_new = {
                        let mut seen = seen_files.write().await;
                        seen.insert(path.clone())
                    };

                    if is_new {
                        process_file(path, state, chunk_size).await;
                    }
                }
            }
        }
        _ => {}
    }
}

async fn run_polling_mode(
    watch_dir: PathBuf,
    state: SharedState,
    chunk_size: usize,
    seen_files: Arc<RwLock<HashSet<PathBuf>>>,
) {
    info!(
        mode = "polling",
        interval_secs = POLL_INTERVAL_SECS,
        "Running in polling fallback mode"
    );

    loop {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        let mut entries = match tokio::fs::read_dir(&watch_dir).await {
            Ok(e) => e,
            Err(e) => {
                error!(path = %watch_dir.display(), error = %e, "Failed to read watch directory");
                continue;
            }
        };

        loop {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    if path.is_file() {
                        let is_new = {
                            let mut seen = seen_files.write().await;
                            seen.insert(path.clone())
                        };

                        if is_new {
                            process_file(&path, &state, chunk_size).await;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "Failed to read directory entry");
                }
            }
        }
    }
}

async fn process_file(file_path: &Path, state: &SharedState, chunk_size: usize) {
    let filename = match file_path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_string(),
        None => {
            warn!(path = %file_path.display(), "Invalid file name, skipping");
            return;
        }
    };

    info!(
        role = "sender",
        file_path = %file_path.display(),
        filename = %filename,
        "Detected new file, starting upload"
    );

    match tokio::fs::read(file_path).await {
        Ok(data) => {
            upload_file_data(filename, data, state, chunk_size).await;
        }
        Err(e) => {
            error!(
                role = "sender",
                file_path = %file_path.display(),
                error = %e,
                "Failed to read file"
            );
        }
    }
}

async fn upload_file_data(
    filename: String,
    data: Vec<u8>,
    state: &SharedState,
    chunk_size: usize,
) {
    let (file_id, _) = match state.uploader.create_session(filename.clone(), state).await {
        Ok(result) => result,
        Err(e) => {
            error!(
                role = "sender",
                filename = %filename,
                error = %e,
                "Failed to create upload session"
            );
            return;
        }
    };

    info!(
        role = "sender",
        file_id = %file_id,
        filename = %filename,
        total_size = data.len(),
        "Upload session created"
    );

    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.is_empty() {
            continue;
        }

        match state
            .uploader
            .write_chunk(&file_id, index as u32, chunk)
            .await
        {
            Ok(chunk_meta) => {
                info!(
                    role = "sender",
                    file_id = %file_id,
                    chunk_index = index,
                    chunk_size = chunk_meta.size,
                    "Chunk written"
                );
            }
            Err(e) => {
                error!(
                    role = "sender",
                    file_id = %file_id,
                    chunk_index = index,
                    error = %e,
                    "Failed to write chunk"
                );
                return;
            }
        }
    }

    match state.uploader.complete_upload(&file_id, state).await {
        Ok(manifest) => {
            info!(
                role = "sender",
                file_id = %file_id,
                filename = %filename,
                total_size = manifest.total_size,
                chunk_count = manifest.chunk_count,
                status = ?manifest.status,
                "Upload completed successfully"
            );

            if state.config.receiver_addr.is_some() {
                state
                    .update_file_status(&file_id, misogi_core::FileStatus::Transferring)
                    .await;

                info!(
                    role = "sender",
                    file_id = %file_id,
                    receiver_addr = %state.config.receiver_addr.as_deref().unwrap_or(""),
                    "Transfer triggered automatically"
                );
            }
        }
        Err(e) => {
            error!(
                role = "sender",
                file_id = %file_id,
                error = %e,
                "Failed to complete upload"
            );
        }
    }
}
