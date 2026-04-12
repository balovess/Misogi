use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::{error, info, warn};

use crate::config::ReceiverConfig;
use crate::state::SharedState;

const POLL_INTERVAL_SECS: u64 = 10;

pub async fn run_daemon(config: ReceiverConfig, state: SharedState) {
    let output_dir = match &config.output_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            error!("Output directory not specified for daemon mode");
            return;
        }
    };

    if !output_dir.exists() {
        if let Err(e) = tokio::fs::create_dir_all(&output_dir).await {
            error!(path = %output_dir.display(), error = %e, "Failed to create output directory");
            return;
        }
    }

    let download_dir = PathBuf::from(&config.download_dir);

    if !download_dir.exists() {
        if let Err(e) = tokio::fs::create_dir_all(&download_dir).await {
            error!(
                path = %download_dir.display(),
                error = %e,
                "Failed to create download directory"
            );
            return;
        }
    }

    info!(
        role = "receiver",
        mode = "daemon",
        download_dir = %download_dir.display(),
        output_dir = %output_dir.display(),
        poll_interval_secs = POLL_INTERVAL_SECS,
        "Receiver daemon starting"
    );

    loop {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        scan_and_move_files(&download_dir, &output_dir, &state).await;
    }
}

async fn scan_and_move_files(
    download_dir: &Path,
    output_dir: &Path,
    state: &SharedState,
) {
    let mut entries = match tokio::fs::read_dir(download_dir).await {
        Ok(e) => e,
        Err(e) => {
            error!(
                path = %download_dir.display(),
                error = %e,
                "Failed to read download directory"
            );
            return;
        }
    };

    loop {
        let entry_result = entries.next_entry().await;
        match entry_result {
            Ok(Some(entry)) => {
                let path = entry.path();

                if path.is_file() {
                    process_ready_file(&path, output_dir, state).await;
                } else if path.is_dir() {
                    process_ready_directory(&path, output_dir, state).await;
                }
            }
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "Failed to read directory entry");
            }
        }
    }
}

async fn process_ready_file(file_path: &Path, output_dir: &Path, _state: &SharedState) {
    let filename = match file_path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_string(),
        None => {
            warn!(path = %file_path.display(), "Invalid file name, skipping");
            return;
        }
    };

    info!(
        role = "receiver",
        filename = %filename,
        file_path = %file_path.display(),
        "Processing ready file"
    );

    let destination = output_dir.join(&filename);

    match tokio::fs::copy(file_path, &destination).await {
        Ok(bytes_copied) => {
            info!(
                role = "receiver",
                filename = %filename,
                bytes_copied = bytes_copied,
                destination = %destination.display(),
                "File copied to output directory"
            );

            if let Err(e) = tokio::fs::remove_file(file_path).await {
                warn!(
                    role = "receiver",
                    filename = %filename,
                    error = %e,
                    "Failed to remove source file after copy"
                );
            }
        }
        Err(e) => {
            error!(
                role = "receiver",
                filename = %filename,
                error = %e,
                destination = %destination.display(),
                "Failed to copy file to output directory"
            );
        }
    }
}

async fn process_ready_directory(dir_path: &Path, output_dir: &Path, _state: &SharedState) {
    let dir_name = match dir_path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_string(),
        None => {
            warn!(path = %dir_path.display(), "Invalid directory name, skipping");
            return;
        }
    };

    info!(
        role = "receiver",
        directory = %dir_name,
        dir_path = %dir_path.display(),
        "Processing ready directory"
    );

    let destination = output_dir.join(&dir_name);

    match copy_directory_recursive(dir_path, &destination).await {
        Ok(_) => {
            info!(
                role = "receiver",
                directory = %dir_name,
                destination = %destination.display(),
                "Directory copied to output"
            );

            if let Err(e) = tokio::fs::remove_dir_all(dir_path).await {
                warn!(
                    role = "receiver",
                    directory = %dir_name,
                    error = %e,
                    "Failed to remove source directory after copy"
                );
            }
        }
        Err(e) => {
            error!(
                role = "receiver",
                directory = %dir_name,
                error = %e,
                "Failed to copy directory"
            );
        }
    }
}

async fn copy_directory_recursive(source: &Path, destination: &Path) -> std::io::Result<u64> {
    if let Err(e) = tokio::fs::create_dir_all(destination).await {
        return Err(e);
    }

    let mut total_bytes = 0u64;
    let mut entries = tokio::fs::read_dir(source).await?;

    loop {
        let entry_result = entries.next_entry().await?;
        match entry_result {
            Some(entry) => {
                let src_path = entry.path();
                let dest_path = destination.join(
                    src_path
                        .file_name()
                        .expect("Invalid file name in directory"),
                );

                if src_path.is_file() {
                    let bytes = tokio::fs::copy(&src_path, &dest_path).await?;
                    total_bytes += bytes;
                } else if src_path.is_dir() {
                    let bytes = Box::pin(copy_directory_recursive(&src_path, &dest_path)).await?;
                    total_bytes += bytes;
                }
            }
            None => break,
        }
    }

    Ok(total_bytes)
}
