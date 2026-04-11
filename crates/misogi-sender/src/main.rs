mod cli;
mod config;
mod state;
mod upload_engine;
mod http_routes;
mod approval_routes;
mod grpc_service;
mod router;
mod tunnel_task;
mod daemon;

use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};
use clap::Parser;
use crate::cli::CommandLine;
use crate::config::SenderConfig;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    let cli = CommandLine::parse();

    let config = SenderConfig::load_with_cli(&cli);

    fmt()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .json()
        .init();

    match cli.mode.as_str() {
        "server" => run_server(config).await,
        "daemon" => run_daemon_mode(config).await,
        other => {
            eprintln!("Unknown mode: {}. Use 'server' or 'daemon'", other);
            std::process::exit(1);
        }
    }
}

async fn run_server(config: SenderConfig) {
    tracing::info!(
        role = "sender",
        mode = "server",
        addr = %config.server_addr,
        storage_dir = %config.storage_dir,
        chunk_size = config.chunk_size,
        driver_type = %config.transfer_driver_type,
        "Misogi Sender starting in server mode (Task 5.14: Pluggable Trait Layer)"
    );

    if let Some(ref receiver) = config.tunnel_remote_addr {
        tracing::info!(receiver_addr = %receiver, "Receiver configured (direct_tcp mode)");
    }

    tokio::fs::create_dir_all(&config.storage_dir)
        .await
        .expect("Failed to create storage directory");

    // Use AppState::from_config() for full pluggable trait layer initialization (Task 5.14)
    // This constructs all trait objects: TransferDriver, CDRStrategy chain, FileTypeDetector,
    // PIIDetector, LogFormatter, etc. based on configuration settings.
    let state = AppState::from_config(&config);

    let app = router::build_router(state.clone());

    let listener = tokio::net::TcpListener::bind(&state.config.server_addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!(addr = %state.config.server_addr, "Listening on");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn run_daemon_mode(config: SenderConfig) {
    tracing::info!(
        role = "sender",
        mode = "daemon",
        storage_dir = %config.storage_dir,
        chunk_size = config.chunk_size,
        watch_dir = ?config.watch_dir.as_deref(),
        driver_type = %config.transfer_driver_type,
        "Misogi Sender starting in daemon mode (Task 5.14: Pluggable Trait Layer)"
    );

    tokio::fs::create_dir_all(&config.storage_dir)
        .await
        .expect("Failed to create storage directory");

    // Use AppState::from_config() for full pluggable trait layer initialization (Task 5.14)
    let state = AppState::from_config(&config);

    daemon::run_daemon(state.config.clone(), state).await;
}
