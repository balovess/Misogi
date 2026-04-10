mod cli;
mod config;
mod state;
mod upload_engine;
mod http_routes;
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
        "Misogi Sender starting in server mode"
    );

    if let Some(ref receiver) = config.receiver_addr {
        tracing::info!(receiver_addr = %receiver, "Receiver configured");
    }

    tokio::fs::create_dir_all(&config.storage_dir)
        .await
        .expect("Failed to create storage directory");

    let state = Arc::new(AppState::new(config));

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
        "Misogi Sender starting in daemon mode"
    );

    tokio::fs::create_dir_all(&config.storage_dir)
        .await
        .expect("Failed to create storage directory");

    let state = Arc::new(AppState::new(config));

    daemon::run_daemon(state.config.clone(), state).await;
}
