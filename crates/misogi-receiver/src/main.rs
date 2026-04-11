mod cli;
mod config;
mod state;
mod storage;
mod http_routes;
mod grpc_service;
mod router;
mod daemon;
mod tunnel_handler;

use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};
use clap::Parser;
use crate::cli::CommandLine;
use crate::config::ReceiverConfig;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    let cli = CommandLine::parse();

    let config = ReceiverConfig::load_with_cli(&cli);

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

async fn run_server(config: ReceiverConfig) {
    tracing::info!(
        role = "receiver",
        mode = "server",
        addr = %config.server_addr,
        download_dir = %config.download_dir.display(),
        storage_dir = %config.storage_dir,
        tunnel_port = config.tunnel_port,
        "Misogi Receiver starting in server mode"
    );

    let state = Arc::new(AppState::new(config.clone()));

    let tunnel_addr = format!("0.0.0.0:{}", config.tunnel_port);
    let tunnel_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::tunnel_handler::run_tunnel_server(tunnel_state, tunnel_addr).await {
            tracing::error!(error = %e, "Tunnel server crashed");
        }
    });

    let app = router::build_router(state.clone());

    let listener = tokio::net::TcpListener::bind(&state.config.server_addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!(addr = %state.config.server_addr, "Listening on");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn run_daemon_mode(config: ReceiverConfig) {
    tracing::info!(
        role = "receiver",
        mode = "daemon",
        download_dir = %config.download_dir.display(),
        output_dir = ?config.output_dir.as_deref(),
        "Misogi Receiver starting in daemon mode"
    );

    let state = Arc::new(AppState::new(config));

    daemon::run_daemon(state.config.clone(), state).await;
}
