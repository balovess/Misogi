mod cli;
mod config;
mod state;
mod driver_instance;
mod upload_engine;
mod http_routes;
mod approval_routes;
mod grpc_service;
mod router;
mod tunnel_task;
mod daemon;
mod jtd_handler;

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

    tracing::info!(addr = %state.config.server_addr, "HTTP listening on");

    let grpc_port = state.config.tunnel_local_port + 1000;
    let grpc_addr = format!("0.0.0.0:{}", grpc_port);
    let grpc_addr_log = grpc_addr.clone();
    let grpc_state = state.clone();
    tokio::spawn(async move {
        let v1_svc = crate::grpc_service::SenderGrpcService::new(grpc_state).into_server();

        // Multi-version gRPC: mount V1 service on the same TCP port.
        // When V2 is ready, uncomment the line below to enable V2 multiplexing:
        //
        //   let v2_svc = crate::grpc_service_v2::SenderGrpcServiceV2::new(grpc_state);
        //
        // Tonic's multiplexing allows v1 and v2 clients (using different
        // proto packages: misogi.file_transfer.v1 vs .v2) to coexist
        // on a single port without conflict.
        let builder = tonic::transport::Server::builder()
            .add_service(v1_svc);
            // .add_service(v2_svc.into_server());  // Enable when V2 is implemented

        if let Err(e) = builder.serve(grpc_addr.parse().unwrap()).await {
            tracing::error!(error = %e, "Multi-version gRPC server crashed");
        }
    });
    tracing::info!(grpc_addr = %grpc_addr_log, "gRPC listening (v1+v2 multiplexed)");

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
