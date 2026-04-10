use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "misogi-receiver")]
#[command(about = "Misogi Receiver - file reception and storage node")]
#[command(version)]
pub struct CommandLine {
    #[arg(long, default_value = "server")]
    pub mode: String,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = "0.0.0.0:3002")]
    pub addr: Option<String>,

    #[arg(long, default_value = "./data/receiver/chunks")]
    pub storage_dir: Option<String>,

    #[arg(long, default_value = "./data/receiver/downloads")]
    pub download_dir: Option<String>,

    #[arg(long, default_value = "9000")]
    pub tunnel_port: Option<u16>,

    #[arg(long)]
    pub output: Option<PathBuf>,

    #[arg(long, default_value = "info")]
    pub log_level: Option<String>,
}
