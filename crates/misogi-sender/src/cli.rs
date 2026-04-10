use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, ValueEnum)]
pub enum RunMode {
    Server,
    Daemon,
}

#[derive(Parser, Debug)]
#[command(name = "misogi-sender")]
#[command(about = "Misogi Sender - file upload and transfer node")]
#[command(version)]
pub struct CommandLine {
    #[arg(long, default_value = "server")]
    pub mode: String,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = "0.0.0.0:3001")]
    pub addr: Option<String>,

    #[arg(long, default_value = "./data/sender/uploads")]
    pub storage_dir: Option<String>,

    #[arg(long)]
    pub receiver: Option<String>,

    #[arg(long)]
    pub watch: Option<PathBuf>,

    #[arg(long, default_value = "8388608")]
    pub chunk_size: Option<usize>,

    #[arg(long, default_value = "info")]
    pub log_level: Option<String>,
}
