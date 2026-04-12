//! Misogi No-Code Administration CLI Binary.
//!
//! This is the entry point for the `misogi-admin` command-line tool,
//! which provides no-code configuration management for the Misogi secure
//! file transfer system.

use clap::Parser;
use misogi_nocode::cli::{self, Cli};

#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Execute the requested command and exit with appropriate code
    let exit_code = cli::execute(cli).await;
    std::process::exit(exit_code);
}
