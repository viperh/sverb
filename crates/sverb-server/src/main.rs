//! `sverb-server` entry point (SPEC §10.6).

use std::process::ExitCode;

use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    sverb_server::cli::run(sverb_server::cli::Cli::parse()).await
}
