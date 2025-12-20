//! Gabby - Voice AI SIP Agent
//!
//! Talk to an AI over the phone using SIP/RTP.

mod audio;
mod call;
mod config;
mod pipeline;
mod server;

use clap::Parser;
use config::GabbyConfig;
use server::GabbyServer;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Gabby - Voice AI SIP Agent
#[derive(Parser, Debug)]
#[command(name = "gabby")]
#[command(version, about = "Talk to an AI over the phone")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "gabby.toml")]
    config: PathBuf,

    /// SIP port to listen on (overrides config)
    #[arg(short, long)]
    port: Option<u16>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

/// Gabby application errors.
#[derive(Debug, thiserror::Error)]
pub enum GabbyError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Server error: {0}")]
    Server(#[from] server::ServerError),
}

#[tokio::main]
async fn main() -> Result<(), GabbyError> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Gabby voice AI agent");

    // Load configuration
    let mut config = GabbyConfig::load_or_default(&cli.config)?;

    // Apply CLI overrides
    if let Some(port) = cli.port {
        config.server.sip_port = port;
    }

    tracing::info!(
        "Configuration loaded: SIP {}:{}, STT model: {:?}",
        config.server.sip_host,
        config.server.sip_port,
        config.stt.model_path
    );

    // Create and run server
    let server = GabbyServer::new(config).await?;

    // Handle Ctrl+C for graceful shutdown
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
                return Err(e.into());
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down...");
        }
    }

    tracing::info!("Gabby shutdown complete");
    Ok(())
}
