mod config;
mod pathing;
mod proxy;
mod tor_client;

use anyhow::Result;
use clap::Parser;
use config::{AppConfig, Cli};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_provider()?;

    let cli = Cli::parse();
    let config = AppConfig::load(cli)?;

    init_tracing(&config.log_filter)?;
    pathing::configure(config.mode);

    info!(mode = %config.mode, socks = %config.socks, "starting ArtiHop");

    let tor_client = tor_client::bootstrap().await?;
    info!("Tor client bootstrapped");

    tokio::select! {
        result = proxy::run_socks5(config.socks, tor_client) => result,
        result = tokio::signal::ctrl_c() => {
            result?;
            warn!("shutdown signal received");
            Ok(())
        }
    }
}

fn init_tracing(filter: &str) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(filter))?;

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true))
        .init();

    Ok(())
}

fn install_rustls_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow::anyhow!("failed to install rustls ring crypto provider"))?;
    }

    Ok(())
}
