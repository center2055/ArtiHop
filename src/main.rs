mod config;
mod control;
mod pathing;
mod proxy;
mod tor_client;

use anyhow::Result;
use clap::Parser;
use config::{AppConfig, Cli};
use tor_client::SharedClient;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_provider()?;

    let cli = Cli::parse();
    let config = AppConfig::load(cli)?;

    init_tracing(&config.log_filter)?;
    let using_bridges = match config.bridges_config.as_deref() {
        Some(path) => tor_client::uses_bridges(path)?,
        None => false,
    };
    let mode = pathing::effective_mode(config.mode, using_bridges);
    pathing::configure(mode);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        mode = %mode,
        socks = %config.socks,
        bridges = using_bridges,
        control = config.control.is_some(),
        "starting ArtiHop"
    );

    let client = SharedClient::new(tor_client::bootstrap(config.bridges_config.as_deref()).await?);
    info!("Tor client bootstrapped");

    let control = async {
        match config.control {
            Some(addr) => control::run_control(addr, client.clone()).await,
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        result = proxy::run_socks5(config.socks, client.clone()) => result,
        result = control => result,
        result = shutdown_signal() => {
            result?;
            warn!("shutdown signal received");
            Ok(())
        }
    }
}

/// Ctrl+C everywhere, and SIGTERM on Unix, so a launcher stopping the process politely lets Arti
/// save its state (guards, circuit timings) on the way out.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
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
