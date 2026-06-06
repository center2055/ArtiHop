use std::path::Path;

use anyhow::{Context, Result};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

pub type ArtiClient = TorClient<PreferredRuntime>;

pub async fn bootstrap(bridges_config: Option<&Path>) -> Result<ArtiClient> {
    let config = build_config(bridges_config)?;
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}

/// Build the Tor client config. With no bridges file we use the defaults (direct connection); with a
/// bridges file we load Arti's native [bridges] / [[bridges.transports]] config from it, so ArtiHop
/// connects through the given bridges + pluggable transports.
fn build_config(bridges_config: Option<&Path>) -> Result<TorClientConfig> {
    let Some(path) = bridges_config else {
        return Ok(TorClientConfig::default());
    };

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bridges config {}", path.display()))?;
    let builder: TorClientConfigBuilder = toml::from_str(&contents)
        .with_context(|| format!("failed to parse bridges config {}", path.display()))?;
    builder
        .build()
        .context("failed to build Tor client config from bridges file")
}
