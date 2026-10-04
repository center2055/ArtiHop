use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use tor_rtcompat::PreferredRuntime;
use tracing::{info, warn};

pub type ArtiClient = Arc<TorClient<PreferredRuntime>>;

/// The client new streams are opened with. `NEWNYM` swaps it for an isolated client, so streams
/// opened afterwards get fresh circuits (and so, usually, a new exit); streams that are already
/// open keep the client they started on.
#[derive(Clone)]
pub struct SharedClient(Arc<RwLock<ArtiClient>>);

impl SharedClient {
    pub fn new(client: ArtiClient) -> Self {
        Self(Arc::new(RwLock::new(client)))
    }

    pub fn current(&self) -> ArtiClient {
        self.0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn new_identity(&self) {
        let mut client = self
            .0
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fresh = client.isolated_client();
        *client = fresh;
    }
}

pub async fn bootstrap(bridges_config: Option<&Path>) -> Result<ArtiClient> {
    let config = build_config(bridges_config)?;
    let client = TorClient::builder()
        .config(config)
        .create_unbootstrapped()
        .context("failed to create the Tor client")?;

    // Report progress while bootstrapping instead of going quiet until it is done, so a launcher can
    // show how far it got and a stuck bootstrap shows where it is stuck.
    let progress = tokio::spawn(log_bootstrap_progress(client.clone()));
    let result = client.bootstrap().await;
    progress.abort();
    result.context("failed to bootstrap the Tor client")?;

    Ok(client)
}

async fn log_bootstrap_progress(client: ArtiClient) {
    let mut events = client.bootstrap_events();
    let mut last_percent = None;
    let mut last_blockage = None;

    while let Some(status) = events.next().await {
        let percent = (status.as_frac() * 100.0).round() as u8;
        if last_percent != Some(percent) {
            last_percent = Some(percent);
            info!(percent, "bootstrap progress: {status}");
        }

        let blockage = status.blocked().map(|blockage| blockage.to_string());
        if blockage.is_some() && blockage != last_blockage {
            warn!(
                blockage = blockage.as_deref().unwrap_or_default(),
                "bootstrap is blocked"
            );
        }
        last_blockage = blockage;
    }
}

/// Whether an Arti config file actually routes through bridges: a non-empty `bridges.bridges` list
/// that is not switched off with `bridges.enabled = false`. The file can also carry only other
/// settings, such as `[storage]`, and then ArtiHop connects directly.
pub fn uses_bridges(path: &Path) -> Result<bool> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bridges config {}", path.display()))?;
    let value: toml::Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse bridges config {}", path.display()))?;
    Ok(config_uses_bridges(&value))
}

fn config_uses_bridges(value: &toml::Value) -> bool {
    let Some(bridges) = value.get("bridges") else {
        return false;
    };

    let listed = bridges
        .get("bridges")
        .and_then(toml::Value::as_array)
        .is_some_and(|lines| !lines.is_empty());
    let switched_off = bridges.get("enabled").and_then(toml::Value::as_bool) == Some(false);
    listed && !switched_off
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> toml::Value {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn a_bridge_list_means_bridges() {
        assert!(config_uses_bridges(&parse(
            "[bridges]\nbridges = [\"obfs4 192.0.2.1:443 ABCD cert=x iat-mode=0\"]\n"
        )));
    }

    #[test]
    fn storage_only_or_switched_off_is_direct() {
        assert!(!config_uses_bridges(&parse(
            "[storage]\nstate_dir = \"x\"\n"
        )));
        assert!(!config_uses_bridges(&parse("[bridges]\nbridges = []\n")));
        assert!(!config_uses_bridges(&parse(
            "[bridges]\nenabled = false\nbridges = [\"192.0.2.1:443 ABCD\"]\n"
        )));
    }
}
