use std::sync::{Arc, Mutex};

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

pub type ArtiClient = TorClient<PreferredRuntime>;

/// Shared, swappable Tor client. New SOCKS connections snapshot the current client; a control
/// "NEWNYM" replaces it with a freshly isolated client so subsequent traffic uses new circuits.
pub type SharedClient = Arc<Mutex<ArtiClient>>;

pub async fn bootstrap() -> Result<ArtiClient> {
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}
