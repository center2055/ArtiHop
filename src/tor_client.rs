use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

pub type ArtiClient = TorClient<PreferredRuntime>;

pub async fn bootstrap() -> Result<ArtiClient> {
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}
