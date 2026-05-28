//! Minimal local control listener.
//!
//! Lets an embedder (e.g. OnionHop) trigger a "new identity" without restarting ArtiHop. On the
//! line `NEWNYM`, the shared Tor client is swapped for a freshly isolated client, so subsequent
//! SOCKS connections build new circuits (new exit) — analogous to Tor's NEWNYM signal. Bind to
//! loopback only.

use std::net::SocketAddr;

use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tracing::{info, warn};

use crate::tor_client::SharedClient;

/// Run the control listener. When `addr` is `None`, this future never completes, so it can sit in
/// a `tokio::select!` alongside the SOCKS server without ending it.
pub async fn run(addr: Option<SocketAddr>, client: SharedClient) -> Result<()> {
    let addr = match addr {
        Some(addr) => addr,
        None => return std::future::pending().await,
    };

    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "control listener ready (send NEWNYM to rotate identity)");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, client).await {
                warn!(error = ?error, "control connection ended with error");
            }
        });
    }
}

async fn handle(stream: TcpStream, client: SharedClient) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        match line.trim().to_ascii_uppercase().as_str() {
            "NEWNYM" => {
                rotate_identity(&client);
                info!("identity rotated: subsequent connections use fresh circuits");
                write_half.write_all(b"OK\n").await?;
            }
            "PING" => {
                write_half.write_all(b"OK\n").await?;
            }
            "" => {}
            other => {
                warn!(command = %other, "unknown control command");
                write_half.write_all(b"ERR unknown command\n").await?;
            }
        }
    }

    Ok(())
}

fn rotate_identity(client: &SharedClient) {
    if let Ok(mut guard) = client.lock() {
        let fresh = guard.isolated_client();
        *guard = fresh;
    }
}
