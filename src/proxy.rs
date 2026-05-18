use std::{fmt, net::SocketAddr};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::tor_client::ArtiClient;

const SOCKS_VERSION_5: u8 = 0x05;
const SOCKS_AUTH_NONE: u8 = 0x00;
const SOCKS_AUTH_NO_ACCEPTABLE: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

const STATUS_SUCCEEDED: u8 = 0x00;
const STATUS_GENERAL_FAILURE: u8 = 0x01;
const STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const STATUS_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

pub async fn run_socks5(listen_addr: SocketAddr, tor_client: ArtiClient) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind SOCKS listener on {listen_addr}"))?;
    let actual_addr = listener.local_addr()?;

    info!(%actual_addr, "SOCKS5 listener ready");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tor_client = tor_client.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, tor_client).await {
                warn!(%peer_addr, error = %error, "SOCKS connection closed with error");
            }
        });
    }
}

async fn handle_client(mut inbound: TcpStream, tor_client: ArtiClient) -> Result<()> {
    negotiate_auth(&mut inbound).await?;
    let target = read_connect_request(&mut inbound).await?;

    debug!(%target, "opening Tor stream");

    let mut tor_stream = match tor_client
        .connect((target.host.as_str(), target.port))
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            write_reply(&mut inbound, STATUS_GENERAL_FAILURE).await?;
            return Err(error).context("failed to open Tor stream");
        }
    };

    write_reply(&mut inbound, STATUS_SUCCEEDED).await?;

    let (from_client, from_tor) = tokio::io::copy_bidirectional(&mut inbound, &mut tor_stream)
        .await
        .context("failed while relaying proxied stream")?;

    debug!(%target, from_client, from_tor, "SOCKS stream finished");
    Ok(())
}

async fn negotiate_auth(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION_5 {
        bail!("client did not start a SOCKS5 handshake");
    }

    let method_count = header[1] as usize;
    if method_count == 0 {
        bail!("client offered no SOCKS authentication methods");
    }

    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&SOCKS_AUTH_NONE) {
        stream
            .write_all(&[SOCKS_VERSION_5, SOCKS_AUTH_NONE])
            .await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS_VERSION_5, SOCKS_AUTH_NO_ACCEPTABLE])
            .await?;
        bail!("client did not offer no-auth SOCKS5");
    }
}

async fn read_connect_request(stream: &mut TcpStream) -> Result<Target> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION_5 {
        write_reply(stream, STATUS_GENERAL_FAILURE).await?;
        bail!("client sent a non-SOCKS5 request");
    }

    if header[1] != SOCKS_CMD_CONNECT {
        write_reply(stream, STATUS_COMMAND_NOT_SUPPORTED).await?;
        bail!("only SOCKS5 CONNECT is supported");
    }

    if header[2] != 0 {
        write_reply(stream, STATUS_GENERAL_FAILURE).await?;
        bail!("SOCKS5 reserved byte was not zero");
    }

    let host = match header[3] {
        SOCKS_ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bytes = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("SOCKS hostname was not valid UTF-8")?
        }
        SOCKS_ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            write_reply(stream, STATUS_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            bail!("unsupported SOCKS5 address type");
        }
    };

    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;

    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

async fn write_reply(stream: &mut TcpStream, status: u8) -> Result<()> {
    stream
        .write_all(&[
            SOCKS_VERSION_5,
            status,
            0x00,
            SOCKS_ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await?;
    stream.flush().await?;
    Ok(())
}
