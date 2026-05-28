use std::{fmt, io::ErrorKind, net::SocketAddr};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tor_socksproto::{
    Buffer, Handshake, NextStep, PreciseReads, SocksAddr, SocksCmd, SocksProxyHandshake,
    SocksRequest, SocksStatus,
};
use tracing::{debug, info, warn};

use crate::tor_client::ArtiClient;

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

impl TryFrom<&SocksRequest> for Target {
    type Error = anyhow::Error;

    fn try_from(request: &SocksRequest) -> Result<Self> {
        if request.command() != SocksCmd::CONNECT {
            bail!("only SOCKS CONNECT is supported");
        }

        let host = match request.addr() {
            SocksAddr::Hostname(hostname) => hostname.as_ref().to_owned(),
            SocksAddr::Ip(ip) => ip.to_string(),
        };

        Ok(Self {
            host,
            port: request.port(),
        })
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
                if is_routine_disconnect(&error) {
                    debug!(%peer_addr, error = ?error, "SOCKS connection closed");
                } else {
                    warn!(%peer_addr, error = ?error, "SOCKS connection closed with error");
                }
            }
        });
    }
}

async fn handle_client(mut inbound: TcpStream, tor_client: ArtiClient) -> Result<()> {
    let request = read_socks_request(&mut inbound).await?;
    let target = match Target::try_from(&request) {
        Ok(target) => target,
        Err(error) => {
            write_socks_reply(&mut inbound, &request, SocksStatus::COMMAND_NOT_SUPPORTED).await?;
            return Err(error);
        }
    };

    debug!(%target, "opening Tor stream");

    let mut tor_stream = match connect_with_retry(&tor_client, &target).await {
        Ok(stream) => stream,
        Err(error) => {
            write_socks_reply(&mut inbound, &request, SocksStatus::GENERAL_FAILURE).await?;
            return Err(error).context("failed to open Tor stream");
        }
    };

    write_socks_reply(&mut inbound, &request, SocksStatus::SUCCEEDED).await?;

    match tokio::io::copy_bidirectional(&mut inbound, &mut tor_stream).await {
        Ok((from_client, from_tor)) => {
            debug!(%target, from_client, from_tor, "SOCKS stream finished");
        }
        Err(error) => {
            debug!(%target, error = %error, kind = ?error.kind(), "SOCKS stream ended during relay");
        }
    }

    Ok(())
}

/// Open a Tor stream to the target, retrying transient failures on a fresh circuit.
///
/// Shortened (experimental) circuits open streams less reliably than full 3-hop paths: a guard or
/// exit can refuse a stream, leaving an otherwise-fine destination failing. Rather than surface that
/// to the SOCKS client immediately, retry on freshly isolated circuits so a single bad circuit does
/// not break browsing. The first attempt reuses existing circuits (fast path); retries force a new
/// circuit via a fresh isolation token.
async fn connect_with_retry(
    tor_client: &ArtiClient,
    target: &Target,
) -> Result<arti_client::DataStream> {
    const MAX_ATTEMPTS: usize = 3;
    let addr = (target.host.as_str(), target.port);
    let mut last_error: Option<arti_client::Error> = None;

    for attempt in 1..=MAX_ATTEMPTS {
        let result = if attempt == 1 {
            tor_client.connect(addr).await
        } else {
            let mut prefs = arti_client::StreamPrefs::new();
            prefs.set_isolation(arti_client::IsolationToken::new());
            tor_client.connect_with_prefs(addr, &prefs).await
        };

        match result {
            Ok(stream) => {
                if attempt > 1 {
                    debug!(%target, attempt, "Tor stream opened after retry");
                }
                return Ok(stream);
            }
            Err(error) => {
                debug!(%target, attempt, error = ?error, "Tor stream attempt failed");
                last_error = Some(error);
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        }
    }

    Err(last_error.expect("at least one attempt must have run").into())
}

fn is_routine_disconnect(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                error.kind(),
                ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::BrokenPipe
            )
        {
            return true;
        }

        if matches!(
            cause.downcast_ref::<tor_socksproto::Error>(),
            Some(tor_socksproto::Error::UnexpectedEof)
        ) {
            return true;
        }
    }

    false
}

async fn read_socks_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = SocksProxyHandshake::new();
    let mut buffer = Buffer::<PreciseReads>::new_precise();

    loop {
        match handshake
            .step(&mut buffer)
            .context("SOCKS handshake failed")?
        {
            NextStep::Send(reply) => {
                stream.write_all(&reply).await?;
                stream.flush().await?;
            }
            NextStep::Recv(mut recv) => {
                let read = stream.read(recv.buf()).await?;
                recv.note_received(read)?;
            }
            NextStep::Finished(finished) => {
                return finished
                    .into_output()
                    .context("SOCKS parser finished with unread handshake bytes");
            }
        }
    }
}

async fn write_socks_reply<S>(
    stream: &mut S,
    request: &SocksRequest,
    status: SocksStatus,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reply = request.reply(status, None)?;
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tor_socksproto::{SocksAuth, SocksVersion};

    use super::*;

    #[tokio::test]
    async fn parses_socks5_domain_connect() {
        let (mut client, mut server) = duplex(128);

        let server_task = tokio::spawn(async move { read_socks_request(&mut server).await });

        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth_reply = [0_u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [5, 0]);

        client
            .write_all(&[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0, 80,
            ])
            .await
            .unwrap();

        let request = server_task.await.unwrap().unwrap();
        assert_eq!(request.version(), SocksVersion::V5);
        assert_eq!(request.command(), SocksCmd::CONNECT);
        assert_eq!(request.addr().to_string(), "example.com");
        assert_eq!(request.port(), 80);
        assert_eq!(request.auth(), &SocksAuth::NoAuth);
    }

    #[tokio::test]
    async fn parses_socks4a_connect() {
        let (mut client, mut server) = duplex(128);

        let server_task = tokio::spawn(async move { read_socks_request(&mut server).await });

        client
            .write_all(&[
                4, 1, 1, 187, 0, 0, 0, 1, 0, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o',
                b'n', b'i', b'o', b'n', 0,
            ])
            .await
            .unwrap();

        let request = server_task.await.unwrap().unwrap();
        assert_eq!(request.version(), SocksVersion::V4);
        assert_eq!(request.command(), SocksCmd::CONNECT);
        assert_eq!(request.addr().to_string(), "example.onion");
        assert_eq!(request.port(), 443);
    }

    #[test]
    fn converts_request_targets() {
        let request = SocksRequest::new(
            SocksVersion::V5,
            SocksCmd::CONNECT,
            SocksAddr::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            443,
            SocksAuth::NoAuth,
        )
        .unwrap();

        let target = Target::try_from(&request).unwrap();
        assert_eq!(target.host, "93.184.216.34");
        assert_eq!(target.port, 443);
    }

    #[tokio::test]
    async fn writes_socks5_success_reply() {
        let request = SocksRequest::new(
            SocksVersion::V5,
            SocksCmd::CONNECT,
            "example.com"
                .to_owned()
                .try_into()
                .map(SocksAddr::Hostname)
                .unwrap(),
            80,
            SocksAuth::NoAuth,
        )
        .unwrap();

        let (mut client, mut server) = duplex(16);
        let server_task = tokio::spawn(async move {
            write_socks_reply(&mut server, &request, SocksStatus::SUCCEEDED).await
        });

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        server_task.await.unwrap().unwrap();

        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn classifies_routine_disconnects() {
        let error = anyhow::Error::new(std::io::Error::from(ErrorKind::ConnectionReset));
        assert!(is_routine_disconnect(&error));

        let error = anyhow::Error::msg("not routine");
        assert!(!is_routine_disconnect(&error));
    }
}
