use std::{
    collections::HashMap,
    fmt,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use arti_client::{
    CountryCode, DataStream, ErrorKind as TorErrorKind, HasKind, IsolationToken, StreamPrefs,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tor_socksproto::{
    Buffer, Handshake, NextStep, PreciseReads, SocksAddr, SocksAuth, SocksCmd, SocksProxyHandshake,
    SocksRequest, SocksStatus,
};
use tracing::{debug, info, warn};

use crate::exit::ExitCountry;
use crate::tor_client::{ArtiClient, SharedClient};

/// A client that connects and never finishes the SOCKS handshake is dropped after this long, instead
/// of holding a task and a socket forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Relay buffer per direction. tokio's default is 8 KiB; bigger buffers mean fewer, larger reads
/// and writes when a lot of data is moving.
const RELAY_BUFFER: usize = 64 * 1024;

/// Attempts to open one stream; see `connect_with_retry`.
const MAX_ATTEMPTS: usize = 3;
const RETRY_DELAY: Duration = Duration::from_millis(300);

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

impl From<&SocksRequest> for Target {
    fn from(request: &SocksRequest) -> Self {
        let host = match request.addr() {
            SocksAddr::Hostname(hostname) => hostname.as_ref().to_owned(),
            SocksAddr::Ip(ip) => ip.to_string(),
        };

        Self {
            host,
            port: request.port(),
        }
    }
}

/// Streams are kept apart the way Tor's own SOCKS port does by default (IsolateClientAddr and
/// IsolateSOCKSAuth): connections from different client addresses, or with different SOCKS
/// credentials, never share a circuit. Tor Browser relies on the credentials part to keep each
/// site on its own circuit; before this, every stream through ArtiHop could share one.
#[derive(Clone, Default)]
struct IsolationMap(Arc<Mutex<HashMap<(IpAddr, SocksAuth), IsolationToken>>>);

impl IsolationMap {
    /// Bounded so a client that keeps inventing credentials cannot grow it forever. When full it
    /// starts over, which only means some later streams build new circuits.
    const MAX_ENTRIES: usize = 4096;

    fn token_for(&self, client: IpAddr, auth: &SocksAuth) -> IsolationToken {
        let key = (client, auth.clone());
        let mut tokens = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if tokens.len() >= Self::MAX_ENTRIES && !tokens.contains_key(&key) {
            tokens.clear();
        }

        *tokens.entry(key).or_insert_with(IsolationToken::new)
    }
}

pub async fn run_socks5(
    listen_addr: SocketAddr,
    client: SharedClient,
    exit_country: ExitCountry,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind SOCKS listener on {listen_addr}"))?;
    let actual_addr = listener.local_addr()?;

    info!(%actual_addr, "SOCKS5 listener ready");

    let isolation = IsolationMap::default();
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        // Handshake replies and interactive traffic are small writes: send them now instead of
        // letting Nagle's algorithm hold them back waiting for more.
        let _ = stream.set_nodelay(true);
        let tor_client = client.current();
        let isolation = isolation.clone();
        let exit_country = exit_country.get();

        tokio::spawn(async move {
            if let Err(error) =
                handle_client(stream, peer_addr, tor_client, isolation, exit_country).await
            {
                // `{:#}` keeps the whole cause chain on one line, so a launcher that shows our
                // output line by line gets one entry per failure.
                let message = format!("{error:#}");
                if is_routine_disconnect(&error) || is_destination_answer(&error) {
                    debug!(%peer_addr, error = %message, "SOCKS connection closed");
                } else {
                    warn!(%peer_addr, error = %message, "SOCKS connection closed with error");
                }
            }
        });
    }
}

async fn handle_client(
    mut inbound: TcpStream,
    peer_addr: SocketAddr,
    tor_client: ArtiClient,
    isolation: IsolationMap,
    exit_country: Option<CountryCode>,
) -> Result<()> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_socks_request(&mut inbound))
        .await
        .map_err(|_| anyhow!("SOCKS handshake timed out"))??;

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(isolation.token_for(peer_addr.ip(), request.auth()));
    // Retries keep the country too: they clone these preferences and only swap the isolation.
    if let Some(country) = exit_country {
        prefs.exit_country(country);
    }

    let command = request.command();
    if command == SocksCmd::CONNECT {
        connect(inbound, &request, &tor_client, prefs).await
    } else if command == SocksCmd::RESOLVE {
        resolve(inbound, &request, &tor_client, &prefs).await
    } else if command == SocksCmd::RESOLVE_PTR {
        resolve_ptr(inbound, &request, &tor_client, &prefs).await
    } else {
        write_socks_reply(
            &mut inbound,
            &request,
            SocksStatus::COMMAND_NOT_SUPPORTED,
            None,
        )
        .await?;
        bail!("unsupported SOCKS command {command}")
    }
}

async fn connect(
    mut inbound: TcpStream,
    request: &SocksRequest,
    tor_client: &ArtiClient,
    prefs: StreamPrefs,
) -> Result<()> {
    let target = Target::from(request);
    debug!(%target, "opening Tor stream");

    let mut tor_stream = match connect_with_retry(tor_client, &target, prefs).await {
        Ok(stream) => stream,
        Err(error) => {
            let status = socks_status_for(error.kind());
            let _ = write_socks_reply(&mut inbound, request, status, None).await;
            return Err(anyhow::Error::new(error)).context("failed to open Tor stream");
        }
    };

    write_socks_reply(&mut inbound, request, SocksStatus::SUCCEEDED, None).await?;

    match tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut tor_stream,
        RELAY_BUFFER,
        RELAY_BUFFER,
    )
    .await
    {
        Ok((from_client, from_tor)) => {
            debug!(%target, from_client, from_tor, "SOCKS stream finished");
        }
        Err(error) => {
            debug!(%target, error = %error, kind = ?error.kind(), "SOCKS stream ended during relay");
        }
    }

    Ok(())
}

/// Tor's RESOLVE extension, used by tools like `tor-resolve`: look a name up through Tor.
async fn resolve(
    mut inbound: TcpStream,
    request: &SocksRequest,
    tor_client: &ArtiClient,
    prefs: &StreamPrefs,
) -> Result<()> {
    let host = request.addr().to_string();
    let address = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        match tor_client.resolve_with_prefs(&host, prefs).await {
            Ok(addresses) if !addresses.is_empty() => addresses[0],
            Ok(_) => {
                write_socks_reply(&mut inbound, request, SocksStatus::HOST_UNREACHABLE, None)
                    .await?;
                bail!("lookup returned no addresses");
            }
            Err(error) => {
                let status = socks_status_for(error.kind());
                write_socks_reply(&mut inbound, request, status, None).await?;
                return Err(anyhow::Error::new(error)).context("lookup through Tor failed");
            }
        }
    };

    write_socks_reply(
        &mut inbound,
        request,
        SocksStatus::SUCCEEDED,
        Some(&SocksAddr::Ip(address)),
    )
    .await
}

/// Tor's RESOLVE_PTR extension: reverse lookup through Tor.
async fn resolve_ptr(
    mut inbound: TcpStream,
    request: &SocksRequest,
    tor_client: &ArtiClient,
    prefs: &StreamPrefs,
) -> Result<()> {
    let Ok(ip) = request.addr().to_string().parse::<IpAddr>() else {
        write_socks_reply(
            &mut inbound,
            request,
            SocksStatus::ADDRTYPE_NOT_SUPPORTED,
            None,
        )
        .await?;
        bail!("reverse lookup needs an IP address");
    };

    let names = match tor_client.resolve_ptr_with_prefs(ip, prefs).await {
        Ok(names) => names,
        Err(error) => {
            let status = socks_status_for(error.kind());
            write_socks_reply(&mut inbound, request, status, None).await?;
            return Err(anyhow::Error::new(error)).context("reverse lookup through Tor failed");
        }
    };

    let Some(name) = names.into_iter().next() else {
        write_socks_reply(&mut inbound, request, SocksStatus::HOST_UNREACHABLE, None).await?;
        bail!("reverse lookup returned no names");
    };

    let hostname = SocksAddr::Hostname(name.try_into().context("reverse lookup name too long")?);
    write_socks_reply(
        &mut inbound,
        request,
        SocksStatus::SUCCEEDED,
        Some(&hostname),
    )
    .await
}

/// Open a Tor stream to the target, retrying on a fresh circuit when the failure is one a different
/// circuit can fix.
///
/// Shortened (experimental) circuits open streams less reliably than full 3-hop paths: a guard or
/// exit can refuse a stream, leaving an otherwise-fine destination failing. The first attempt uses
/// the stream's own isolation (fast path, existing circuits); retries force a new circuit with a
/// fresh isolation token. A name that does not exist or a port the destination refuses fails the
/// same way on every circuit, so those are reported at once instead of after three tries.
async fn connect_with_retry(
    tor_client: &ArtiClient,
    target: &Target,
    prefs: StreamPrefs,
) -> std::result::Result<DataStream, arti_client::Error> {
    let addr = (target.host.as_str(), target.port);
    let mut attempt = 1;

    loop {
        let result = if attempt == 1 {
            tor_client.connect_with_prefs(addr, &prefs).await
        } else {
            let mut retry_prefs = prefs.clone();
            retry_prefs.set_isolation(IsolationToken::new());
            tor_client.connect_with_prefs(addr, &retry_prefs).await
        };

        match result {
            Ok(stream) => {
                if attempt > 1 {
                    debug!(%target, attempt, "Tor stream opened after retry");
                }
                return Ok(stream);
            }
            Err(error) if attempt < MAX_ATTEMPTS && is_retryable(error.kind()) => {
                debug!(%target, attempt, error = ?error, "Tor stream attempt failed, retrying on a new circuit");
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(error) => {
                debug!(%target, attempt, error = ?error, "Tor stream attempt failed");
                return Err(error);
            }
        }
    }
}

/// Failures a different circuit can fix: the circuit, a relay or the exit's path to the destination
/// went wrong.
fn is_retryable(kind: TorErrorKind) -> bool {
    use TorErrorKind as EK;
    matches!(
        kind,
        EK::TorNetworkTimeout
            | EK::CircuitCollapse
            | EK::CircuitRefused
            | EK::ExitTimeout
            | EK::ExitPolicyRejected
            | EK::RelayTooBusy
            | EK::TransientFailure
            | EK::TorProtocolViolation
            | EK::RemoteNetworkTimeout
            | EK::RemoteNetworkFailed
            | EK::RemoteStreamReset
            | EK::RemoteStreamClosed
            | EK::RemoteStreamError
    )
}

/// The SOCKS reply code for a failure. Follows Arti's own SOCKS proxy (including the extended codes
/// for onion services from Tor proposal 304), plus the two standard codes that let a client tell
/// "no such host" and "connection refused" apart from a generic failure.
fn socks_status_for(kind: TorErrorKind) -> SocksStatus {
    use {SocksStatus as S, TorErrorKind as EK};
    match kind {
        EK::RemoteHostNotFound | EK::RemoteHostResolutionFailed => S::HOST_UNREACHABLE,
        EK::RemoteConnectionRefused => S::CONNECTION_REFUSED,
        EK::RemoteNetworkFailed => S::TTL_EXPIRED,
        EK::OnionServiceNotFound => S::HS_DESC_NOT_FOUND,
        EK::OnionServiceAddressInvalid => S::HS_BAD_ADDRESS,
        EK::OnionServiceMissingClientAuth => S::HS_MISSING_CLIENT_AUTH,
        EK::OnionServiceWrongClientAuth => S::HS_WRONG_CLIENT_AUTH,
        EK::OnionServiceNotRunning
        | EK::OnionServiceConnectionFailed
        | EK::OnionServiceProtocolViolation => S::HS_INTRO_FAILED,
        _ => S::GENERAL_FAILURE,
    }
}

/// The destination's own answer, such as a name that does not exist, a refused port or an onion
/// service that is down. The client already got it as a SOCKS reply code; for a proxy that is a
/// normal outcome, not something to warn about on every failing page.
fn is_destination_answer(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<arti_client::Error>())
        .any(|error| is_destination_kind(error.kind()))
}

fn is_destination_kind(kind: TorErrorKind) -> bool {
    socks_status_for(kind) != SocksStatus::GENERAL_FAILURE
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
    addr: Option<&SocksAddr>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reply = request.reply(status, addr)?;
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

        let target = Target::from(&request);
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
            write_socks_reply(&mut server, &request, SocksStatus::SUCCEEDED, None).await
        });

        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        server_task.await.unwrap().unwrap();

        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn a_silent_client_is_cut_off() {
        // A client that never speaks SOCKS must not hold the connection open forever.
        let (_client, mut server) = duplex(16);
        let result =
            tokio::time::timeout(Duration::from_millis(50), read_socks_request(&mut server)).await;
        assert!(
            result.is_err(),
            "the handshake should still be waiting, so the timeout fires"
        );
    }

    #[test]
    fn classifies_routine_disconnects() {
        let error = anyhow::Error::new(std::io::Error::from(ErrorKind::ConnectionReset));
        assert!(is_routine_disconnect(&error));

        let error = anyhow::Error::msg("not routine");
        assert!(!is_routine_disconnect(&error));
    }

    #[test]
    fn retries_only_what_a_new_circuit_can_fix() {
        assert!(is_retryable(TorErrorKind::TorNetworkTimeout));
        assert!(is_retryable(TorErrorKind::CircuitCollapse));
        assert!(is_retryable(TorErrorKind::ExitPolicyRejected));
        // The same on every circuit: retrying only slowed down a failing page.
        assert!(!is_retryable(TorErrorKind::RemoteHostNotFound));
        assert!(!is_retryable(TorErrorKind::RemoteConnectionRefused));
        assert!(!is_retryable(TorErrorKind::ForbiddenStreamTarget));
        assert!(!is_retryable(TorErrorKind::OnionServiceNotFound));
    }

    #[test]
    fn maps_failures_to_socks_reply_codes() {
        assert_eq!(
            socks_status_for(TorErrorKind::RemoteHostNotFound),
            SocksStatus::HOST_UNREACHABLE
        );
        assert_eq!(
            socks_status_for(TorErrorKind::RemoteConnectionRefused),
            SocksStatus::CONNECTION_REFUSED
        );
        assert_eq!(
            socks_status_for(TorErrorKind::OnionServiceNotFound),
            SocksStatus::HS_DESC_NOT_FOUND
        );
        assert_eq!(
            socks_status_for(TorErrorKind::TorNetworkTimeout),
            SocksStatus::GENERAL_FAILURE
        );
    }

    #[test]
    fn only_tor_side_failures_are_warnings() {
        assert!(is_destination_kind(TorErrorKind::RemoteHostNotFound));
        assert!(is_destination_kind(TorErrorKind::RemoteConnectionRefused));
        assert!(is_destination_kind(TorErrorKind::OnionServiceNotRunning));
        assert!(!is_destination_kind(TorErrorKind::TorNetworkTimeout));
        assert!(!is_destination_kind(TorErrorKind::CircuitCollapse));
    }

    #[test]
    fn isolates_by_client_address_and_credentials() {
        let map = IsolationMap::default();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let site_a = SocksAuth::Username(b"a.example".to_vec(), b"x".to_vec());
        let site_b = SocksAuth::Username(b"b.example".to_vec(), b"x".to_vec());

        // Same client, no credentials: shared, like before.
        assert_eq!(
            map.token_for(local, &SocksAuth::NoAuth),
            map.token_for(local, &SocksAuth::NoAuth)
        );
        // Different credentials (Tor Browser's per-site isolation): separate circuits.
        assert_ne!(map.token_for(local, &site_a), map.token_for(local, &site_b));
        assert_eq!(map.token_for(local, &site_a), map.token_for(local, &site_a));
        // Different devices on the LAN: separate circuits.
        assert_ne!(
            map.token_for(local, &SocksAuth::NoAuth),
            map.token_for(lan, &SocksAuth::NoAuth)
        );
    }

    #[test]
    fn isolation_map_stays_bounded() {
        let map = IsolationMap::default();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for i in 0..(IsolationMap::MAX_ENTRIES + 10) {
            let auth = SocksAuth::Username(i.to_string().into_bytes(), Vec::new());
            map.token_for(local, &auth);
        }
        assert!(map.0.lock().unwrap().len() <= IsolationMap::MAX_ENTRIES);
    }
}
