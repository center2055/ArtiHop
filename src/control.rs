//! Loopback control listener, one command per line:
//!
//! - `NEWNYM`: streams opened from now on use fresh circuits, like Tor's signal of that name.
//! - `EXITCOUNTRY <cc|auto>`: streams opened from now on leave through an exit in that country
//!   (two letters, e.g. `de`), or through any exit for `auto`.
//! - `PING`: answers `OK`, so a launcher can check the process is alive and listening.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::exit::{self, ExitCountry, parse_exit_country};
use crate::tor_client::SharedClient;

/// How long a control client gets to send its command.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest command line read; anything longer is not a command.
const MAX_LINE: u64 = 64;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    NewNym,
    /// The argument as sent; it is checked when the command runs.
    ExitCountry(String),
    Ping,
    Unknown,
}

fn parse(line: &str) -> Command {
    let line = line.trim().to_ascii_uppercase();
    if let Some(country) = line.strip_prefix("EXITCOUNTRY ") {
        return Command::ExitCountry(country.trim().to_owned());
    }

    match line.as_str() {
        "NEWNYM" | "SIGNAL NEWNYM" => Command::NewNym,
        "PING" => Command::Ping,
        _ => Command::Unknown,
    }
}

pub async fn run_control(
    listen_addr: SocketAddr,
    client: SharedClient,
    exit_country: ExitCountry,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind control listener on {listen_addr}"))?;
    info!(addr = %listener.local_addr()?, "control listener ready");

    loop {
        let (stream, peer) = listener.accept().await?;
        let client = client.clone();
        let exit_country = exit_country.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, &client, &exit_country).await {
                debug!(%peer, error = ?error, "control connection ended with an error");
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    client: &SharedClient,
    exit_country: &ExitCountry,
) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read.take(MAX_LINE));
    let mut line = String::new();
    tokio::time::timeout(COMMAND_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("control client sent no command in time")??;

    let reply = match parse(&line) {
        Command::NewNym => {
            client.new_identity();
            info!("NEWNYM: streams opened from now on use fresh circuits");
            "OK\n"
        }
        Command::ExitCountry(argument) => match parse_exit_country(&argument) {
            Ok(country) => {
                exit_country.set(country);
                info!(
                    exit_country = %exit::describe(country),
                    "EXITCOUNTRY: streams opened from now on use this exit country"
                );
                "OK\n"
            }
            Err(error) => {
                warn!(%error, "EXITCOUNTRY refused");
                "ERR not a two-letter country code or auto\n"
            }
        },
        Command::Ping => "OK\n",
        Command::Unknown => {
            warn!("unknown control command ignored");
            "ERR unknown command\n"
        }
    };

    write.write_all(reply.as_bytes()).await?;
    let _ = write.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands_case_insensitively() {
        assert_eq!(parse("NEWNYM\n"), Command::NewNym);
        assert_eq!(parse("newnym\r\n"), Command::NewNym);
        assert_eq!(parse("SIGNAL NEWNYM"), Command::NewNym);
        assert_eq!(parse(" ping "), Command::Ping);
        assert_eq!(
            parse("exitcountry de\r\n"),
            Command::ExitCountry("DE".to_owned())
        );
        assert_eq!(
            parse("EXITCOUNTRY  auto"),
            Command::ExitCountry("AUTO".to_owned())
        );
    }

    #[test]
    fn anything_else_is_unknown() {
        assert_eq!(parse(""), Command::Unknown);
        assert_eq!(parse("NEWNYM please"), Command::Unknown);
        assert_eq!(parse("GETINFO version"), Command::Unknown);
        assert_eq!(parse("EXITCOUNTRY"), Command::Unknown);
    }
}
