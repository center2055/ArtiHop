# ArtiHop

ArtiHop is a standalone Rust microservice that exposes a local SOCKS5 proxy and routes traffic through the Tor network using Arti.

Normal mode uses upstream `arti-client` behavior. The supported shortened mode is an explicit 2-hop local fork experiment implemented through a vendored `tor-circmgr` patch, because stable `arti-client` does not expose a supported path-length injection API.

## Status

- Normal mode: implemented and live-tested through Tor.
- `short-2`: implemented as Guard -> Exit through the vendored circuit-manager patch; live SOCKS smoke test succeeds.

## Usage

```powershell
cargo run -- --mode normal --socks 127.0.0.1:9050
cargo run -- --mode short-2 --socks 127.0.0.1:9050
```

With a config file:

```toml
mode = "normal"
socks = "127.0.0.1:9050"
log_filter = "artihop=info,arti_client=info,tor_proto=warn,tor_circmgr=info"
```

```powershell
cargo run -- --config .\artihop.toml
```

`artihop.example.toml` contains the default local setup.

## Architecture

```text
local app -> SOCKS5 -> ArtiHop -> arti-client -> Tor network
```

Project layout:

- `src/config.rs`: CLI and TOML config.
- `src/tor_client.rs`: Arti bootstrap.
- `src/proxy.rs`: SOCKS listener and bidirectional relay, using `tor-socksproto`.
- `src/pathing.rs`: startup switch for normal and 2-hop experimental circuit modes.
- `src/main.rs`: runtime, logging, shutdown.
- `vendor/tor-circmgr`: local Arti circuit-manager patch used by the 2-hop mode.

## Verification

Local checks:

```powershell
cargo fmt --check
cargo check
cargo test
cargo build
```

Live smoke test:

```powershell
cargo run -- --mode normal --socks 127.0.0.1:19050
curl.exe --socks5-hostname 127.0.0.1:19050 https://check.torproject.org/api/ip
```

The expected response includes `"IsTor":true`.

## Circuit Modes

`normal` uses Arti's standard circuit selection through `TorClient::connect`.

`short-2` uses the same SOCKS and `TorClient::connect` surface, but the patched `tor-circmgr` selects only Guard -> Exit for exit circuits.

## Security

Two-hop Tor-style circuits reduce anonymity. They are not normal Tor anonymity and should be treated as experimental diagnostic or performance mode only.
