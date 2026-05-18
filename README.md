# ArtiHop

ArtiHop is a standalone Rust microservice that exposes a local SOCKS5 proxy and routes traffic through the Tor network using Arti.

The working target is deliberately conservative: normal Tor behavior through `arti-client`. Shortened-circuit modes are present as CLI/config options for research planning, but they fail closed because the stable `arti-client` API does not provide a supported way to force one-hop or two-hop exit circuits.

## Status

- Normal mode: implemented and live-tested through Tor.
- `short-2`: planned experiment, not active in the MVP.
- `short-1`: planned diagnostic mode, not active in the MVP.

## Usage

```powershell
cargo run -- --mode normal --socks 127.0.0.1:9050
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
- `src/pathing.rs`: shortened-circuit mode boundary.
- `src/main.rs`: runtime, logging, shutdown.

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

`short-2` and `short-1` are intentionally blocked in this version. A real implementation needs lower-level Arti circuit-management work and may require `experimental-api` or an Arti fork. See `docs/API_AUDIT.md` for the current feasibility notes.

## Security

One-hop and two-hop Tor-style circuits reduce anonymity. They are not normal Tor anonymity and should be treated as experimental diagnostic or performance modes only.
