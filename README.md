# ArtiHop

ArtiHop is a standalone Rust microservice that exposes a local SOCKS5 proxy and routes traffic through the Tor network using Arti.

Normal mode uses upstream `arti-client` behavior. The supported shortened mode is an explicit 2-hop local fork experiment implemented through a vendored `tor-circmgr` patch, because stable `arti-client` does not expose a supported path-length injection API.

## Status

- Built on Arti 2.7 (`arti-client` 0.47).
- Normal mode: implemented and live-tested through Tor.
- `short-2`: implemented as Guard -> Exit through the vendored circuit-manager patch; live SOCKS smoke test succeeds.
- Bridges and pluggable transports through Arti's own `[bridges]` config. Shortened circuits do not work through a bridge (Tor exits refuse Bridge -> Exit streams), so with bridges ArtiHop always uses normal 3-hop circuits.
- `.onion` addresses work (onion service client support is compiled in).

## Usage

```powershell
cargo run -- --mode normal --socks 127.0.0.1:9050
cargo run -- --mode short-2 --socks 127.0.0.1:9050
cargo run -- --mode short-2 --socks 127.0.0.1:9050 --control 127.0.0.1:9051
```

With a config file:

```toml
mode = "normal"
socks = "127.0.0.1:9050"
log_filter = "artihop=info,arti_client=info,tor_proto=warn,tor_circmgr=info"
# control = "127.0.0.1:9051"
# bridges_config = "bridges.toml"
```

```powershell
cargo run -- --config .\artihop.toml
```

`artihop.example.toml` contains the default local setup.

## SOCKS behaviour

- SOCKS4, SOCKS4a and SOCKS5 `CONNECT`, plus Tor's `RESOLVE` and `RESOLVE_PTR` extensions.
- Stream isolation like Tor's SOCKS port defaults (`IsolateClientAddr`, `IsolateSOCKSAuth`): different client addresses, or different SOCKS usernames and passwords, never share a circuit. Tor Browser uses the credentials to keep sites apart.
- Failures get meaningful reply codes: host not found, connection refused, and the onion service codes from Tor proposal 304, otherwise general failure.
- A stream that fails for a reason a new circuit can fix (timeouts, a collapsed circuit, an exit refusing the stream) is retried twice on fresh circuits. A name that does not exist or a refused port fails at once.
- Clients that connect and never finish the SOCKS handshake are dropped after 30 seconds.

## Control listener

`--control ADDR` opens a loopback-only listener that takes one command per line:

- `NEWNYM`: streams opened from now on use fresh circuits (and usually a new exit), like Tor's signal of that name. Open streams are not cut.
- `PING`: answers `OK`.

Each command is answered with `OK`, or `ERR` for anything unknown.

## Architecture

```text
local app -> SOCKS5 -> ArtiHop -> arti-client -> Tor network
```

Project layout:

- `src/config.rs`: CLI and TOML config.
- `src/tor_client.rs`: Arti bootstrap (with progress logging) and the swappable client used by `NEWNYM`.
- `src/proxy.rs`: SOCKS listener, isolation, retries and bidirectional relay, using `tor-socksproto`.
- `src/control.rs`: loopback control listener.
- `src/pathing.rs`: startup switch for normal and 2-hop experimental circuit modes.
- `src/main.rs`: runtime, logging, shutdown (Ctrl+C, and SIGTERM on Unix).
- `vendor/tor-circmgr`: local Arti circuit-manager patch used by the 2-hop mode.
- `vendor/saturating-time`: upstream's crate with a Windows fix; see below.

On Windows the binary links the C runtime statically (`.cargo/config.toml`), so it does not need the Visual C++ Redistributable.

## Updating Arti

The vendored `tor-circmgr` is upstream's crate plus the ArtiHop patch. To move to a new Arti release: take the matching `tor-circmgr` from crates.io, re-apply the patch (`experimental_path.rs`, `pick_exit_path` in `path.rs`, `pick_path_for_current_mode` in `path/exitpath.rs`, and the three call sites in `usage.rs`), and bump the pinned `arti-client`, `tor-circmgr`, `tor-rtcompat` and `tor-socksproto` versions together.

The vendored `saturating-time` is 0.5.0 with one fix: its search for the earliest and latest `SystemTime` never ends on Windows, where `SystemTime` counts in 100ns steps and smaller steps change nothing. Arti 2.7 runs that search while parsing every consensus, so without the fix ArtiHop (and Arti itself) hangs at 100% CPU during bootstrap on Windows. When a fixed `saturating-time` is released, remove the vendored copy and its `[patch]` entry.

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

`normal` uses Arti's standard circuit selection.

`short-2` uses the same SOCKS surface, but the patched `tor-circmgr` selects only Guard -> Exit for exit circuits.

## Security

Two-hop Tor-style circuits reduce anonymity. They are not normal Tor anonymity and should be treated as experimental diagnostic or performance mode only.
