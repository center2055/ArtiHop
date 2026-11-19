# ArtiHop

ArtiHop is a standalone Rust microservice that exposes a local SOCKS5 proxy and routes traffic through the Tor network using Arti.

Normal mode uses upstream `arti-client` behavior. The supported shortened mode is an explicit 2-hop local fork experiment implemented through a vendored `tor-circmgr` patch, because stable `arti-client` does not expose a supported path-length injection API.

## Status

- Built on Arti 2.8 (`arti-client` 0.48).
- Normal mode: implemented and live-tested through Tor.
- `short-2`: implemented as Guard -> Exit through the vendored circuit-manager patch; live SOCKS smoke test succeeds.
- Bridges and pluggable transports through Arti's own `[bridges]` config. Shortened circuits do not work through a bridge (Tor exits refuse Bridge -> Exit streams), so with bridges ArtiHop always uses normal 3-hop circuits.
- `.onion` addresses work (onion service client support is compiled in).
- Exit country: streams can be made to leave through exit relays in one country, in both modes, and the country can be changed while ArtiHop runs.

## Usage

```powershell
cargo run -- --mode normal --socks 127.0.0.1:9050
cargo run -- --mode short-2 --socks 127.0.0.1:9050
cargo run -- --mode short-2 --socks 127.0.0.1:9050 --control 127.0.0.1:9051
cargo run -- --mode short-2 --socks 127.0.0.1:9050 --exit-country de
```

With a config file:

```toml
mode = "normal"
socks = "127.0.0.1:9050"
log_filter = "artihop=info,arti_client=info,tor_proto=warn,tor_circmgr=info"
# control = "127.0.0.1:9051"
# bridges_config = "bridges.toml"
# exit_country = "de"
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

## Exit country

`--exit-country CC` (or `exit_country` in the config file) takes a two-letter country code such as `de`. Streams then only use exit relays whose address is in that country, according to the GeoIP database that comes with Arti. `auto` means any country and is the default. It works in the 2-hop mode too, since the exit is picked the same way there. A stream fails if no exit in that country allows its destination and port. Onion services have no exit and are not affected.

## Control listener

`--control ADDR` opens a loopback-only listener that takes one command per line:

- `NEWNYM`: streams opened from now on use fresh circuits (and usually a new exit), like Tor's signal of that name. Open streams are not cut.
- `EXITCOUNTRY CC`: streams opened from now on use exits in that country; `EXITCOUNTRY auto` goes back to any. Open streams are not cut.
- `PING`: answers `OK`.

Each command is answered with `OK`, or `ERR` for anything unknown or a country code that is not two letters.

## Architecture

```text
local app -> SOCKS5 -> ArtiHop -> arti-client -> Tor network
```

Project layout:

- `src/config.rs`: CLI and TOML config.
- `src/tor_client.rs`: Arti bootstrap (with progress logging) and the swappable client used by `NEWNYM`.
- `src/proxy.rs`: SOCKS listener, isolation, retries and bidirectional relay, using `tor-socksproto`.
- `src/control.rs`: loopback control listener.
- `src/exit.rs`: the exit country, shared by the SOCKS and control listeners.
- `src/pathing.rs`: startup switch for normal and 2-hop experimental circuit modes.
- `src/main.rs`: runtime, logging, shutdown (Ctrl+C, and SIGTERM on Unix).
- `vendor/tor-circmgr`: local Arti circuit-manager patch used by the 2-hop mode.

On Windows the binary links the C runtime statically (`.cargo/config.toml`), so it does not need the Visual C++ Redistributable.

## Updating Arti

The vendored `tor-circmgr` is upstream's crate plus the ArtiHop patch. To move to a new Arti release: take the matching `tor-circmgr` from crates.io, re-apply the patch (`experimental_path.rs`, `pick_exit_path` in `path.rs`, `pick_path_for_current_mode` in `path/exitpath.rs`, and the three call sites in `usage.rs`), and bump the pinned `arti-client`, `tor-circmgr`, `tor-rtcompat` and `tor-socksproto` versions together.

Arti 2.7 needed a vendored `saturating-time` with a Windows fix (its search for the earliest and latest `SystemTime` never ended there, so bootstrap hung at 100% CPU). `saturating-time` 0.6.0, which Arti 2.8 uses, has that fix, so the vendored copy is gone.

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
