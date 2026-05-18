# ArtiHop API Feasibility Audit

## 1. API Feasibility Audit

`arti-client` is the correct public entry point for normal Tor client streams. It provides `TorClient::create_bootstrapped` and `TorClient::connect`, with Tokio `AsyncRead`/`AsyncWrite` support when the `tokio` feature is enabled.

The stable normal-mode path only needs:

- `arti-client` for bootstrapping and opening streams.
- `tor-rtcompat` for the concrete `PreferredRuntime` type.
- Tokio and the local proxy code for the SOCKS listener.

Shortened exit circuits are not directly supported by the stable `arti-client` API. `TorClient` exposes `circmgr()`, `dirmgr()`, and `chanmgr()` only behind `experimental-api`, and those handles are lower-level implementation surfaces rather than a stable path-selection injection API.

The lower-level crates relevant to shortened-circuit experiments are:

- `tor-circmgr`, especially `CircMgr`, exit path builders, `path::TorPath`, and circuit build code.
- `tor-netdir` for relay selection inputs.
- `tor-guardmgr` for guard selection and guard-state behavior.
- `tor-proto` / `tor-chanmgr` for lower-level channel and circuit mechanics.
- `tor-relay-selection` for relay-selection policy internals.

`TorPath::new_one_hop` and `TorPath::new_multihop` are not enough by themselves. They construct path values, but the stable `TorClient::connect` path does not accept a caller-provided `TorPath`, and forcing one into exit circuit construction requires lower-level build plumbing. `new_one_hop` is documented for directory-cache style one-hop paths, not as a supported low-anonymity exit-stream mode.

Current stability line:

- Stable-enough public MVP path: `arti-client` normal streams via `TorClient::connect`.
- Public but pre-1.0 and still moving: `arti-client` generally.
- Experimental: `arti-client` `experimental-api` handles such as `circmgr`, `dirmgr`, `chanmgr`.
- More unstable/internal by design: lower-level Arti crates used to assemble and launch circuits directly.

## 2. Recommended Architecture

Run `artihop` as a standalone local process:

```text
application -> 127.0.0.1:9050 SOCKS5 -> ArtiHop -> Arti TorClient -> Tor network
```

CLI:

```text
artihop --mode normal --socks 127.0.0.1:9050
artihop --mode short-2 --socks 127.0.0.1:9050
artihop --mode short-1 --socks 127.0.0.1:9050
```

Config file:

```toml
mode = "normal"
socks = "127.0.0.1:9050"
log_filter = "artihop=info,arti_client=info,tor_proto=warn,tor_circmgr=info"
```

Normal mode should stay isolated from experimental path work. The shortened modes in this repository are now built against a deliberate local `tor-circmgr` fork through `[patch.crates-io]`.

## 3. Compileable MVP

The implementation in this repository starts a local SOCKS listener, accepts CONNECT requests, and routes them through `arti-client`.

For `normal`, Arti's standard exit path selection is unchanged.

For `short-2`, the vendored `tor-circmgr` patch selects a Guard -> Exit path for exit circuits.

For `short-1`, the patch selects a single exit relay as the path. This constructs the intended low-anonymity circuit shape, but public Tor relays reject data streams over it with `END TORPROTOCOL` in live testing. That mode is therefore useful only as a diagnostic/private-relay experiment unless relay-side behavior changes.

Modules:

- `config.rs`: CLI and TOML configuration.
- `tor_client.rs`: Arti bootstrap.
- `proxy.rs`: SOCKS handshake via `tor-socksproto` and stream relay.
- `pathing.rs`: startup switch for the process-wide circuit mode.
- `main.rs`: process wiring, logging, shutdown.
- `vendor/tor-circmgr`: local Arti circuit-manager fork.

## 4. Experimental Shortened-Circuit Implementation Plan

The shortened-circuit backend hooks below `TorClient::connect`, near circuit construction and path selection in `tor-circmgr`. The fork adds a small process-wide mode switch and routes Arti's exit path builder through one of three shapes:

- standard Guard -> Middle -> Exit
- experimental Guard -> Exit
- experimental Exit only

Remaining work areas:

- Preserve guard-manager invariants for `short-2` as the fork evolves.
- Add targeted tests inside the vendored circuit manager for path length selection.
- Decide whether `short-1` should remain a public CLI mode, because public relays reject single-hop exit streams and the relay gets direct client/source visibility.
- Track upstream Arti changes closely; this patch is not a stable extension point.

`TorPath` constructors are path representation helpers, not a complete integration point. They do not replace the need for relay policy checks, circuit parameter generation, channel acquisition, circuit extension, and stream attachment.

## 5. Security Note

`short-1` and `short-2` modes are low-anonymity modes. They should be treated as diagnostic or performance experiments only. They must not be presented as normal Tor anonymity, and they should require explicit opt-in naming, visible warnings, and preferably build-time feature gates before they can carry user traffic.
