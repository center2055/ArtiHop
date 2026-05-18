# ArtiHop API Feasibility Audit

## 1. API Feasibility Audit

`arti-client` is the correct public entry point for normal Tor client streams. It provides `TorClient::create_bootstrapped` and `TorClient::connect`, with Tokio `AsyncRead`/`AsyncWrite` support when the `tokio` feature is enabled.

The compileable MVP only needs:

- `arti-client` for bootstrapping and opening streams.
- `tor-rtcompat` for the concrete `PreferredRuntime` type.
- Tokio and the local proxy code for the SOCKS listener.

Shortened exit circuits are not directly supported by the stable `arti-client` API. `TorClient` exposes `circmgr()`, `dirmgr()`, and `chanmgr()` only behind `experimental-api`, and those handles are lower-level implementation surfaces rather than a stable path-selection injection API.

The lower-level crates relevant to shortened-circuit experiments are:

- `tor-circmgr`, especially `CircMgr`, `path::TorPath`, and circuit build code.
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

Normal mode should stay isolated from experimental path work. The shortened modes should fail closed unless built against a deliberate experimental/forked Arti pathing backend.

## 3. Compileable MVP

The MVP in this repository starts a local SOCKS5 listener, accepts CONNECT requests, and routes them through `arti-client` with normal Arti circuit behavior.

Modules:

- `config.rs`: CLI and TOML configuration.
- `tor_client.rs`: Arti bootstrap.
- `proxy.rs`: SOCKS5 handshake and stream relay.
- `pathing.rs`: shortened-circuit placeholders that fail closed.
- `main.rs`: process wiring, logging, shutdown.

## 4. Experimental Shortened-Circuit Implementation Plan

A real shortened-circuit backend needs to hook below `TorClient::connect`, near circuit construction and path selection in `tor-circmgr`. The experiment would need a custom path builder that can select a guard/exit pair for `short-2`, or a single relay for `short-1`, then launch an exit-capable circuit or stream over it.

Likely work areas:

- Audit `tor-circmgr::build` direct-circuit APIs for current visibility and feature gates.
- Inspect how `CircMgr::get_or_launch_exit` derives supported exit usage and chooses paths.
- Preserve guard-manager invariants for `short-2`; do not bypass guard policy casually.
- Decide whether `short-1` is limited to controlled diagnostics, because a one-hop exit stream gives the relay direct client/source visibility.
- Fork Arti or build with `experimental-api` only if public APIs cannot accept the needed path-selection hooks.

`TorPath` constructors are path representation helpers, not a complete integration point. They do not replace the need for relay policy checks, circuit parameter generation, channel acquisition, circuit extension, and stream attachment.

## 5. Security Note

`short-1` and `short-2` modes are low-anonymity modes. They should be treated as diagnostic or performance experiments only. They must not be presented as normal Tor anonymity, and they should require explicit opt-in naming, visible warnings, and preferably build-time feature gates before they can carry user traffic.
