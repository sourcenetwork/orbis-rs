# Network crate

Trait-based networking for Orbis with a **QUIC / [iroh](https://github.com/n0-computer/iroh)** implementation: persistent connections, many independent bidirectional streams per connection, ALPN-style protocol routing, and length-prefixed messages.

**Scope:** This crate defines [`Network`](src/trait.rs), [`PeerConnection`](src/trait.rs), [`Connection`](src/trait.rs), [`ProtocolHandler`](src/trait.rs), and router traits, plus the iroh types in [`src/iroh/`](src/iroh/). Types such as **`PeerConnectionPool`**, **`GenericProtocolHandler`**, and protocol **coordinators** (DKG / PRE / Sign) live in **`bin/orbis-node`**, not here—they call `Network::connect`, cache connections, and supply `ProtocolHandler` implementations.

## Architecture (this crate + typical node layering)

```
┌─────────────────────────────────────────────────────────────────────┐
│  APPLICATION (e.g. orbis-node — not defined in crates/network)     │
│                                                                     │
│   DkgCoordinator / PreCoordinator / SignCoordinator               │
│         │                     │                     │               │
│         └─────────────────────┼─────────────────────┘               │
│                               │                                     │
│              PeerConnectionPool (caches per peer+protocol)          │
│              calls Network::connect() + open_stream()               │
└───────────────────────────────┼─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  crates/network                                                     │
│                                                                     │
│   Network::connect()  ──────────────►  IrohPeerConnection           │
│   (IrohNetwork)                         (one QUIC connection)       │
│                                                │                    │
│                                                │  open_stream()     │
│                                                ▼                    │
│                                         IrohStreamWrapper           │
│                                         one bidirectional stream    │
│                                         send() / recv()             │
└─────────────────────────────────────────────────────────────────────┘
                                │
                         iroh QUIC transport
                                │
         ┌──────────────────────┼──────────────────────┐
         │  same IrohPeerConnection                   │
         │  = same QUIC conn                          │
         │  each open_stream() = new QUIC stream      │
         │  (independent ordering vs other streams)   │
         └────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Router (server side) — [`src/iroh/router.rs`](src/iroh/router.rs)   │
│                                                                     │
│   IrohRouterBuilder::spawn() → IrohRouterWrapper                  │
│   Per ALPN: accept_bi() → ingress limits → ProtocolHandler::handle │
│                                                                     │
│   Application registers handlers (e.g. orbis-node’s generic       │
│   handler that deserializes and forwards to a coordinator).         │
└─────────────────────────────────────────────────────────────────────┘
```

## Message framing

[`IrohStreamWrapper`](src/iroh/base.rs) frames payloads as **`[4-byte big-endian length][payload]`** on send and expects the same on recv. `Message::data` is the payload only; length is not part of `Bytes` in the `Message` struct.

## Protocol identifiers

Re-exported from [`src/protocol.rs`](src/protocol.rs):

| Constant | Bytes |
|----------|--------|
| `DKG` | `b"orbis/dkg/0"` |
| `REENCRYPT` | `b"orbis/reencrypt/0"` |
| `SIGN` | `b"orbis/sign/0"` |

These are ALPN / protocol names passed to `connect` and router registration.

## Traits and iroh implementations

| Trait | Iroh type | Notes |
|-------|-----------|--------|
| `Network` | [`IrohNetwork`](src/iroh/base.rs) | `connect`, `listen`, `create_router_builder`, `bound_addresses`, … |
| `PeerConnection` | [`IrohPeerConnection`](src/iroh/base.rs) | `open_stream`, `close` |
| `Connection` | [`IrohStreamWrapper`](src/iroh/base.rs) | `send` / `recv` with length prefix |
| `ProtocolHandler` | *application* | e.g. orbis-node wraps coordinators; this crate only has [`IrohProtocolHandlerWrapper`](src/iroh/router.rs) (internal) to bridge iroh’s handler API |
| `RouterBuilder` | [`IrohRouterBuilder`](src/iroh/router.rs) | `accept`, `max_message_size`, ingress limits, `spawn` |
| `Router` | [`IrohRouterWrapper`](src/iroh/router.rs) | `shutdown` |

Public re-exports (with `feature = "iroh"`): **`NetworkImpl`** (`IrohNetwork`), **`IrohNetworkBuilder`**, **`IrohRouterBuilder`**, **`IrohRouterWrapper`**, **`SecretKey`**.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| `iroh` | yes | Full iroh implementation |
| `gossip` | no | Pulls in optional [`iroh-gossip`](https://crates.io/crates/iroh-gossip) (`Cargo.toml`); no integration in this crate’s sources yet |
| `fault-injection` | no | [`FaultNetwork`](src/fault.rs) / [`FaultNetworkController`](src/fault.rs) — block outbound peers to simulate partitions in tests |

## Ingress Limits

[`RouterIngressLimits`](src/trait.rs) bounds inbound work before a protocol handler runs:

- `max_concurrent_streams` caps concurrently executing handler tasks per registered protocol.
- `max_streams_per_peer_per_second` caps accepted streams from one remote peer per protocol in a fixed one-second window.
- `max_message_size` still applies inside [`IrohStreamWrapper`](src/iroh/base.rs) before payload allocation.

The iroh router drops excess streams before DKG/PRE/Sign deserialization or crypto work. Dropped streams are counted under `p2p_errors_total` with `ingress_rate_limit` or `ingress_concurrency_limit`.

## Orchestration behavior (orbis-node, not this crate)

The following are **not** enforced inside `crates/network`; they describe how the node binary typically uses these APIs:

- **Connection pooling** — One cached `PeerConnection` per `(peer_id, protocol)` in `PeerConnectionPool` (replaced on reconnect after errors).
- **DKG session ordering** — DKG may use a **long-lived stream per `(session_id, peer)`** so session messages stay ordered; **fresh streams** may be used for fire-and-forget. Implementation is in the coordinator / pool, not in this crate.
- **PRE / Sign** — Usually **one stream per request** (request/response), then drop.

## Key invariants (this crate)

- **`PeerConnection::open_stream`** creates a **new** bidirectional QUIC stream; streams are independent (no head-of-line blocking between concurrent streams on the same connection).
- **Incoming side:** [`IrohProtocolHandlerWrapper`](src/iroh/router.rs) runs `accept_bi()` in a loop, applies ingress limits, and spawns **`ProtocolHandler::handle`** per accepted stream.
- **`IrohStreamWrapper` drop** finishes the send half so the peer sees **STREAM_FIN** rather than reset (see `Drop` impl in [`base.rs`](src/iroh/base.rs)).

## Metrics

[`src/metrics.rs`](src/metrics.rs) records connection and message send/recv metrics (Prometheus).

## Dependencies (high level)

`iroh`, `tokio`, `bytes`, `async-trait`, `serde`, `prometheus`; `iroh-gossip` is an optional dependency when `gossip` is enabled.
