# Network Crate

QUIC-based peer-to-peer networking abstraction built on [iroh](https://github.com/n0-computer/iroh).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                            │
│                                                                     │
│   DkgCoordinator        PreCoordinator        SignCoordinator       │
│         │                     │                     │               │
│         └─────────────────────┼─────────────────────┘               │
│                               │                                     │
│                    PeerConnectionPool                               │
│              HashMap<(peer_id, protocol), Arc<PeerConnection>>      │
│              (one persistent QUIC conn per peer+protocol, forever)  │
└───────────────────────────────┼─────────────────────────────────────┘
                                │
                                │  get_or_connect()
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      NETWORK TRAIT LAYER                            │
│                                                                     │
│   Network::connect()  ──────────────────►  PeerConnection           │
│   (IrohNetwork)                           (IrohPeerConnection)      │
│                                           wraps one QUIC connection  │
│                                                │                    │
│                                                │  open_stream()     │
│                                                ▼                    │
│                                           Connection                │
│                                           (IrohStreamWrapper)       │
│                                           one QUIC bidirectional    │
│                                           stream — send() + recv()  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                    iroh QUIC transport
                                │
         ┌──────────────────────┼──────────────────────┐
         │  same PeerConnection │  each open_stream()  │
         │  = same QUIC conn    │  = new QUIC stream   │
         │                      │  (independent, no    │
         │                      │   HoL blocking)      │
         └──────────────────────┼──────────────────────┘
                                │
                                ▼  (remote peer)
┌─────────────────────────────────────────────────────────────────────┐
│                        ROUTER (server side)                         │
│                                                                     │
│   IrohRouter  ──accept()──►  per connection task                    │
│                                     │                               │
│                              loop { accept_bi() }                   │
│                                     │  ◄── fires only when sender   │
│                                     │       writes first byte       │
│                                     │                               │
│                              spawns task per stream                 │
│                                     │                               │
│                                     ▼                               │
│                           ProtocolHandler::handle(stream)           │
│                                                                     │
│   DKG: GenericProtocolHandler  ──►  DkgCoordinator::handle_message  │
│   PRE: GenericProtocolHandler  ──►  PreCoordinator::handle_message  │
│   Sign: GenericProtocolHandler ──►  SignCoordinator::handle_message  │
└─────────────────────────────────────────────────────────────────────┘
```

## Message Flow

### Outbound (coordinator → peer)

**DKG (session messages)**
Pool → `PeerConnection` → cached stream per `(session_id, peer_id)` → all messages in a session travel on the same stream → ordered delivery guaranteed (SessionInit → Commitment → Share).

**DKG (fire-and-forget)**
Pool → `PeerConnection` → fresh stream → dropped after send.

**PRE / Sign**
Pool → `PeerConnection` → fresh stream → send request → recv response on same stream → drop.

### Inbound (peer → handler loop)

iroh accepts QUIC connection → `accept_bi()` loop per connection → spawns handler task per stream → handler: `recv()` → deserialize → if response: store in `response_state` → if request: handle + send reply back on same stream.

## Key Invariants

- **One `PeerConnection` per `(peer_id, protocol)`** — never closed, lives in the pool forever. Replaced only on connection-level error.
- **One `Connection` (stream) per logical operation** — independent streams, no head-of-line blocking between concurrent sessions to the same peer.
- **DKG uses cached streams per `(session_id, peer_id)`** — ensures SessionInit → Commitment → Share arrive in order at the receiver. Streams are dropped when the session is removed.
- **`accept_bi()` only fires when the sender writes the first byte** — opening a stream without sending data does nothing on the receiver side (QUIC lazy stream creation).

## Traits

| Trait | Impl | Description |
|---|---|---|
| `Network` | `IrohNetwork` | Creates connections and router builders |
| `PeerConnection` | `IrohPeerConnection` | Persistent QUIC connection, opens streams |
| `Connection` | `IrohStreamWrapper` | Single QUIC bidirectional stream, send/recv |
| `ProtocolHandler` | `GenericProtocolHandler<C>` | Server-side stream handler loop |
| `RouterBuilder` | `IrohRouterBuilder` | Registers protocol handlers, spawns router |
| `Router` | `IrohRouterWrapper` | Running router, shutdown handle |
