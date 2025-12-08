### Primary: Base Iroh (QUIC Connections)

**Use Case**: Primary networking layer for all direct peer-to-peer communication

**Why**: 
- Orbis requires **reliable, bidirectional communication** for:
  - DKG protocol phases (private share sending, commitments, complaints)
  - Re-encryption requests/responses (Bob ↔ Ring nodes)
  - Ring node coordination (Charlie ↔ Dave)
- Base iroh provides:
  - Direct QUIC connections with authenticated encryption
  - Bidirectional streams for request/response patterns
  - Datagram support for low-latency messages
  - Built-in hole-punching and relay fallback

**Implementation**:
- Use `iroh::Endpoint` for establishing connections
- Use `Connection::open_bi()` for bidirectional streams
- Use `Connection::send_datagram()` for small, low-latency messages (DKG commitments)
- Custom protocol handlers for DKG, re-encryption, and coordination messages

**ALPN Examples**:
- `"orbis/dkg/0"` - DKG protocol between ring nodes
- `"orbis/reencrypt/0"` - Re-encryption requests (Bob → Ring nodes)
- `"orbis/coord/0"` - Ring node coordination

### Secondary: Iroh Gossip (Optional)

**Use Case**: Ring node discovery and coordination

**Why**:
- Could help with **ring node discovery** (finding Charlie, Dave, etc.)
- Useful for **broadcasting DKG commitments** (Phase 1) to all ring nodes
- Enables **topic-based pub/sub** for ring coordination events

**When to Use**:
- If you need dynamic ring node discovery (nodes joining/leaving)
- For broadcasting non-sensitive coordination messages
- For reshare/refresh coordination (future feature)

**Limitations**:
- Not suitable for private share transmission (Phase 2 DKG) - use direct connections
- Gossip is best-effort, not guaranteed delivery (DKG needs reliability)

**Recommendation**: Start with base iroh only. Add gossip later if you need discovery/coordination features.

### Not Recommended

**iroh-blobs**: 
- Designed for large content-addressed data (KB to TB)
- Orbis deals with small secrets and crypto operations
- Overkill for this use case

**iroh-docs**:
- Multi-dimensional key-value store with sync
- Could theoretically be used for BulletinBoard, but:
  - BulletinBoard trait interface doesn't match docs API
  - SourceHub is already planned for BulletinBoard
  - Would add unnecessary complexity

### Recommended Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Network Layer                        │
├─────────────────────────────────────────────────────────┤
│  Base Iroh (QUIC) - Primary Transport                   │
│  ├── Direct connections for all P2P communication        │
│  ├── Custom protocol handlers per use case              │
│  └── Router for ALPN-based protocol routing             │
│                                                          │
│  Iroh Gossip (Optional) - Discovery/Coordination       │
│  └── Only if dynamic discovery needed                    │
└─────────────────────────────────────────────────────────┘
```

### Implementation Strategy

1. **v0.0.1**: Start with base iroh only
   - Direct connections between all participants
   - Custom protocol handlers for DKG and re-encryption
   - Assume ring node endpoints are known (no discovery needed yet)

2. **Future**: Add iroh-gossip if needed
   - For dynamic ring node discovery
   - For reshare/refresh coordination
   - For broadcasting non-sensitive coordination messages

### Example Network Trait

The network trait should abstract over iroh (and potentially other backends):

```rust
pub trait Network {
    // Establish connection to a peer
    async fn connect(&self, peer_id: &PeerId) -> Result<Connection>;
    
    // Send message (uses appropriate transport: stream or datagram)
    async fn send(&self, conn: &Connection, msg: Message) -> Result<()>;
    
    // Receive message
    async fn recv(&self, conn: &Connection) -> Result<Message>;
    
    // Listen for incoming connections
    async fn listen(&self, handler: ProtocolHandler) -> Result<()>;
}
```

### Dependencies

```toml
# network/Cargo.toml
[dependencies]
iroh = "0.95"  # Base iroh library
iroh-gossip = { version = "0.95", optional = true }  # Optional for discovery

[features]
default = []
gossip = ["dep:iroh-gossip"]
```

### References

- [Iroh Documentation](https://www.iroh.computer/docs)
- [Iroh Base Library](https://github.com/n0-computer/iroh)
- [Iroh Gossip](https://github.com/n0-computer/iroh-gossip)
- [Writing Custom Protocols](https://www.iroh.computer/docs/protocols/writing)

