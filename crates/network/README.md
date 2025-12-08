# Network Crate

Network abstraction layer for Orbis, providing a trait-based interface for peer-to-peer communication.

## Overview

This crate provides:
- **Network trait**: Abstract interface for networking operations
- **Iroh implementation**: QUIC-based networking using iroh
- **Protocol routing**: ALPN-based protocol routing support

## Usage

### Basic Setup

```rust
use network::{IrohNetwork, Network, ProtocolHandler};
use async_trait::async_trait;

// Create a network instance
let mut network = IrohNetwork::new().await?;

// Register a protocol handler
struct MyHandler;
#[async_trait]
impl ProtocolHandler for MyHandler {
    async fn handle(&self, mut conn: Box<dyn Connection>) -> Result<()> {
        let msg = conn.recv().await?;
        // Process message...
        Ok(())
    }
}

network.listen("orbis/dkg/0", Box::new(MyHandler)).await?;
network.start_accept_loop().await?;
```

### Connecting to Peers

```rust
use network::{IrohNetwork, Network, PeerId};

let network = IrohNetwork::new().await?;
let peer_id = PeerId::new(peer_address_bytes);
let mut conn = network.connect(&peer_id, "orbis/dkg/0").await?;

// Send message
conn.send(Message::new(data, "orbis/dkg/0")).await?;

// Receive response
let response = conn.recv().await?;
```

### ALPN Protocols

The crate defines standard ALPN identifiers for Orbis protocols:

```rust
use network::iroh::router::alpn;

// DKG protocol between ring nodes
alpn::DKG  // "orbis/dkg/0"

// Re-encryption requests (Bob → Ring nodes)
alpn::REENCRYPT  // "orbis/reencrypt/0"

// Ring node coordination
alpn::COORD  // "orbis/coord/0"
```

## Architecture

- **trait_**: Core networking traits (Network, Connection, ProtocolHandler)
- **iroh/base**: Iroh QUIC implementation
- **iroh/router**: ALPN-based protocol routing
- **error**: Error types for network operations

## Dependencies

- `iroh`: Base iroh library for QUIC networking
- `tokio`: Async runtime
- `async-trait`: Async trait support

## Features

- `gossip`: Enable iroh-gossip for discovery (optional)

