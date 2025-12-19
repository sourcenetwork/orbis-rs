# Orbis

A Rust implementation of threshold cryptography with Distributed Key Generation (DKG) and Proxy Re-Encryption (PRE) protocols.

## Overview

Orbis enables secure, distributed encryption where:
- A **ring** of nodes collaboratively generates a shared public key via DKG
- Data encrypted to the ring can only be decrypted by a threshold of ring nodes working together
- **Proxy Re-Encryption** allows the ring to transform ciphertext for a designated reader without exposing the plaintext

### Participants

- **Alice** - Encrypts data using the ring's aggregate public key
- **Bob** - Requests re-encryption and decrypts using his private key
- **Ring Nodes** - Threshold nodes that perform DKG and PRE operations
- **Eve** - Administrator who configures the ring (threshold, node count, cryptographic parameters)

## Architecture

```
orbis-rs/
├── crates/
│   ├── crypto/         # Cryptographic primitives and protocols
│   ├── network/        # P2P networking abstraction
│   └── local-storage/  # Encrypted key-value storage
└── bin/
    └── orbis-node/     # Main node binary with gRPC services
```

## Crates

### [`crypto`](crates/crypto/)

Cryptographic abstractions for DKG and PRE protocols with a BLS12-381 implementation.

**Traits:**
| Trait | Description |
|-------|-------------|
| [`Dkg`](crates/crypto/src/trait.rs) | 4-phase Distributed Key Generation protocol |
| [`ThresholdDealer`](crates/crypto/src/trait.rs) | Proxy Re-Encryption with threshold verification |
| [`PolynomialCommitment`](crates/crypto/src/trait.rs) | Polynomial commitment with share verification |
| [`PubPoly`](crates/crypto/src/trait.rs) | Public polynomial evaluation |
| [`CryptoSerialize`](crates/crypto/src/trait.rs) | Generic crypto type serialization |
| [`CryptoDeserialize`](crates/crypto/src/trait.rs) | Generic crypto type deserialization |

### [`network`](crates/network/)

Trait-based P2P networking using QUIC (via Iroh).

**Traits:**
| Trait | Description |
|-------|-------------|
| [`Network`](crates/network/src/trait.rs) | Main interface for peer connections |
| [`Connection`](crates/network/src/trait.rs) | Bidirectional peer communication |
| [`ProtocolHandler`](crates/network/src/trait.rs) | Handle incoming protocol connections |
| [`Router`](crates/network/src/trait.rs) | Manage multiple protocol handlers |
| [`RouterBuilder`](crates/network/src/trait.rs) | Builder pattern for router configuration |

### [`local-storage`](crates/local-storage/)

Encrypted local key-value storage for persisting node secrets.

**Traits:**
| Trait | Description |
|-------|-------------|
| [`LocalStorage`](crates/local-storage/src/trait.rs) | Key-value storage with optional AES-256-GCM encryption |

## Protocol Flow

### Phase 1: Ring Setup (DKG)

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Node 1  │     │ Node 2  │     │ Node 3  │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     │ 1. Generate polynomial        │
     │    & commitment               │
     │──────────────────────────────►│
     │◄──────────────────────────────│
     │               │               │
     │ 2. Exchange encrypted shares  │
     │──────────────────────────────►│
     │◄──────────────────────────────│
     │               │               │
     │ 3. Verify & compute final     │
     │    secret share + public key  │
     │               │               │
```

### Phase 2: Encryption & Re-Encryption (PRE)

```
┌───────┐         ┌──────────┐         ┌───────┐
│ Alice │         │   Ring   │         │  Bob  │
└───┬───┘         └────┬─────┘         └───┬───┘
    │                  │                   │
    │ 1. Encrypt with  │                   │
    │    ring's PK     │                   │
    │─────────────────►│                   │
    │                  │                   │
    │                  │ 2. Bob requests   │
    │                  │    re-encryption  │
    │                  │◄──────────────────│
    │                  │                   │
    │                  │ 3. Ring nodes     │
    │                  │    produce shares │
    │                  │──────────────────►│
    │                  │                   │
    │                  │ 4. Bob recovers   │
    │                  │    & decrypts     │
    │                  │                   │
```

## Quick Start

### Running a Node

```bash
# Build the project
cargo build --release

# Run a node (default address [::1]:50051)
./target/release/orbis-node

# Run with custom address and debug logging
./target/release/orbis-node --addr 127.0.0.1:8080 --log-level debug
```

### Configuration

**Password for encrypted storage** (checked in order):
1. File: `~/.orbis_password`
2. Environment: `ORBIS_PASSWORD`
3. Interactive prompt

### gRPC Services

- **DKG Service** - Initiate and participate in distributed key generation
- **PRE Service** - Request proxy re-encryption for designated readers

## Development

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p crypto
cargo test -p network
cargo test -p local-storage

# Check compilation
cargo check

# Run with tracing
RUST_LOG=debug cargo run -p orbis-node

# Docker 3 node network (for testing only)
docker compose -f docker/docker-compose.3-node.yml up
```

## Documentation

- [Architecture](docs/Architecture.md) - System design and component overview
- [Specification](docs/Spec.md) - Protocol specifications
- [Roadmap](docs/Roadmap.md) - Future development plans

## Security

- Private keys and secret shares are **never logged**
- Only public keys and metadata appear in trace output
- Local storage uses AES-256-GCM with Argon2 key derivation
- All share transmissions include nonces and session IDs to prevent replay attacks

## License

[Add license information]
