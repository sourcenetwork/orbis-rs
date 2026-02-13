# Crypto Crate

Cryptographic abstractions for Distributed Key Generation (DKG) and Proxy Re-Encryption (PRE) protocols.

## Overview

This crate provides:
- **Trait definitions** for pluggable cryptographic implementations
- **BLS12-381 implementation** using the `ark-bls12-381` curve
- **Data structures** for shares, commitments, and encrypted secrets

## Traits

### Core Serialization

```rust
/// Serialize crypto types to bytes
pub trait CryptoSerialize: Sized {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn serialized_size() -> usize;
}

/// Deserialize crypto types from bytes
pub trait CryptoDeserialize: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}
```

### Polynomial Commitments

```rust
/// Public polynomial for evaluation at indices
pub trait PubPoly: Clone + Debug + Send + Sync {
    type PublicKey;
    fn eval(&self, i: u32) -> Self::PublicKey;
}

/// Polynomial commitment with share verification
pub trait PolynomialCommitment: Clone + Debug + Send + Sync {
    type PublicKey;
    type ShareValue;
    fn eval(&self, i: u32) -> Self::PublicKey;
    fn verify_share(&self, share_id: u32, share_value: &Self::ShareValue) -> bool;
}
```

### Distributed Key Generation (DKG)

```rust
pub trait Dkg: Send + Sync {
    type ShareValue;
    type PublicKey;
    type PubPoly;
    type PolynomialCommitment;

    /// Initialize a new DKG node
    fn new(id: u32, threshold: usize, total_nodes: usize) -> Result<Box<Self>>;

    /// Phase 1: Generate polynomial and commitment
    fn generate_polynomial(&mut self) -> Result<()>;

    /// Phase 2: Generate shares for all nodes
    fn generate_shares(&self) -> Result<Vec<DistributedShare<Self::ShareValue>>>;

    /// Phase 3: Receive and verify a share
    fn receive_share(&mut self, share: DistributedShare<Self::ShareValue>) -> Result<()>;

    /// Receive a commitment from another node
    fn receive_commitment(&mut self, from_id: u32, commitment: Self::PolynomialCommitment) -> Result<()>;

    /// Phase 4: Compute final secret share
    fn compute_secret_share(&self) -> Result<PriShare<Self::ShareValue>>;

    /// Compute the aggregate public key
    fn compute_aggregate_public_key(&self) -> Result<Self::PublicKey>;

    /// Get the public polynomial for verification
    fn compute_public_polynomial(&self) -> Result<Self::PubPoly>;
}
```

**Protocol Flow:**
1. Each node generates a random polynomial of degree `(threshold - 1)`
2. Nodes exchange polynomial commitments (public)
3. Nodes exchange encrypted shares (private)
4. Each node computes their final secret share

### Proxy Re-Encryption (PRE)

```rust
pub trait ThresholdDealer {
    type DistKeyShare;
    type Secret;
    type PublicKey;
    type ShareValue;
    type ReencryptReply;
    type PubPoly;

    /// Re-encrypt using node's DKG share
    fn reencrypt(
        &self,
        dist_key_share: &Self::DistKeyShare,
        secret: &Self::Secret,
        reader_pk: &Self::PublicKey,
    ) -> Result<Self::ReencryptReply>;

    /// Verify a re-encryption proof (NIZK)
    fn verify(
        &self,
        reader_pk: &Self::PublicKey,
        dkg_commitment: &Self::PubPoly,
        enc_commitment: &Self::PublicKey,
        reply: &Self::ReencryptReply,
    ) -> Result<()>;

    /// Recover commitment from threshold shares
    fn recover(
        &self,
        shares: &[PubShare<Self::PublicKey>],
        threshold: usize,
        total: usize,
    ) -> Result<Option<Self::PublicKey>>;

    /// Encrypt data with ring's public key
    fn encrypt_secret(pk: &Self::PublicKey, data: &[u8]) -> Result<(Self::PublicKey, Self::Secret)>;

    /// Decrypt with reader's private key
    fn decrypt_secret(
        dkg_pk: &Self::PublicKey,
        reencrypted_commitment: &Self::PublicKey,
        reader_sk: &Self::ShareValue,
        secret: &Self::Secret,
    ) -> Result<Vec<u8>>;
}
```

## Data Structures

```rust
/// Share distributed from one participant to another
pub struct DistributedShare<ShareValue> {
    pub from_id: u32,
    pub to_id: u32,
    pub value: ShareValue,
    pub nonce: [u8; 16],    // Replay attack prevention
    pub session_id: u64,    // Session binding
}

/// Private share (index + scalar)
pub struct PriShare<ShareValue> {
    pub i: u32,
    pub v: ShareValue,
}

/// Public share (index + point)
pub struct PubShare<PublicKey> {
    pub i: u32,
    pub v: PublicKey,
}

/// Distributed key share for PRE
pub struct DistKeyShare<ShareValue> {
    pub pri_share: PriShare<ShareValue>,
}

/// Encrypted secret with Schnorr commitment
pub struct Secret {
    pub enc_cmt: Vec<u8>,        // rG - Schnorr commitment
    pub encrypted_data: Vec<u8>, // AES-GCM encrypted data
    pub nonce: Vec<u8>,          // AES-GCM nonce
}

/// Re-encryption reply with NIZK proof
pub struct ReencryptReply<ShareValue, PublicKey> {
    pub share: PubShare<PublicKey>,
    pub challenge: ShareValue,
    pub proof: ShareValue,
}
```

## BLS12-381 Implementation

Located in `src/bls12_381/`:

| Type | Description |
|------|-------------|
| `DKGNode` | Implements `Dkg` trait using BLS12-381 |
| `ThresholdDealerNode` | Implements `ThresholdDealer` trait |
| `PolynomialCommitment` | G1Affine point commitments |
| `PubPoly` | Public polynomial for share verification |

**Curve Parameters:**
- `Fr` - Scalar field elements (secret shares)
- `G1Affine` - Group elements (public keys, commitments)

## Usage

```rust
use crypto::bls12_381::{DKGNode, ThresholdDealerNode};
use crypto::r#trait::{Dkg, ThresholdDealer};

// Create a 2-of-3 DKG node
let mut node = DKGNode::new(1, 2, 3)?;
node.set_session_id(12345);

// Phase 1: Generate polynomial
node.generate_polynomial()?;
let commitment = node.commitment().clone();

// Phase 2: Generate shares for other nodes
let shares = node.generate_shares()?;

// ... exchange commitments and shares with other nodes ...

// Phase 4: Compute final share and public key
let secret_share = node.compute_secret_share()?;
let aggregate_pk = node.compute_aggregate_public_key()?;
```

## Security Properties

- **Threshold security**: Requires `t` of `n` nodes to reconstruct
- **Replay protection**: Nonces and session IDs prevent share reuse
- **NIZK proofs**: Re-encryption includes zero-knowledge proofs
- **Constant-time verification**: Share verification uses constant-time comparison

## Benchmarks

Run benchmarks with:

```bash
cargo bench --package crypto --features test-helpers --bench dkg_benchmarks
```
replace dkg_benchmarks with pre, or sign

To Run a different impl
```bash
cargo bench --package crypto --no-default-features --features "test-helpers,decaf377" --bench dkg_benchmarks
```

To save a named baseline (useful for comparing branches):

```bash
cargo bench --package crypto --features test-helpers -- --save-baseline main
```

To view results as a table, install [`critcmp`](https://github.com/BurntSushi/critcmp):

```bash
cargo install critcmp
critcmp
```

To compare two baselines side-by-side:

```bash
# save baseline on each branch, then compare
critcmp main feature
```

## Dependencies

- `ark-bls12-381` - BLS12-381 curve implementation
- `ark-ec` - Elliptic curve abstractions
- `ark-ff` - Finite field operations
- `ark-serialize` - Serialization for arkworks types
- `aes-gcm` - Authenticated encryption for secrets
- `sha2` - Hash function for challenges

## ⚠️ Virtual Machines & Entropy

This project relies on cryptographically secure randomness provided by the operating system via:

```rust
OsRng
```

All key material, nonces, and ephemeral secrets across the protocol stack (e.g., DKG, signing, encryption, re-encryption, etc.) are generated from the OS CSPRNG.

### Entropy in Virtualized Environments

When running inside:

* Virtual machines
* Containers
* CI pipelines
* Fresh cloud instances
* Snapshot / cloned environments

the OS entropy pool may not be properly initialized.

Potential issues include:

* Insufficient entropy during early boot
* VM snapshots duplicating RNG state
* Misconfigured or missing virtual RNG devices
* Deterministic entropy sources in constrained environments

If multiple instances start from identical RNG state, they could generate identical private keys, nonces, or ephemeral secrets. In cryptographic systems, reuse of randomness can result in:

* Private key compromise
* Loss of forward secrecy
* Broken threshold assumptions
* Invalid or forgeable proofs

### Recommendations

To mitigate entropy-related risks:

* Ensure the system entropy pool is fully initialized before starting services.
* Avoid snapshotting or cloning VMs before sufficient entropy has accumulated.
* Prefer hypervisors with `virtio-rng` or equivalent hardware RNG passthrough.
* On Linux, verify entropy availability (e.g., `/proc/sys/kernel/random/entropy_avail`).
* Avoid custom or userland RNG implementations.
* Never persist or reuse ephemeral randomness across restarts.

### Security Assumption

This system assumes a correctly functioning, cryptographically secure OS RNG. If the underlying entropy source is compromised, duplicated, or predictable, the security guarantees of the protocol no longer hold.
