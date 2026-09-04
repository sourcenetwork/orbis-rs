# Crypto crate

Cryptographic abstractions and implementations for Orbis: **distributed key generation (DKG)** with proactive / committee-change flows, **proxy re-encryption (PRE)** with threshold dealers, and **threshold signing**. The same trait surface is implemented for two curve backends; you pick one at compile time.

## What this crate provides

- **Traits** (`crypto::trait`): serialization, polynomial commitments, DKG (including refresh and resharing), PRE (`ThresholdDealer`), and threshold signing (`ThresholdSigner`). Shared value types (`DistributedShare`, `PriShare`, `PubShare`, `Secret`, `ReencryptReply`, `EncryptionProof`, etc.) live here.
- **BLS12-381** (default feature `bls12-381`): DKG on G1, PRE on G1, **threshold BLS** with G1 public keys and G2 signatures (“swapped” BLS so DKG output matches PRE).
- **Decaf377** (feature `decaf377`): DKG and PRE on the decaf377 group; **FROST** threshold Schnorr signing (two-round interactive), since BLS pairings are unavailable on this curve.

The node / network layer in the wider repo orchestrates MPC sessions; this crate is the curve-specific math and protocol steps.

## Feature selection

| Feature | Effect |
|--------|--------|
| `bls12-381` | Default. Enables `crypto::bls12_381` (`ark-bls12-381`). |
| `decaf377` | Enables `crypto::decaf377` (`decaf377` group operations). |
| `test-helpers` | Test utilities and Criterion benches (see below). |

**`bls12-381` and `decaf377` are mutually exclusive.** To use decaf377:

```bash
cargo build -p crypto --no-default-features --features decaf377
```

## Core traits (summary)

Full definitions: [`src/trait.rs`](src/trait.rs).

- **`CryptoSerialize` / `CryptoDeserialize`**: Canonical byte encoding for network messages and storage.
- **`PubPoly` / `PolynomialCommitment`**: Public polynomials and Pedersen-style commitments; `verify_share` uses constant-time comparison where applicable.
- **`Dkg`**: Feldman-style DKG with session binding and replay protection on shares.
  - **`DkgRole`**: `Standard`, `Dealer`, `Receiver`, `DealerReceiver` — used for **resharing** (committee change) so some nodes only send shares, some only receive, or both.
  - **`DkgMode`**: `Fresh` (new secret), `Refresh` (share rotation, zero constant term), `Reshare { ... }` (redistribute the same secret to a new committee with Lagrange-weighted constants).
  - Constructor takes **`session_id`** and **`role`** up front. After share exchange, **`get_complaints`** exposes dispute information; **`combine_pub_poly_bytes`** adds serialized public polynomials (used when refreshing the public polynomial after a refresh-style update — PSS-style public-side updates in the orchestration layer).
- **`ThresholdDealer` (PRE)**: Re-encryption of encrypted secrets under the DKG key, with **Schnorr-style NIZK** on re-encryption shares and, for client-side encryption (`encrypt_secret` / `verify_encryption`), a **Schnorr proof of knowledge of the encryption randomness** bound (via a SHA-512 Fiat–Shamir challenge) to SHA-256 `CiphertextContext` and ciphertext digests. The KEM shared point (`r·s·G`, from which the AES key is derived) is never serialized. Optional **capability derivation** scalars (`derive_public_key`) bind encryption and decryption to derived keys.
- **`ThresholdSigner`**: Threshold signing over DKG outputs.
  - **`INTERACTIVE`**: `false` for BLS (single signing round; empty nonce state), `true` for FROST (nonce commitments + signing state).
  - Optional signing **derivation** and **metadata** (domain-separated) to derive `d * pk` and bind policy bytes into the derivation.

## Implementations

| Module | DKG | PRE | Signing |
|--------|-----|-----|-----------|
| `bls12_381::dkg::DKGNode` | ✓ | | |
| `bls12_381::pre::ThresholdDealerNode` | | ✓ | |
| `bls12_381::sign::ThresholdBlsSigner` | | | Threshold BLS (G1 pk, G2 sig) |
| `decaf377::dkg::DKGNode` | ✓ | | |
| `decaf377::pre::ThresholdDealerNode` | | ✓ | |
| `decaf377::sign::ThresholdDecafSigner` | | | FROST Schnorr |

Re-exports from the crate root (when the matching feature is on) include `DkgImpl`, `PreImpl`, `SignImpl`, scalar/group types, and sizes such as `SCALAR_SIZE` / `GROUP_POINT_SIZE` for protocol framing.

## Usage (BLS12-381 DKG sketch)

```rust
use crypto::bls12_381::DKGNode;
use crypto::r#trait::{Dkg, DkgMode, DkgRole};

let session_id = 12_345u64;
let mut node = DKGNode::new(1, 2, 3, session_id, DkgRole::Standard)?;
node.generate_polynomial(DkgMode::Fresh)?;
let _commitment = node.commitment().clone();
let shares = node.generate_shares()?;
// ... exchange commitments and shares with peers ...
let secret_share = node.compute_secret_share()?;
let aggregate_pk = node.compute_aggregate_public_key()?;
```

## Security notes (brief)

- **Threshold**: Reconstruction of secrets or signatures needs at least `t` honest participants; specifics depend on the orchestration layer.
- **Replay protection**: DKG shares carry nonces and a **session id** agreed by participants.
- **Proofs**: PRE uses a NIZK on each re-encryption share and a Schnorr PoK of the encryption randomness (bound to the policy/ring context and the ciphertext) for client-side encryption; verification APIs are on `ThresholdDealer`. The KEM shared secret is never published, so a party holding only the bulletin data (`enc_cmt`, ciphertext, nonce, proof, policy fields) cannot derive the AES key — recovery requires a threshold re-encryption.
- **VMs and entropy**: Randomness comes from the OS (`OsRng` / `rand_core`); see the section below.

## Benchmarks

```bash
cargo bench --package crypto --features test-helpers --bench dkg_benchmarks
```

Use `pre_benchmarks` or `sign_benchmarks` instead of `dkg_benchmarks` as needed.

Decaf377:

```bash
cargo bench --package crypto --no-default-features --features "test-helpers,decaf377" --bench dkg_benchmarks
```

Save/compare baselines (e.g. with [`critcmp`](https://github.com/BurntSushi/critcmp)):

```bash
cargo bench --package crypto --features test-helpers -- --save-baseline main
cargo install critcmp
critcmp main feature-branch
```

## Dependencies (high level)

- **BLS12-381 path**: `ark-bls12-381`, `ark-ec`, `ark-ff`, `ark-serialize`, `sha2`, `aes-gcm`, `hkdf`, `subtle`, `zeroize`, `serde`, etc.
- **Decaf377 path**: `decaf377`, plus shared `ark-*` / crypto crates (`sha2`, `aes-gcm`, `hkdf`, `subtle`, …) as used by the implementation.

## Virtual machines and entropy

This stack relies on a **cryptographically secure OS RNG** for keys, nonces, and ephemeral secrets across DKG, signing, encryption, and re-encryption.

In VMs, containers, CI, fresh cloud instances, or restored snapshots, the entropy pool may be weak or duplicated. If multiple instances share RNG state, keys or nonces could collide — which breaks threshold assumptions, forward secrecy, and proofs.

**Mitigations:** Ensure the guest has a proper entropy source (e.g. `virtio-rng` on Linux), avoid cloning VMs before sufficient entropy, avoid persisting ephemeral randomness across restarts, and do not replace the OS RNG with a userland PRNG for this code.

**Assumption:** Security holds only if the underlying OS RNG is unpredictable and not duplicated across independent parties.
