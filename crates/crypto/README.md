# Crypto crate

Cryptographic abstractions and implementations for Orbis: **distributed key generation (DKG)** with proactive / committee-change flows, **proxy re-encryption (PRE)** with threshold dealers, and **threshold signing**. The same trait surface is implemented for two curve backends; you pick one at compile time.

## What this crate provides

- **Traits** (`crypto::trait`): serialization, polynomial commitments, DKG (including refresh and resharing), PRE (`ThresholdDealer`), and threshold signing (`ThresholdSigner`). Shared value types (`DistributedShare`, `PriShare`, `PubShare`, `Secret`, `ReencryptReply`, `EncryptionProof`, etc.) live here.
- **BLS12-381** (default feature `bls12-381`): DKG on G1, PRE on G1, **threshold BLS** with G1 public keys and G2 signatures (“swapped” BLS so DKG output matches PRE).
- **Jubjub** (feature `jubjub`): DKG, PSS (refresh and resharing), PRE, and PET on the prime-order Jubjub subgroup; **FROST** threshold Schnorr signing (two-round interactive), since BLS pairings are unavailable on this curve.

The node / network layer in the wider repo orchestrates MPC sessions; this crate is the curve-specific math and protocol steps.

## Feature selection

| Feature | Effect |
|--------|--------|
| `bls12-381` | Default. Enables `crypto::bls12_381` (`ark-bls12-381`). |
| `jubjub` | Enables `crypto::jubjub` (`jubjub` group operations). |
| `test-helpers` | Test utilities and Criterion benches (see below). |

**`bls12-381` and `jubjub` are mutually exclusive.** To use Jubjub:

```bash
cargo build -p crypto --no-default-features --features jubjub
```

## Jubjub migration

The `jubjub` feature replaces the retired `decaf377` backend. BLS12-381 remains the default.
All participants in a ring must select the same backend. Existing decaf377 keys,
shares, ciphertexts, PET tags, and signatures cannot be reused as Jubjub material:
create new rings with fresh Jubjub DKG and re-encrypt any data that must migrate.
The cross-commit upgrade harness requires both revisions to support the selected
curve; it does not convert existing rings between curves.

The Vera revision currently pinned in `docker/VERA_REF` does not yet recognize
`jubjub_frost`. Chain-backed reports and reshare finalization require a Vera
release with matching Jubjub signature verification and ring-key validation,
followed by updating that pin. Local crypto and in-process node tests can run
independently of this chain update.
An independently generated [FROST verification vector](src/jubjub/test_vectors/frost.json)
pins the generator, encoding, challenge transcript, and signature for external verifiers.

Jubjub points and scalars each use exactly 32 canonical bytes; FROST signatures
use 64 bytes. Point decoding rejects points outside the prime-order subgroup,
including torsion and mixed-order points. Identity points remain representable
for zero polynomial coefficients and refresh commitments; protocol entry points
reject identities where required. Arithmetic delegates to zkcrypto's constant-time
implementation. Local wrappers preserve Orbis serialization and secret-zeroization
interfaces. The signing scheme identifier is `jubjub_frost`, with Jubjub-specific
proof, derivation, signing, and KDF domains.

The three Jubjub DLEQ proofs (PRE re-encryption shares, PET partial checks, and
PET blinding correctness) use unkeyed **BLAKE2b-512** for their Fiat–Shamir
challenges. The full 64-byte digest is interpreted as a little-endian integer
and reduced modulo the Jubjub scalar order; the challenge remains a 32-byte
canonical scalar. Each proof retains its domain separator and transcript
ordering. FROST, single-base Schnorr knowledge proofs, fingerprint/key
derivation, and HKDF retain their existing hashes.

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
| `jubjub::dkg::DKGNode` | ✓ | | |
| `jubjub::pre::ThresholdDealerNode` | | ✓ | |
| `jubjub::sign::ThresholdJubjubSigner` | | | FROST Schnorr |

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

Jubjub:

```bash
cargo bench --package crypto --no-default-features --features "test-helpers,jubjub" --bench dkg_benchmarks
```

Save/compare baselines (e.g. with [`critcmp`](https://github.com/BurntSushi/critcmp)):

```bash
cargo bench --package crypto --features test-helpers -- --save-baseline main
cargo install critcmp
critcmp main feature-branch
```

## Dependencies (high level)

- **BLS12-381 path**: `ark-bls12-381`, `ark-ec`, `ark-ff`, `ark-serialize`, `sha2`, `aes-gcm`, `hkdf`, `subtle`, `zeroize`, `serde`, etc.
- **Jubjub path**: [`zkcrypto/jubjub`](https://github.com/zkcrypto/jubjub) 0.11.1 with native `zeroize` support, `ff` / `group` 0.14, and shared crypto crates (`sha2`, `aes-gcm`, `hkdf`, `subtle`, …).

## Virtual machines and entropy

This stack relies on a **cryptographically secure OS RNG** for keys, nonces, and ephemeral secrets across DKG, signing, encryption, and re-encryption.

In VMs, containers, CI, fresh cloud instances, or restored snapshots, the entropy pool may be weak or duplicated. If multiple instances share RNG state, keys or nonces could collide — which breaks threshold assumptions, forward secrecy, and proofs.

**Mitigations:** Ensure the guest has a proper entropy source (e.g. `virtio-rng` on Linux), avoid cloning VMs before sufficient entropy, avoid persisting ephemeral randomness across restarts, and do not replace the OS RNG with a userland PRNG for this code.

**Assumption:** Security holds only if the underlying OS RNG is unpredictable and not duplicated across independent parties.
