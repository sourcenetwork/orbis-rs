# Authn crate

JWT-based authentication for Orbis gRPC: **did:key issuers**, **Ed25519 (EdDSA) signatures**, and **typed claims** for DKG, PRE, threshold signing, and store-secret flows.

## Responsibilities

- **`BearerToken<T>`** — Standard JWT claims (`iss`, `iat`, `exp`, optional `nbf`) plus flattened custom claims `T` (see below).
- **`resolve_jwt_did`** — Verify a bearer JWT: enforce **EdDSA** in the header, resolve **`iss`** as a **`did:key`** URI via [`did-key`](https://crates.io/crates/did-key), verify the signature with the resolved public key, then apply time and lifetime checks (clock skew, expiry, `nbf`, max token lifetime).
- **`JwtSigner`** — Build tokens with a fresh or existing `did:key` Ed25519 key pair; helpers wrap common Orbis claim bundles with a **1-hour** validity unless you use `sign` directly.
- **Tonic helpers** — `extract_bearer_token`, `add_auth_header`, `create_authenticated_request` for `Authorization: Bearer <jwt>` on gRPC metadata.

Verification logic lives in [`src/lib.rs`](src/lib.rs); signing and gRPC utilities in [`src/jwt_builder.rs`](src/jwt_builder.rs).

## Custom claim types

| Struct | Used for |
|--------|----------|
| `PreClaims` | PRE: reader pubkey, object/namespace, optional derivation and salt |
| `SignClaims` | Threshold signing: namespace, derivation bulletin id, message bytes |
| `DkgClaims` | DKG: threshold, peer ids, optional `pss_interval` (automatic PSS refresh cadence) |
| `StoreSecretClaims` | Storing encrypted material: ciphertext, commitments, policy fields, Chaum–Pedersen proof fields, optional tier/timestamp/metadata hash |

Use `BearerToken<()>` when you only need the base claims.

## Verification rules (`resolve_jwt_did`)

1. Algorithm must be **EdDSA** (reject others).
2. **`iss`** must be a resolvable **`did:key`**; the signing key is taken from the resolved DID document.
3. Signature must verify against that key (issuer cannot spoof another DID).
4. **`exp`**: current time must be strictly before expiration.
5. **`iat`**: must not be in the future relative to `current_time`.
6. **`nbf`**: if present, `current_time` must be ≥ `nbf`.
7. **`iat` < `exp`**.
8. **`exp - iat` ≤ `max_token_lifetime_secs`** (policy cap on how long a token may be valid, independent of wall-clock expiry).

Pass a caller-supplied **`current_time`** (Unix seconds) so tests and nodes can use a single clock policy.

## Signing (`JwtSigner`)

- **`JwtSigner::new()`** / **`from_key_pair`** — Ed25519 via `did-key`; **`did_uri`** is `did:key:<fingerprint>`.
- **`sign(claims, duration)`** — Generic EdDSA JWT with `jsonwebtoken`; issuer is set to **`did_uri`**.
- Convenience methods **`create_dkg_jwt`**, **`create_pre_jwt`**, **`create_sign_jwt`**, **`create_store_secret_jwt`** — Build the corresponding `*Claims` and sign (default **1 hour** in the helpers).

## gRPC usage

```rust
use authn::{create_authenticated_request, extract_bearer_token, resolve_jwt_did, PreClaims};

// Client: attach Bearer token
let req = create_authenticated_request(my_body, &jwt_string)?;

// Server: read and verify
let token_str = extract_bearer_token(&request)?;
let bearer: authn::BearerToken<PreClaims> =
    resolve_jwt_did(token_str, current_unix_secs, max_lifetime_secs)?;
```

## Errors

[`AuthNError`](src/error.rs): **`DidError`** (resolution / key material), **`JwtError`** (decode, algorithm, signature, lifetime), **`Unauthorized`** (missing or malformed `Authorization` header).

## Dependencies (high level)

- **`did-key`** — `did:key` resolution and Ed25519 key material  
- **`jsonwebtoken`** — Sign outgoing JWTs and decode/verify incoming JWTs
- **`tonic`** — Request metadata for bearer extraction  
- **`serde`**, **`thiserror`**, **`zeroize`**

## Tests

```bash
cargo test -p authn
```

Integration tests in [`src/tests.rs`](src/tests.rs) cover verification, lifetime bounds, `nbf`, and signature mismatch when `iss` does not match the signing key.
