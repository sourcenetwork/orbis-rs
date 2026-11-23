# Authn crate

JWT-based authentication for Orbis gRPC: **did:key issuers**, **Ed25519 (EdDSA) signatures**, and **typed claims** for DKG, PRE, threshold signing, and store-secret flows.

## Responsibilities

- **`BearerToken<T>`** — Standard JWT claims (`iss`, `iat`, `exp`, optional `nbf`) plus flattened custom claims `T` (see below).
- **`resolve_jwt_did`** — Verify a bearer JWT: enforce **EdDSA** in the header, resolve **`iss`** as an Ed25519 **`did:key`** URI, verify the signature with the resolved public key, then apply time and lifetime checks (clock skew, expiry, `nbf`, max token lifetime).
- **`JwtSigner`** — Build tokens with a fresh or existing `did:key` Ed25519 key pair; helpers wrap common Orbis claim bundles with a **1-hour** validity unless you use `sign` directly.
- **Tonic helpers** — `extract_bearer_token`, `add_auth_header`, `create_authenticated_request` for `Authorization: Bearer <jwt>` on gRPC metadata.

Verification logic lives in [`src/lib.rs`](src/lib.rs); signing and gRPC utilities in [`src/jwt_builder.rs`](src/jwt_builder.rs).

## Custom claim types

| Struct | Used for |
|--------|----------|
| `PreClaims` | PRE: reader pubkey, object/namespace, optional derivation and salt |
| `SignClaims` | Threshold signing: namespace, derivation bulletin id, message bytes |
| `DkgClaims` | DKG: threshold, peer ids, optional `pss_interval` (automatic PSS refresh cadence) |
| `StoreSecretClaims` | Storing encrypted material: ciphertext, commitment, policy fields, encryption‑proof fields (Schnorr PoK: `challenge`, `response`), optional tier/timestamp |

Use `BearerToken<()>` when you only need the base claims.

## `endpoints` — the normal (JWT) path, one file per endpoint

[`src/endpoints/`](src/endpoints/) defines the `EndpointAuth` trait and one
marker type per endpoint (`sign::SignEndpoint`, `pre::PreEndpoint`,
`store_secret::StoreSecretEndpoint`) describing how to validate a JWT's
claims against a live request — nothing here knows WebAuthn, or any other
extra authentication mechanism, exists. `resolve_jwt_auth::<E: EndpointAuth>`
is the complete, self-contained JWT authentication path for one endpoint:
resolve the bearer token, then check its claims against the request via
`E::validate_claims`.

A mechanism that wants to add an *alternative* to JWT for some endpoint
extends `EndpointAuth` with its own trait in its own crate — see
`orbis_webauthn::WebAuthnEndpoint` for how WebAuthn does this (implementing
its trait for e.g. `endpoints::sign::SignEndpoint` from *that* crate, which
the orphan rule allows since the trait being implemented is local to it).
`authn` never depends on `orbis-webauthn`, or on any other mechanism's
crate: this crate can describe an endpoint's normal shape, but it isn't
the place that decides whether JWT or some extra mechanism applies to a
given request. That decision — "try JWT, then fall back to WebAuthn if
the request carries it, then try the next mechanism if that one doesn't
apply either" — is `orbis-node`'s `helpers::auth::resolve_request_auth`,
since orchestrating between mechanisms needs a caller that depends on all
of them, which no single mechanism's crate can be.

DKG's `start_dkg` has no per-caller authentication at all — ring
authorization already happened on-chain at ring creation — so it has no
`EndpointAuth` impl; there is no existing JWT boundary to extend.

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

- **`JwtSigner::new()`** / **`from_seed`** — Ed25519 via Ring; **`did_uri`** is `did:key:<fingerprint>`.
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
    resolve_jwt_did(
        token_str,
        current_unix_secs,
        max_lifetime_secs,
        max_jwt_bytes,
        clock_skew_leeway_secs,
    )?;
```

Pass `0` for strict wall-clock validation, or an explicit leeway in seconds to
tolerate host/container clock skew.

## Errors

[`AuthNError`](src/error.rs): **`DidError`** (resolution / key material), **`JwtError`** (decode, algorithm, signature, lifetime), **`Unauthorized`** (missing or malformed `Authorization` header).

## Dependencies (high level)

- **Ring / ed25519-dalek** — Ed25519 key material and validation
- **`jsonwebtoken`** — Sign outgoing JWTs and decode/verify incoming JWTs
- **`tonic`** — Request metadata for bearer extraction  
- **`serde`**, **`thiserror`**, **`zeroize`**

## Tests

```bash
cargo test -p authn
```

Integration tests in [`src/tests.rs`](src/tests.rs) cover verification, lifetime bounds, `nbf`, and signature mismatch when `iss` does not match the signing key.
