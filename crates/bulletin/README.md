# Bulletin crate

A small async abstraction over a **namespace/key-value bulletin**: register namespaces, **post** opaque payloads, **read** posts by id, and compute **deterministic post ids** from `(namespace, payload)`.

Orbis uses this for shared metadata (rings, encrypted document handles, key-derivation records). The default backend is **SourceHub** on-chain bulletin storage; an in-memory **dummy** implementation ships for tests and local development.

## `Bulletin` trait

Defined in [`src/trait.rs`](src/trait.rs):

| Method | Role |
|--------|------|
| `register(namespace)` | Create / claim a bulletin namespace (chain-specific). |
| `post(namespace, payload, artifact)` | Store a post; id is implied by chain or local rules. |
| `read(namespace, id)` | Load a `BulletinPost` (`id`, `namespace`, `payload`). |
| `get_post_id(namespace, payload)` | Deterministic id for a payload under a namespace (must match on-chain rules for SourceHub). |

Shared **value types** (JSON serde):

- **`BulletinPost`** — `id`, `namespace`, raw **`payload`** bytes.
- **`DocumentPayload`** — Encrypted document + Chaum–Pedersen proof fields + policy binding (`ring_id`, `policy_id`, `resource`, `permission`, optional tier/timestamp).
- **`RingPayload`** — Ring metadata: `ring_pk`, `peer_ids`, `threshold`, optional `pss_interval`, optional **`next_peer_ids`** / **`new_threshold`** for reshare coordination.
- **`KeyDerivation`** — Bulletin entry for signing/PRE derivation: `ring_id`, `derivation`, policy fields.

`TryFrom` helpers convert between posts and these structs (JSON in `payload`).

## Feature flags

| Feature | Default | `BulletinImpl` |
|---------|---------|----------------|
| `sourcehub` | **yes** | [`SourceHubBulletin`](src/sourcehub/mod.rs) |
| `dummy` | no | [`DummyBulletin`](src/dummy/mod.rs) |

**`sourcehub` and `dummy` are mutually exclusive** (only one can be enabled). Default builds use SourceHub.

The **`dummy`** module is **always compiled** (in-memory store, useful in unit tests). The **`dummy`** *feature* only switches **`BulletinImpl`** to `DummyBulletin` and must not be combined with `sourcehub`:

```bash
cargo build -p bulletin --no-default-features --features dummy
```

## SourceHub implementation

**`SourceHubBulletin`** wraps [`SourceHubClient`](../common) from the workspace `common` crate.

- **`register`** — `bulletin_register_namespace`.
- **`post`** — `bulletin_create_post` (optional `artifact`).
- **`read`** — Reads posts stored under the chain prefix **`bulletin/{namespace}`** (the implementation prepends `bulletin/` when querying).
- **`get_post_id` / `compute_post_id`** — SHA-256 over **`"bulletin/{namespace}"` as bytes concatenated with `payload`**, hex-encoded — matches on-chain id derivation.

Construction:

- **`SourceHubBulletin::new(ChainConfigBuilder)`** — Read-focused client.
- **`SourceHubBulletin::with_signer(..., balance_check_amount)`** — Client with **`TxSigner`**; optionally waits (exponential backoff) until the account balance ≥ threshold, then performs a minimal **self-transfer** to register the account on-chain.

Diagnostics name: **`"bulletin/sourcehub"`**.

Integration tests in [`src/sourcehub/tests.rs`](src/sourcehub/tests.rs) may require **Docker** (SourceHub stack), similar to other `common`-based tests.

## Dummy implementation

**`DummyBulletin`** keeps posts in a process-local **`HashMap`**, keyed by `(namespace, id)`. Post ids use the **same** `compute_post_id` rule as SourceHub so tests can assert deterministic behavior.

Extras for tests: **`set_post`**, **`get_posts_by_namespace`**.

Diagnostics name: **`"bulletin/dummy"`**.

## Errors

[`BulletinError`](src/error.rs): **`ChainError`**, **`ParseError`**, **`NotFound { namespace, id }`**.

## Dependencies (high level)

- **`async-trait`**, **`serde`** / **`serde_json`**
- **`sha2`**, **`hex`** — deterministic post-id hashing
- **`backoff`** — balance retries in `with_signer`
- **`common`** — SourceHub chain client

## Spec notes

The repo includes a short intent doc [`bulletin_spec.md`](bulletin_spec.md): first implementation is SourceHub; other bulletin backends can be added if they honor the same contract expectations (namespaces, posts, deterministic ids where applicable). Filling out the spec is a TODO

## Tests

```bash
cargo test -p bulletin
```
