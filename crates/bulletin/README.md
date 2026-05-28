# Bulletin crate

A small async abstraction over typed Orbis bulletin objects: **read** rings by authoritative id, and **post** fresh ring finalizations, node info, encrypted document handles, and key-derivation records.

The default backend is SourceHub `x/orbis`; an in-memory **dummy** implementation ships for tests and local development.

## `Bulletin` trait

Defined in [`src/trait.rs`](src/trait.rs):

| Method | Role |
|--------|------|
| `register()` | Backend setup hook. SourceHub typed objects do not require namespace registration. |
| `post(kind, payload)` | Store a typed write object and return its authoritative id. Write kinds are `Finalize`, `Document`, `KeyDerivation`, and `NodeInfo`. |
| `read(id, kind)` | Load a `BulletinPost` (`id`, `payload`). |

Shared **value types** (JSON serde):

- **`BulletinPost`** — `id`, raw **`payload`** bytes.
- **`DocumentPayload`** — Encrypted document + Chaum–Pedersen proof fields + policy binding (`ring_id`, `policy_id`, `resource`, `permission`, optional tier/timestamp).
- **`RingPayload`** — Ring metadata: `ring_pk`, `peer_node_keys`, `threshold`, optional `pss_interval`, optional **`new_peer_node_keys`** / **`new_threshold`** for reshare coordination, and **`block_number_nonce`** used as anti-replay input to the reshare finalization sign doc.
- **`RingFinalizationPayload`** — Fresh DKG finalization confirmation: `ring_id` and aggregate `ring_pk`.
- **`KeyDerivation`** — Bulletin entry for signing/PRE derivation: `ring_id`, `derivation`, policy fields.
- **`NodeInfo`** — Node registration: `peer_id`, `controller_key`, `whitelisted_policy_ids`, and `whitelisted_ring_ids`.

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

- **`register`** — no-op for typed SourceHub `x/orbis` objects.
- **`post`** — routes to fresh `FinalizeRing`, `StoreDocument`, `StoreKeyDerivation`, or `CreateNodeInfo`, returning the chain id for the written object.
- **`read`** — routes to typed `x/orbis` queries by object id.
- Ring creation is intentionally outside this abstraction; callers receive a `ring_id` from SourceHub `CreateRing` and pass that id through DKG.

Construction:

- **`SourceHubBulletin::new(ChainConfigBuilder)`** — Read-focused client.
- **`SourceHubBulletin::with_signer(..., balance_check_amount)`** — Client with **`TxSigner`**; optionally waits (exponential backoff) until the account balance ≥ threshold, then performs a minimal **self-transfer** to register the account on-chain.

Diagnostics name: **`"bulletin/sourcehub"`**.

Integration tests in [`src/sourcehub/tests.rs`](src/sourcehub/tests.rs) may require **Docker** (SourceHub stack), similar to other `common`-based tests.

## Dummy implementation

**`DummyBulletin`** keeps typed objects in a process-local **`HashMap`**, keyed by object id. Document and key-derivation writes return the same typed ids as SourceHub.

Extras for tests: **`set_post`**, **`set_ring`**, **`set_node_info`**, **`get_posts`**, and **`finalization_count`**. `DummyBulletin::post` rejects `NodeInfo` because the dummy backend has no signer to derive the node key.

Diagnostics name: **`"bulletin/dummy"`**.

## Errors

[`BulletinError`](src/error.rs): **`ChainError`**, **`ParseError`**, **`NotFound { id }`**.

## Dependencies (high level)

- **`async-trait`**, **`serde`** / **`serde_json`**
- **`sha2`**, **`hex`** — canonical ring hash helpers
- **`backoff`** — balance retries in `with_signer`
- **`common`** — SourceHub chain client

## Spec notes

The repo includes a short intent doc [`bulletin_spec.md`](bulletin_spec.md): first implementation is SourceHub; other bulletin backends can be added if they honor the same typed-object contract expectations and deterministic ids where applicable. Filling out the spec is a TODO.

## Tests

```bash
cargo test -p bulletin
```
