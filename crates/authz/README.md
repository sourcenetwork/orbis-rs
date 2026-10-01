# Authz crate

Async **authorization** behind a small trait: given opaque **`permission`** bytes and a **`subject`** (caller identity string), decide whether access is allowed.

The default implementation talks to **Vera** over the shared **`common`** service client and evaluates **ACP** (access-control policy) membership. A **dummy** allow-all backend exists only for tests.

## `Authz` trait

Defined in [`src/trait.rs`](src/trait.rs):

```rust
#[async_trait]
pub trait Authz: Send + Sync {
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool>;
    async fn check_at(&self, permission: Vec<u8>, subject: &str, anchor: &str) -> Result<bool>;
    async fn current_anchor(&self) -> Result<String>;
    async fn anchor_time(&self, anchor: &str) -> Result<u64>;
}
```

Callers serialize their intent into **`permission`**; the implementation defines the encoding. For Vera, that encoding is JSON for [`AccessCheckRequest`](src/request.rs).

## Native authorization

The `native` feature exposes `native::NativeAuth`. Connect it with a service
endpoint, independently provisioned consensus key and deployment root, and an
explicit maximum evidence age. Connection verifies the first revision against
that root. Current checks verify bounded permission proofs locally, enforce the
age limit (with at most 15 seconds of future clock drift), and reject revision
regression.

Anchors bind the deployment root, exact revision and certified digest.
`check_at` verifies that revision and its permission evidence; it returns an error
if the service cannot provide evidence for the selected historical state. It
never substitutes current authorization. `anchor_time` verifies the same anchor
before returning its timestamp. Historical-state retention remains a service
qualification requirement.

Requests reject unknown and duplicate fields. Timestamp/window pairing and
inclusion retain the existing consumer behavior; tier remains metadata and does
not select a different policy evaluator. This library is not yet selected by
node startup.

The focused service fixture requires a built native node:

```bash
HUBD_BINARY=/path/to/hubd cargo test -p authz --features native --test native_service -- --ignored
```

## Feature flags

| Feature | Default | Purpose |
|---------|---------|---------|
| `vera` | **yes** | [`VeraAuth`](src/vera/mod.rs) and re-export **`AuthzImpl`** = `VeraAuth`. |
| `native` | no | Certified current checks and exact revision anchors. |
| `test-helpers` | no | [`dummy::DummyAuthZ`](src/dummy/mod.rs) — always returns **`true`**; **not for production**. |

Disable defaults only if you wire another `Authz` implementation at the application layer:

```bash
cargo build -p authz --no-default-features
```

## Vera implementation (`feature = "vera"`)

**`VeraAuth`** holds a [`VeraClient`](../common) (from the workspace `common` crate) and implements **`check`** by:

1. Deserializing **`permission`** as JSON **`AccessCheckRequest`** (`policy_id`, `resource`, `object_id`, `permission`, optional `tier`, `timestamp`, optional **`ValidWindow`**).
2. Optionally enforcing a **validity window**: if both **`valid_window`** and **`timestamp`** are set, the timestamp must lie in `[start, end]`; if only one of them is set, **`check`** returns **`InvalidRequest`**.
3. Building an **`AccessRequest`** for the chain (actor = **`subject`**, object = resource + id, operation permission) and calling **`acp_verify_access`** for the given **`policy_id`**.

Helper **`get_policy`** loads a policy record by id (for inspection or tooling).

Construction: **`VeraAuth::new(ChainConfigBuilder)`** — async, connects the client.

**Name string** (for logging / diagnostics): **`"authz/vera"`**.

Integration tests in [`src/vera/tests.rs`](src/vera/tests.rs) use Docker (**Vera** test container); they are serial to avoid port conflicts.

## Dummy implementation (`feature = "test-helpers"`)

**`DummyAuthZ`** implements **`check`** as **`Ok(true)`** regardless of input. Use only in unit tests. See [`src/dummy/README.md`](src/dummy/README.md).

## Errors

[`AuthZError`](src/error.rs): **`Authentication`**, **`InvalidRequest`**, **`ChainError`**, **`NotFound`**.

## Dependencies

- **`async-trait`**, **`serde`** / **`serde_json`**
- **`thiserror`**
- **`common`** (workspace) — chain config, **`VeraClient`**, ACP types

## Tests

```bash
# Unit tests that do not need Docker
cargo test -p authz

# Default feature includes vera; Docker-backed tests run with `cargo test` if present
```

Vera integration tests require a running **Docker** environment as used by **`VeraTestContainer`** in the `common` crate.

## Re-exports

With **`vera`** enabled, the crate root re-exports:

```rust
pub use vera::VeraAuth as AuthzImpl;
```

Application code can depend on **`authz::AuthzImpl`** when building the node with default features.
