# Authz crate

Async **authorization** behind a small trait: given opaque **`permission`** bytes and a **`subject`** (caller identity string), decide whether access is allowed.

The implementation verifies **Vera** permission proofs and evaluates **ACP** (access-control policy) membership locally. A **dummy** allow-all backend exists only for tests.

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

## Vera authorization

The `vera` feature (default) exposes `vera::VeraAuth`. Connect it with a service
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
not select a different policy evaluator. Node startup selects this
implementation at compile time (the `authz-vera` build feature); the
node's `--services-config` `authz` section supplies its endpoint, deployment
root and consensus key.

Vera failures are defined in [`vera::error`](src/vera/error.rs). The shared
`AuthZError` wraps that concrete error only when `vera` is enabled, preserving
client, decoding, identity, clock and anchor-parsing sources.

The focused service fixture requires a built `verad`:

```bash
VERAD_BINARY=/path/to/verad cargo test -p authz --features vera --test vera_service -- --ignored
```

## Feature flags

| Feature | Default | Purpose |
|---------|---------|---------|
| `vera` | **yes** | [`VeraAuth`](src/vera/mod.rs): certified current checks and exact revision anchors. |
| `startup` | no | `AuthzFactory`/`PreparedAuthz` traits. |
| `select-vera` | no | Re-exports `AuthzFactoryImpl` = `VeraAuthzFactory` for the node's services composer. |
| `test-helpers` | no | [`dummy::DummyAuthZ`](src/dummy/mod.rs) — always returns **`true`**; **not for production**. |

## Dummy implementation (`feature = "test-helpers"`)

**`DummyAuthZ`** implements **`check`** as **`Ok(true)`** regardless of input. Use only in unit tests. See [`src/dummy/README.md`](src/dummy/README.md).

## Errors

[`AuthZError`](src/error.rs): **`Native`** (wrapping `vera::Error`), **`Authentication`**, **`InvalidRequest`**, **`ChainError`**, **`NotFound`**.

## Tests

```bash
cargo test -p authz
```
