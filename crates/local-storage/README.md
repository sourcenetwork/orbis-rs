# Local storage crate

Encrypted local key-value storage for persisting node secrets (ring shares, indexes, keys). Two pluggable backends share the same crypto and [`LocalStorage`](src/trait.rs) API.

## Backends (features)

| Feature | Default | Type alias | Persistence |
|---------|---------|------------|-------------|
| `redb` | **yes** | `LocalStorageImpl` = [`RedbStorage`](src/redb/mod.rs) | Embedded [`redb`](https://crates.io/crates/redb) database at `db_path` |
| `memory` | no | `LocalStorageImpl` = [`MemoryStorage`](src/memory/mod.rs) | In-memory `HashMap` (tests / ephemeral) |

**`redb` and `memory` are mutually exclusive.** Use `--no-default-features --features memory` to build the in-memory backend only.

## `LocalStorage` trait

See [`src/trait.rs`](src/trait.rs) for the full definition. Summary:

- **`name() -> String`** — Backend identifier (e.g. `"local-storage/redb"`).
- **`new(password: Option<String>, db_path: String) -> Result<Self>`** — `db_path` is the database file path for **`redb`**; **`memory`** ignores it but the parameter is still required for a uniform API.
- **`get` / `set` / `delete` / `contains`** — Plain bytes at rest (no extra encryption layer from these helpers).
- **`get_encrypted` / `set_encrypted`** — AES-256-GCM at rest using a key derived from **`password`** when provided; plaintext is handled as **`Zeroizing`** so sensitive buffers are cleared on drop.

Return types match the code: **`get_encrypted`** returns **`Result<Option<Zeroizing<Vec<u8>>>>`**; **`set_encrypted`** takes **`Zeroizing<Vec<u8>>`**.

### Password behavior

- **With `Some(password)`**: Argon2 key derivation from password + stored salt (**`redb`** persists salt and an encrypted password check; **`memory`** keeps salt only in RAM). Opening an existing **`redb`** DB verifies the password before returning.
- **With `None`**: A random 32-byte AES key is generated per process (**not persisted**). `get_encrypted` / `set_encrypted` still encrypt stored blobs, but the key is lost on restart — suitable only for ephemeral use; do not rely on it for durable encrypted storage without a password.

## `LocalStorageKeys`

```rust
pub enum LocalStorageKeys {
    /// Encrypted `RingShareBundle` for one ring, keyed by `aggregate_pk.to_string()`.
    /// Threshold share, public polynomial, last PSS refresh time — not ring config
    /// (peer_ids, threshold, etc. live on the bulletin).
    RingKey(String),
    /// JSON `Vec<RingIndexEntry>`: local key + bulletin `post_id` for `RingPayload`.
    RingIndex,
    NodeSecretKey,
    NodeSigningKey,
}
```

## Usage

### `LocalStorageImpl` (default: Redb)

```rust
use local_storage::LocalStorageImpl;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use zeroize::Zeroizing;

let storage = LocalStorageImpl::new(
    Some("my-secret-password".to_string()),
    "/path/to/orbis.db".to_string(),
)?;

let secret_share = Zeroizing::new(vec![/* ... */]);
storage.set_encrypted(LocalStorageKeys::RingKey("aggregate_pk_hex".into()), secret_share)?;

let decrypted = storage.get_encrypted(LocalStorageKeys::RingKey("aggregate_pk_hex".into()))?;
```

Unencrypted keys (e.g. index blobs) use **`get`** / **`set`** as plain **`Vec<u8>`**.

## Crypto details ([`src/common.rs`](src/common.rs))

- **KDF**: **`argon2::Argon2::default()`** with **`hash_password_into`** into a 32-byte key (see the [`argon2`](https://docs.rs/argon2) crate for default time / memory / parallelism).
- **AEAD**: **AES-256-GCM**; 12-byte random nonce prepended to the ciphertext returned by **`aes-gcm`** (ciphertext includes the authentication tag).
- **Nonces**: **`OsRng`** / **`rand_core`** for nonce and ephemeral keys.

## Security notes

1. **Zeroizing**: Derived keys and decrypted plaintext use **`zeroize`** where applicable so sensitive bytes are cleared when dropped.
2. **Authentication**: GCM provides confidentiality and integrity for **`get_encrypted`** / **`set_encrypted`** payloads.
3. **No password**: Random-key mode does **not** survive restart; use a password for durable encrypted storage.

## Dependencies (high level)

- **`aes-gcm`**, **`argon2`**, **`rand`**, **`rand_core`**, **`zeroize`**, **`serde`**, **`thiserror`**
- **`redb`**, **`bincode`** — disk backend and key serialization
- **`memory`** backend adds no extra deps beyond the shared stack
