# Local Storage Crate

Encrypted local key-value storage for persisting node secrets.

## Overview

This crate provides:
- **LocalStorage trait** for pluggable storage backends
- **MemoryStorage** implementation with optional encryption
- **AES-256-GCM encryption** with Argon2 key derivation

## Trait

```rust
pub trait LocalStorage {
    /// Create a new storage instance
    /// If password is provided, encrypted operations will use it
    fn new(password: Option<String>) -> Self;

    /// Get an item from storage (unencrypted)
    fn get(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>>;

    /// Set an item in storage (unencrypted)
    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()>;

    /// Delete an item from storage
    fn delete(&self, key: LocalStorageKeys) -> Result<()>;

    /// Check if an item exists
    fn contains(&self, key: LocalStorageKeys) -> Result<bool>;

    /// Get and decrypt an item (requires password)
    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>>;

    /// Encrypt and store an item (requires password)
    fn set_encrypted(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()>;
}
```

## Storage Keys

```rust
pub enum LocalStorageKeys {
    /// Node's ring key share + polynomial (encrypted at rest)
    RingKey(String),

    /// Index of rings this node has joined: Vec<RingIndexEntry> (ring_pk_str + bulletin_post_id)
    RingIndex,

    /// The node's iroh secret key for deterministic peer identity
    NodeSecretKey,

    /// The node's secp256k1 signing key for chain transactions
    NodeSigningKey,
}
```

## Usage

### Basic Storage (Unencrypted)

```rust
use local_storage::LocalStorageImpl;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};

// Create storage without encryption
let storage = LocalStorageImpl::new(None, "".to_string());

// Store and retrieve data
storage.set(LocalStorageKeys::RingKey("abc123".into()), vec![1, 2, 3])?;
let data = storage.get(LocalStorageKeys::RingKey("abc123".into()))?;
```

### Encrypted Storage

```rust
use local_storage::LocalStorageImpl;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};

// Create storage with password for encryption
let storage = LocalStorageImpl::new(Some("my-secret-password".to_string()), "".to_string());

// Store sensitive data encrypted
let secret_share = vec![/* ... secret bytes ... */];
storage.set_encrypted(
    LocalStorageKeys::RingKey("session-123".into()),
    secret_share
)?;

// Retrieve and decrypt
let decrypted = storage.get_encrypted(
    LocalStorageKeys::RingKey("session-123".into())
)?;
```

## MemoryStorage Implementation

The `MemoryStorage` backend stores data in an in-memory `HashMap`.

**Encryption Details:**
- **Key Derivation**: Argon2id with configurable parameters
- **Encryption**: AES-256-GCM authenticated encryption
- **Nonce**: 12-byte random nonce prepended to ciphertext
- **Format**: `[nonce (12 bytes)][ciphertext][auth tag (16 bytes)]`

```rust
// Encryption parameters
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;  // AES-256

// Argon2 parameters (configurable)
// - Memory: 64 MB
// - Iterations: 3
// - Parallelism: 4
```

## Security Considerations

1. **Secure Memory Handling**: Derived key bytes are wrapped in `Zeroizing<[u8; 32]>` and automatically zeroed when they go out of scope, preventing key material from lingering in memory
2. **Key Derivation**: Argon2id provides resistance against GPU/ASIC attacks
3. **Nonce Generation**: Uses `OsRng` for cryptographically secure random nonces
4. **Authentication**: GCM mode provides both confidentiality and integrity

## Dependencies

- `aes-gcm` - AES-256-GCM authenticated encryption
- `argon2` - Password-based key derivation
- `rand` - Secure random number generation
- `serde` - Serialization for storage keys
- `zeroize` - Secure memory zeroing for sensitive data
