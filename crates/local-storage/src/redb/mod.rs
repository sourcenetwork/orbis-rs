use crate::{
    common::{decrypt_value, derive_cipher, encrypt_value, key_commitment, StoredKdfParams},
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use redb::{Database, ReadableDatabase, TableDefinition, TableError};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("orbis_local");

// Internal keys (prefixed with __internal__ to avoid collisions with serialized
// `LocalStorageKeys`). Salt, KDF parameters, and key commitment are not secret
// and are stored in the clear; the password check is encrypted+AAD-bound.
const INTERNAL_SALT_KEY: &[u8] = b"__internal__salt";
const INTERNAL_KDF_PARAMS_KEY: &[u8] = b"__internal__kdf_params";
const INTERNAL_KEY_COMMITMENT_KEY: &[u8] = b"__internal__key_commitment";
const INTERNAL_PASSWORD_CHECK_KEY: &[u8] = b"__internal__password_check";
const PASSWORD_CHECK_VALUE: &[u8] = b"password_check_ok";

/// Domain separator prefixing every AAD built by this backend.
const AAD_DOMAIN: &[u8] = b"orbis-local-storage-aad-v1";

const NAME: &str = "local-storage/redb";

#[derive(Clone)]
pub struct RedbStorage {
    pub store: Arc<Database>,
    cipher: Aes256Gcm,
    salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests;

impl LocalStorage for RedbStorage {
    fn name() -> String {
        NAME.to_string()
    }

    fn new(password: String, db_path: String) -> Result<Self> {
        let db = open_database(&db_path)?;

        let existing_salt = raw_get(&db, INTERNAL_SALT_KEY)?;

        let (cipher, salt_bytes) = if let Some(stored_salt) = existing_salt {
            // Existing database — re-derive with the *persisted* KDF parameters
            // (a changed default / env override must not silently produce a
            // different key), then check the key commitment before anything else
            // so "wrong password" and "salt/commitment tampered" are
            // distinguishable from a value that merely fails to decrypt.
            let kdf_params = StoredKdfParams::from_bytes(
                &raw_get(&db, INTERNAL_KDF_PARAMS_KEY)?.ok_or(LocalStorageError::CorruptData)?,
            )?;
            let (cipher, key) = derive_cipher(&password, &stored_salt, &kdf_params)?;

            let stored_commitment =
                raw_get(&db, INTERNAL_KEY_COMMITMENT_KEY)?.ok_or(LocalStorageError::CorruptData)?;
            if stored_commitment.len() != 32 || key_commitment(&key)[..] != stored_commitment[..] {
                return Err(LocalStorageError::KeyCommitmentMismatch);
            }

            // Independent AEAD round-trip check (belt-and-suspenders behind the
            // commitment): proves the derived cipher actually decrypts.
            let encrypted_check =
                raw_get(&db, INTERNAL_PASSWORD_CHECK_KEY)?.ok_or(LocalStorageError::CorruptData)?;
            let decrypted = decrypt_value(
                &cipher,
                &internal_aad(INTERNAL_PASSWORD_CHECK_KEY),
                &encrypted_check,
            )
            .map_err(|_| LocalStorageError::InvalidPassword)?;
            if decrypted != PASSWORD_CHECK_VALUE {
                return Err(LocalStorageError::InvalidPassword);
            }

            (cipher, stored_salt)
        } else {
            // New database — KDF parameters come from the default / env override
            // and are persisted so every later open uses these exact values.
            let salt = SaltString::generate(&mut OsRng);
            let salt_bytes = salt.as_salt().as_str().as_bytes().to_vec();
            let kdf_params = StoredKdfParams::for_new_db();
            let (cipher, key) = derive_cipher(&password, &salt_bytes, &kdf_params)?;

            raw_set(&db, INTERNAL_SALT_KEY, &salt_bytes)?;
            raw_set(&db, INTERNAL_KDF_PARAMS_KEY, &kdf_params.to_bytes())?;
            raw_set(&db, INTERNAL_KEY_COMMITMENT_KEY, &key_commitment(&key))?;
            let encrypted_check = encrypt_value(
                &cipher,
                &internal_aad(INTERNAL_PASSWORD_CHECK_KEY),
                PASSWORD_CHECK_VALUE,
            )?;
            raw_set(&db, INTERNAL_PASSWORD_CHECK_KEY, &encrypted_check)?;

            (cipher, salt_bytes)
        };

        Ok(Self {
            store: db.into(),
            cipher,
            salt: Some(salt_bytes),
        })
    }

    fn get(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        let key_bytes = serialize_key(&key)?;
        raw_get(&self.store, &key_bytes)
    }

    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        raw_set(&self.store, &key_bytes, &value)
    }

    fn delete(&self, key: LocalStorageKeys) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        raw_delete(&self.store, &key_bytes)
    }

    fn contains(&self, key: LocalStorageKeys) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key_bytes = serialize_key(&key)?;
        let Some(stored) = raw_get(&self.store, &key_bytes)? else {
            return Ok(None);
        };

        let aad = slot_aad(&key_bytes);
        decrypt_value(&self.cipher, &aad, &stored)
            .map(Zeroizing::new)
            .map(Some)
            .map_err(|_| LocalStorageError::IntegrityCheckFailed)
    }

    fn set_encrypted(&self, key: LocalStorageKeys, value: Zeroizing<Vec<u8>>) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        let value_blob = encrypt_value(&self.cipher, &slot_aad(&key_bytes), &value)?;
        raw_set(&self.store, &key_bytes, &value_blob)
    }
}

/// AAD binding a stored value to its slot. Stops a ciphertext from one slot being
/// substituted into another within the same database — e.g. a `RingKey(A)` share
/// dropped into `RingKey(B)`'s slot, or a share blob dropped into the
/// `NodeSigningKey` slot — which the shared key alone would not catch.
///
/// Cross-*database* isolation comes for free from the random per-database salt
/// (a shared password still yields different keys). Rollback of a slot to an
/// earlier value of its own is *not* detected — see SEC-04 in
/// `docs/security-review-findings.md` for why that was deliberately left out.
///
/// `AAD_DOMAIN` is fixed-length so `key_bytes` (a `bincode`-encoded
/// `LocalStorageKeys`) needs no length prefix to be unambiguous.
fn slot_aad(key_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + key_bytes.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(key_bytes);
    aad
}

/// AAD for the backend's own encrypted internal slots. The `internal:` prefix
/// keeps these distinct from data-slot AAD (a `bincode`-encoded `LocalStorageKeys`
/// starts with a little-endian variant index, never ASCII).
fn internal_aad(internal_key: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 9 + internal_key.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(b"internal:");
    aad.extend_from_slice(internal_key);
    aad
}

/// Create parent directories as needed and open (or create) the redb database.
fn open_database(db_path: &str) -> Result<Database> {
    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                LocalStorageError::UniqueDBError(format!(
                    "Failed to create database directory: {}",
                    e
                ))
            })?;
        }
    }

    Database::create(db_path)
        .map_err(|e| LocalStorageError::UniqueDBError(format!("Failed to create database: {}", e)))
}

fn serialize_key(key: &LocalStorageKeys) -> Result<Vec<u8>> {
    bincode::serialize(key)
        .map_err(|e| LocalStorageError::UniqueDBError(format!("Failed to serialize key: {}", e)))
}

/// Raw get operation on database (used during initialization before self exists)
fn raw_get(db: &Database, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let read_txn = db.begin_read().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to begin read transaction: {}", e))
    })?;
    let table = match read_txn.open_table(TABLE) {
        Ok(table) => table,
        Err(TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(error) => {
            return Err(LocalStorageError::UniqueDBError(format!(
                "Failed to open table: {}",
                error
            )));
        }
    };
    let value = table
        .get(key)
        .map_err(|e| LocalStorageError::UniqueDBError(format!("Failed to get value: {}", e)))?;
    Ok(value.map(|v| v.value().to_vec()))
}

/// Raw set operation on database
fn raw_set(db: &Database, key: &[u8], value: &[u8]) -> Result<()> {
    let write_txn = db.begin_write().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to begin write transaction: {}", e))
    })?;
    {
        let mut table = write_txn.open_table(TABLE).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        table.insert(key, value).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to insert value: {}", e))
        })?;
    }
    write_txn.commit().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to commit transaction: {}", e))
    })?;
    Ok(())
}

/// Raw delete operation on database
fn raw_delete(db: &Database, key: &[u8]) -> Result<()> {
    let write_txn = db.begin_write().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to begin write transaction: {}", e))
    })?;
    {
        let mut table = write_txn.open_table(TABLE).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        table.remove(key).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to delete value: {}", e))
        })?;
    }
    write_txn.commit().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to commit transaction: {}", e))
    })?;
    Ok(())
}

impl std::fmt::Debug for RedbStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbStorage")
            .field("store", &"<Database>")
            .field("cipher", &"<Aes256Gcm>")
            .field("salt", &self.salt.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}
