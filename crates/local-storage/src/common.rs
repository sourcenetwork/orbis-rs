use crate::error::{LocalStorageError, Result};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Domain separator for the key-commitment hash. Storing `SHA-256(DOMAIN || key)`
/// lets a reader tell "wrong password" apart from "salt / keying material
/// tampered" without revealing the key.
const KEY_COMMIT_DOMAIN: &[u8] = b"orbis-local-storage-key-commit-v1";

/// Argon2id memory / iteration cost. Strong by default (256 MiB, t=3) — this is
/// derived once per process at storage open. Overridable via
/// `ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB` / `ORBIS_LOCAL_STORAGE_KDF_T_COST` so the
/// test suites (many `RedbStorage::new` calls) are not each forced through a
/// hundreds-of-millisecond derivation; unit tests in this crate default weak.
fn kdf_params() -> Result<Params> {
    fn env_u32(name: &str) -> Option<u32> {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
    }
    let (default_m, default_t) = if cfg!(test) { (8, 1) } else { (262_144, 3) };
    let m_cost = env_u32("ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB").unwrap_or(default_m);
    let t_cost = env_u32("ORBIS_LOCAL_STORAGE_KDF_T_COST").unwrap_or(default_t);
    Params::new(m_cost, t_cost, 1, Some(32))
        .map_err(|e| LocalStorageError::KeyDerivationError(e.to_string()))
}

/// Encrypt `value` under `cipher` with `aad` bound into the AES-256-GCM tag.
///
/// Layout: `nonce(12) || ciphertext || tag(16)`. `aad` is authenticated but not
/// stored — the reader recomputes it, so a ciphertext only decrypts in the exact
/// context (slot id, database id) it was written in.
pub fn encrypt_value(cipher: &Aes256Gcm, aad: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: value, aad })
        .map_err(|_| LocalStorageError::EncryptionError)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a value produced by [`encrypt_value`], authenticating it against
/// `aad`. Returns [`LocalStorageError::DecryptionError`] on any tag failure —
/// wrong key, tampered bytes, or `aad` that does not match the write context.
pub fn decrypt_value(cipher: &Aes256Gcm, aad: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 {
        return Err(LocalStorageError::CorruptData);
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| LocalStorageError::DecryptionError)
}

/// Derive the 32-byte AES key and its GCM cipher from `password` and `salt`
/// using Argon2id. Returns the raw key too so the caller can store / verify the
/// key commitment.
pub fn derive_cipher(password: &str, salt: &[u8]) -> Result<(Aes256Gcm, Zeroizing<[u8; 32]>)> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, kdf_params()?);

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key_bytes.as_mut())
        .map_err(|e| LocalStorageError::KeyDerivationError(e.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
    Ok((cipher, key_bytes))
}

/// `SHA-256(KEY_COMMIT_DOMAIN || key)`. Preimage resistance means storing this in
/// the clear does not weaken the key; a mismatch on open means the password is
/// wrong or the salt/commitment was swapped.
pub fn key_commitment(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_COMMIT_DOMAIN);
    hasher.update(key);
    hasher.finalize().into()
}

/// Generate a random 32-byte per-database identifier. Mixed into every value's
/// AAD so a ciphertext from one database (e.g. another committee member's, under
/// a shared password) cannot be substituted into this one. Not secret.
pub fn generate_db_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    id
}
