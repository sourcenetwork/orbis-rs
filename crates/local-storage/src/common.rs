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

/// The Argon2id cost parameters a database was created with.
///
/// Persisted (plaintext, not secret) alongside the salt so that reopening a
/// database always re-derives its key with the *same* parameters. A change to
/// the compiled-in default or the environment override would otherwise silently
/// produce a different key and fail the key-commitment check on the next open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredKdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// `argon2::Version` in numeric form (`0x13` == 19).
    pub version: u32,
}

impl StoredKdfParams {
    pub const SERIALIZED_LEN: usize = 16;

    /// Parameters for a **new** database: strong by default (256 MiB, t=3);
    /// weak for this crate's own unit tests (`cfg!(test)`); overridable via
    /// `ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB` / `ORBIS_LOCAL_STORAGE_KDF_T_COST`
    /// so test suites with many `RedbStorage::new` calls aren't each forced
    /// through a hundreds-of-millisecond derivation. Existing databases ignore
    /// this and use their persisted values.
    pub fn for_new_db() -> Self {
        fn env_u32(name: &str) -> Option<u32> {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| *v > 0)
        }
        let (default_m, default_t) = if cfg!(test) { (8, 1) } else { (262_144, 3) };
        Self {
            m_cost_kib: env_u32("ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB").unwrap_or(default_m),
            t_cost: env_u32("ORBIS_LOCAL_STORAGE_KDF_T_COST").unwrap_or(default_t),
            p_cost: 1,
            version: u32::from(Version::V0x13),
        }
    }

    pub fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut out = [0u8; Self::SERIALIZED_LEN];
        out[0..4].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.t_cost.to_le_bytes());
        out[8..12].copy_from_slice(&self.p_cost.to_le_bytes());
        out[12..16].copy_from_slice(&self.version.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(LocalStorageError::CorruptData);
        }
        let u32_at = |i: usize| {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[i..i + 4]);
            u32::from_le_bytes(b)
        };
        Ok(Self {
            m_cost_kib: u32_at(0),
            t_cost: u32_at(4),
            p_cost: u32_at(8),
            version: u32_at(12),
        })
    }

    fn argon2(&self) -> Result<Argon2<'static>> {
        let version = Version::try_from(self.version).map_err(|e| {
            LocalStorageError::KeyDerivationError(format!(
                "unsupported Argon2 version {}: {}",
                self.version, e
            ))
        })?;
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| LocalStorageError::KeyDerivationError(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, version, params))
    }
}

/// Encrypt `value` under `cipher` with `aad` bound into the AES-256-GCM tag.
///
/// Layout: `nonce(12) || ciphertext || tag(16)`. `aad` is authenticated but not
/// stored — the reader recomputes it, so a ciphertext only decrypts in the exact
/// context (slot id) it was written in.
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

/// Derive the 32-byte AES key and its GCM cipher from `password`, `salt`, and
/// `params` using Argon2id. Returns the raw key too so the caller can store /
/// verify the key commitment.
pub fn derive_cipher(
    password: &str,
    salt: &[u8],
    params: &StoredKdfParams,
) -> Result<(Aes256Gcm, Zeroizing<[u8; 32]>)> {
    let argon2 = params.argon2()?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_kdf_params_round_trip() {
        let params = StoredKdfParams {
            m_cost_kib: 262_144,
            t_cost: 3,
            p_cost: 1,
            version: u32::from(Version::V0x13),
        };
        let bytes = params.to_bytes();
        assert_eq!(bytes.len(), StoredKdfParams::SERIALIZED_LEN);
        assert_eq!(StoredKdfParams::from_bytes(&bytes).unwrap(), params);
        assert!(matches!(
            StoredKdfParams::from_bytes(&bytes[..15]),
            Err(LocalStorageError::CorruptData)
        ));
    }

    #[test]
    fn stored_kdf_params_argon2_rejects_unknown_version() {
        let bad = StoredKdfParams {
            version: 999,
            ..StoredKdfParams::for_new_db()
        };
        assert!(bad.argon2().is_err());
    }
}
