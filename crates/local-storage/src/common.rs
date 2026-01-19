use crate::error::{LocalStorageError, Result};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::Argon2;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Encrypt a value with the given cipher
pub fn encrypt_value(cipher: &Aes256Gcm, value: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, value)
        .map_err(|_| LocalStorageError::EncryptionError)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a value with the given cipher
pub fn decrypt_value(cipher: &Aes256Gcm, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 {
        return Err(LocalStorageError::CorruptData);
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LocalStorageError::DecryptionError)
}

/// Derive cipher from password and salt using Argon2
pub fn derive_cipher(password: &str, salt: &[u8]) -> Result<Aes256Gcm> {
    let argon2 = Argon2::default();
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key_bytes.as_mut())
        .map_err(|e| LocalStorageError::KeyDerivationError(e.to_string()))?;
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(
        key_bytes.as_ref(),
    )))
}
