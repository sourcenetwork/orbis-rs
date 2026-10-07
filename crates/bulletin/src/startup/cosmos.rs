//! Cosmos identity support shared by chain and injected bulletin startup.

use super::{NodeIdentity, StartupError};
use common::blockchain::{ChainConfig, TxSigner};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub fn identity(signer: &TxSigner) -> NodeIdentity {
    NodeIdentity {
        node_key: signer.public_key_hex(),
        public_address: signer.address(),
    }
}

/// Read an existing encrypted key; a storage error never generates a replacement.
pub fn read_signer(
    storage: &impl LocalStorage,
    config: ChainConfig,
) -> Result<TxSigner, StartupError> {
    let bytes = storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)?
        .ok_or(StartupError::MissingIdentity)?;
    Ok(TxSigner::from_hex_key(
        std::str::from_utf8(&bytes)?,
        config,
    )?)
}

/// Prepare the stored signing identity and its public address file.
/// `initial_key` is used only when storage has no existing identity.
pub fn prepare_signer(
    storage: &impl LocalStorage,
    config: ChainConfig,
    base: &Path,
    initial_key: Option<&str>,
) -> Result<TxSigner, StartupError> {
    fs::create_dir_all(base).map_err(|source| StartupError::Io {
        operation: "create identity directory",
        path: base.into(),
        source,
    })?;
    let stored = storage.get_encrypted(LocalStorageKeys::NodeSigningKey)?;
    let encoded = match stored.as_ref() {
        Some(bytes) => Zeroizing::new(std::str::from_utf8(bytes)?.to_owned()),
        None => {
            let key = match initial_key.map(str::trim).filter(|key| !key.is_empty()) {
                Some(key) => Zeroizing::new(key.to_owned()),
                None => {
                    let mut bytes = Zeroizing::new([0u8; 32]);
                    getrandom::getrandom(bytes.as_mut())?;
                    Zeroizing::new(hex::encode(bytes.as_ref()))
                }
            };
            storage.set_encrypted(
                LocalStorageKeys::NodeSigningKey,
                Zeroizing::new(key.as_bytes().to_vec()),
            )?;
            key
        }
    };
    let signer = TxSigner::from_hex_key(&encoded, config)?;
    let path = base.join("public_key.txt");
    fs::write(&path, signer.address()).map_err(|source| StartupError::Io {
        operation: "write public identity",
        path,
        source,
    })?;
    Ok(signer)
}
