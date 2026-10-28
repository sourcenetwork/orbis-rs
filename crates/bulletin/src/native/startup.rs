//! Native identity preparation and durable worker connection.

use super::{
    decode_node_signing_key, NativeBulletin, NativeBulletinConfig, NativeConfig, NativeVeraClient,
};
use crate::startup::{BulletinFactory, BulletinStartupError, NodeIdentity, PreparedBulletin};
use async_trait::async_trait;
use common::startup::{PrepareContext, StartupProgress};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    redb::RedbStorage,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use vera_client::VeraClient;
use zeroize::Zeroizing;

pub struct NativeBulletinFactory;

impl BulletinFactory for NativeBulletinFactory {
    const NAME: &'static str = "bulletin/native";
    type Config = NativeBulletinConfig;
    type Prepared = PreparedNativeBulletin;

    fn prepare(
        config: Self::Config,
        context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, BulletinStartupError> {
        let config = NativeConfig::try_from(config)
            .map_err(|e| BulletinStartupError::Configuration(e.to_string()))?;
        PreparedNativeBulletin::prepare(config, context.storage, context.runtime_base_path)
    }
}

pub struct PreparedNativeBulletin {
    identity: NodeIdentity,
    config: NativeConfig,
    storage: RedbStorage,
    base: PathBuf,
}

impl PreparedNativeBulletin {
    pub fn prepare(
        config: NativeConfig,
        storage: &RedbStorage,
        base: &Path,
    ) -> Result<Self, BulletinStartupError> {
        Ok(Self {
            identity: initialize_identity(storage, base)?,
            config,
            storage: storage.clone(),
            base: base.into(),
        })
    }
}

#[async_trait]
impl PreparedBulletin for PreparedNativeBulletin {
    fn identity(&self) -> &NodeIdentity {
        &self.identity
    }
    fn name(&self) -> &'static str {
        "bulletin/native"
    }

    async fn connect(
        self: Box<Self>,
        _progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn crate::r#trait::Bulletin + Send + Sync>, BulletinStartupError> {
        tokio::time::timeout(self.config.timeout, async {
            let writer = NativeVeraClient::open(
                VeraClient::new(&self.config.endpoint),
                self.config.trusted,
                self.config.root,
                self.config.deployment_id,
                &self
                    .base
                    .join("native-vera")
                    .join(hex::encode(self.config.root)),
                &self.storage,
            )?;
            let bulletin = NativeBulletin::connect(
                writer,
                VeraClient::new(&self.config.endpoint),
                self.config.maximum_age,
                self.config.timeout,
            )
            .await?;
            Ok(Arc::new(bulletin) as Arc<dyn crate::r#trait::Bulletin + Send + Sync>)
        })
        .await?
    }
}

pub fn initialize_identity(
    storage: &RedbStorage,
    base: &Path,
) -> Result<NodeIdentity, BulletinStartupError> {
    let stored = storage.get_encrypted(LocalStorageKeys::NodeSigningKey)?;
    let authority = match stored.as_ref() {
        Some(bytes) => decode_node_signing_key(bytes)?,
        None => loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(bytes.as_mut())?;
            if let Ok(key) = k256::ecdsa::SigningKey::from_slice(bytes.as_ref()) {
                break key;
            }
        },
    };
    let key_bytes = Zeroizing::new(authority.to_bytes());
    let encoded = Zeroizing::new(hex::encode(key_bytes.as_slice()));
    if stored.is_none() {
        storage.set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(encoded.as_bytes().to_vec()),
        )?;
    }
    let node_key = hex::encode(authority.verifying_key().to_sec1_bytes());
    fs::create_dir_all(base).map_err(|source| BulletinStartupError::Io {
        operation: "create identity directory",
        path: base.into(),
        source,
    })?;
    let path = base.join("public_key.txt");
    fs::write(&path, &node_key).map_err(|source| BulletinStartupError::Io {
        operation: "write public identity",
        path,
        source,
    })?;
    Ok(NodeIdentity {
        public_address: node_key.clone(),
        node_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_identity_preserves_existing_keys_and_refuses_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let storage = RedbStorage::new(
            "test".into(),
            dir.path().join("keys.redb").to_string_lossy().into(),
        )
        .unwrap();
        let generated = initialize_identity(&storage, dir.path()).unwrap();
        assert_eq!(
            initialize_identity(&storage, dir.path()).unwrap(),
            generated
        );
        let expected = hex::encode(
            k256::ecdsa::SigningKey::from_slice(&[31; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_bytes(),
        );
        let encoded = hex::encode([31; 32]).into_bytes();
        storage
            .set_encrypted(
                LocalStorageKeys::NodeSigningKey,
                Zeroizing::new(encoded.clone()),
            )
            .unwrap();
        assert_eq!(
            initialize_identity(&storage, dir.path()).unwrap().node_key,
            expected
        );
        assert_eq!(
            storage
                .get_encrypted(LocalStorageKeys::NodeSigningKey)
                .unwrap()
                .unwrap()
                .as_slice(),
            encoded
        );
        for invalid in [
            vec![31; 32],
            format!("0x{}", hex::encode([31; 32])).into_bytes(),
            hex::encode([0; 32]).into_bytes(),
        ] {
            storage
                .set_encrypted(
                    LocalStorageKeys::NodeSigningKey,
                    Zeroizing::new(invalid.clone()),
                )
                .unwrap();
            assert!(initialize_identity(&storage, dir.path()).is_err());
            assert_eq!(
                storage
                    .get_encrypted(LocalStorageKeys::NodeSigningKey)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                invalid
            );
        }
    }
}
