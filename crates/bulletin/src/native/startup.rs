//! Native identity preparation and durable worker connection.

use super::{
    decode_node_signing_key, NativeBulletin, NativeBulletinConfig, NativeConfig, NativeVeraClient,
};
use crate::startup::{BulletinFactory, BulletinStartupError, NodeIdentity, PreparedBulletin};
use async_trait::async_trait;
use common::startup::{PrepareContext, StartupProgress};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
#[cfg(test)]
use local_storage::redb::RedbStorage;
use std::{fs, marker::PhantomData, path::Path, sync::Arc};
use vera_client::VeraClient;
use zeroize::Zeroizing;

/// Selects whether a brand-new node accepts a deterministic initial signing
/// key (integration tests) or always generates one randomly (production).
/// Mirrors `vera::startup::VeraStartupPolicy`'s own role for the Cosmos
/// backend exactly — see that trait's doc comment for the rationale.
pub trait NativeStartupPolicy: Send + 'static {
    fn initial_signing_key() -> Option<String>;
}

pub struct ProductionNativeStartup;

impl NativeStartupPolicy for ProductionNativeStartup {
    fn initial_signing_key() -> Option<String> {
        None
    }
}

pub struct NativeBulletinFactory<P = ProductionNativeStartup>(PhantomData<P>);

impl<P: NativeStartupPolicy> BulletinFactory for NativeBulletinFactory<P> {
    const NAME: &'static str = "bulletin/native";
    type Config = NativeBulletinConfig;
    type ValidatedConfig = NativeConfig;
    type Prepared = PreparedNativeBulletin;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, BulletinStartupError> {
        NativeConfig::try_from(config)
            .map_err(|e| BulletinStartupError::Configuration(e.to_string()))
    }

    fn prepare(
        config: Self::ValidatedConfig,
        context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, BulletinStartupError> {
        let initial_key = P::initial_signing_key();
        PreparedNativeBulletin::prepare(
            config,
            context.storage,
            context.runtime_base_path,
            initial_key.as_deref(),
        )
    }
}

pub struct PreparedNativeBulletin {
    identity: NodeIdentity,
    config: NativeConfig,
    writer: NativeVeraClient,
}

impl PreparedNativeBulletin {
    pub fn prepare(
        config: NativeConfig,
        storage: &(impl LocalStorage + ?Sized),
        base: &Path,
        initial_key: Option<&str>,
    ) -> Result<Self, BulletinStartupError> {
        let identity = initialize_identity(storage, base, initial_key)?;
        let writer = NativeVeraClient::open(
            VeraClient::new(&config.endpoint),
            config.trusted,
            config.root,
            config.deployment_id,
            &base.join("native-vera").join(hex::encode(config.root)),
            storage,
        )?;
        Ok(Self {
            identity,
            config,
            writer,
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
            let bulletin = NativeBulletin::connect(
                self.writer,
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

/// `initial_key` is used only when storage has no existing identity — same
/// contract as `startup::cosmos::prepare_signer`'s own `initial_key`
/// parameter. A malformed `initial_key` is a hard error (nothing persisted),
/// not a silent fallback to a random key, so a misconfigured integration
/// test fails loudly rather than running against a key it didn't ask for.
pub fn initialize_identity(
    storage: &(impl LocalStorage + ?Sized),
    base: &Path,
    initial_key: Option<&str>,
) -> Result<NodeIdentity, BulletinStartupError> {
    let stored = storage.get_encrypted(LocalStorageKeys::NodeSigningKey)?;
    let authority = match stored.as_ref() {
        Some(bytes) => decode_node_signing_key(bytes)?,
        None => match initial_key.map(str::trim).filter(|key| !key.is_empty()) {
            Some(key) => decode_node_signing_key(key.as_bytes())?,
            None => loop {
                let mut bytes = Zeroizing::new([0u8; 32]);
                getrandom::getrandom(bytes.as_mut())?;
                if let Ok(key) = vera_client::Secp256k1SigningKey::from_slice(bytes.as_ref()) {
                    break key;
                }
            },
        },
    };
    let key_bytes = Zeroizing::new(authority.to_bytes());
    // generic-array 0.14 deprecates itself wholesale under rustc >= 1.65 ("please
    // upgrade to generic-array 1.x"), but k256's elliptic-curve dep has no
    // non-deprecated path off it yet; the API itself is unaffected.
    #[allow(deprecated)]
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
        let generated = initialize_identity(&storage, dir.path(), None).unwrap();
        assert_eq!(
            initialize_identity(&storage, dir.path(), None).unwrap(),
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
            initialize_identity(&storage, dir.path(), None)
                .unwrap()
                .node_key,
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
            assert!(initialize_identity(&storage, dir.path(), None).is_err());
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

    #[test]
    fn native_identity_uses_initial_key_only_when_storage_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let storage = RedbStorage::new(
            "test".into(),
            dir.path().join("keys.redb").to_string_lossy().into(),
        )
        .unwrap();
        let initial_key_hex = hex::encode([31; 32]);
        let expected = hex::encode(
            k256::ecdsa::SigningKey::from_slice(&[31; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_bytes(),
        );

        let identity = initialize_identity(&storage, dir.path(), Some(&initial_key_hex)).unwrap();
        assert_eq!(identity.node_key, expected);
        assert_eq!(
            storage
                .get_encrypted(LocalStorageKeys::NodeSigningKey)
                .unwrap()
                .unwrap()
                .as_slice(),
            initial_key_hex.as_bytes()
        );

        // Storage is no longer empty -- a different `initial_key` on a later
        // call must not override the now-persisted identity.
        let other_key_hex = hex::encode([32; 32]);
        let unchanged = initialize_identity(&storage, dir.path(), Some(&other_key_hex)).unwrap();
        assert_eq!(unchanged.node_key, expected);
    }

    #[test]
    fn native_identity_rejects_a_malformed_initial_key_without_persisting_anything() {
        let dir = tempfile::tempdir().unwrap();
        let storage = RedbStorage::new(
            "test".into(),
            dir.path().join("keys.redb").to_string_lossy().into(),
        )
        .unwrap();

        assert!(initialize_identity(&storage, dir.path(), Some("not-a-signing-key")).is_err());
        assert!(storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .unwrap()
            .is_none());
    }
}
