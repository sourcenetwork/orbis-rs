use super::backend::Services;
use authz::native::NativeAuth;
use bulletin::native::{decode_node_signing_key, NativeBulletin, NativeVeraClient};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use std::{fs, path::Path, sync::Arc};
use vera_client::VeraClient;
use zeroize::Zeroizing;

pub(super) use bulletin::native::NativeConfig as Config;

pub(super) fn initialize_identity(
    storage: &LocalStorageImpl,
    base: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
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
    fs::create_dir_all(base)?;
    fs::write(base.join("public_key.txt"), &node_key)?;
    Ok(node_key)
}

pub(super) async fn connect(
    config: Config,
    storage: &LocalStorageImpl,
    base: &Path,
) -> Result<Services, Box<dyn std::error::Error>> {
    tokio::time::timeout(config.timeout, async {
        let authz = NativeAuth::connect(
            VeraClient::new(&config.endpoint),
            config.trusted,
            config.root,
            config.maximum_age,
        )
        .await?;
        let writer = NativeVeraClient::open(
            VeraClient::new(&config.endpoint),
            config.trusted,
            config.root,
            config.deployment_id,
            &base.join("native-vera").join(hex::encode(config.root)),
            storage,
        )?;
        let bulletin = NativeBulletin::connect(
            writer,
            VeraClient::new(&config.endpoint),
            config.maximum_age,
            config.timeout,
        )
        .await?;
        Ok(Services {
            authz: Arc::new(authz),
            bulletin: Arc::new(bulletin),
        })
    })
    .await
    .map_err(|_| "native Vera connection timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_identity_preserves_existing_keys_and_refuses_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorageImpl::new(
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
        assert_eq!(initialize_identity(&storage, dir.path()).unwrap(), expected);
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
