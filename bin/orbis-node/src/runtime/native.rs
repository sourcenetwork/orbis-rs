use super::*;
use authz::native::NativeAuth;
use bulletin::native::{decode_node_signing_key, NativeBulletin, NativeVeraClient};
use hub_client::HubClient;
use local_storage::r#trait::LocalStorageKeys;
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub(super) use bulletin::native::NativeConfig as Config;

fn initialize_identity(
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
    if stored
        .as_ref()
        .is_none_or(|bytes| bytes.as_slice() != encoded.as_bytes())
    {
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

pub(super) async fn run(
    config: Config,
    args: Args,
    cors_policy: CorsPolicy,
    network: Arc<dyn Network>,
    local_storage: LocalStorageImpl,
    base: PathBuf,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node_key = initialize_identity(&local_storage, &base)?;
    let bootstrap = start_bootstrap_info_server_with_identity(
        args.addr.parse()?,
        network.clone(),
        local_storage.clone(),
        cors_policy.clone(),
        Some(node_key.clone()),
    )?;
    tracing::info!(grpc_addr = %bootstrap.local_addr(), "Connecting to native Vera");
    let initialization = async move {
        let (authz, bulletin) = tokio::time::timeout(config.timeout, async {
            let authz = NativeAuth::connect(
                HubClient::new(&config.endpoint),
                config.trusted,
                config.root,
                config.maximum_age,
            )
            .await?;
            let writer = NativeVeraClient::open(
                HubClient::new(&config.endpoint),
                config.trusted,
                config.root,
                config.deployment_id,
                &base.join("native-vera").join(hex::encode(config.root)),
                &local_storage,
            )?;
            let bulletin = NativeBulletin::connect(
                writer,
                HubClient::new(&config.endpoint),
                config.maximum_age,
                config.timeout,
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error>>((authz, bulletin))
        })
        .await
        .map_err(|_| "native Vera connection timed out")??;
        ensure_node_info(&bulletin, &node_key, network.as_ref(), &args).await?;
        init_node(NodeConfig {
            args,
            cors_policy,
            node_key,
            network,
            local_storage,
            authz: Arc::new(authz),
            bulletin: Arc::new(bulletin),
        })
        .await
    };
    let Some(node) =
        complete_initialization_or_shutdown(bootstrap, initialization, shutdown.clone()).await?
    else {
        return Ok(());
    };
    run_server(node, shutdown).await
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
        for encoded in [
            vec![31; 32],
            hex::encode([31; 32]).into_bytes(),
            format!("0x{}", hex::encode([31; 32])).into_bytes(),
        ] {
            storage
                .set_encrypted(LocalStorageKeys::NodeSigningKey, Zeroizing::new(encoded))
                .unwrap();
            assert_eq!(initialize_identity(&storage, dir.path()).unwrap(), expected);
            assert_eq!(
                storage
                    .get_encrypted(LocalStorageKeys::NodeSigningKey)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                hex::encode([31; 32]).as_bytes()
            );
        }
        let corrupt = vec![0; 32];
        storage
            .set_encrypted(
                LocalStorageKeys::NodeSigningKey,
                Zeroizing::new(corrupt.clone()),
            )
            .unwrap();
        assert!(initialize_identity(&storage, dir.path()).is_err());
        assert_eq!(
            storage
                .get_encrypted(LocalStorageKeys::NodeSigningKey)
                .unwrap()
                .unwrap()
                .as_slice(),
            corrupt
        );
    }
}
