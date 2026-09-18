//! Bulletin operations: namespace/collaborator administration and posting/reading
//! bulletin entries (documents, rings, key derivations).

use anyhow::{anyhow, Result};
use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, KeyDerivation, RingPayload};
use bulletin::vera::VeraBulletin;
use common::blockchain::{ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY};
use crypto::r#trait::ThresholdSigner;
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine as G1Affine, SignImpl};

use super::chain::{chain_config_builder, signed_vera_client, vera_client};

pub async fn register_bulletin_namespace(
    namespace: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let read_client = VeraClient::new(config.clone())
        .await
        .map_err(|e| anyhow!("Failed to create chain client: {}", e))?;

    if read_client.bulletin_get_namespace(&namespace).await.is_ok() {
        println!("Bulletin namespace already exists: {}", namespace);
        return Ok(());
    }

    let client = signed_vera_client(config, signing_key_hex).await?;

    match client.bulletin_register_namespace(&namespace).await {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") || msg.contains("namespace already exists") {
                println!("Bulletin namespace already exists: {}", namespace);
                return Ok(());
            }
            return Err(anyhow!("Failed to register namespace: {}", e));
        }
    }

    println!("Registered bulletin namespace: {}", namespace);
    Ok(())
}

pub async fn add_bulletin_collaborator(
    namespace: String,
    collaborator_address: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;

    let result = match client
        .bulletin_add_collaborator(&namespace, &collaborator_address)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") || msg.contains("collaborator already exists") {
                println!(
                    "Collaborator {} already on namespace {}",
                    collaborator_address, namespace
                );
                return Ok(());
            }
            return Err(anyhow!("Failed to add collaborator: {}", e));
        }
    };

    if result.code != 0 {
        let log = result.log;
        if log.contains("already exists") || log.contains("collaborator already exists") {
            println!(
                "Collaborator {} already on namespace {}",
                collaborator_address, namespace
            );
            return Ok(());
        }
        return Err(anyhow!(
            "Failed to add collaborator: code {} {}",
            result.code,
            log
        ));
    }

    println!(
        "Added collaborator {} to namespace {}",
        collaborator_address, namespace
    );
    Ok(())
}

pub async fn create_bulletin_post(kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String> {
    create_bulletin_post_with_config(kind, payload, ChainConfig::local()).await
}

pub async fn create_bulletin_post_with_config(
    kind: BulletinWriteKind,
    payload: Vec<u8>,
    config: ChainConfig,
) -> Result<String> {
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let bulletin = VeraBulletin::with_signer(chain_config_builder(&config), signer, None)
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    let post_id = bulletin
        .post(kind, payload)
        .await
        .map_err(|e| anyhow!("Failed to create post: {}", e))?;

    println!("Created bulletin post with ID: {}", post_id);
    Ok(post_id)
}

pub async fn read_bulletin_post_with_config(
    id: String,
    kind: BulletinKind,
    config: ChainConfig,
) -> Result<Vec<u8>> {
    let bulletin = VeraBulletin::new(chain_config_builder(&config))
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    let post = bulletin
        .read(id, kind)
        .await
        .map_err(|e| anyhow!("Failed to read bulletin post: {}", e))?;

    Ok(post.payload)
}

/// List all bulletin posts in a namespace
pub async fn list_bulletin_posts(namespace: String, config: ChainConfig) -> Result<Vec<Vec<u8>>> {
    let client = vera_client(config).await?;

    let posts = client
        .bulletin_list_posts(&namespace)
        .await
        .map_err(|e| anyhow!("Failed to list bulletin posts: {}", e))?;

    Ok(posts.into_iter().map(|p| p.payload).collect())
}

/// Post a `KeyDerivation` to the bulletin under `namespace`.
///
/// Returns `(post_id, derived_pk_hex)` where `post_id` is used as the
/// `derivation_id` in sign requests and `derived_pk_hex` is the public key
/// derived from the ring PK and the derivation bytes.
///
/// The caller must ensure the node's public address has been added as a
/// collaborator on the namespace before posting.
async fn post_key_derivation_impl(
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<(String, String)> {
    // Fetch ring payload from bulletin to get the ring public key
    let ring_bulletin = VeraBulletin::new(chain_config_builder(&config))
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;
    let ring_post = ring_bulletin
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .map_err(|e| anyhow!("Failed to read ring post '{}': {}", ring_id, e))?;
    let ring_payload: RingPayload = serde_json::from_slice(&ring_post.payload)
        .map_err(|e| anyhow!("Failed to parse RingPayload: {}", e))?;

    // Compute derived public key using the signer's derivation (not PRE's)
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
        .map_err(|e| anyhow!("Invalid ring_pk hex in bulletin: {}", e))?;
    let ring_pk_point =
        G1Affine::from_bytes(&ring_pk_bytes).map_err(|e| anyhow!("Invalid ring_pk: {}", e))?;
    let metadata = SignImpl::encode_metadata(&policy_id, &resource, &permission);
    let derived_pk =
        SignImpl::derive_public_key(&ring_pk_point, derivation.as_bytes(), Some(&metadata))
            .map_err(|e| anyhow!("Failed to derive public key: {}", e))?;
    let derived_pk_hex = hex::encode(
        derived_pk
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize derived_pk: {}", e))?,
    );

    let signer = TxSigner::from_hex_key(signing_key_hex, config.clone())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let bulletin = VeraBulletin::with_signer(chain_config_builder(&config), signer, None)
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    let key_derivation = KeyDerivation {
        ring_id: ring_id.clone(),
        derivation: derivation.clone(),
        policy_id: policy_id.clone(),
        resource: resource.clone(),
        permission: permission.clone(),
    };

    let payload: Vec<u8> = serde_json::to_vec(&key_derivation)
        .map_err(|e| anyhow!("Failed to serialize KeyDerivation: {}", e))?;

    let post_id = bulletin
        .post(BulletinWriteKind::KeyDerivation, payload)
        .await
        .map_err(|e| anyhow!("Failed to post KeyDerivation: {}", e))?;

    println!(
        "Posted KeyDerivation: derivation_id={} derived_pk={}",
        post_id, derived_pk_hex
    );
    Ok((post_id, derived_pk_hex))
}

pub async fn post_key_derivation(
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<(String, String)> {
    post_key_derivation_impl(
        ring_id,
        derivation,
        policy_id,
        resource,
        permission,
        config,
        signing_key_hex,
    )
    .await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn post_key_derivation_with_config(
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
    config: ChainConfig,
) -> Result<(String, String)> {
    post_key_derivation_impl(
        ring_id,
        derivation,
        policy_id,
        resource,
        permission,
        config,
        TEST_ACCOUNT_HEX_KEY,
    )
    .await
}
