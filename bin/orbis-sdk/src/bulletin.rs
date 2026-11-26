//! Bulletin: namespace/collaborator administration and posting/reading
//! bulletin entries (documents, rings, key derivations) — the on-chain
//! provisioning every ring needs before any end-user Sign/PRE request can
//! be made against it (a `derivation_id` has to exist before `Sign` can
//! reference it; a namespace has to exist and have a collaborator before
//! anything can be posted to it).
//!
//! These are plain functions rather than [`crate::OrbisClient`] methods:
//! unlike Sign/PRE/StoreSecret, there's no single orbis-node endpoint
//! these talk to — they go straight to the chain, addressed by
//! `ChainConfig`.
//!
//! None of these assume a signing key: every write here takes
//! `signing_key_hex` as a plain argument, with no built-in fallback to any
//! well-known test account. A caller wanting a convenience default (e.g.
//! `cli-tool`'s own devnet tooling) decides that for itself and passes the
//! key in explicitly.

use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, KeyDerivation, RingPayload};
use bulletin::vera_go::VeraGoBulletin;
use common::blockchain::{ChainConfig, ChainConfigBuilder, TxSigner, VeraGoClient};
use crypto::r#trait::ThresholdSigner;
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine as G1Affine, SignImpl};

use crate::error::{Result, SdkError};

fn chain_config_builder(config: &ChainConfig) -> ChainConfigBuilder {
    ChainConfigBuilder::default()
        .chain_id(Some(config.chain_id.clone()))
        .rpc_url(Some(config.rpc_url.clone()))
        .rest_url(Some(config.rest_url.clone()))
        .grpc_url(Some(config.grpc_url.clone()))
        .account_prefix(Some(config.account_prefix.clone()))
        .default_gas_limit(Some(config.default_gas_limit))
        .gas_price(Some(config.gas_price.clone()))
        .gas_multiplier(Some(config.gas_multiplier))
        .allow_insecure_rpc(Some(config.allow_insecure_rpc))
}

async fn vera_client(config: ChainConfig) -> Result<VeraGoClient> {
    VeraGoClient::new(config)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to create chain client: {e}")))
}

fn tx_signer(signing_key_hex: &str, config: ChainConfig) -> Result<TxSigner> {
    TxSigner::from_hex_key(signing_key_hex, config)
        .map_err(|e| SdkError::Chain(format!("failed to create signer: {e}")))
}

async fn signed_vera_client(config: ChainConfig, signing_key_hex: &str) -> Result<VeraGoClient> {
    let signer = tx_signer(signing_key_hex, config.clone())?;
    VeraGoClient::with_signer(config, signer)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to create signed chain client: {e}")))
}

async fn bulletin_client(config: ChainConfig) -> Result<VeraGoBulletin> {
    VeraGoBulletin::new(chain_config_builder(&config))
        .await
        .map_err(|e| SdkError::Chain(format!("failed to create bulletin client: {e}")))
}

async fn signed_bulletin_client(
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<VeraGoBulletin> {
    let signer = tx_signer(signing_key_hex, config.clone())?;
    VeraGoBulletin::with_signer(chain_config_builder(&config), signer, None)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to create bulletin client: {e}")))
}

/// Registers a bulletin namespace on chain — a one-time setup step before
/// anything can be posted to it. Returns `Ok(true)` if this call actually
/// registered it, `Ok(false)` if it already existed (not an error either
/// way — idempotent).
pub async fn register_bulletin_namespace(
    namespace: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<bool> {
    let read_client = vera_client(config.clone()).await?;
    if read_client.bulletin_get_namespace(&namespace).await.is_ok() {
        return Ok(false);
    }

    let client = signed_vera_client(config, signing_key_hex).await?;
    match client.bulletin_register_namespace(&namespace).await {
        Ok(_) => Ok(true),
        Err(e) if e.to_string().contains("already exists") => Ok(false),
        Err(e) => Err(SdkError::Chain(format!(
            "failed to register namespace: {e}"
        ))),
    }
}

/// Grants `collaborator_address` permission to post to `namespace`.
/// Returns `Ok(true)` if this call actually added it, `Ok(false)` if it
/// was already a collaborator (not an error either way — idempotent).
pub async fn add_bulletin_collaborator(
    namespace: String,
    collaborator_address: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<bool> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = match client
        .bulletin_add_collaborator(&namespace, &collaborator_address)
        .await
    {
        Ok(r) => r,
        Err(e) if e.to_string().contains("already exists") => return Ok(false),
        Err(e) => return Err(SdkError::Chain(format!("failed to add collaborator: {e}"))),
    };

    if result.code != 0 {
        if result.log.contains("already exists") {
            return Ok(false);
        }
        return Err(SdkError::Chain(format!(
            "failed to add collaborator: code {} {}",
            result.code, result.log
        )));
    }
    Ok(true)
}

/// Posts an arbitrary bulletin entry, signed by `signing_key_hex`.
/// Returns the new post's id.
pub async fn create_bulletin_post(
    kind: BulletinWriteKind,
    payload: Vec<u8>,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<String> {
    let bulletin = signed_bulletin_client(config, signing_key_hex).await?;
    bulletin
        .post(kind, payload)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to create post: {e}")))
}

/// Reads one bulletin entry by id. Read-only; no signing key needed.
pub async fn read_bulletin_post(
    id: String,
    kind: BulletinKind,
    config: ChainConfig,
) -> Result<Vec<u8>> {
    let bulletin = bulletin_client(config).await?;
    let post = bulletin
        .read(id, kind)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to read bulletin post: {e}")))?;
    Ok(post.payload)
}

/// Lists every post in a namespace. Read-only; no signing key needed.
pub async fn list_bulletin_posts(namespace: String, config: ChainConfig) -> Result<Vec<Vec<u8>>> {
    let client = vera_client(config).await?;
    let posts = client
        .bulletin_list_posts(&namespace)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to list bulletin posts: {e}")))?;
    Ok(posts.into_iter().map(|p| p.payload).collect())
}

/// Posts a `KeyDerivation` to the bulletin under the ring's namespace —
/// the on-chain provisioning step that makes a `derivation_id` exist for
/// [`crate::OrbisClient::submit_sign_with_jwt`]/`submit_sign_with_evidence`
/// to reference later. Returns `(derivation_id, derived_pk_hex)`, where
/// `derived_pk_hex` is the public key derived from the ring's own key and
/// `derivation`.
///
/// `signing_key_hex`'s own account must already be a collaborator on the
/// ring's bulletin namespace (see [`add_bulletin_collaborator`]).
pub async fn post_key_derivation(
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<(String, String)> {
    let ring_bulletin = bulletin_client(config.clone()).await?;
    let ring_post = ring_bulletin
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to read ring post '{ring_id}': {e}")))?;
    let ring_payload: RingPayload = serde_json::from_slice(&ring_post.payload)
        .map_err(|e| SdkError::Encoding(format!("failed to parse RingPayload: {e}")))?;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
        .map_err(|e| SdkError::Encoding(format!("invalid ring_pk hex in bulletin: {e}")))?;
    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| SdkError::Encoding(format!("invalid ring_pk: {e}")))?;
    let metadata = SignImpl::encode_metadata(&policy_id, &resource, &permission);
    let derived_pk =
        SignImpl::derive_public_key(&ring_pk_point, derivation.as_bytes(), Some(&metadata))
            .map_err(|e| SdkError::Crypto(format!("failed to derive public key: {e}")))?;
    let derived_pk_hex = hex::encode(
        derived_pk
            .to_bytes()
            .map_err(|e| SdkError::Encoding(format!("failed to serialize derived_pk: {e}")))?,
    );

    let bulletin = signed_bulletin_client(config, signing_key_hex).await?;
    let key_derivation = KeyDerivation {
        ring_id,
        derivation,
        policy_id,
        resource,
        permission,
    };
    let payload = serde_json::to_vec(&key_derivation)
        .map_err(|e| SdkError::Encoding(format!("failed to serialize KeyDerivation: {e}")))?;

    let post_id = bulletin
        .post(BulletinWriteKind::KeyDerivation, payload)
        .await
        .map_err(|e| SdkError::Chain(format!("failed to post KeyDerivation: {e}")))?;

    Ok((post_id, derived_pk_hex))
}
