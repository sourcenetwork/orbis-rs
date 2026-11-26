//! Bulletin operations: namespace/collaborator administration and posting/reading
//! bulletin entries (documents, rings, key derivations).
//!
//! Thin wrappers over `orbis-sdk`: this module's job is CLI output
//! (`println!`) and cli-tool's own devnet convenience of defaulting to a
//! well-known test signing key where the original CLI surface never asked
//! for one — `orbis-sdk` itself makes no such assumption and always
//! requires the key as an explicit argument.

use anyhow::Result;
use common::blockchain::{ChainConfig, TEST_ACCOUNT_HEX_KEY};
use orbis_sdk::{BulletinKind, BulletinWriteKind};

pub async fn register_bulletin_namespace(
    namespace: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let newly_registered =
        orbis_sdk::register_bulletin_namespace(namespace.clone(), config, signing_key_hex).await?;
    if newly_registered {
        println!("Registered bulletin namespace: {namespace}");
    } else {
        println!("Bulletin namespace already exists: {namespace}");
    }
    Ok(())
}

pub async fn add_bulletin_collaborator(
    namespace: String,
    collaborator_address: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let newly_added = orbis_sdk::add_bulletin_collaborator(
        namespace.clone(),
        collaborator_address.clone(),
        config,
        signing_key_hex,
    )
    .await?;
    if newly_added {
        println!("Added collaborator {collaborator_address} to namespace {namespace}");
    } else {
        println!("Collaborator {collaborator_address} already on namespace {namespace}");
    }
    Ok(())
}

/// Posts an arbitrary bulletin entry, signed by `cli-tool`'s own
/// well-known devnet test account — a convenience for local/CI use, never
/// a real deployment. Unused outside this crate's own tests; see
/// [`create_bulletin_post_with_config`] for the version that takes a
/// `ChainConfig`.
pub async fn create_bulletin_post(kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String> {
    create_bulletin_post_with_config(kind, payload, ChainConfig::local()).await
}

pub async fn create_bulletin_post_with_config(
    kind: BulletinWriteKind,
    payload: Vec<u8>,
    config: ChainConfig,
) -> Result<String> {
    let post_id =
        orbis_sdk::create_bulletin_post(kind, payload, config, TEST_ACCOUNT_HEX_KEY).await?;
    println!("Created bulletin post with ID: {post_id}");
    Ok(post_id)
}

pub async fn read_bulletin_post_with_config(
    id: String,
    kind: BulletinKind,
    config: ChainConfig,
) -> Result<Vec<u8>> {
    orbis_sdk::read_bulletin_post(id, kind, config)
        .await
        .map_err(Into::into)
}

/// List all bulletin posts in a namespace
pub async fn list_bulletin_posts(namespace: String, config: ChainConfig) -> Result<Vec<Vec<u8>>> {
    orbis_sdk::list_bulletin_posts(namespace, config)
        .await
        .map_err(Into::into)
}

/// Post a `KeyDerivation` to the bulletin under `namespace`.
///
/// Returns `(post_id, derived_pk_hex)` where `post_id` is used as the
/// `derivation_id` in sign requests and `derived_pk_hex` is the public key
/// derived from the ring PK and the derivation bytes.
///
/// The caller must ensure the node's public address has been added as a
/// collaborator on the namespace before posting.
pub async fn post_key_derivation(
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<(String, String)> {
    let (derivation_id, derived_pk_hex) = orbis_sdk::post_key_derivation(
        ring_id,
        derivation,
        policy_id,
        resource,
        permission,
        config,
        signing_key_hex,
    )
    .await?;
    println!("Posted KeyDerivation: derivation_id={derivation_id} derived_pk={derived_pk_hex}");
    Ok((derivation_id, derived_pk_hex))
}

/// Same as [`post_key_derivation`], but signed by `cli-tool`'s own
/// well-known devnet test account — a convenience for local/CI tooling
/// (`orbis-bench`, integration tests) that doesn't manage its own ring-admin
/// key. Never a real deployment's provisioning path.
// Only called via the `cli-tool` lib target (orbis-bench, orbis-node integration tests);
// unused from the bin target.
#[allow(dead_code)]
pub async fn post_key_derivation_with_config(
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
    config: ChainConfig,
) -> Result<(String, String)> {
    post_key_derivation(
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
