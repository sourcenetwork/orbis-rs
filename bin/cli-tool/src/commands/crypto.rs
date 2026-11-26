//! Local cryptography: encryption, key generation, and DID derivation.
//!
//! Nothing in this module talks to an orbis-node endpoint or the chain — every
//! function here is a pure, local computation.
//!
//! Thin wrappers over `orbis-sdk`: `prepare_secret`/`generate_pet_tag`/
//! `prove_pet_tag_knowledge`/`reader_did_from_seed` need no CLI-specific
//! behavior at all, so they're re-exported directly rather than wrapped.

use anyhow::{anyhow, Result};
use orbis_sdk::{ChainIdentity, InMemoryChainIdentity};

pub use orbis_sdk::{prepare_secret, reader_did_from_seed, PreparedSecret};
// Only used via the `cli-tool` lib target (orbis-node integration tests,
// orbis-bench); unused from the bin target. `PreparedPetTag` itself isn't
// listed here since `node.rs` names it directly, which already keeps it
// "used" from the bin target's perspective.
#[allow(unused_imports)]
pub use orbis_sdk::{generate_pet_tag, prove_pet_tag_knowledge, PreparedPetTag};

pub async fn do_encrypt_secret(
    ring_pk: String,
    secret: String,
    derivation: Option<Vec<u8>>,
    policy_id: String,
    resource: String,
    permission: String,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
) -> Result<()> {
    println!("Encrypting secret to ring public key...");
    println!("  Ring PK: {}...", &ring_pk[..ring_pk.len().min(20)]);
    println!();

    let encrypted_secret = orbis_sdk::encrypt_secret(
        &ring_pk,
        secret.as_bytes(),
        derivation,
        policy_id,
        resource,
        permission,
        tier,
        timestamp,
        salt,
    )?;
    let secret_json = String::from_utf8(encrypted_secret)
        .map_err(|e| anyhow!("Failed to decode encrypted secret as UTF-8: {}", e))?;

    println!("Encrypted Secret (JSON):");
    println!("{}", "=".repeat(60));
    println!("{}", secret_json);

    Ok(())
}

/// Derive a did:key from a compressed secp256k1 public key, using the same
/// multicodec encoding (0xe7 0x01 prefix, base58) Vera uses to resolve
/// the ACP actor identity for signed transactions (e.g. MsgCreateRing's
/// `create_ring` permission, MsgFinalizeRing's `update_ring` permission) --
/// a different derivation from the Ed25519 `--reader-did-pk` scheme, since
/// those transactions are authenticated by tx signature, not a JWT.
pub(crate) fn secp256k1_pubkey_to_did(pubkey_hex: &str) -> Result<String> {
    let pubkey_bytes: [u8; 33] = hex::decode(pubkey_hex)
        .map_err(|e| anyhow!("Invalid public key hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow!("Invalid public key: expected 33 compressed bytes"))?;
    Ok(orbis_sdk::secp256k1_pubkey_to_did(&pubkey_bytes))
}

/// Derive the compressed secp256k1 public key and did:key for a signing key.
/// Pure local computation, no network calls. Use this to find out, ahead of
/// time, which DID needs an ACP relation granted (e.g. `ring_creator`) before
/// a transaction signed with this key -- such as `create-ring` -- will be
/// authorized.
pub fn derive_signer_did(signing_key_hex: &str) -> Result<(String, String)> {
    let identity = InMemoryChainIdentity::from_hex_key(signing_key_hex)
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;
    let pubkey_hex = hex::encode(identity.compressed_public_key());
    let did = secp256k1_pubkey_to_did(&pubkey_hex)?;
    Ok((pubkey_hex, did))
}
