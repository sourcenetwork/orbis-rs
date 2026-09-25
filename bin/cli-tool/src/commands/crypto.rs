//! Local cryptography: encryption, key generation, and DID derivation.
//!
//! Nothing in this module talks to an orbis-node endpoint or the chain — every
//! function here is a pure, local computation.

use anyhow::{anyhow, Result};
use common::blockchain::ChainConfig;
use crypto::context::CiphertextContext;
use crypto::r#trait::{EncryptionProof, Pet, PetTag, Secret, TagKnowledgeProof, ThresholdDealer};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{GroupAffine as G1Affine, PetImpl, PreImpl as ThresholdDealerNode};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint};
use sha2::{Digest, Sha256};

use super::chain::tx_signer;

/// Prepared secret ready for storage - can be reused for retries
/// This contains the encrypted data and proof, which are deterministic
/// for a given plaintext and ring public key encryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreparedSecret {
    /// Encrypted document as serialized bytes
    pub encrypted_document: Vec<u8>,
    /// Encryption commitment bytes (compressed G1 point)
    pub enc_cmt: Vec<u8>,
    /// Fiat-Shamir challenge for the encryption proof
    pub challenge: Vec<u8>,
    /// Response for the encryption proof
    pub response: Vec<u8>,
    /// Ciphertext-binding context the proof commits to. The single source of the
    /// policy fields that must be posted alongside the document.
    pub context: CiphertextContext,
}

/// Prepare a secret for storage by encrypting it locally.
/// The returned PreparedSecret can be stored and reused for retries,
/// ensuring idempotent storage (same encrypted data = same object_id).
#[allow(clippy::too_many_arguments)]
pub fn prepare_secret(
    secret: &[u8],
    ring_pk_hex: &str,
    derivation: Option<Vec<u8>>,
    policy_id: String,
    resource: String,
    permission: String,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
) -> Result<PreparedSecret> {
    // Parse ring public key
    let ring_pk_bytes =
        hex::decode(ring_pk_hex).map_err(|e| anyhow!("Invalid ring_pk hex: {}", e))?;
    let ring_pk_point =
        G1Affine::from_bytes(&ring_pk_bytes).map_err(|e| anyhow!("Invalid ring_pk: {}", e))?;

    let context = CiphertextContext {
        ring_pk: ring_pk_bytes,
        policy_id,
        resource,
        permission,
        tier,
        timestamp,
        salt,
    };

    // Encrypt locally - node never sees plaintext
    let (enc_cmt, encrypted_secret, proof) = ThresholdDealerNode::encrypt_secret(
        &ring_pk_point,
        secret,
        derivation.as_deref(),
        &context,
    )
    .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let encrypted_document = serde_json::to_vec(&encrypted_secret)
        .map_err(|e| anyhow!("Failed to serialize encrypted secret: {}", e))?;
    let enc_cmt = enc_cmt
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize enc_cmt: {}", e))?
        .to_vec();

    Ok(PreparedSecret {
        encrypted_document,
        enc_cmt,
        challenge: proof.challenge,
        response: proof.response,
        context,
    })
}

/// A PET ownership tag plus its knowledge proof, ready to attach to a
/// document. Mirrors the role of [`PreparedSecret`] one layer up: a pure,
/// local computation the caller can inspect, serialize, or attach to a
/// request without any network dependency.
// Only constructed via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PreparedPetTag {
    pub tag: PetTag,
    pub tag_proof: TagKnowledgeProof,
}

/// Build a valid PET ownership tag for `owner_id` against a ring's public PET
/// checking key — a stand-in for what Bankd does in production when it
/// encrypts a document on a `requires_pet` ring.
///
/// Needs only public information: the ring's `pet_pk` (no secret share is
/// ever involved — `masked_fingerprint = F(owner_id) + r_tag*pet_pk` is
/// computable by anyone who knows `pet_pk`) and the already-`prepare_secret`d
/// payload this tag will be bound to, since the tag-knowledge proof commits
/// to the complete payload envelope (see
/// `crypto::pet_context::tag_proof_digest`'s docs) — the same binding
/// `pet::v0::coordinator::verification::verify_pet_check_request` recomputes
/// and checks on the node side.
// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub fn prepare_pet_tag(
    prepared: &PreparedSecret,
    ring_id: &str,
    pet_pk_hex: &str,
    owner_id: &str,
) -> Result<PreparedPetTag> {
    let pet_pk_bytes = hex::decode(pet_pk_hex).map_err(|e| anyhow!("Invalid pet_pk hex: {}", e))?;
    let _: G1Affine =
        G1Affine::from_bytes(&pet_pk_bytes).map_err(|e| anyhow!("Invalid pet_pk: {}", e))?;

    let (r_tag, r_point) = crypto::helpers::generate_keypair()
        .map_err(|e| anyhow!("Failed to generate r_tag: {}", e))?;
    let ephemeral_point =
        CryptoSerialize::to_bytes(&r_point).map_err(|e| anyhow!("Failed to serialize R: {}", e))?;

    // r_tag * pet_pk, reusing `Pet::partial_pet_check`'s "scalar * arbitrary
    // point" shape (it doesn't care that `pet_pk` isn't really a tag's
    // ephemeral point — that field is just a compressed group element to it).
    let staging_tag = PetTag {
        ephemeral_point: pet_pk_bytes.clone(),
        masked_fingerprint: Vec::new(),
    };
    let blinding = PetImpl::partial_pet_check(&r_tag, &staging_tag)
        .map_err(|e| anyhow!("Failed to compute r_tag*pet_pk: {}", e))?;
    let fingerprint = PetImpl::owner_fingerprint(owner_id.as_bytes())
        .map_err(|e| anyhow!("Failed to compute owner fingerprint: {}", e))?;
    let masked_fingerprint_point = crypto::helpers::add_points(&fingerprint, &blinding)
        .map_err(|e| anyhow!("Failed to combine fingerprint and blinding: {}", e))?;
    let masked_fingerprint = CryptoSerialize::to_bytes(&masked_fingerprint_point)
        .map_err(|e| anyhow!("Failed to serialize masked fingerprint: {}", e))?;

    let tag = PetTag {
        ephemeral_point,
        masked_fingerprint,
    };

    let secret: Secret = serde_json::from_slice(&prepared.encrypted_document)
        .map_err(|e| anyhow!("Failed to parse prepared secret: {}", e))?;
    let payload_proof = EncryptionProof {
        challenge: prepared.challenge.clone(),
        response: prepared.response.clone(),
    };
    let digest = crypto::pet_context::tag_proof_digest(
        &tag.ephemeral_point,
        &tag.masked_fingerprint,
        &pet_pk_bytes,
        ring_id,
        &prepared.context,
        &secret,
        &payload_proof,
    );

    let tag_proof = PetImpl::prove_tag_knowledge(&r_tag, &tag, &digest)
        .map_err(|e| anyhow!("Failed to prove tag knowledge: {}", e))?;

    Ok(PreparedPetTag { tag, tag_proof })
}

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

    // Parse the ring public key from hex
    let ring_pk_bytes =
        hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;

    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

    let context = CiphertextContext {
        ring_pk: ring_pk_bytes,
        policy_id,
        resource,
        permission,
        tier,
        timestamp,
        salt,
    };

    // Encrypt the secret
    let (_enc_cmt, encrypted_secret, _proof) = ThresholdDealerNode::encrypt_secret(
        &ring_pk_point,
        secret.as_bytes(),
        derivation.as_deref(),
        &context,
    )
    .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Output the full secret as JSON (this is what PRE expects)
    let secret_json = serde_json::to_string(&encrypted_secret)
        .map_err(|e| anyhow!("Failed to serialize secret: {}", e))?;

    println!("Encrypted Secret (JSON):");
    println!("{}", "=".repeat(60));
    println!("{}", secret_json);

    Ok(())
}

pub fn do_generate_reader_key() -> Result<()> {
    let (sk, pk) = crypto::helpers::generate_keypair()
        .map_err(|e| anyhow!("Failed to generate keypair: {}", e))?;

    // Serialize to bytes then hex (use trait method explicitly to avoid inherent method shadowing)
    let sk_bytes = CryptoSerialize::to_bytes(&sk)
        .map_err(|e| anyhow!("Failed to serialize secret key: {}", e))?;
    let pk_bytes = CryptoSerialize::to_bytes(&pk)
        .map_err(|e| anyhow!("Failed to serialize public key: {}", e))?;

    let sk_hex = hex::encode(&sk_bytes);
    let pk_hex = hex::encode(&pk_bytes);

    println!("Generated Reader Keypair:");
    println!("{}", "=".repeat(60));
    println!("Reader Secret Key (--reader-sk):");
    println!("{}", sk_hex);
    println!();
    println!("Reader Public Key (--reader-pk):");
    println!("{}", pk_hex);

    Ok(())
}

/// Derive a 32-byte Ed25519 seed from an arbitrary string via SHA-256.
///
/// `did_key::generate` only uses the seed deterministically when it is exactly
/// 32 bytes; for any other length it falls back to a random key. Hashing to 32
/// bytes ensures consistent, reproducible DIDs regardless of the input length.
pub(crate) fn did_seed(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// Derive the Ed25519 did:key from an arbitrary seed string -- the same scheme
/// used everywhere `--reader-did-pk` is accepted (JWT-authenticated requests
/// to orbis-node: pre, sign, store-secret, store-prepared-secret), and by
/// `set_relationship_on_chain_with_config`'s own `reader_did_pk` parameter.
/// Public so a caller granting a relationship to a chosen seed (e.g. an ACP
/// "owner" relation for a PET audit target) can independently recompute the
/// exact DID that ends up on-chain.
pub fn reader_did_from_seed(seed: &str) -> String {
    let hashed = did_seed(seed);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&hashed));
    format!("did:key:{}", key_pair.fingerprint())
}

/// Derive a did:key from a compressed secp256k1 public key, using the same
/// multicodec encoding (0xe7 0x01 prefix, base58) Vera uses to resolve
/// the ACP actor identity for signed transactions (e.g. MsgCreateRing's
/// `create_ring` permission, MsgFinalizeRing's `update_ring` permission) --
/// a different derivation from the Ed25519 `--reader-did-pk` scheme, since
/// those transactions are authenticated by tx signature, not a JWT.
pub(crate) fn secp256k1_pubkey_to_did(pubkey_hex: &str) -> Result<String> {
    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|e| anyhow!("Invalid public key hex: {}", e))?;
    let mut prefixed = vec![0xe7u8, 0x01u8];
    prefixed.extend_from_slice(&pubkey_bytes);
    Ok(format!(
        "did:key:z{}",
        bs58::encode(&prefixed).into_string()
    ))
}

/// Derive the compressed secp256k1 public key and did:key for a signing key.
/// Pure local computation, no network calls. Use this to find out, ahead of
/// time, which DID needs an ACP relation granted (e.g. `ring_creator`) before
/// a transaction signed with this key -- such as `create-ring` -- will be
/// authorized.
pub fn derive_signer_did(signing_key_hex: &str, config: ChainConfig) -> Result<(String, String)> {
    let signer = tx_signer(signing_key_hex, config)?;
    let public_key_hex = signer.public_key_hex();
    let did = secp256k1_pubkey_to_did(&public_key_hex)?;
    Ok((public_key_hex, did))
}
