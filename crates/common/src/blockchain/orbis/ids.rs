//! Deterministic hashing for x/orbis: the reshare finalize sign doc and
//! document/key-derivation object-id derivation.

use crate::blockchain::{BlockchainError, Result};
use k256::sha2::{Digest, Sha256};
use prost::Message;

pub const RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN: &str = "orbis-ring-reshare-finalize";

/// Canonical sign document for finalizing a ring reshare via threshold signature.
#[derive(Clone, Message)]
pub struct RingReshareFinalizeSignDoc {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(string, tag = "2")]
    pub chain_id: String,
    #[prost(string, tag = "3")]
    pub ring_id: String,
    #[prost(string, tag = "4")]
    pub ring_pk: String,
    #[prost(bytes = "vec", tag = "5")]
    pub current_ring_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub finalized_ring_sha256: Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub block_number_nonce: u64,
}

/// Canonical Orbis protocol state hashed into reshare finalization sign docs.
///
/// This intentionally excludes Vera storage-only fields such as creator DID,
/// fresh-DKG confirmations, and operational scheduling metadata such as PSS
/// interval. Participant lists must be sorted before hashing.
#[derive(Clone, Message)]
pub struct RingReshareSignState {
    #[prost(string, tag = "1")]
    pub ring_pk: String,
    #[prost(string, repeated, tag = "2")]
    pub peer_node_keys: Vec<String>,
    #[prost(uint32, tag = "3")]
    pub threshold: u32,
    #[prost(string, repeated, tag = "4")]
    pub new_peer_node_keys: Vec<String>,
    #[prost(uint32, optional, tag = "5")]
    pub new_threshold: Option<u32>,
    #[prost(uint64, tag = "7")]
    pub block_number_nonce: u64,
    #[prost(string, tag = "8")]
    pub policy_id: String,
    #[prost(string, repeated, tag = "9")]
    pub trusted_auth_relay_dids: Vec<String>,
    #[prost(bool, tag = "10")]
    pub allow_trusted_auth_relays: bool,
}

/// Build Vera-compatible sign bytes for a ring reshare finalization.
/// `current_ring_sha256` and `finalized_ring_sha256` must each be exactly 32 bytes —
/// SHA-256 of the canonical Orbis reshare sign-state for the current and finalized states.
pub fn ring_reshare_finalize_sign_bytes(
    chain_id: &str,
    ring_id: &str,
    ring_pk: &str,
    current_ring_sha256: Vec<u8>,
    finalized_ring_sha256: Vec<u8>,
    block_number_nonce: u64,
) -> Result<Vec<u8>> {
    if current_ring_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "current_ring_sha256 must be 32 bytes, got {}",
            current_ring_sha256.len()
        )));
    }
    if finalized_ring_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "finalized_ring_sha256 must be 32 bytes, got {}",
            finalized_ring_sha256.len()
        )));
    }

    Ok(RingReshareFinalizeSignDoc {
        domain: RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN.to_string(),
        chain_id: chain_id.to_string(),
        ring_id: ring_id.to_string(),
        ring_pk: ring_pk.to_string(),
        current_ring_sha256,
        finalized_ring_sha256,
        block_number_nonce,
    }
    .encode_to_vec())
}

/// Hash a canonicalized reshare sign-state for use in reshare sign docs.
pub fn ring_reshare_sign_state_hash(state: &RingReshareSignState) -> [u8; 32] {
    let mut canonical = state.clone();
    canonical.peer_node_keys.sort();
    canonical.new_peer_node_keys.sort();
    canonical.trusted_auth_relay_dids.sort();
    Sha256::digest(canonical.encode_to_vec()).into()
}

/// The encrypted document, as far as the object‑id derivation is concerned: the
/// three byte fields of the crypto `Secret`.
///
/// `deny_unknown_fields` + exact key names is deliberate: the id must be derived
/// from the *same* three values on both sides of the wire. Go's `encoding/json`
/// matches field names case‑insensitively (a later `"ENC_CMT"` overrides
/// `"enc_cmt"`), so a permissive parser here would let one ciphertext acquire two
/// object ids — one Vera hashes, one this crate verifies. Rejecting any extra or
/// differently‑cased key closes that.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdDocumentSecret {
    enc_cmt: Vec<u8>,
    encrypted_data: Vec<u8>,
    nonce: Vec<u8>,
}

/// The encryption proof, as far as the object‑id derivation is concerned. See
/// [`IdDocumentSecret`] for why the field set is exact.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdDocumentProof {
    challenge: Vec<u8>,
    response: Vec<u8>,
}

/// The PET tag ciphertext, as far as the object-id derivation is concerned. See
/// [`IdDocumentSecret`] for why the field set is exact.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdPetTag {
    ephemeral_point: Vec<u8>,
    masked_fingerprint: Vec<u8>,
}

/// The PET tag-knowledge proof, as far as the object-id derivation is
/// concerned. See [`IdDocumentSecret`] for why the field set is exact.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdPetTagProof {
    challenge: Vec<u8>,
    response: Vec<u8>,
}

/// Compute the deterministic document ID matching Vera's on-chain
/// `GenerateDocumentID`.
///
/// `document` and `proof` are the JSON strings from `DocumentPayload`; they are
/// parsed and re‑encoded into a canonical length‑prefixed form before hashing so
/// that two byte‑different JSON encodings of the *same* ciphertext produce the
/// *same* id (the authorization identity must be a function of the ciphertext's
/// meaning, not its serialization). Returns an error if either string is not the
/// expected shape.
///
/// `pet_tag`/`pet_tag_proof` are the JSON strings from `DocumentPayload`'s
/// optional PET attachment (`None` on an ordinary, non-PET document). They must
/// be present or absent *together*; one without the other is rejected. When
/// both are absent, nothing is hashed for them at all — not even a presence
/// marker — so an ordinary document's id is unchanged from before this
/// attachment existed. When both are present, their decoded fields are hashed
/// the same way as `document`/`proof`, so this id covers the tag attachment
/// and its knowledge proof as well as the payload.
#[allow(clippy::too_many_arguments)]
pub fn generate_document_id(
    ring_id: &str,
    document: &str,
    proof: &str,
    policy_id: &str,
    resource: &str,
    permission: &str,
    tier: Option<&str>,
    timestamp: Option<u64>,
    pet_tag: Option<&str>,
    pet_tag_proof: Option<&str>,
) -> Result<String> {
    let secret: IdDocumentSecret = serde_json::from_str(document)?;
    let proof: IdDocumentProof = serde_json::from_str(proof)?;

    let mut h = Sha256::new();

    write_string(&mut h, "orbis/document/v1");
    write_string(&mut h, ring_id);
    write_bytes(&mut h, &secret.enc_cmt);
    write_bytes(&mut h, &secret.encrypted_data);
    write_bytes(&mut h, &secret.nonce);
    write_bytes(&mut h, &proof.challenge);
    write_bytes(&mut h, &proof.response);
    write_string(&mut h, policy_id);
    write_string(&mut h, resource);
    write_string(&mut h, permission);
    write_optional_string(&mut h, tier);
    write_optional_u64(&mut h, timestamp);
    write_optional_pet_tag(&mut h, pet_tag, pet_tag_proof)?;

    Ok(hex::encode(h.finalize()))
}

/// Fold the optional PET tag attachment and its knowledge proof into the
/// document-id hash. See [`generate_document_id`]'s docs for why an absent
/// attachment hashes nothing at all, unlike every other optional field in this
/// function.
fn write_optional_pet_tag(
    h: &mut Sha256,
    pet_tag: Option<&str>,
    pet_tag_proof: Option<&str>,
) -> Result<()> {
    match (pet_tag, pet_tag_proof) {
        (None, None) => Ok(()),
        (Some(tag), Some(proof)) => {
            let tag: IdPetTag = serde_json::from_str(tag)?;
            let proof: IdPetTagProof = serde_json::from_str(proof)?;
            write_bytes(h, &tag.ephemeral_point);
            write_bytes(h, &tag.masked_fingerprint);
            write_bytes(h, &proof.challenge);
            write_bytes(h, &proof.response);
            Ok(())
        }
        _ => Err(BlockchainError::Serialization(
            "pet_tag and pet_tag_proof must be present or absent together".to_string(),
        )),
    }
}

/// Compute the deterministic key derivation ID matching Vera's on-chain `GenerateKeyDerivationID`.
pub fn generate_key_derivation_id(
    ring_id: &str,
    derivation: &str,
    policy_id: &str,
    resource: &str,
    permission: &str,
) -> String {
    let mut h = Sha256::new();

    write_string(&mut h, "orbis/key_derivation/v1");
    write_string(&mut h, ring_id);
    write_string(&mut h, derivation);
    write_string(&mut h, policy_id);
    write_string(&mut h, resource);
    write_string(&mut h, permission);

    hex::encode(h.finalize())
}

fn write_string(h: &mut Sha256, s: &str) {
    write_bytes(h, s.as_bytes());
}

fn write_bytes(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u32).to_be_bytes());
    h.update(b);
}

fn write_optional_string(h: &mut Sha256, value: Option<&str>) {
    match value {
        None => h.update([0u8]),
        Some(v) => {
            h.update([1u8]);
            write_string(h, v);
        }
    }
}

fn write_optional_u64(h: &mut Sha256, value: Option<u64>) {
    match value {
        None => h.update([0u8]),
        Some(v) => {
            h.update([1u8]);
            h.update(v.to_be_bytes());
        }
    }
}
