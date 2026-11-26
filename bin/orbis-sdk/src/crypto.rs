//! Local cryptography: encryption and PET ownership tags.
//!
//! Nothing in this module talks to an orbis-node endpoint or the chain —
//! every function here is a pure, local computation. DID derivation lives
//! in [`crate::identity`] instead.

use crate::error::{Result, SdkError};
use crypto::context::{CiphertextContext, PetTagBinding};
use crypto::r#trait::{
    Dkg, EncryptionProof, Pet, PetTag, Secret, TagKnowledgeProof, ThresholdDealer,
};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{
    DkgImpl, GroupAffine as G1Affine, PetImpl, PreImpl as ThresholdDealerNode, ScalarField as Fr,
};

/// Prepared secret ready for storage — can be reused for retries. Contains
/// the encrypted data and proof, which are deterministic for a given
/// plaintext and ring public key encryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreparedSecret {
    /// Encrypted document as serialized bytes.
    pub encrypted_document: Vec<u8>,
    /// Encryption commitment bytes (compressed G1 point).
    pub enc_cmt: Vec<u8>,
    /// Fiat-Shamir challenge for the encryption proof.
    pub challenge: Vec<u8>,
    /// Response for the encryption proof.
    pub response: Vec<u8>,
    /// Ciphertext-binding context the proof commits to. The single source
    /// of the policy fields that must be posted alongside the document.
    pub context: CiphertextContext,
}

/// Prepare a secret for storage by encrypting it locally. The returned
/// `PreparedSecret` can be stored and reused for retries, ensuring
/// idempotent storage (same encrypted data = same object_id).
///
/// `pet_tag_binding` must be `Some` — generated via [`generate_pet_tag`] —
/// for a `requires_pet` ring, and `None` otherwise. Binding it into the
/// encryption context here, *before* the payload is encrypted, is what
/// lets a verifier detect a copied ciphertext/proof reattached to a
/// different tag: see [`PetTagBinding`]'s doc comment. Passing `None` for a
/// `requires_pet` ring's document (or generating the tag *after* calling
/// this) silently reopens that gap.
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
    pet_tag_binding: Option<PetTagBinding>,
) -> Result<PreparedSecret> {
    let ring_pk_bytes = hex::decode(ring_pk_hex)
        .map_err(|e| SdkError::Encoding(format!("invalid ring_pk hex: {e}")))?;
    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| SdkError::Encoding(format!("invalid ring_pk: {e}")))?;

    let context = CiphertextContext {
        ring_pk: ring_pk_bytes,
        policy_id,
        resource,
        permission,
        tier,
        timestamp,
        salt,
        pet_tag: pet_tag_binding,
    };

    // Encrypt locally - node never sees plaintext.
    let (enc_cmt, encrypted_secret, proof) = ThresholdDealerNode::encrypt_secret(
        &ring_pk_point,
        secret,
        derivation.as_deref(),
        &context,
    )
    .map_err(|e| SdkError::Crypto(format!("encryption failed: {e}")))?;

    let encrypted_document = serde_json::to_vec(&encrypted_secret)
        .map_err(|e| SdkError::Encoding(format!("failed to serialize encrypted secret: {e}")))?;
    let enc_cmt = enc_cmt
        .to_bytes()
        .map_err(|e| SdkError::Encoding(format!("failed to serialize enc_cmt: {e}")))?
        .to_vec();

    Ok(PreparedSecret {
        encrypted_document,
        enc_cmt,
        challenge: proof.challenge,
        response: proof.response,
        context,
    })
}

/// Encrypt `secret` to `ring_pk` and return the serialized ciphertext PRE
/// expects, without posting it anywhere. A lower-level cousin of
/// [`prepare_secret`] for a caller that wants the raw encrypted-secret JSON
/// itself rather than a [`PreparedSecret`] ready for `StoreSecret`.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_secret(
    ring_pk: &str,
    secret: &[u8],
    derivation: Option<Vec<u8>>,
    policy_id: String,
    resource: String,
    permission: String,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
) -> Result<Vec<u8>> {
    let ring_pk_bytes = hex::decode(ring_pk)
        .map_err(|e| SdkError::Encoding(format!("invalid ring_pk hex: {e}")))?;
    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| SdkError::Encoding(format!("invalid ring_pk: {e}")))?;

    let context = CiphertextContext {
        ring_pk: ring_pk_bytes,
        policy_id,
        resource,
        permission,
        tier,
        timestamp,
        salt,
        pet_tag: None,
    };

    let (_enc_cmt, encrypted_secret, _proof) = ThresholdDealerNode::encrypt_secret(
        &ring_pk_point,
        secret,
        derivation.as_deref(),
        &context,
    )
    .map_err(|e| SdkError::Crypto(format!("encryption failed: {e}")))?;

    serde_json::to_vec(&encrypted_secret)
        .map_err(|e| SdkError::Encoding(format!("failed to serialize secret: {e}")))
}

/// A PET ownership tag plus its knowledge proof, ready to attach to a
/// document. Mirrors the role of [`PreparedSecret`] one layer up: a pure,
/// local computation the caller can inspect, serialize, or attach to a
/// request without any network dependency.
#[derive(Debug, Clone)]
pub struct PreparedPetTag {
    pub tag: PetTag,
    pub tag_proof: TagKnowledgeProof,
}

/// Generate a fresh PET ownership tag ciphertext `(R, T)` for `owner_id`
/// against a ring's public PET checking key — step 1 of the required
/// noncircular construction order: the tag must exist *before* the payload
/// it will be attached to is encrypted, so the payload's own encryption can
/// bind to it (via [`PetTagBinding`], passed to [`prepare_secret`]). Only
/// after that payload is complete should [`prove_pet_tag_knowledge`] be
/// called, with the exact `tag`/`r_tag` returned here.
///
/// Needs only public information: the ring's `pet_pk` (no secret share is
/// ever involved — `masked_fingerprint = F(owner_id) + r_tag*pet_pk` is
/// computable by anyone who knows `pet_pk`).
///
/// Returns the tag plus the secret `r_tag` the caller must hold onto for
/// [`prove_pet_tag_knowledge`] — it is never persisted.
pub fn generate_pet_tag(pet_pk_hex: &str, owner_id: &str) -> Result<(PetTag, Fr)> {
    let pet_pk_bytes = hex::decode(pet_pk_hex)
        .map_err(|e| SdkError::Encoding(format!("invalid pet_pk hex: {e}")))?;
    let pet_pk: G1Affine = G1Affine::from_bytes(&pet_pk_bytes)
        .map_err(|e| SdkError::Encoding(format!("invalid pet_pk: {e}")))?;
    // An identity checking key would make `r_tag*pet_pk` the identity too,
    // so the "masked" fingerprint would just be `F(owner)` in the clear —
    // reject it outright rather than silently producing a tag that exposes
    // the owner fingerprint.
    if DkgImpl::public_key_is_identity(&pet_pk) {
        return Err(SdkError::InvalidInput(
            "invalid pet_pk: cannot be the identity element".to_string(),
        ));
    }

    let (r_tag, r_point) = crypto::helpers::generate_keypair()
        .map_err(|e| SdkError::Crypto(format!("failed to generate r_tag: {e}")))?;
    let ephemeral_point = CryptoSerialize::to_bytes(&r_point)
        .map_err(|e| SdkError::Encoding(format!("failed to serialize R: {e}")))?;

    // `r_tag` is secret ephemeral randomness, not a public scalar — must go
    // through the constant-time path (see `mul_point_secret`'s doc
    // comment).
    let blinding = crypto::helpers::mul_point_secret(&pet_pk, &r_tag)
        .map_err(|e| SdkError::Crypto(format!("failed to compute r_tag*pet_pk: {e}")))?;
    let fingerprint = PetImpl::owner_fingerprint(owner_id.as_bytes())
        .map_err(|e| SdkError::Crypto(format!("failed to compute owner fingerprint: {e}")))?;
    let masked_fingerprint_point =
        crypto::helpers::add_points(&fingerprint, &blinding).map_err(|e| {
            SdkError::Crypto(format!("failed to combine fingerprint and blinding: {e}"))
        })?;
    let masked_fingerprint = CryptoSerialize::to_bytes(&masked_fingerprint_point)
        .map_err(|e| SdkError::Encoding(format!("failed to serialize masked fingerprint: {e}")))?;

    Ok((
        PetTag {
            ephemeral_point,
            masked_fingerprint,
        },
        r_tag,
    ))
}

/// Complete a PET tag's knowledge proof over an *already-encrypted* payload
/// — step 3 of the required construction order (see [`generate_pet_tag`]).
/// `prepared` must have come from [`prepare_secret`] called with `tag`
/// bound into its context (as a [`PetTagBinding`]); otherwise the resulting
/// proof's digest won't match what a verifier independently reconstructs.
///
/// `tag`/`r_tag` must be the exact pair [`generate_pet_tag`] returned —
/// this function never generates its own randomness.
pub fn prove_pet_tag_knowledge(
    prepared: &PreparedSecret,
    ring_id: &str,
    pet_pk_hex: &str,
    tag: PetTag,
    r_tag: Fr,
) -> Result<PreparedPetTag> {
    // `r_tag` is secret ephemeral randomness (see `generate_pet_tag`'s doc
    // comment) — zeroize it on every exit rather than leaving it sitting in
    // this frame until overwritten.
    let r_tag = zeroize::Zeroizing::new(r_tag);
    let pet_pk_bytes = hex::decode(pet_pk_hex)
        .map_err(|e| SdkError::Encoding(format!("invalid pet_pk hex: {e}")))?;

    let secret: Secret = serde_json::from_slice(&prepared.encrypted_document)
        .map_err(|e| SdkError::Encoding(format!("failed to parse prepared secret: {e}")))?;
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
        .map_err(|e| SdkError::Crypto(format!("failed to prove tag knowledge: {e}")))?;

    Ok(PreparedPetTag { tag, tag_proof })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode_point(point: &G1Affine) -> String {
        hex::encode(CryptoSerialize::to_bytes(point).expect("serialize point"))
    }

    fn binding_for(tag: &PetTag, ring_id: &str, pet_pk_hex: &str) -> PetTagBinding {
        PetTagBinding {
            ring_id: ring_id.to_string(),
            pet_pk: hex::decode(pet_pk_hex).expect("decode pet_pk hex"),
            ephemeral_point: tag.ephemeral_point.clone(),
            masked_fingerprint: tag.masked_fingerprint.clone(),
        }
    }

    #[test]
    fn prepare_secret_roundtrips_through_json() {
        let (_ring_sk, ring_pk) =
            crypto::helpers::generate_keypair().expect("generate ring keypair");
        let prepared = prepare_secret(
            b"test secret",
            &hex_encode_point(&ring_pk),
            None,
            "test-policy".to_string(),
            "test-resource".to_string(),
            "read".to_string(),
            None,
            None,
            None,
            None,
        )
        .expect("prepare_secret should succeed");

        let json = serde_json::to_string(&prepared).expect("serialize PreparedSecret");
        let round_tripped: PreparedSecret =
            serde_json::from_str(&json).expect("deserialize PreparedSecret");
        assert_eq!(
            round_tripped.encrypted_document,
            prepared.encrypted_document
        );
        assert_eq!(round_tripped.enc_cmt, prepared.enc_cmt);
        assert_eq!(round_tripped.challenge, prepared.challenge);
        assert_eq!(round_tripped.response, prepared.response);
        assert_eq!(round_tripped.context.policy_id, prepared.context.policy_id);
    }

    #[test]
    fn prepare_secret_rejects_invalid_hex_ring_pk() {
        let result = prepare_secret(
            b"test secret",
            "not-hex",
            None,
            "test-policy".to_string(),
            "test-resource".to_string(),
            "read".to_string(),
            None,
            None,
            None,
            None,
        );
        assert!(
            matches!(result, Err(SdkError::Encoding(msg)) if msg.contains("invalid ring_pk hex"))
        );
    }

    #[test]
    fn prepare_secret_rejects_hex_that_is_not_a_valid_curve_point() {
        let result = prepare_secret(
            b"test secret",
            "aabb",
            None,
            "test-policy".to_string(),
            "test-resource".to_string(),
            "read".to_string(),
            None,
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(SdkError::Encoding(msg)) if msg.contains("invalid ring_pk")));
    }

    /// A genuine, independently generated checking key must retain normal
    /// behavior — confirms `generate_pet_tag`'s identity-key rejection
    /// isn't vacuous against a helper that rejects everything. Also
    /// exercises the full required construction order end to end: generate
    /// the tag, bind it into `prepare_secret`'s context, then prove
    /// knowledge over the completed payload.
    #[test]
    fn generate_and_prove_pet_tag_succeeds_for_a_genuine_checking_key() {
        let (_ring_sk, ring_pk) =
            crypto::helpers::generate_keypair().expect("generate ring keypair");
        let (_pet_sk, pet_pk) =
            crypto::helpers::generate_keypair().expect("generate pet checking keypair");
        let pet_pk_hex = hex_encode_point(&pet_pk);
        let ring_id = "test-ring";

        let (tag, r_tag) =
            generate_pet_tag(&pet_pk_hex, "owner-1").expect("generate a genuine tag");
        let prepared = prepare_secret(
            b"test secret",
            &hex_encode_point(&ring_pk),
            None,
            "test-policy".to_string(),
            "test-resource".to_string(),
            "read".to_string(),
            None,
            None,
            None,
            Some(binding_for(&tag, ring_id, &pet_pk_hex)),
        )
        .expect("prepare_secret should succeed");

        let result = prove_pet_tag_knowledge(&prepared, ring_id, &pet_pk_hex, tag, r_tag);
        assert!(
            result.is_ok(),
            "a genuine checking key must still produce a provable tag: {:?}",
            result.err()
        );
    }

    /// Finding from the pre-extraction implementation: an identity PET
    /// checking key would make `r_tag*pet_pk` the identity too, so
    /// `masked_fingerprint` would just be `F(owner)` in the clear.
    /// `generate_pet_tag` must reject it outright.
    #[test]
    fn generate_pet_tag_rejects_an_identity_checking_key() {
        let identity_pet_pk_hex = hex_encode_point(&G1Affine::default());
        let result = generate_pet_tag(&identity_pet_pk_hex, "owner-1");
        assert!(
            result.is_err(),
            "an identity PET checking key must be rejected, not silently accepted"
        );
    }

    /// Copying a payload's ciphertext and encryption proof and reattaching
    /// a *different* tag — generated with fresh, independent randomness,
    /// and with a perfectly valid proof of its own — must make the
    /// *original* payload proof fail to verify. This is the actual attack
    /// the noncircular construction order exists to close.
    #[test]
    fn reattaching_a_different_tag_fails_the_original_payload_proof() {
        let (_ring_sk, ring_pk) =
            crypto::helpers::generate_keypair().expect("generate ring keypair");
        let (_pet_sk, pet_pk) =
            crypto::helpers::generate_keypair().expect("generate pet checking keypair");
        let pet_pk_hex = hex_encode_point(&pet_pk);
        let ring_id = "test-ring";

        let (original_tag, _r_tag) =
            generate_pet_tag(&pet_pk_hex, "charlie").expect("generate Charlie's tag");
        let prepared = prepare_secret(
            b"Charlie's secret",
            &hex_encode_point(&ring_pk),
            None,
            "test-policy".to_string(),
            "test-resource".to_string(),
            "read".to_string(),
            None,
            None,
            None,
            Some(binding_for(&original_tag, ring_id, &pet_pk_hex)),
        )
        .expect("prepare_secret should succeed");
        let proof = EncryptionProof {
            challenge: prepared.challenge.clone(),
            response: prepared.response.clone(),
        };
        let secret: Secret =
            serde_json::from_slice(&prepared.encrypted_document).expect("parse encrypted document");

        // Attacker: fresh tag, own randomness, no knowledge of the plaintext.
        let (forged_tag, _forged_r_tag) =
            generate_pet_tag(&pet_pk_hex, "alice").expect("generate Alice's tag");
        let mut reattached_context = prepared.context.clone();
        reattached_context.pet_tag = Some(binding_for(&forged_tag, ring_id, &pet_pk_hex));

        assert!(
            ThresholdDealerNode::verify_encryption(&proof, &reattached_context, &secret).is_err(),
            "Charlie's original payload proof must not verify against Alice's reattached tag"
        );
        assert!(
            ThresholdDealerNode::verify_encryption(&proof, &prepared.context, &secret).is_ok(),
            "the original, unmodified context must still verify"
        );
    }
}
