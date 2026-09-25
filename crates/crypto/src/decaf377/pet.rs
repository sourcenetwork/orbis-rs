use super::common::{ELEMENT_COMPRESSED_SIZE, FR_COMPRESSED_SIZE};
use crate::{
    error::{CryptoError, Result},
    r#trait::{CryptoDeserialize, Pet, PetTag, PubShare, TagKnowledgeProof},
};
use ark_ff_05::{One, Zero};
use ark_serialize_05::CanonicalSerialize;
use decaf377::{Element, Fr};
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const NAME: &str = "pet/decaf377";
/// Domain separator for the PET owner-fingerprint hash-to-scalar. Distinct from
/// `DERIVATION_DOMAIN` (capability derivation) in `decaf377::pre` so the two
/// hash-to-scalar uses can never collide on the same input bytes.
const FINGERPRINT_DOMAIN: &[u8] = b"orbis-pet-fingerprint-v1";
/// Domain separator for the tag-knowledge proof's Fiat-Shamir challenge.
const TAG_KNOWLEDGE_PROOF_DOMAIN: &[u8] = b"orbis-pet-tag-knowledge-proof-v1";

#[derive(Clone, Debug)]
pub struct PetNode {}

impl Pet for PetNode {
    type PublicKey = Element;
    type ShareValue = Fr;

    fn new() -> Self {
        PetNode {}
    }

    fn name() -> String {
        NAME.to_string()
    }

    fn owner_fingerprint(owner_id: &[u8]) -> Result<Self::PublicKey> {
        let mut hasher = Sha512::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(owner_id);
        let scalar = Fr::from_le_bytes_mod_order(&hasher.finalize());
        Ok(Element::GENERATOR * scalar)
    }

    fn prove_tag_knowledge(
        r_tag: &Self::ShareValue,
        tag: &PetTag,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<TagKnowledgeProof> {
        let ephemeral_point = Self::decode_group_element(&tag.ephemeral_point, "ephemeral_point")?;

        let mut rng = OsRng;
        // Zeroizing: `k` is this proof's secret nonce. If it survived in process
        // memory, `r_tag = (z - k) / c` would recover the tag's owner fingerprint
        // from the public proof (see `Pet::prove_tag_knowledge`'s docs).
        let k = Zeroizing::new(loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        });
        let r1 = Element::GENERATOR * *k;

        let c = Self::tag_knowledge_proof_challenge(&ephemeral_point, &r1, tag_transcript_digest)?;
        // z = k + c*r_tag. Unlike the BLS12-381 backend, there is no
        // constant-time scalar-arithmetic path available for decaf377's `Fr` in
        // this codebase (no blst-equivalent) — flagged to the user rather than
        // improvised; see the PET review discussion for the follow-up decision.
        let z = *k + (c * r_tag);

        let mut challenge_bytes = Vec::new();
        c.serialize_compressed(&mut challenge_bytes)?;
        let mut response_bytes = Vec::new();
        z.serialize_compressed(&mut response_bytes)?;

        Ok(TagKnowledgeProof {
            challenge: challenge_bytes,
            response: response_bytes,
        })
    }

    fn verify_tag_knowledge(
        tag: &PetTag,
        proof: &TagKnowledgeProof,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<()> {
        let ephemeral_point = Self::decode_group_element(&tag.ephemeral_point, "ephemeral_point")?;

        if proof.challenge.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid tag-knowledge-proof challenge length: expected {}, got {}",
                FR_COMPRESSED_SIZE,
                proof.challenge.len()
            )));
        }
        let challenge = Fr::from_bytes(&proof.challenge[..]).map_err(|e| {
            CryptoError::ElGamalError(format!(
                "Failed to deserialize tag-knowledge-proof challenge: {:?}",
                e
            ))
        })?;
        if proof.response.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid tag-knowledge-proof response length: expected {}, got {}",
                FR_COMPRESSED_SIZE,
                proof.response.len()
            )));
        }
        let response = Fr::from_bytes(&proof.response[..]).map_err(|e| {
            CryptoError::ElGamalError(format!(
                "Failed to deserialize tag-knowledge-proof response: {:?}",
                e
            ))
        })?;

        // R1' = z*G - c*R
        let r1_prime = Element::GENERATOR * response - ephemeral_point * challenge;

        let recomputed_challenge = Self::tag_knowledge_proof_challenge(
            &ephemeral_point,
            &r1_prime,
            tag_transcript_digest,
        )?;

        let mut challenge_bytes = [0u8; 32];
        let mut recomputed_bytes = [0u8; 32];
        challenge
            .serialize_compressed(&mut &mut challenge_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        recomputed_challenge
            .serialize_compressed(&mut &mut recomputed_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        if challenge_bytes.ct_ne(&recomputed_bytes).into() {
            return Err(CryptoError::ElGamalError(
                "Tag knowledge proof verification failed".to_string(),
            ));
        }

        Ok(())
    }

    fn partial_pet_check(share_i: &Self::ShareValue, tag: &PetTag) -> Result<Self::PublicKey> {
        let r_point = Self::decode_group_element(&tag.ephemeral_point, "ephemeral_point")?;
        // No constant-time scalar-multiplication path available for decaf377
        // in this codebase (same gap as `prove_tag_knowledge`'s `z`
        // computation) — flagged for the planned Jubjub migration, not
        // improvised here.
        Ok(r_point * *share_i)
    }

    fn combine_pet_check_shares(
        shares: &[PubShare<Self::PublicKey>],
        threshold: usize,
        n: usize,
    ) -> Result<Self::PublicKey> {
        if shares.len() < threshold {
            return Err(CryptoError::ElGamalError(format!(
                "Insufficient PET check shares: got {}, need {}",
                shares.len(),
                threshold
            )));
        }
        let shares_to_use = &shares[..threshold];

        let mut seen_indices = HashSet::new();
        for share in shares_to_use {
            if share.i < 1 || share.i > n as u32 {
                return Err(CryptoError::ElGamalError(format!(
                    "Invalid PET check share index: {} (must be in range [1, {}])",
                    share.i, n
                )));
            }
            if !seen_indices.insert(share.i) {
                return Err(CryptoError::ElGamalError(format!(
                    "Duplicate PET check share index: {}",
                    share.i
                )));
            }
        }

        let mut result = Element::default();
        for (i, share_i) in shares_to_use.iter().enumerate() {
            let mut num = Fr::one();
            let mut den = Fr::one();
            for (j, share_j) in shares_to_use.iter().enumerate() {
                if i != j {
                    let xi = Fr::from(share_i.i as u64);
                    let xj = Fr::from(share_j.i as u64);
                    num *= xj;
                    den *= xj - xi;
                }
            }
            let lambda = num * den.inverse().ok_or_else(|| {
                CryptoError::ElGamalError(
                    "Division by zero in Lagrange interpolation - this should not happen after validation"
                        .to_string(),
                )
            })?;
            result += share_i.v * lambda;
        }
        Ok(result)
    }

    fn verify_pet_match(
        tag: &PetTag,
        combined_check: &Self::PublicKey,
        target_fingerprint: &Self::PublicKey,
    ) -> Result<()> {
        let masked_fingerprint =
            Self::decode_group_element(&tag.masked_fingerprint, "masked_fingerprint")?;
        let expected = *target_fingerprint + *combined_check;

        let mut expected_bytes = Vec::new();
        expected.serialize_compressed(&mut expected_bytes)?;
        let mut actual_bytes = Vec::new();
        masked_fingerprint.serialize_compressed(&mut actual_bytes)?;

        if expected_bytes.ct_ne(&actual_bytes).into() {
            return Err(CryptoError::ElGamalError(
                "PET check failed: tag does not match the audit target".to_string(),
            ));
        }
        Ok(())
    }
}

impl PetNode {
    /// Decompress and validate a tag component (`ephemeral_point` or
    /// `masked_fingerprint`): must be a canonically-encoded, non-identity
    /// point. decaf377: no separate subgroup check needed — the decaf
    /// construction guarantees every deserialized point is already in the
    /// prime-order group. `field_name` is used only for error messages.
    fn decode_group_element(bytes: &[u8], field_name: &str) -> Result<Element> {
        if bytes.len() != ELEMENT_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid {} length: expected {}, got {}",
                field_name,
                ELEMENT_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let point = Element::from_bytes(bytes).map_err(|e| {
            CryptoError::ElGamalError(format!("failed to decompress {}: {:?}", field_name, e))
        })?;
        if point == Element::default() {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid {}: cannot be the identity element",
                field_name
            )));
        }
        Ok(point)
    }

    /// Fiat-Shamir challenge:
    /// `Fr::from_le_bytes_mod_order(SHA512(TAG_KNOWLEDGE_PROOF_DOMAIN || compress(R)
    ///   || compress(R1) || tag_transcript_digest))`.
    fn tag_knowledge_proof_challenge(
        ephemeral_point: &Element,
        r1: &Element,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<Fr> {
        let mut hasher = Sha512::new();
        hasher.update(TAG_KNOWLEDGE_PROOF_DOMAIN);

        let mut bytes = Vec::with_capacity(ELEMENT_COMPRESSED_SIZE);
        for point in [ephemeral_point, r1] {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }
        hasher.update(tag_transcript_digest);

        Ok(Fr::from_le_bytes_mod_order(&hasher.finalize()))
    }
}
