use super::common::{FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE};
use crate::{
    error::{CryptoError, Result},
    r#trait::{CryptoDeserialize, Pet, PetTag, TagKnowledgeProof},
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const NAME: &str = "pet/bls12_381";
/// Domain separator for the PET owner-fingerprint hash-to-scalar. Distinct from
/// `DERIVATION_DOMAIN` (capability derivation) in `bls12_381::pre` so the two
/// hash-to-scalar uses can never collide on the same input bytes.
const FINGERPRINT_DOMAIN: &[u8] = b"orbis-pet-fingerprint-v1";
/// Domain separator for the tag-knowledge proof's Fiat-Shamir challenge.
const TAG_KNOWLEDGE_PROOF_DOMAIN: &[u8] = b"orbis-pet-tag-knowledge-proof-v1";

#[derive(Clone, Debug)]
pub struct PetNode {}

impl Pet for PetNode {
    type PublicKey = G1Affine;
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
        Ok((G1Projective::generator() * scalar).into())
    }

    fn prove_tag_knowledge(
        r_tag: &Self::ShareValue,
        tag: &PetTag,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<TagKnowledgeProof> {
        let ephemeral_point = Self::decode_ephemeral_point(&tag.ephemeral_point)?;

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
        // `k` is this proof's fresh nonce — constant-time.
        let r1: G1Affine =
            crate::bls12_381::ct::ct_mul_g1(&G1Affine::from(G1Projective::generator()), &k)?;

        let c = Self::tag_knowledge_proof_challenge(&ephemeral_point, &r1, tag_transcript_digest)?;
        // z = k + c*r_tag — constant-time scalar arithmetic, since r_tag is secret.
        let z = crate::bls12_381::ct::ct_scalar_mul_add(&k, &c, r_tag)?;

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
        let ephemeral_point = Self::decode_ephemeral_point(&tag.ephemeral_point)?;

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
        let r1_prime: G1Affine = (G1Projective::generator() * response
            - G1Projective::from(ephemeral_point) * challenge)
            .into();

        let recomputed_challenge = Self::tag_knowledge_proof_challenge(
            &ephemeral_point,
            &r1_prime,
            tag_transcript_digest,
        )?;

        // Constant-time compare. Fr serializes to exactly 32 bytes for BLS12-381.
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
}

impl PetNode {
    /// Decompress and validate a tag's `ephemeral_point` (`R`): must be a
    /// canonically-encoded, non-identity point in the correct subgroup.
    fn decode_ephemeral_point(bytes: &[u8]) -> Result<G1Affine> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid ephemeral_point length: expected {}, got {}",
                G1_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let point = G1Affine::from_bytes(bytes).map_err(|e| {
            CryptoError::ElGamalError(format!("failed to decompress ephemeral_point: {:?}", e))
        })?;
        if point.is_zero() {
            return Err(CryptoError::ElGamalError(
                "Invalid ephemeral_point: cannot be the identity element".to_string(),
            ));
        }
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(CryptoError::ElGamalError(
                "Invalid ephemeral_point: not in correct subgroup".to_string(),
            ));
        }
        Ok(point)
    }

    /// Fiat-Shamir challenge:
    /// `Fr::from_le_bytes_mod_order(SHA512(TAG_KNOWLEDGE_PROOF_DOMAIN || compress(R)
    ///   || compress(R1) || tag_transcript_digest))`.
    fn tag_knowledge_proof_challenge(
        ephemeral_point: &G1Affine,
        r1: &G1Affine,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<Fr> {
        let mut hasher = Sha512::new();
        hasher.update(TAG_KNOWLEDGE_PROOF_DOMAIN);

        let mut bytes = Vec::with_capacity(G1_COMPRESSED_SIZE);
        for point in [ephemeral_point, r1] {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }
        hasher.update(tag_transcript_digest);

        Ok(Fr::from_le_bytes_mod_order(&hasher.finalize()))
    }
}
