use super::common::{PubPoly, FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE};
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        CryptoDeserialize, Pet, PetCheckReply, PetTag, PubPoly as PubPolyTrait, PubShare,
        TagKnowledgeProof,
    },
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const NAME: &str = "pet/bls12_381";
/// Domain separator for the PET owner-fingerprint hash-to-scalar. Distinct from
/// `DERIVATION_DOMAIN` (capability derivation) in `bls12_381::pre` so the two
/// hash-to-scalar uses can never collide on the same input bytes.
const FINGERPRINT_DOMAIN: &[u8] = b"orbis-pet-fingerprint-v1";
/// Domain separator for the tag-knowledge proof's Fiat-Shamir challenge.
const TAG_KNOWLEDGE_PROOF_DOMAIN: &[u8] = b"orbis-pet-tag-knowledge-proof-v1";
/// Domain separator for the per-share PET-check DLEQ proof's Fiat-Shamir
/// challenge. Distinct from `TAG_KNOWLEDGE_PROOF_DOMAIN` and from PRE's own
/// reencryption-proof domain (`bls12_381::pre::PROTOCOL`) so a proof from one
/// scheme can never be confused for or replayed as another's.
const PET_CHECK_DLEQ_DOMAIN: &[u8] = b"orbis-pet-check-dleq-proof-v1";

#[derive(Clone, Debug)]
pub struct PetNode {}

impl Pet for PetNode {
    type PublicKey = G1Affine;
    type ShareValue = Fr;
    type PubPoly = PubPoly;

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

    fn partial_pet_check(
        share_i: &Self::ShareValue,
        node_id: u32,
        tag: &PetTag,
    ) -> Result<PetCheckReply<Self::ShareValue, Self::PublicKey>> {
        let r_point = Self::decode_group_element(&tag.ephemeral_point, "ephemeral_point")?;
        // Constant-time: share_i is this node's secret DKG share.
        let partial = crate::bls12_381::ct::ct_mul_g1(&r_point, share_i)?;

        let generator = G1Affine::from(G1Projective::generator());
        // Recomputed locally so the challenge below binds this node's own
        // claimed public share: an honest prover's value here equals
        // `pub_poly.eval(node_id)`; `verify_partial_pet_check` uses the
        // authoritative polynomial value instead, so a dishonest prover's
        // mismatched share makes the challenge recomputation there fail to
        // match. Constant-time: share_i is secret.
        let public_share = crate::bls12_381::ct::ct_mul_g1(&generator, share_i)?;

        // Zeroizing: `ri` is this proof's secret nonce — same rationale as
        // `prove_tag_knowledge`'s `k`.
        let mut rng = OsRng;
        let ri = Zeroizing::new(loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        });
        // `ri` is this proof's fresh nonce — constant-time.
        let ui_hat = crate::bls12_381::ct::ct_mul_g1(&r_point, &ri)?;
        let hi_hat = crate::bls12_381::ct::ct_mul_g1(&generator, &ri)?;

        let challenge = Self::pet_check_proof_challenge(
            node_id,
            &r_point,
            &public_share,
            &partial,
            &[ui_hat, hi_hat],
        )?;
        // proof = ri + challenge*share_i — constant-time scalar arithmetic,
        // since share_i is secret. Matches `prove_tag_knowledge`'s
        // convention, intentionally stricter than `bls12_381::pre`'s older
        // plain-arithmetic response computation.
        let proof = crate::bls12_381::ct::ct_scalar_mul_add(&ri, &challenge, share_i)?;

        Ok(PetCheckReply {
            partial: PubShare {
                i: node_id,
                v: partial,
            },
            challenge,
            proof,
        })
    }

    fn verify_partial_pet_check(
        pub_poly: &Self::PubPoly,
        tag: &PetTag,
        reply: &PetCheckReply<Self::ShareValue, Self::PublicKey>,
    ) -> Result<()> {
        let r_point = Self::decode_group_element(&tag.ephemeral_point, "ephemeral_point")?;
        let node_id = reply.partial.i;
        // Authoritative — never the prover's own claimed value.
        let public_share = pub_poly.eval(node_id);

        // UiHat = f*R - e*partial
        let ui_hat: G1Affine = (G1Projective::from(r_point) * reply.proof
            - G1Projective::from(reply.partial.v) * reply.challenge)
            .into();
        // HiHat = f*G - e*public_share
        let hi_hat: G1Affine = (G1Projective::generator() * reply.proof
            - G1Projective::from(public_share) * reply.challenge)
            .into();

        let recomputed_challenge = Self::pet_check_proof_challenge(
            node_id,
            &r_point,
            &public_share,
            &reply.partial.v,
            &[ui_hat, hi_hat],
        )?;

        // Constant-time comparison. Fr serializes to exactly 32 bytes for BLS12-381.
        let mut claimed_bytes = [0u8; 32];
        let mut recomputed_bytes = [0u8; 32];
        reply
            .challenge
            .serialize_compressed(&mut &mut claimed_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        recomputed_challenge
            .serialize_compressed(&mut &mut recomputed_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        if claimed_bytes.ct_ne(&recomputed_bytes).into() {
            return Err(CryptoError::ElGamalError(
                "PET check share verification failed".to_string(),
            ));
        }

        Ok(())
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

        let mut result = G1Projective::zero();
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
            result += G1Projective::from(share_i.v) * lambda;
        }
        Ok(result.into())
    }

    fn verify_pet_match(
        tag: &PetTag,
        combined_check: &Self::PublicKey,
        target_fingerprint: &Self::PublicKey,
    ) -> Result<()> {
        let masked_fingerprint =
            Self::decode_group_element(&tag.masked_fingerprint, "masked_fingerprint")?;
        let expected: G1Affine =
            (G1Projective::from(*target_fingerprint) + G1Projective::from(*combined_check)).into();

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
    /// point in the correct subgroup. `field_name` is used only for error
    /// messages.
    fn decode_group_element(bytes: &[u8], field_name: &str) -> Result<G1Affine> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid {} length: expected {}, got {}",
                field_name,
                G1_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let point = G1Affine::from_bytes(bytes).map_err(|e| {
            CryptoError::ElGamalError(format!("failed to decompress {}: {:?}", field_name, e))
        })?;
        if point.is_zero() {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid {}: cannot be the identity element",
                field_name
            )));
        }
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid {}: not in correct subgroup",
                field_name
            )));
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

    /// Fiat-Shamir challenge for the per-share PET-check DLEQ proof:
    /// `Fr::from_le_bytes_mod_order(SHA512(PET_CHECK_DLEQ_DOMAIN || node_id
    ///   || compress(R) || compress(public_share) || compress(partial)
    ///   || compress(each of proof_points)))`.
    ///
    /// Binds the claimed index, the (claimed or authoritative, depending on
    /// caller) public share, the input point, and the contribution itself —
    /// under-binding any of these would let a proof computed for one
    /// index/share/context be replayed against another.
    fn pet_check_proof_challenge(
        node_id: u32,
        r_point: &G1Affine,
        public_share: &G1Affine,
        partial: &G1Affine,
        proof_points: &[G1Affine],
    ) -> Result<Fr> {
        let mut hasher = Sha512::new();
        hasher.update(PET_CHECK_DLEQ_DOMAIN);
        hasher.update(node_id.to_le_bytes());

        let mut bytes = Vec::with_capacity(G1_COMPRESSED_SIZE);
        for point in [r_point, public_share, partial] {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }
        for point in proof_points {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }

        Ok(Fr::from_le_bytes_mod_order(&hasher.finalize()))
    }
}
