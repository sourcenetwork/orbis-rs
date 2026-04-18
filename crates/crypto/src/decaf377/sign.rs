//! FROST Threshold Signing implementation for decaf377
//!
//! decaf377 is a prime-order group without pairings, so BLS threshold
//! signatures are impossible. Instead we implement FROST (Flexible
//! Round-Optimized Schnorr Threshold signatures), which requires two
//! interactive rounds:
//!
//! **Round 1 (Nonce Commitment):** Each signer generates random nonces
//! (d_i, e_i), computes commitments (D_i = d_i*G, E_i = e_i*G), and
//! broadcasts them.
//!
//! **Round 2 (Signing):** Given all commitments, each signer computes
//! a partial signature z_i. The coordinator aggregates these into the
//! final Schnorr signature (R, z).

use super::common::PubPoly;
use crate::error::{CryptoError, Result};
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, PubPoly as PubPolyTrait, PubShare,
    ThresholdSigner,
};
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::{Element, Fr};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use super::common::{ELEMENT_COMPRESSED_SIZE, FR_COMPRESSED_SIZE};

/// Domain separation tag for signing key derivation (distinct from PRE derivation domain).
const SIGN_DERIVATION_DOMAIN: &[u8] = b"sign-derivation-v1";

/// Domain separation tag for signing metadata encoding.
const SIGN_METADATA_DOMAIN: &[u8] = b"orbis-sign-metadata-v1";

// ============================================================================
// FROST Types
// ============================================================================

/// Final Schnorr signature (R, z) where verify checks z*G == R + c*Y
#[derive(Clone, Debug)]
pub struct SchnorrSignature {
    pub r_point: Element,
    pub z: Fr,
}

impl PartialEq for SchnorrSignature {
    fn eq(&self, other: &Self) -> bool {
        self.r_point == other.r_point && self.z == other.z
    }
}

impl CryptoSerialize for SchnorrSignature {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(ELEMENT_COMPRESSED_SIZE + FR_COMPRESSED_SIZE);
        self.r_point.serialize_compressed(&mut bytes)?;
        self.z.serialize_compressed(&mut bytes)?;
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        ELEMENT_COMPRESSED_SIZE + FR_COMPRESSED_SIZE
    }
}

impl CryptoDeserialize for SchnorrSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected = ELEMENT_COMPRESSED_SIZE + FR_COMPRESSED_SIZE;
        if bytes.len() != expected {
            return Err(CryptoError::InvalidSignature);
        }
        let r_point = Element::deserialize_compressed(&bytes[..ELEMENT_COMPRESSED_SIZE])?;
        let z = Fr::deserialize_compressed(&bytes[ELEMENT_COMPRESSED_SIZE..expected])?;
        Ok(Self { r_point, z })
    }
}

/// Nonce commitment (D_i, E_i) broadcast in Round 1
#[derive(Clone, Debug)]
pub struct FrostNonceCommitment {
    pub hiding: Element,  // D_i = d_i * G
    pub binding: Element, // E_i = e_i * G
}

impl CryptoSerialize for FrostNonceCommitment {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(2 * ELEMENT_COMPRESSED_SIZE);
        self.hiding.serialize_compressed(&mut bytes)?;
        self.binding.serialize_compressed(&mut bytes)?;
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        2 * ELEMENT_COMPRESSED_SIZE
    }
}

impl CryptoDeserialize for FrostNonceCommitment {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected = 2 * ELEMENT_COMPRESSED_SIZE;
        if bytes.len() != expected {
            return Err(CryptoError::InvalidSignatureShare);
        }
        let hiding = Element::deserialize_compressed(&bytes[..ELEMENT_COMPRESSED_SIZE])?;
        let binding = Element::deserialize_compressed(&bytes[ELEMENT_COMPRESSED_SIZE..expected])?;
        Ok(Self { hiding, binding })
    }
}

/// Secret nonce state held between Round 1 and Round 2
#[derive(Debug)]
pub struct FrostSigningState {
    pub hiding_nonce: Fr,  // d_i (secret)
    pub binding_nonce: Fr, // e_i (secret)
    pub participant_index: u32,
}

impl CryptoSerialize for FrostSigningState {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(4 + 2 * FR_COMPRESSED_SIZE);
        bytes.extend_from_slice(&self.participant_index.to_le_bytes());
        self.hiding_nonce.serialize_compressed(&mut bytes)?;
        self.binding_nonce.serialize_compressed(&mut bytes)?;
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        4 + 2 * FR_COMPRESSED_SIZE
    }
}

impl CryptoDeserialize for FrostSigningState {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected = 4 + 2 * FR_COMPRESSED_SIZE;
        if bytes.len() != expected {
            return Err(CryptoError::InvalidSignatureShare);
        }
        let participant_index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CryptoError::InvalidSignatureShare)?,
        );
        let hiding_nonce = Fr::deserialize_compressed(&bytes[4..4 + FR_COMPRESSED_SIZE])?;
        let binding_nonce = Fr::deserialize_compressed(&bytes[4 + FR_COMPRESSED_SIZE..expected])?;
        Ok(Self {
            hiding_nonce,
            binding_nonce,
            participant_index,
        })
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Domain separation tags
const FROST_BINDING_DOMAIN: &[u8] = b"FROST-decaf377-binding";
const FROST_CHALLENGE_DOMAIN: &[u8] = b"FROST-decaf377-challenge";

/// Compute binding factor for participant j:
///   rho_j = H(BINDING_DOMAIN || j || msg || encoded_commitments)
fn compute_binding_factor(
    participant_id: u32,
    msg: &[u8],
    all_commitments: &[(u32, FrostNonceCommitment)],
) -> Result<Fr> {
    let mut hasher = Sha256::new();
    hasher.update(FROST_BINDING_DOMAIN);
    hasher.update(participant_id.to_le_bytes());
    hasher.update((msg.len() as u64).to_le_bytes());
    hasher.update(msg);
    // Encode all commitments deterministically (sorted by participant_id)
    hasher.update((all_commitments.len() as u32).to_le_bytes());
    for (id, commitment) in all_commitments {
        hasher.update(id.to_le_bytes());
        let bytes = commitment.to_bytes()?;
        hasher.update(&bytes);
    }
    let hash = hasher.finalize();
    Ok(fr_from_hash(&hash))
}

/// Compute the group commitment R = sum(D_j + rho_j * E_j)
fn compute_group_commitment(
    all_commitments: &[(u32, FrostNonceCommitment)],
    msg: &[u8],
) -> Result<(Element, Vec<(u32, Fr)>)> {
    // Canonicalize: sort by participant_id so compute_binding_factor sees deterministic ordering
    let mut canonical: Vec<(u32, FrostNonceCommitment)> = all_commitments.to_vec();
    canonical.sort_by_key(|(id, _)| *id);

    // Reject duplicate participant_ids
    for i in 1..canonical.len() {
        if canonical[i].0 == canonical[i - 1].0 {
            return Err(CryptoError::InvalidSignatureShare);
        }
    }

    let mut r = Element::default(); // identity
    let mut binding_factors = Vec::with_capacity(canonical.len());

    for (id, commitment) in &canonical {
        let rho = compute_binding_factor(*id, msg, &canonical)?;
        r += commitment.hiding + commitment.binding * rho;
        binding_factors.push((*id, rho));
    }

    Ok((r, binding_factors))
}

/// Fiat-Shamir challenge: c = H(CHALLENGE_DOMAIN || R || Y || msg)
fn compute_challenge(r_point: &Element, aggregate_pk: &Element, msg: &[u8]) -> Result<Fr> {
    let mut hasher = Sha256::new();
    hasher.update(FROST_CHALLENGE_DOMAIN);
    let mut r_bytes = Vec::new();
    r_point
        .serialize_compressed(&mut r_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    hasher.update(&r_bytes);
    let mut pk_bytes = Vec::new();
    aggregate_pk
        .serialize_compressed(&mut pk_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    hasher.update(&pk_bytes);
    hasher.update(msg);
    let hash = hasher.finalize();
    Ok(fr_from_hash(&hash))
}

/// Convert a 32-byte hash to an Fr element (reduce mod p)
fn fr_from_hash(hash: &[u8]) -> Fr {
    // Interpret as little-endian u256 and reduce mod the field modulus.
    // decaf377::Fr::from_le_bytes_mod_order handles this correctly.
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Lagrange coefficient: lambda_i = product_{j != i} (x_j / (x_j - x_i)) evaluated at x=0
fn lagrange_coefficient(idx: u32, participant_ids: &[u32]) -> Result<Fr> {
    let xi = Fr::from(idx as u64);
    let mut num = Fr::one();
    let mut den = Fr::one();

    for &j in participant_ids {
        if j == idx {
            continue;
        }
        let xj = Fr::from(j as u64);
        num *= xj;
        den *= xj - xi;
    }

    let den_inv = den.inverse().ok_or(CryptoError::InvalidSignatureShare)?;

    Ok(num * den_inv)
}

/// Get aggregate public key from pub_poly: Y = pub_poly.eval(0) (constant term)
fn aggregate_pk_from_pub_poly(pub_poly: &PubPoly) -> Element {
    pub_poly.eval(0)
}

/// Generate a random non-zero scalar
fn random_nonzero_scalar() -> Fr {
    loop {
        let s = Fr::rand(&mut OsRng);
        if !s.is_zero() {
            return s;
        }
    }
}

// ============================================================================
// ThresholdSigner implementation
// ============================================================================

/// Threshold FROST signer for decaf377
pub struct ThresholdDecafSigner;

impl ThresholdSigner for ThresholdDecafSigner {
    const INTERACTIVE: bool = true;

    type ShareValue = Fr;
    type Signature = SchnorrSignature;
    type PublicKey = Element;
    type PubPoly = PubPoly;
    type DistKeyShare = DistKeyShare<Fr>;
    type SigShare = PubShare<Fr>;
    type NonceCommitment = FrostNonceCommitment;
    type SigningState = FrostSigningState;

    fn new() -> Self {
        ThresholdDecafSigner
    }

    fn name() -> String {
        "threshold-frost-decaf377".to_string()
    }

    fn hash_message(&self, _msg: &[u8]) -> Result<Self::Signature> {
        Err(CryptoError::InvalidSignature)
    }

    fn generate_nonces(
        &self,
        dist_key_share: &Self::DistKeyShare,
    ) -> Result<(Self::NonceCommitment, Self::SigningState)> {
        let d = random_nonzero_scalar();
        let e = random_nonzero_scalar();

        let commitment = FrostNonceCommitment {
            hiding: Element::GENERATOR * d,
            binding: Element::GENERATOR * e,
        };

        let state = FrostSigningState {
            hiding_nonce: d,
            binding_nonce: e,
            participant_index: dist_key_share.pri_share.i,
        };

        Ok((commitment, state))
    }

    fn sign(
        &self,
        dist_key_share: &Self::DistKeyShare,
        msg: &[u8],
        pub_poly: &Self::PubPoly,
        signing_state: Option<&Self::SigningState>,
        all_commitments: &[(u32, Self::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<Self::SigShare> {
        let signing_state = signing_state.ok_or(CryptoError::InvalidSignatureShare)?;

        let idx = dist_key_share.pri_share.i;
        let s_i = dist_key_share.pri_share.v;

        if idx != signing_state.participant_index {
            return Err(CryptoError::InvalidSignatureShare);
        }

        // Verify our own commitment wasn't tampered with by the coordinator.
        // Recompute from our secret nonces and check against what's in all_commitments.
        let our_commitment = all_commitments
            .iter()
            .find(|(id, _)| *id == idx)
            .map(|(_, c)| c)
            .ok_or(CryptoError::InvalidSignatureShare)?;

        let expected_hiding = Element::GENERATOR * signing_state.hiding_nonce;
        let expected_binding = Element::GENERATOR * signing_state.binding_nonce;
        if our_commitment.hiding != expected_hiding || our_commitment.binding != expected_binding {
            return Err(CryptoError::SigningError(
                "Commitment mismatch: coordinator may have tampered with our nonce commitment"
                    .to_string(),
            ));
        }

        // Compute group commitment R and binding factors
        let (r_point, binding_factors) = compute_group_commitment(all_commitments, msg)?;

        // Find our binding factor
        let rho_i = binding_factors
            .iter()
            .find(|(id, _)| *id == idx)
            .map(|(_, rho)| *rho)
            .ok_or(CryptoError::InvalidSignatureShare)?;

        // Aggregate public key; use derived pk in challenge when derivation is provided.
        // Metadata is folded into the derivation scalar for binding.
        let aggregate_pk = aggregate_pk_from_pub_poly(pub_poly);
        let effective_pk = if let Some(deriv) = derivation {
            let d = derive_sign_scalar(deriv, metadata);
            if d.is_zero() {
                return Err(CryptoError::SigningError(
                    "Zero derivation scalar".to_string(),
                ));
            }
            aggregate_pk * d
        } else {
            aggregate_pk
        };

        // Fiat-Shamir challenge binds to derived public key (which encodes metadata via d)
        let c = compute_challenge(&r_point, &effective_pk, msg)?;

        // Lagrange coefficient
        let participant_ids: Vec<u32> = all_commitments.iter().map(|(id, _)| *id).collect();
        let lambda_i = lagrange_coefficient(idx, &participant_ids)?;

        // Apply derivation (with metadata) to secret share: s_i' = d * s_i
        let s_i_eff = if let Some(deriv) = derivation {
            s_i * derive_sign_scalar(deriv, metadata)
        } else {
            s_i
        };

        // Partial signature: z_i = d_i + rho_i * e_i + lambda_i * s_i' * c
        let z_i = signing_state.hiding_nonce
            + rho_i * signing_state.binding_nonce
            + lambda_i * s_i_eff * c;

        Ok(PubShare { i: idx, v: z_i })
    }

    fn verify_share(
        &self,
        msg: &[u8],
        pub_poly: &Self::PubPoly,
        sig_share: &Self::SigShare,
        all_commitments: &[(u32, Self::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<()> {
        let idx = sig_share.i;
        let z_i = sig_share.v;

        // Find this participant's commitment
        let commitment = all_commitments
            .iter()
            .find(|(id, _)| *id == idx)
            .map(|(_, c)| c)
            .ok_or(CryptoError::InvalidSignatureShare)?;

        // Compute group commitment R and binding factor for this participant
        let (r_point, binding_factors) = compute_group_commitment(all_commitments, msg)?;

        let rho_i = binding_factors
            .iter()
            .find(|(id, _)| *id == idx)
            .map(|(_, rho)| *rho)
            .ok_or(CryptoError::InvalidSignatureShare)?;

        // Aggregate public key; use derived pk (with metadata binding) in challenge
        let aggregate_pk = aggregate_pk_from_pub_poly(pub_poly);
        let effective_pk = if let Some(deriv) = derivation {
            aggregate_pk * derive_sign_scalar(deriv, metadata)
        } else {
            aggregate_pk
        };
        let c = compute_challenge(&r_point, &effective_pk, msg)?;

        // Lagrange coefficient
        let participant_ids: Vec<u32> = all_commitments.iter().map(|(id, _)| *id).collect();
        let lambda_i = lagrange_coefficient(idx, &participant_ids)?;

        // Public key share for this participant: pk_i' = d * pub_poly.eval(idx)
        let pk_i_eff = if let Some(deriv) = derivation {
            pub_poly.eval(idx) * derive_sign_scalar(deriv, metadata)
        } else {
            pub_poly.eval(idx)
        };

        // Verify: z_i * G == D_i + rho_i * E_i + lambda_i * c * pk_i'
        let lhs = Element::GENERATOR * z_i;
        let rhs = commitment.hiding + commitment.binding * rho_i + pk_i_eff * (lambda_i * c);

        if lhs != rhs {
            return Err(CryptoError::InvalidSignatureShare);
        }

        Ok(())
    }

    fn recover(
        &self,
        shares: &[Self::SigShare],
        t: usize,
        _n: usize,
        msg: &[u8],
        all_commitments: &[(u32, Self::NonceCommitment)],
    ) -> Result<Option<Self::Signature>> {
        if t == 0 {
            return Err(CryptoError::InvalidSignature);
        }
        if shares.len() < t {
            return Ok(None);
        }

        // Sum partial signatures: z = sum(z_i)
        let z = shares.iter().fold(Fr::zero(), |acc, share| acc + share.v);

        // Compute group commitment R
        let (r_point, _) = compute_group_commitment(all_commitments, msg)?;

        Ok(Some(SchnorrSignature { r_point, z }))
    }

    fn verify(&self, pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<()> {
        // Verify: z * G == R + c * Y
        let c = compute_challenge(&sig.r_point, pk, msg)?;
        let lhs = Element::GENERATOR * sig.z;
        let rhs = sig.r_point + *pk * c;

        if lhs != rhs {
            return Err(CryptoError::InvalidSignature);
        }

        Ok(())
    }

    fn encode_metadata(policy_id: &str, resource: &str, permission: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(SIGN_METADATA_DOMAIN);
        hasher.update((policy_id.len() as u64).to_le_bytes());
        hasher.update(policy_id.as_bytes());
        hasher.update((resource.len() as u64).to_le_bytes());
        hasher.update(resource.as_bytes());
        hasher.update((permission.len() as u64).to_le_bytes());
        hasher.update(permission.as_bytes());
        hasher.finalize().to_vec()
    }

    fn derive_public_key(
        dkg_pk: &Self::PublicKey,
        derivation: &[u8],
        metadata: Option<&[u8]>,
    ) -> Result<Self::PublicKey> {
        let d = derive_sign_scalar(derivation, metadata);
        if d.is_zero() {
            return Err(CryptoError::SigningError(
                "Zero derivation scalar".to_string(),
            ));
        }
        Ok(*dkg_pk * d)
    }
}

/// Derive a scalar for multiplicative key tweaking.
///
/// Without metadata: `d = H(SIGN_DERIVATION_DOMAIN || derivation)`
/// With metadata:    `d = H(SIGN_DERIVATION_DOMAIN || derivation || \x00 || len(metadata) || metadata)`
///
/// The null-byte separator guarantees no collision between derivation-only and
/// derivation+metadata inputs. Backward compatible: passing `None` for metadata
/// yields the same hash as the previous single-argument form.
fn derive_sign_scalar(derivation: &[u8], metadata: Option<&[u8]>) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(SIGN_DERIVATION_DOMAIN);
    hasher.update(derivation);
    if let Some(meta) = metadata {
        hasher.update(b"\x00"); // separator — prevents collision with derivation-only path
        hasher.update((meta.len() as u64).to_le_bytes());
        hasher.update(meta);
    }
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}
