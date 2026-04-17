//! Threshold BLS Signing implementation for BLS12-381
//!
//! This implements the "swapped" BLS variant where:
//! - Public keys are in G1 (same as PRE, reuses existing DKG)
//! - Signatures are in G2
//!
//! This allows sharing the same DKG output and public polynomial
//! for both PRE and signing operations.

use crate::bls12_381::common::{G2Point, PubPoly};
use crate::error::{CryptoError, Result};
use crate::r#trait::{DistKeyShare, PubPoly as PubPolyTrait, PubShare, ThresholdSigner};
use ark_bls12_381::{
    g2::Config as G2Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, Field, One, PrimeField as _, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::collections::HashSet;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Domain separation tag for BLS signatures (IETF standard)
/// Format: "BLS_SIG_" || curve || "_" || hash || "_" || map || "_" || variant
const BLS_SIG_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Domain separation tag for signing key derivation (distinct from PRE derivation domain).
const SIGN_DERIVATION_DOMAIN: &[u8] = b"sign-derivation-v1";

/// Domain separation tag for signing metadata encoding.
const SIGN_METADATA_DOMAIN: &[u8] = b"orbis-sign-metadata-v1";

/// Threshold BLS Signer using the swapped variant (G1 keys, G2 signatures)
pub struct ThresholdBlsSigner;

impl ThresholdSigner for ThresholdBlsSigner {
    const INTERACTIVE: bool = false;

    type ShareValue = Fr;
    type Signature = G2Point;
    type PublicKey = G1Affine;
    type PubPoly = PubPoly;
    type DistKeyShare = DistKeyShare<Fr>;
    type SigShare = PubShare<G2Point>;
    type NonceCommitment = ();
    type SigningState = ();

    fn new() -> Self {
        ThresholdBlsSigner
    }

    fn name() -> String {
        "threshold-bls-g2".to_string()
    }

    fn hash_message(&self, msg: &[u8]) -> Result<Self::Signature> {
        hash_to_g2(msg)
    }

    fn generate_nonces(
        &self,
        _dist_key_share: &Self::DistKeyShare,
    ) -> Result<(Self::NonceCommitment, Self::SigningState)> {
        Ok(((), ()))
    }

    fn sign(
        &self,
        dist_key_share: &Self::DistKeyShare,
        msg: &[u8],
        _pub_poly: &Self::PubPoly,
        _signing_state: Option<&Self::SigningState>,
        _all_commitments: &[(u32, Self::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<Self::SigShare> {
        let idx = dist_key_share.pri_share.i;
        let ski = dist_key_share.pri_share.v;

        // Validate index
        if idx == 0 {
            return Err(CryptoError::InvalidSignatureShare);
        }

        // Apply derivation (with optional metadata binding): s_i' = d * s_i
        let ski_eff = if let Some(deriv) = derivation {
            let d = derive_sign_scalar(deriv, metadata);
            if d.is_zero() {
                return Err(CryptoError::SigningError(
                    "Zero derivation scalar".to_string(),
                ));
            }
            ski * d
        } else {
            ski
        };

        // Hash message to G2
        let h_msg = hash_to_g2(msg)?;

        // Compute signature share: sig_i = s_i' * H(msg)
        let sig_share: G2Affine = (G2Projective::from(*h_msg.inner()) * ski_eff).into_affine();

        Ok(PubShare {
            i: idx,
            v: G2Point::new(sig_share),
        })
    }

    fn verify_share(
        &self,
        msg: &[u8],
        pub_poly: &Self::PubPoly,
        sig_share: &Self::SigShare,
        _all_commitments: &[(u32, Self::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<()> {
        // Get the public key share for this index, applying derivation (with optional metadata
        // binding) if present: pk_i' = d * pk_i
        let pk_share_base = pub_poly.eval(sig_share.i);
        let pk_share: G1Affine = if let Some(deriv) = derivation {
            let d = derive_sign_scalar(deriv, metadata);
            (G1Projective::from(pk_share_base) * d).into()
        } else {
            pk_share_base
        };

        // Validate points are not identity
        if pk_share.is_zero() {
            return Err(CryptoError::InvalidSignatureShare);
        }
        if sig_share.v.is_zero() {
            return Err(CryptoError::InvalidSignatureShare);
        }

        // Hash message to G2
        let h_msg = hash_to_g2(msg)?;

        // Verify: e(pk_share', H(msg)) == e(G1_gen, sig_share)
        let g1_gen = G1Affine::generator();

        let lhs = Bls12_381::pairing(pk_share, *h_msg.inner());
        let rhs = Bls12_381::pairing(g1_gen, *sig_share.v.inner());

        // Constant-time comparison of pairing results
        let mut lhs_bytes = Vec::new();
        let mut rhs_bytes = Vec::new();
        lhs.0
            .serialize_compressed(&mut lhs_bytes)
            .map_err(|_| CryptoError::InvalidSignatureShare)?;
        rhs.0
            .serialize_compressed(&mut rhs_bytes)
            .map_err(|_| CryptoError::InvalidSignatureShare)?;

        if lhs_bytes.ct_ne(&rhs_bytes).into() {
            return Err(CryptoError::InvalidSignatureShare);
        }

        Ok(())
    }

    fn recover(
        &self,
        shares: &[Self::SigShare],
        t: usize,
        n: usize,
        _msg: &[u8],
        _all_commitments: &[(u32, Self::NonceCommitment)],
    ) -> Result<Option<Self::Signature>> {
        // Validate parameters
        if t == 0 {
            return Err(CryptoError::InvalidSignature);
        }
        if t > n {
            return Err(CryptoError::InvalidSignature);
        }
        if shares.len() < t {
            return Ok(None);
        }

        recover_signature(shares, t, n)
    }

    fn verify(&self, pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<()> {
        // Validate inputs
        if pk.is_zero() {
            return Err(CryptoError::InvalidSignature);
        }
        if sig.is_zero() {
            return Err(CryptoError::InvalidSignature);
        }

        // Hash message to G2
        let h_msg = hash_to_g2(msg)?;

        // Verify: e(pk, H(msg)) == e(G1_gen, sig)
        let g1_gen = G1Affine::generator();

        let lhs = Bls12_381::pairing(*pk, *h_msg.inner());
        let rhs = Bls12_381::pairing(g1_gen, *sig.inner());

        // Constant-time comparison
        let mut lhs_bytes = Vec::new();
        let mut rhs_bytes = Vec::new();
        lhs.0
            .serialize_compressed(&mut lhs_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;
        rhs.0
            .serialize_compressed(&mut rhs_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if lhs_bytes.ct_ne(&rhs_bytes).into() {
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
        Ok((G1Projective::from(*dkg_pk) * d).into())
    }
}

/// Hash a message to G2 using IETF-standard hash-to-curve
///
/// This implements the full IETF hash-to-curve specification for BLS12-381 G2:
/// - Suite: BLS12381G2_XMD:SHA-256_SSWU_RO_
/// - Uses the Simplified SWU map with isogeny
/// - Produces points with unknown discrete logarithm
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve>
pub fn hash_to_g2(msg: &[u8]) -> Result<G2Point> {
    // Create the IETF-compliant hasher for BLS12-381 G2
    // This uses:
    // - SHA-256 for the hash function
    // - expand_message_xmd for domain separation
    // - Simplified SWU map with 3-isogeny for mapping to the curve
    type G2Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256>, WBMap<G2Config>>;

    let hasher = G2Hasher::new(BLS_SIG_DOMAIN).map_err(|_| CryptoError::InvalidSignature)?;

    let point: G2Affine = hasher
        .hash(msg)
        .map_err(|_| CryptoError::InvalidSignature)?;

    // The IETF hash-to-curve guarantees the output is a valid curve point
    // in the correct subgroup, but we verify anyway for defense in depth
    if point.is_zero() {
        return Err(CryptoError::InvalidSignature);
    }

    Ok(G2Point::new(point))
}

/// Recover a full signature from threshold shares using Lagrange interpolation
fn recover_signature(shares: &[PubShare<G2Point>], t: usize, n: usize) -> Result<Option<G2Point>> {
    let shares_to_use = &shares[..t];

    // Validate all share indices are distinct
    let mut seen_indices = HashSet::new();
    for share in shares_to_use {
        let idx = share.i;

        // Validate index is in valid range [1, n]
        if idx < 1 || idx > n as u32 {
            return Err(CryptoError::InvalidSignatureShare);
        }

        // Check for duplicates
        if !seen_indices.insert(idx) {
            return Err(CryptoError::InvalidSignatureShare);
        }
    }

    // Lagrange interpolation in the exponent
    let mut result = G2Projective::zero();

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

        // Compute Lagrange coefficient
        let lambda = num * den.inverse().ok_or(CryptoError::InvalidSignatureShare)?;

        result += G2Projective::from(*share_i.v.inner()) * lambda;
    }

    Ok(Some(G2Point::from(result)))
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
