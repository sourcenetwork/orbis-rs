//! Constant-time scalar multiplication for BLS12-381, backed by `blst` (via
//! `blstrs`).
//!
//! arkworks' default group multiplication (`ark-ec`'s `mul_projective`,
//! reached through the `*` operator on `G1Projective`/`G2Projective`) is a
//! textbook double-and-add that branches on every bit of the scalar:
//!
//! ```ignore
//! for b in BitIteratorBE::without_leading_zeros(scalar) {
//!     res.double_in_place();
//!     if b { res += base; }   // <- secret-bit-dependent branch
//! }
//! ```
//!
//! arkworks' short-Weierstrass point addition also isn't a "complete"
//! formula — it branches on point equality (add vs. double) and on the
//! identity — so a constant-time ladder cannot safely be built on top of it
//! without implementing complete addition formulas from scratch. `blst`
//! already solves this: its scalar-multiplication routines are documented in
//! its own source as constant-time (`blst/src/ec_mult.h`: "Key feature of
//! these constant-time subroutines..."), it's the same library vera's chain
//! side already uses for this curve, and — verified here — its point and
//! scalar encodings are byte-identical to arkworks' for BLS12-381 G1/G2/Fr.
//!
//! So the fix is narrow: convert through `blstrs` only at the call sites
//! that multiply a *secret* scalar (a long-lived share, a derived secret, or
//! a per-operation nonce) by a point, and leave every other multiplication
//! (public derivation scalars, Lagrange coefficients, proof
//! responses/challenges already published) on the existing arkworks types.

use crate::error::{CryptoError, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use group::Curve;

fn to_blst_scalar(scalar: &Fr) -> Result<blstrs::Scalar> {
    let mut bytes = [0u8; 32];
    scalar.serialize_compressed(&mut bytes[..])?;
    Option::from(blstrs::Scalar::from_bytes_le(&bytes))
        .ok_or_else(|| CryptoError::SigningError("Scalar out of range for blst".to_string()))
}

/// Constant-time `base * scalar` in G1. Use for any multiplication where
/// `scalar` is secret (a share, a derived secret, or a nonce).
pub fn ct_mul_g1(base: &G1Affine, scalar: &Fr) -> Result<G1Affine> {
    let mut base_bytes = [0u8; 48];
    base.serialize_compressed(&mut base_bytes[..])?;
    let blst_base: blstrs::G1Affine = Option::from(blstrs::G1Affine::from_compressed(&base_bytes))
        .ok_or_else(|| CryptoError::SigningError("Invalid G1 point for blst".to_string()))?;
    let blst_scalar = to_blst_scalar(scalar)?;

    let blst_result = (blst_base * blst_scalar).to_affine();
    let result_bytes = blst_result.to_compressed();
    Ok(G1Affine::deserialize_compressed(&result_bytes[..])?)
}

/// Constant-time `base * scalar` in G1, taking a projective base (avoids an
/// extra affine conversion at call sites that already have one).
pub fn ct_mul_g1_projective(base: &G1Projective, scalar: &Fr) -> Result<G1Projective> {
    Ok(ct_mul_g1(&base.into_affine(), scalar)?.into())
}

/// Constant-time `base * scalar` in G2. Use for any multiplication where
/// `scalar` is secret (a share, a derived secret, or a nonce).
pub fn ct_mul_g2(base: &G2Affine, scalar: &Fr) -> Result<G2Affine> {
    let mut base_bytes = [0u8; 96];
    base.serialize_compressed(&mut base_bytes[..])?;
    let blst_base: blstrs::G2Affine = Option::from(blstrs::G2Affine::from_compressed(&base_bytes))
        .ok_or_else(|| CryptoError::SigningError("Invalid G2 point for blst".to_string()))?;
    let blst_scalar = to_blst_scalar(scalar)?;

    let blst_result = (blst_base * blst_scalar).to_affine();
    let result_bytes = blst_result.to_compressed();
    Ok(G2Affine::deserialize_compressed(&result_bytes[..])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G2Projective;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use rand_core::OsRng;

    /// The whole point of this module: prove it computes exactly what the
    /// existing (non-constant-time) arkworks operator computes, for many
    /// random inputs, including edge cases.
    #[test]
    fn ct_mul_g1_matches_naive_mul() {
        let mut rng = OsRng;
        for _ in 0..200 {
            let base = G1Projective::rand(&mut rng).into_affine();
            let scalar = Fr::rand(&mut rng);
            let expected: G1Affine = (G1Projective::from(base) * scalar).into_affine();
            let actual = ct_mul_g1(&base, &scalar).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn ct_mul_g2_matches_naive_mul() {
        let mut rng = OsRng;
        for _ in 0..200 {
            let base = G2Projective::rand(&mut rng).into_affine();
            let scalar = Fr::rand(&mut rng);
            let expected: G2Affine = (G2Projective::from(base) * scalar).into_affine();
            let actual = ct_mul_g2(&base, &scalar).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn ct_mul_g1_edge_cases() {
        let gen = G1Affine::generator();
        assert_eq!(ct_mul_g1(&gen, &Fr::from(0u64)).unwrap(), G1Affine::zero());
        assert_eq!(ct_mul_g1(&gen, &Fr::from(1u64)).unwrap(), gen);
        assert_eq!(
            ct_mul_g1(&G1Affine::zero(), &Fr::from(12345u64)).unwrap(),
            G1Affine::zero()
        );
    }

    #[test]
    fn ct_mul_g2_edge_cases() {
        let gen = G2Affine::generator();
        assert_eq!(ct_mul_g2(&gen, &Fr::from(0u64)).unwrap(), G2Affine::zero());
        assert_eq!(ct_mul_g2(&gen, &Fr::from(1u64)).unwrap(), gen);
        assert_eq!(
            ct_mul_g2(&G2Affine::zero(), &Fr::from(12345u64)).unwrap(),
            G2Affine::zero()
        );
    }
}
