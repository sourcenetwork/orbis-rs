#[cfg(feature = "bls12-381")]
use crate::error::CryptoError;
use crate::error::Result;
#[cfg(feature = "bls12-381")]
use ark_ff::Zero;
#[cfg(feature = "bls12-381")]
use ark_serialize::CanonicalSerialize;

/// Draw until the sampler returns a non-zero value.
///
/// Protocol proof nonces must never be zero: for a Schnorr-style response
/// `z = r + c*x`, setting `r = 0` exposes `x` whenever `c` is non-zero.
///
/// bls12-381 only: decaf377's one call site inlines this same loop directly
/// instead of sharing it — see `decaf377/pre.rs`.
#[cfg(feature = "bls12-381")]
pub(crate) fn sample_nonzero<F: Zero>(mut sample: impl FnMut() -> F) -> F {
    loop {
        let candidate = sample();
        if !candidate.is_zero() {
            return candidate;
        }
    }
}
/// Generate a random keypair (secret key scalar, public key point).
///
/// Uses OsRng for cryptographic randomness.
/// pk = sk * G where G is the generator of the selected curve.
#[cfg(feature = "bls12-381")]
pub fn generate_keypair() -> Result<(crate::ScalarField, crate::GroupAffine)> {
    use ark_bls12_381::G1Projective;
    use ark_ec::Group;
    use ark_std::UniformRand;
    use rand_core::OsRng;

    let mut rng = OsRng;
    let sk = crate::ScalarField::rand(&mut rng);
    let pk: crate::GroupAffine = (G1Projective::generator() * sk).into();
    Ok((sk, pk))
}

/// Generate a random keypair (secret key scalar, public key point).
///
/// Uses OsRng for cryptographic randomness.
/// pk = sk * G where G is the generator of the selected curve.
#[cfg(feature = "decaf377")]
pub fn generate_keypair() -> Result<(crate::ScalarField, crate::GroupAffine)> {
    use rand_core::OsRng;

    let mut rng = OsRng;
    let sk = ::decaf377::Fr::rand(&mut rng);
    let pk = ::decaf377::Element::GENERATOR * sk;
    Ok((sk, pk))
}

/// Sample a fresh, uniformly random, nonzero scalar — e.g. an ephemeral
/// per-attempt blinding value, where a zero value is a genuine protocol
/// weakness (callers typically also reject it downstream via an
/// identity-point check, but sampling nonzero directly is cheap and
/// doesn't rely on that check alone) but no corresponding public point is
/// ever needed. Prefer this over [`generate_keypair`] whenever only the
/// scalar half matters: computing the unused public point there costs an
/// extra (variable-time) scalar multiplication for no purpose.
#[cfg(feature = "bls12-381")]
pub fn sample_scalar() -> Result<crate::ScalarField> {
    use ark_std::UniformRand;
    use rand_core::OsRng;

    let mut rng = OsRng;
    Ok(sample_nonzero(|| crate::ScalarField::rand(&mut rng)))
}

/// Same as the bls12-381 variant above, for decaf377 — inlined rather than
/// sharing [`sample_nonzero`], which is bounded by the (incompatible,
/// major-version-0.4) arkworks `Zero` trait bls12-381 uses; decaf377
/// depends on arkworks 0.5 instead (see `decaf377/pre.rs`'s own identical
/// inlined loop, for the same reason).
#[cfg(feature = "decaf377")]
pub fn sample_scalar() -> Result<crate::ScalarField> {
    use ark_ff_05::Zero;
    use rand_core::OsRng;

    let mut rng = OsRng;
    Ok(loop {
        let candidate = ::decaf377::Fr::rand(&mut rng);
        if !candidate.is_zero() {
            break candidate;
        }
    })
}

/// Add two group elements: `a + b`.
///
/// No crypto-trait method exists for plain point addition (every existing
/// trait method that needs it, e.g. Lagrange combination, does the whole
/// computation internally). This is for callers building a value from public
/// pieces outside any trait impl — e.g. a PET tag's
/// `masked_fingerprint = F(owner) + r_tag*pet_pk`, computable entirely from
/// the ring's public `pet_pk` and a fresh nonce, with no secret share
/// involved (see `cli_tool::prepare_pet_tag`, which mints such a tag as a
/// stand-in for what Bankd does in production).
#[cfg(feature = "bls12-381")]
pub fn add_points(a: &crate::GroupAffine, b: &crate::GroupAffine) -> Result<crate::GroupAffine> {
    use ark_bls12_381::G1Projective;
    use ark_ec::CurveGroup;
    Ok((G1Projective::from(*a) + G1Projective::from(*b)).into_affine())
}

/// Add two group elements: `a + b`.
#[cfg(feature = "decaf377")]
pub fn add_points(a: &crate::GroupAffine, b: &crate::GroupAffine) -> Result<crate::GroupAffine> {
    Ok(*a + *b)
}

/// Multiply a group element by a scalar: `point * scalar`.
///
/// **Variable-time in `scalar`. Never call this with a secret scalar** (a
/// nonce, a share, a derived secret) — use [`mul_point_secret`] instead. A
/// public base point does not make the scalar public: e.g. recovering a
/// secret `r_tag` from `r_tag*pet_pk` would reveal
/// `F(owner) = T - r_tag*pet_pk` in a PET tag.
///
/// No crypto-trait method exposes plain scalar multiplication against an
/// arbitrary point (every trait method that needs it, e.g.
/// `Pet::partial_pet_check`, always pairs it with a DLEQ proof the caller
/// doesn't necessarily want). For a caller building a value from public
/// pieces outside any trait impl, entirely from already-public points and a
/// scalar that is *also* already public (e.g. a Lagrange coefficient) — see
/// [`mul_point_secret`] for the PET tag blinding use case, which does need a
/// secret scalar.
#[cfg(feature = "bls12-381")]
pub fn mul_point(
    point: &crate::GroupAffine,
    scalar: &crate::ScalarField,
) -> Result<crate::GroupAffine> {
    use ark_bls12_381::G1Projective;
    use ark_ec::CurveGroup;
    Ok((G1Projective::from(*point) * scalar).into_affine())
}

/// Multiply a group element by a scalar: `point * scalar`.
///
/// **Variable-time in `scalar`. Never call this with a secret scalar** — see
/// [`mul_point_secret`].
#[cfg(feature = "decaf377")]
pub fn mul_point(
    point: &crate::GroupAffine,
    scalar: &crate::ScalarField,
) -> Result<crate::GroupAffine> {
    Ok(*point * *scalar)
}

/// Multiply a group element by a SECRET scalar: `point * scalar`, using a
/// constant-time scalar-multiplication path where one exists for this
/// backend.
///
/// Unlike [`mul_point`] (variable-time, for scalars that are already
/// public — e.g. a Lagrange coefficient), this is for a caller multiplying a
/// point by a genuinely secret scalar it holds (a nonce, a share, a derived
/// secret) — e.g. a PET tag's `masked_fingerprint = F(owner) + r_tag*pet_pk`,
/// where `r_tag` is the tag-preparer's own secret ephemeral randomness (see
/// `cli_tool::prepare_pet_tag`). A public base point (`pet_pk`) does not make
/// `r_tag` public.
///
/// bls12-381: routes through [`crate::bls12_381::ct::ct_mul_g1`], the same
/// constant-time path already used by `Pet::prove_tag_knowledge` and the
/// per-share PET-check DLEQ proof for every other secret-scalar
/// multiplication in this protocol.
#[cfg(feature = "bls12-381")]
pub fn mul_point_secret(
    point: &crate::GroupAffine,
    scalar: &crate::ScalarField,
) -> Result<crate::GroupAffine> {
    crate::bls12_381::ct::ct_mul_g1(point, scalar)
}

/// Multiply a group element by a SECRET scalar: `point * scalar`.
///
/// decaf377 has no constant-time scalar-multiplication path in this
/// codebase — the same documented, tracked gap as `prove_tag_knowledge`'s
/// decaf377 twin (`decaf377/pet.rs`). This is the same operation as
/// [`mul_point`], named separately so call sites document which of their
/// scalars are secret, and so a future constant-time decaf377 path only
/// needs to change this one function.
#[cfg(feature = "decaf377")]
pub fn mul_point_secret(
    point: &crate::GroupAffine,
    scalar: &crate::ScalarField,
) -> Result<crate::GroupAffine> {
    Ok(*point * *scalar)
}

/// Evaluate `coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...` by accumulating
/// a running scalar power of `x` alongside the running sum. This is the
/// shared evaluation loop behind every `PubPoly`/`PolynomialCommitment::eval`
/// in this crate, generic over both curve backends' point type (`A`) and
/// scalar type (`S`) so it needs no curve-specific code itself.
///
/// Panics if `coeffs` is empty — callers own the empty-polynomial case
/// (checked before this is called) since its "zero" value differs by type
/// (identity element vs. affine-zero point).
pub(crate) fn eval_poly_at<A, S>(coeffs: impl IntoIterator<Item = A>, x: S) -> A
where
    A: core::ops::Add<Output = A> + core::ops::Mul<S, Output = A>,
    S: Copy + core::ops::Mul<Output = S>,
{
    let mut iter = coeffs.into_iter();
    let mut result = iter
        .next()
        .expect("eval_poly_at requires a non-empty coefficient list");
    let mut x_power = x;
    for coeff in iter {
        result = result + coeff * x_power;
        x_power = x_power * x;
    }
    result
}

/// Rejects non-canonical encodings by round-tripping through serialization.
///
/// arkworks' `deserialize_compressed` accepts some non-canonical byte strings
/// (e.g. identity points with trailing garbage). This check re-serializes the
/// decoded value and compares it to the original bytes, rejecting anything that
/// doesn't round-trip exactly.
///
/// bls12-381 only: decaf377 has its own twin bound to arkworks 0.5
/// (`decaf377::common::reject_non_canonical`) — see Cargo.toml.
#[cfg(feature = "bls12-381")]
pub(crate) fn reject_non_canonical<T: CanonicalSerialize>(value: &T, bytes: &[u8]) -> Result<()> {
    let mut canonical = Vec::with_capacity(bytes.len());
    value.serialize_compressed(&mut canonical)?;
    if canonical == bytes {
        Ok(())
    } else {
        Err(CryptoError::SerializationError(
            ark_serialize::SerializationError::InvalidData,
        ))
    }
}

#[cfg(all(test, feature = "bls12-381"))]
mod tests {
    use super::{mul_point, mul_point_secret, sample_nonzero};

    #[test]
    fn sample_nonzero_retries_zero() {
        let mut draws = [0u64, 0, 7].into_iter();
        assert_eq!(sample_nonzero(|| draws.next().unwrap()), 7);
        assert!(draws.next().is_none());
    }

    /// Finding #10: `mul_point_secret`'s constant-time path must compute the
    /// exact same group element `mul_point`'s variable-time path does —
    /// switching a call site from one to the other must never change the
    /// resulting point or wire format.
    #[test]
    fn mul_point_secret_matches_mul_point() {
        use ark_ec::Group;
        use ark_std::UniformRand;
        use rand_core::OsRng;

        let mut rng = OsRng;
        for _ in 0..20 {
            let point: crate::GroupAffine = (ark_bls12_381::G1Projective::generator()
                * crate::ScalarField::rand(&mut rng))
            .into();
            let scalar = crate::ScalarField::rand(&mut rng);
            assert_eq!(
                mul_point(&point, &scalar).unwrap(),
                mul_point_secret(&point, &scalar).unwrap()
            );
        }
    }
}
