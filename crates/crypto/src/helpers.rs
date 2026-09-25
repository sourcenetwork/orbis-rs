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
    use super::sample_nonzero;

    #[test]
    fn sample_nonzero_retries_zero() {
        let mut draws = [0u64, 0, 7].into_iter();
        assert_eq!(sample_nonzero(|| draws.next().unwrap()), 7);
        assert!(draws.next().is_none());
    }
}
