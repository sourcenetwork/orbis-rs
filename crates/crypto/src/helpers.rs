use crate::error::Result;

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
