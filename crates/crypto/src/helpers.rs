use crate::error::Result;
use sha2::{Digest, Sha256};

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

/// Generate canonicalized policy metadata bytes for proof binding.
///
/// Uses length-prefixed encoding to prevent concatenation ambiguity:
///   metadata = H(DOMAIN || len(policy_id) || policy_id || len(resource) || resource || len(permission) || permission)
///
/// This ensures that different field values always produce different hashes,
/// even if their concatenation would be identical (e.g., "ab" || "c" vs "a" || "bc").
pub fn generate_policy_metadata(policy_id: &str, resource: &str, permission: &str) -> [u8; 32] {
    const POLICY_METADATA_DOMAIN: &[u8] = b"orbis-policy-metadata-v1";

    let mut hasher = Sha256::new();

    // Domain separation
    hasher.update(POLICY_METADATA_DOMAIN);

    // Length-prefixed policy_id
    hasher.update((policy_id.len() as u64).to_le_bytes());
    hasher.update(policy_id.as_bytes());

    // Length-prefixed resource
    hasher.update((resource.len() as u64).to_le_bytes());
    hasher.update(resource.as_bytes());

    // Length-prefixed permission
    hasher.update((permission.len() as u64).to_le_bytes());
    hasher.update(permission.as_bytes());

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}
