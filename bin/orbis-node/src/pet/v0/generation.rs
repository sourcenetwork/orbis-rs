//! Canonical PET generation validation and atomic bundle matching.

use super::error::{PetError, Result};
use crate::ring_state::RingShareBundle;
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, PolynomialCommitment, PubPoly};
use crypto::{GroupAffine, ScalarField};

pub(crate) const MAX_POLYNOMIAL_BYTES: usize = 64 * 1024;

fn coefficient_count(bytes: &[u8]) -> Result<u32> {
    let header: [u8; 4] = bytes
        .get(..4)
        .and_then(|header| header.try_into().ok())
        .ok_or_else(|| PetError::InvalidInput("truncated PET polynomial".into()))?;
    let count = u32::from_le_bytes(header);
    let expected = (count as usize)
        .checked_mul(crypto::GROUP_POINT_SIZE)
        .and_then(|size| size.checked_add(4));
    if count == 0 || bytes.len() > MAX_POLYNOMIAL_BYTES || expected != Some(bytes.len()) {
        return Err(PetError::InvalidInput(
            "invalid PET polynomial encoded length".into(),
        ));
    }
    Ok(count)
}

/// P(0) checks key consistency only. Generation authority comes from the
/// current committee's threshold-signed, context-bound reveal certificate.
pub(crate) fn decode<P: PubPoly<PublicKey = GroupAffine>>(
    bytes: &[u8],
    threshold: u32,
    pet_pk_hex: &str,
) -> Result<P> {
    if coefficient_count(bytes)? != threshold {
        return Err(PetError::InvalidInput(
            "PET polynomial degree does not match the ring threshold".into(),
        ));
    }
    let polynomial = P::from_bytes(bytes).map_err(|e| PetError::Deserialization(e.to_string()))?;
    if polynomial
        .to_bytes()
        .map_err(|e| PetError::Serialization(e.to_string()))?
        != bytes
    {
        return Err(PetError::InvalidInput("noncanonical PET polynomial".into()));
    }
    let key_bytes =
        hex::decode(pet_pk_hex).map_err(|e| PetError::Deserialization(e.to_string()))?;
    let key = GroupAffine::from_bytes(&key_bytes)
        .map_err(|e| PetError::Deserialization(e.to_string()))?;
    if key == GroupAffine::default()
        || key
            .to_bytes()
            .map_err(|e| PetError::Serialization(e.to_string()))?
            != key_bytes
        || polynomial.eval(0) != key
    {
        return Err(PetError::InvalidInput(
            "PET polynomial has a different checking key".into(),
        ));
    }
    Ok(polynomial)
}

pub(crate) fn match_bundle<P: PubPoly<PublicKey = GroupAffine>>(
    bundle: &RingShareBundle,
    expected: &[u8],
    threshold: u32,
    pet_pk: &str,
) -> Result<P> {
    if threshold == 0 {
        return Err(PetError::InvalidInput("zero PET threshold".into()));
    }
    let expected_count = coefficient_count(expected)?;
    let polynomial = decode::<P>(expected, expected_count, pet_pk)?;
    let local =
        hex::decode(&bundle.public_polynomial).map_err(|e| PetError::Storage(e.to_string()))?;
    // Validate storage separately: corrupt state is not a legitimate refresh race.
    let local_count = coefficient_count(&local).map_err(|e| PetError::Storage(e.to_string()))?;
    decode::<P>(&local, local_count, pet_pk).map_err(|e| PetError::Storage(e.to_string()))?;
    if expected_count != threshold || local != expected {
        return Err(PetError::GenerationMismatch);
    }
    Ok(polynomial)
}

/// Check both the current member index and the scalar/poly consistency of
/// one atomic stored bundle before endorsing a generation or signing a share.
pub(crate) fn member_share<D: Dkg<ShareValue = ScalarField, PublicKey = GroupAffine>>(
    bundle: &RingShareBundle,
    node_key: &str,
    ring: &bulletin::r#trait::RingPayload,
) -> Result<crypto::r#trait::PriShare<ScalarField>> {
    let share = crypto::r#trait::PriShare::from_bytes(&bundle.share_bytes)
        .map_err(|e| PetError::Storage(format!("invalid PET share: {e}")))?;
    if crate::helpers::identity::determine_session_node_id(node_key, &ring.peer_node_keys)
        != Some(share.i)
    {
        return Err(PetError::GenerationMismatch);
    }
    let bytes =
        hex::decode(&bundle.public_polynomial).map_err(|e| PetError::Storage(e.to_string()))?;
    coefficient_count(&bytes).map_err(|e| PetError::Storage(e.to_string()))?;
    let commitment = D::PolynomialCommitment::from_bytes(&bytes)
        .map_err(|e| PetError::Storage(e.to_string()))?;
    if !commitment.verify_share(share.i, &share.v) {
        return Err(PetError::Storage(
            "PET share does not match its stored polynomial".into(),
        ));
    }
    Ok(share)
}

#[cfg(test)]
mod tests;
