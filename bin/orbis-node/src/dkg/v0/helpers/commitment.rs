//! Commitment coefficient (de)serialization and hashing.

use crate::dkg::v0::error::{DkgError, Result};
use crypto::r#trait::CryptoDeserialize;
use crypto::{
    CryptoSerialize, GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    GROUP_POINT_SIZE,
};
use sha2::{Digest, Sha256};

pub(crate) const DKG_COMMITMENT_HASH_DOMAIN: &[u8] = b"orbis-dkg-commitment-hash-v1";

/// Serializes a slice of G1Affine commitment coefficients to a flat byte buffer.
pub fn serialize_commitment_coefficients(coefficients: &[G1Affine]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for coeff in coefficients {
        let coeff_bytes = CryptoSerialize::to_bytes(coeff).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize commitment coefficient: {}", e))
        })?;
        bytes.extend_from_slice(&coeff_bytes);
    }
    Ok(bytes)
}

pub fn deserialize_wire_commitment(
    bytes: &[u8],
) -> std::result::Result<PolynomialCommitment, String> {
    if bytes.is_empty() {
        return Err("commitment cannot be empty".to_string());
    }
    if !bytes.len().is_multiple_of(GROUP_POINT_SIZE) {
        return Err(format!(
            "commitment length {} is not a multiple of {}",
            bytes.len(),
            GROUP_POINT_SIZE
        ));
    }

    let mut coefficients = Vec::with_capacity(bytes.len() / GROUP_POINT_SIZE);
    for (index, chunk) in bytes.as_chunks::<GROUP_POINT_SIZE>().0.iter().enumerate() {
        let coeff =
            G1Affine::from_bytes(chunk).map_err(|error| format!("coefficient {index}: {error}"))?;
        coefficients.push(coeff);
    }

    Ok(PolynomialCommitment { coefficients })
}

pub(crate) fn fresh_commitment_hash(
    session_id: u128,
    from_node_id: u32,
    commitment_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DKG_COMMITMENT_HASH_DOMAIN);
    hasher.update(session_id.to_le_bytes());
    hasher.update(from_node_id.to_le_bytes());
    hasher.update(commitment_bytes);
    hasher.finalize().into()
}

pub(super) fn hash_labeled_bytes(hasher: &mut Sha256, label: &[u8], bytes: &[u8]) {
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
    hasher.update((bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

pub(super) fn hash_labeled_str(hasher: &mut Sha256, label: &[u8], value: &str) {
    hash_labeled_bytes(hasher, label, value.as_bytes());
}

pub(super) fn hash_sorted_strings(hasher: &mut Sha256, label: &[u8], values: &[String]) {
    let mut sorted_values = values.to_vec();
    sorted_values.sort();
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
    hasher.update((sorted_values.len() as u32).to_le_bytes());
    for value in &sorted_values {
        hash_labeled_str(hasher, b"value", value);
    }
}
