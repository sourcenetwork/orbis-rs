use crate::dkg::error::{DkgError, Result};
use authn::{BearerToken, DkgClaims};
use crypto::{CryptoSerialize, GroupAffine as G1Affine};

/// Returns a `SessionNotFound` error for the given session_id.
pub fn session_not_found(session_id: u64) -> DkgError {
    DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
}

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

/// Validates JWT claims against the DKG request.
pub fn validate_dkg_claims(
    token: &BearerToken<DkgClaims>,
    threshold: u32,
    peer_ids: &[String],
) -> Result<()> {
    // Validate threshold matches
    if token.claims.threshold != threshold {
        return Err(DkgError::Unauthorized(format!(
            "Token threshold ({}) does not match request threshold ({})",
            token.claims.threshold, threshold
        )));
    }

    // Validate peer_ids match (order-independent)
    if token.claims.peer_ids.len() != peer_ids.len() {
        return Err(DkgError::Unauthorized(format!(
            "Token peer_ids count ({}) does not match request peer_ids count ({})",
            token.claims.peer_ids.len(),
            peer_ids.len()
        )));
    }

    let mut sorted_token: Vec<&str> = token.claims.peer_ids.iter().map(|s| s.as_str()).collect();
    let mut sorted_req: Vec<&str> = peer_ids.iter().map(|s| s.as_str()).collect();
    sorted_token.sort();
    sorted_req.sort();

    if sorted_token != sorted_req {
        return Err(DkgError::Unauthorized(
            "Token peer_ids do not match request peer_ids".to_string(),
        ));
    }

    Ok(())
}
