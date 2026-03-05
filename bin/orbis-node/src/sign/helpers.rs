use crate::constants::{
    BULLETIN_RING_NAMESPACE, MAX_COMMITMENTS, MAX_COMMITMENT_SIZE, MIN_ITEM_SIZE,
};
use crate::sign::error::{Result, SignError};
use authn::{BearerToken, SignClaims};
use authz::r#trait::Authz;
use authz::sourcehub::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::{Bulletin, KeyDerivation, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, PriShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};

/// Deserializes a ring public key from raw bytes.
pub fn decode_ring_pk_bytes(ring_pk_bytes: &[u8]) -> Result<G1Affine> {
    G1Affine::from_bytes(ring_pk_bytes).map_err(|e| {
        SignError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
    })
}

/// Loads this node's distributed key share for the given ring public key from local storage.
///
/// Returns an error if the share is not found or cannot be deserialized.
pub fn load_dist_key_share(
    local_storage: &impl LocalStorage,
    ring_pk: &G1Affine,
) -> Result<DistKeyShare<Fr>> {
    let final_share_bytes = local_storage
        .get_encrypted(LocalStorageKeys::RingKey(ring_pk.to_string()))
        .map_err(|e| {
            SignError::Storage(format!(
                "Failed to retrieve final share from storage: {}",
                e
            ))
        })?
        .ok_or_else(|| {
            SignError::Storage("Final share not found in storage for ring_pk".to_string())
        })?;

    let pri_share: PriShare<Fr> = PriShare::from_bytes(&final_share_bytes).map_err(|e| {
        SignError::Deserialization(format!("Failed to deserialize final share: {}", e))
    })?;

    Ok(DistKeyShare { pri_share })
}

/// Tries to load this node's distributed key share for the given ring public key from local storage.
///
/// Returns `None` if the share is absent or on any error. Use this in contexts where
/// the node's participation is optional (e.g., when this node may not be in the ring).
pub fn try_load_dist_key_share(
    local_storage: &impl LocalStorage,
    ring_pk: &G1Affine,
) -> Option<DistKeyShare<Fr>> {
    let final_share_bytes = local_storage
        .get_encrypted(LocalStorageKeys::RingKey(ring_pk.to_string()))
        .ok()
        .flatten()?;

    let pri_share = PriShare::<Fr>::from_bytes(&final_share_bytes).ok()?;
    Some(DistKeyShare { pri_share })
}

/// Serializes a list of `(node_id, commitment)` pairs to a length-prefixed byte buffer.
pub fn serialize_commitments<S: ThresholdSigner>(
    commitments: &[(u32, S::NonceCommitment)],
) -> Result<Vec<u8>> {
    if commitments.is_empty() {
        return Ok(Vec::new());
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(commitments.len() as u32).to_le_bytes());
    for (id, commitment) in commitments {
        bytes.extend_from_slice(&id.to_le_bytes());
        let commitment_bytes = CryptoSerialize::to_bytes(commitment).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize commitment: {}", e))
        })?;
        bytes.extend_from_slice(&(commitment_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&commitment_bytes);
    }
    Ok(bytes)
}

/// Deserializes a list of `(node_id, commitment)` pairs from a length-prefixed byte buffer.
pub fn deserialize_commitments<S: ThresholdSigner>(
    bytes: &[u8],
) -> Result<Vec<(u32, S::NonceCommitment)>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    if bytes.len() < 4 {
        return Err(SignError::Deserialization(
            "Commitment bytes too short".to_string(),
        ));
    }

    let count = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| SignError::Deserialization("Invalid commitment count".to_string()))?,
    ) as usize;

    if count > MAX_COMMITMENTS {
        return Err(SignError::Deserialization(format!(
            "Commitment count {} exceeds maximum {}",
            count, MAX_COMMITMENTS
        )));
    }

    // Verify the payload can physically hold `count` items
    let remaining = bytes.len() - 4;
    if count > remaining / MIN_ITEM_SIZE {
        return Err(SignError::Deserialization(format!(
            "Commitment count {} exceeds what fits in {} remaining bytes",
            count, remaining
        )));
    }

    let mut offset = 4usize;
    let mut commitments = Vec::with_capacity(count);

    for _ in 0..count {
        if offset.checked_add(8).map_or(true, |end| end > bytes.len()) {
            return Err(SignError::Deserialization(
                "Commitment bytes truncated".to_string(),
            ));
        }

        let id = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| SignError::Deserialization("Invalid node_id".to_string()))?,
        );
        offset += 4;

        let commitment_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| SignError::Deserialization("Invalid commitment length".to_string()))?,
        ) as usize;
        offset += 4;

        if commitment_len > MAX_COMMITMENT_SIZE {
            return Err(SignError::Deserialization(format!(
                "Commitment length {} exceeds maximum {}",
                commitment_len, MAX_COMMITMENT_SIZE
            )));
        }

        if offset
            .checked_add(commitment_len)
            .map_or(true, |end| end > bytes.len())
        {
            return Err(SignError::Deserialization(
                "Commitment data truncated".to_string(),
            ));
        }

        let commitment = <S::NonceCommitment>::from_bytes(&bytes[offset..offset + commitment_len])
            .map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize commitment: {}", e))
            })?;
        offset += commitment_len;

        commitments.push((id, commitment));
    }

    if offset != bytes.len() {
        return Err(SignError::Deserialization(format!(
            "Trailing bytes: consumed {} of {} bytes",
            offset,
            bytes.len()
        )));
    }

    Ok(commitments)
}

/// Validates JWT claims against the Sign request parameters.
///
/// Ensures the token was issued for exactly this namespace and derivation_id,
/// preventing token reuse across different signing targets. The derivation path
/// itself is fetched from the bulletin and is not client-supplied.
pub fn validate_sign_claims(
    token: &BearerToken<SignClaims>,
    namespace: &str,
    derivation_id: &str,
) -> Result<()> {
    if token.claims.namespace != namespace {
        return Err(SignError::Unauthorized(format!(
            "Token namespace '{}' does not match request namespace '{}'",
            token.claims.namespace, namespace
        )));
    }

    if token.claims.derivation_id != derivation_id {
        return Err(SignError::Unauthorized(format!(
            "Token derivation_id '{}' does not match request derivation_id '{}'",
            token.claims.derivation_id, derivation_id
        )));
    }

    Ok(())
}

/// Checks whether the token issuer has the required policy access for a document.
pub async fn check_policy_access(
    authz: &(dyn Authz + Send + Sync),
    derivation_payload: &KeyDerivation,
    derivation_id: &str,
    issuer_id: &str,
    valid_window: Option<ValidWindow>,
) -> Result<()> {
    let now = if valid_window.is_some() {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )
    } else {
        None
    };

    let permission = AccessCheckRequest::new(
        derivation_payload.policy_id.clone(),
        derivation_payload.resource.clone(),
        derivation_id.to_string(),
        derivation_payload.permission.clone(),
        None,
        now,
        valid_window,
    )
    .to_bytes()
    .map_err(|e| SignError::AuthZ(format!("Error formatting access request: {}", e)))?;

    let is_authorized = authz
        .check(permission, &issuer_id.to_string())
        .await
        .map_err(|e| SignError::AuthZ(format!("Error in Authz request: {}", e)))?;

    if !is_authorized {
        return Err(SignError::Unauthorized(
            "Access denied: policy check failed".to_string(),
        ));
    }

    Ok(())
}

/// Fetches and deserializes the key derivation and ring payloads from the bulletin.
///
/// Reads the key by `namespace`/`object_id`, then follows the embedded
/// `ring_id` to load the corresponding ring payload.
pub async fn fetch_bulletin_payloads(
    bulletin: &(dyn Bulletin + Send + Sync),
    namespace: &str,
    derivation_id: &str,
) -> Result<(KeyDerivation, RingPayload)> {
    let object_info = bulletin
        .read(namespace.to_string(), derivation_id.to_string())
        .await
        .map_err(|e| {
            SignError::Storage(format!("Failed to read object '{}': {}", derivation_id, e))
        })?;

    let derivation_payload = serde_json::from_slice::<KeyDerivation>(&object_info.payload)
        .map_err(|e| {
            SignError::Deserialization(format!("Failed to parse document payload: {}", e))
        })?;

    let ring_info = bulletin
        .read(
            BULLETIN_RING_NAMESPACE.to_string(),
            derivation_payload.ring_id.clone(),
        )
        .await
        .map_err(|e| {
            SignError::Storage(format!(
                "Failed to read ring '{}': {}",
                derivation_payload.ring_id, e
            ))
        })?;

    let ring_payload = serde_json::from_slice::<RingPayload>(&ring_info.payload)
        .map_err(|e| SignError::Deserialization(format!("Failed to parse ring payload: {}", e)))?;

    Ok((derivation_payload, ring_payload))
}
