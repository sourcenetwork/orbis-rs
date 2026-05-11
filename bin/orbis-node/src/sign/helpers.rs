use crate::constants::{
    BULLETIN_RING_NAMESPACE, MAX_COMMITMENTS, MAX_COMMITMENT_SIZE, MIN_ITEM_SIZE,
};
use crate::dkg::session_state::{ReshareSignatureReadyKey, SessionStateManager};
use crate::ring_state::{RingPolyState, RingShareBundle};
use crate::sign::{
    error::{Result, SignError},
    messages::{RingReshareUpdateStatement, SignMessage, RING_RESHARE_UPDATE_DOMAIN},
    response_state::SignResponseManager,
};
use authn::{BearerToken, SignClaims};
use authz::r#trait::Authz;
use authz::sourcehub::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::{Bulletin, BulletinPost, DocumentPayload, KeyDerivation, RingPayload};
use common::blockchain::bulletin::ring_reshare_finalize_sign_bytes_from_hashes;
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::LocalStorage;
use network::PeerId;
use sha2::{Digest, Sha256};
use std::sync::Arc;

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
    let bundle = RingShareBundle::load(local_storage, ring_pk)
        .map_err(|e| SignError::Storage(format!("Failed to load share bundle: {}", e)))?;
    let pri_share = bundle.pri_share().map_err(|e| {
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
    let bundle = RingShareBundle::load(local_storage, ring_pk).ok()?;
    let pri_share = bundle.pri_share().ok()?;
    Some(DistKeyShare { pri_share })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_sha256_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value)
        .map_err(|e| SignError::Deserialization(format!("Failed to decode {label} hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(SignError::InvalidInput(format!(
            "{label} must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn storage_key_from_ring_pk_hex(ring_pk_hex: &str) -> Result<String> {
    let bytes = hex::decode(ring_pk_hex)
        .map_err(|e| SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e)))?;
    let ring_pk = decode_ring_pk_bytes(&bytes)?;
    Ok(ring_pk.to_string())
}

fn payload_ring_pk_matches(
    payload_ring_pk: &str,
    statement_ring_pk_hex: &str,
    storage_key: &str,
) -> bool {
    if payload_ring_pk == statement_ring_pk_hex || payload_ring_pk == storage_key {
        return true;
    }

    hex::decode(payload_ring_pk)
        .ok()
        .and_then(|bytes| G1Affine::from_bytes(&bytes).ok())
        .map(|ring_pk| ring_pk.to_string() == storage_key)
        .unwrap_or(false)
}

fn finalized_ring_payload_bytes(current_payload: &RingPayload) -> Result<Vec<u8>> {
    let mut finalized = current_payload.clone();
    let new_peer_ids = finalized
        .new_peer_ids
        .take()
        .unwrap_or_else(|| current_payload.peer_ids.clone());
    let new_threshold = finalized
        .new_threshold
        .take()
        .unwrap_or(current_payload.threshold);

    finalized.peer_ids = new_peer_ids;
    finalized.threshold = new_threshold;

    serde_json::to_vec(&finalized).map_err(|e| {
        SignError::Serialization(format!("Failed to serialize finalized ring payload: {e}"))
    })
}

/// Serialize the canonical ring reshare update statement.
pub fn ring_reshare_update_message(statement: &RingReshareUpdateStatement) -> Result<Vec<u8>> {
    let current_payload_sha256 =
        decode_sha256_hex("current_payload_sha256", &statement.current_payload_sha256)?;
    let finalized_payload_sha256 = decode_sha256_hex(
        "finalized_payload_sha256",
        &statement.finalized_payload_sha256,
    )?;

    ring_reshare_finalize_sign_bytes_from_hashes(
        &statement.chain_id,
        &statement.namespace,
        &statement.bulletin_post_id,
        &statement.ring_pk,
        current_payload_sha256,
        finalized_payload_sha256,
        statement.block_number_nonce,
    )
    .map_err(|e| {
        SignError::Serialization(format!(
            "Failed to serialize ring reshare finalize sign document: {e}"
        ))
    })
}

/// Context key used to bind FROST nonces to one exact reshare update statement.
pub fn ring_reshare_update_context_key(statement: &RingReshareUpdateStatement) -> Result<String> {
    let bytes = ring_reshare_update_message(statement)?;
    Ok(format!("ring-reshare-update:{}", sha256_hex(&bytes)))
}

/// Validate a ring reshare update statement before signing it.
///
/// This keeps the relay node untrusted: responders only sign when the statement
/// binds the bulletin's current payload to the exact final `RingPayload` implied
/// by the announced reshare.
pub async fn validate_ring_reshare_update_statement(
    bulletin: &(dyn Bulletin + Send + Sync),
    dkg_session_state: &SessionStateManager<impl Dkg + 'static>,
    statement: &RingReshareUpdateStatement,
    expected_message: Option<&[u8]>,
) -> Result<String> {
    if statement.domain != RING_RESHARE_UPDATE_DOMAIN {
        return Err(SignError::Unauthorized(format!(
            "Invalid ring reshare update domain '{}'",
            statement.domain
        )));
    }
    if statement.chain_id != bulletin.chain_id() {
        return Err(SignError::Unauthorized(format!(
            "Ring reshare update chain_id '{}' does not match bulletin chain_id '{}'",
            statement.chain_id,
            bulletin.chain_id()
        )));
    }
    if statement.namespace != BULLETIN_RING_NAMESPACE {
        return Err(SignError::InvalidInput(format!(
            "Ring reshare update namespace '{}' does not match expected '{}'",
            statement.namespace, BULLETIN_RING_NAMESPACE
        )));
    }

    let canonical_message = ring_reshare_update_message(statement)?;
    if let Some(expected) = expected_message {
        if expected != canonical_message.as_slice() {
            return Err(SignError::Unauthorized(
                "Ring reshare update message does not match context statement".to_string(),
            ));
        }
    }

    if statement.bulletin_post_id.is_empty() {
        return Err(SignError::InvalidInput(
            "Ring reshare update bulletin_post_id cannot be empty".to_string(),
        ));
    }
    let statement_storage_key = storage_key_from_ring_pk_hex(&statement.ring_pk)?;

    let current_post = bulletin
        .read(
            statement.namespace.clone(),
            statement.bulletin_post_id.clone(),
        )
        .await
        .map_err(|e| {
            SignError::VerificationFailed(format!(
                "Failed to read ring bulletin post '{}': {}",
                statement.bulletin_post_id, e
            ))
        })?;

    let current_hash = sha256_hex(&current_post.payload);
    if current_hash != statement.current_payload_sha256 {
        return Err(SignError::VerificationFailed(format!(
            "Ring reshare update current payload hash mismatch: expected {}, got {}",
            statement.current_payload_sha256, current_hash
        )));
    }

    let current_payload: RingPayload =
        serde_json::from_slice(&current_post.payload).map_err(|e| {
            SignError::Deserialization(format!("Failed to parse current ring payload: {}", e))
        })?;
    if current_payload.block_number_nonce != statement.block_number_nonce {
        return Err(SignError::Unauthorized(format!(
            "Ring reshare update block_number_nonce {} does not match current payload nonce {}",
            statement.block_number_nonce, current_payload.block_number_nonce
        )));
    }
    let finalized_payload_bytes = finalized_ring_payload_bytes(&current_payload)?;
    let finalized_hash = sha256_hex(&finalized_payload_bytes);
    if finalized_hash != statement.finalized_payload_sha256 {
        return Err(SignError::VerificationFailed(format!(
            "Ring reshare update finalized payload hash mismatch: expected {}, got {}",
            statement.finalized_payload_sha256, finalized_hash
        )));
    }

    if !payload_ring_pk_matches(
        &current_payload.ring_pk,
        &statement.ring_pk,
        &statement_storage_key,
    ) {
        return Err(SignError::Unauthorized(
            "Ring reshare update statement ring_pk does not match current payload".to_string(),
        ));
    }
    let finalized_payload: RingPayload =
        serde_json::from_slice(&finalized_payload_bytes).map_err(|e| {
            SignError::Deserialization(format!("Failed to parse finalized ring payload: {e}"))
        })?;
    if finalized_payload.peer_ids.is_empty() {
        return Err(SignError::InvalidInput(
            "Ring reshare update cannot produce an empty committee".to_string(),
        ));
    }
    if finalized_payload.threshold == 0
        || finalized_payload.threshold as usize > finalized_payload.peer_ids.len()
    {
        return Err(SignError::InvalidInput(format!(
            "Ring reshare update threshold {} is invalid for committee size {}",
            finalized_payload.threshold,
            finalized_payload.peer_ids.len()
        )));
    }

    let ready_key = ReshareSignatureReadyKey {
        ring_key: statement_storage_key,
        session_id: statement.session_id,
        bulletin_post_id: statement.bulletin_post_id.clone(),
        current_payload_sha256: statement.current_payload_sha256.clone(),
        updated_payload_sha256: statement.finalized_payload_sha256.clone(),
    };
    if !dkg_session_state
        .is_reshare_signature_ready(&ready_key)
        .await
    {
        return Err(SignError::ReshareInProgress);
    }

    Ok(statement.ring_pk.clone())
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
    message: Option<&Vec<u8>>,
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

    if let Some(message) = message {
        let expected = Sha256::digest(message);
        if token.claims.message_sha256 != expected.as_slice() {
            return Err(SignError::Unauthorized(
                "Token message_sha256 does not match request message".to_string(),
            ));
        }
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
        .check(permission, issuer_id)
        .await
        .map_err(|e| SignError::AuthZ(format!("Error in Authz request: {}", e)))?;

    if !is_authorized {
        return Err(SignError::Unauthorized(
            "Access denied: policy check failed".to_string(),
        ));
    }

    Ok(())
}

/// Fetches and deserializes only the `KeyDerivation` from the bulletin.
///
/// Use this when the `RingPayload` is not needed, to avoid a second round trip.
pub async fn fetch_key_derivation(
    bulletin: &(dyn Bulletin + Send + Sync),
    namespace: &str,
    derivation_id: &str,
) -> Result<KeyDerivation> {
    let object_info = bulletin
        .read(namespace.to_string(), derivation_id.to_string())
        .await
        .map_err(|e| {
            SignError::Storage(format!("Failed to read object '{}': {}", derivation_id, e))
        })?;

    serde_json::from_slice::<KeyDerivation>(&object_info.payload)
        .map_err(|e| SignError::Deserialization(format!("Failed to parse document payload: {}", e)))
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

/// Verify that a message exists on the bulletin and return the ring_pk, pub_poly
pub async fn verify_message_and_get_info<D: Dkg>(
    message: &[u8],
    local_storage: &impl LocalStorage,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<(String, D::PubPoly)> {
    // 1. Deserialize the BulletinPost from the message
    let post: BulletinPost = message.to_vec().try_into().map_err(|e| {
        SignError::Deserialization(format!("Failed to deserialize BulletinPost: {}", e))
    })?;

    // 2. Verify it exists on bulletin (read by namespace + id)
    let actual_post = bulletin
        .read(post.namespace.clone(), post.id.clone())
        .await
        .map_err(|e| {
            SignError::VerificationFailed(format!(
                "Failed to read from bulletin (namespace={}, id={}): {}",
                post.namespace, post.id, e
            ))
        })?;

    // 3. Verify payload matches what's on bulletin
    if actual_post.payload != post.payload {
        return Err(SignError::VerificationFailed(
            "Payload mismatch: message payload does not match bulletin".to_string(),
        ));
    }

    // 4. Parse the DocumentPayload to get ring_id
    let doc_payload: DocumentPayload = serde_json::from_slice(&post.payload).map_err(|e| {
        SignError::Deserialization(format!("Failed to parse DocumentPayload: {}", e))
    })?;

    // 5. Look up ring info from bulletin
    let ring_info = bulletin
        .read(
            BULLETIN_RING_NAMESPACE.to_string(),
            doc_payload.ring_id.clone(),
        )
        .await
        .map_err(|e| {
            SignError::VerificationFailed(format!(
                "Failed to read ring info for ring_id={}: {}",
                doc_payload.ring_id, e
            ))
        })?;

    let ring_payload: RingPayload = serde_json::from_slice(&ring_info.payload)
        .map_err(|e| SignError::Deserialization(format!("Failed to parse RingPayload: {}", e)))?;

    // 6. Load pub_poly from local RingPolyState (never on the bulletin).
    let poly_state = RingPolyState::load_from_ring_pk_hex(local_storage, &ring_payload.ring_pk)
        .map_err(|e| SignError::Storage(format!("Failed to load ring polynomial state: {}", e)))?;
    let pub_poly_bytes = hex::decode(&poly_state.public_polynomial).map_err(|e| {
        SignError::Deserialization(format!("Failed to decode public polynomial hex: {}", e))
    })?;
    let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
        SignError::Deserialization(format!("Failed to deserialize public polynomial: {}", e))
    })?;

    tracing::debug!(
        post_id = %post.id,
        ring_id = %doc_payload.ring_id,
        "Sign Coordinator: Message verified on bulletin"
    );

    Ok((ring_payload.ring_pk, pub_poly))
}

/// Store a received response (called by protocol handler)
///
/// The response is only accepted if the authenticated `sender_peer_id` is in the
/// expected responder set (established at init time). This rejects both unknown peers
/// and duplicate responses from the same peer. Fake `from_node_id` values are caught
/// downstream by crypto verification (`signer.verify_share()`).
pub async fn store_response(
    message: SignMessage,
    sender_peer_id: &PeerId,
    sign_response_state: &Arc<SignResponseManager>,
) -> bool {
    let request_id = message.request_id().to_string();

    tracing::debug!(
        request_id = %request_id,
        from_node_id = ?message.from_node_id(),
        sender_peer = %hex::encode(sender_peer_id.as_bytes()),
        "Sign Coordinator: Storing response"
    );

    sign_response_state
        .store_response(&request_id, message, sender_peer_id.as_bytes())
        .await
}

#[cfg(test)]
mod ring_reshare_update_tests {
    use super::*;
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::Bulletin;
    use crypto::{CryptoSerialize, DkgImpl};

    async fn fixture(
        next_peer_ids: Option<Vec<String>>,
        new_threshold: Option<u32>,
    ) -> (
        DummyBulletin,
        SessionStateManager<DkgImpl>,
        RingReshareUpdateStatement,
        ReshareSignatureReadyKey,
    ) {
        let (_sk, ring_pk) = crypto::helpers::generate_keypair().expect("generate ring key");
        let ring_pk_bytes = CryptoSerialize::to_bytes(&ring_pk).expect("serialize ring key");
        let ring_pk_hex = hex::encode(ring_pk_bytes);
        let ring_key = storage_key_from_ring_pk_hex(&ring_pk_hex).expect("storage key");
        let old_peer_ids = vec!["old-a".to_string(), "old-b".to_string()];
        let final_peer_ids = next_peer_ids
            .clone()
            .unwrap_or_else(|| old_peer_ids.clone());
        let final_threshold = new_threshold.unwrap_or(2);
        let block_number_nonce = 0;

        let current_payload = RingPayload {
            ring_pk: ring_pk_hex.clone(),
            peer_ids: old_peer_ids,
            new_peer_ids: next_peer_ids,
            new_threshold,
            threshold: 2,
            pss_interval: Some(30),
            block_number_nonce,
        };
        let updated_payload = RingPayload {
            ring_pk: ring_pk_hex.clone(),
            peer_ids: final_peer_ids,
            new_peer_ids: None,
            new_threshold: None,
            threshold: final_threshold,
            pss_interval: Some(30),
            block_number_nonce,
        };

        let current_payload_bytes: Vec<u8> = current_payload
            .try_into()
            .expect("serialize current RingPayload");
        let updated_payload_bytes: Vec<u8> = updated_payload
            .try_into()
            .expect("serialize updated RingPayload");
        let bulletin = DummyBulletin::new().await.expect("dummy bulletin");
        bulletin
            .post(
                BULLETIN_RING_NAMESPACE.to_string(),
                current_payload_bytes.clone(),
                None,
            )
            .await
            .expect("post current payload");
        let bulletin_post_id = bulletin
            .get_post_id(BULLETIN_RING_NAMESPACE, &current_payload_bytes)
            .expect("post id");
        let session_id = 77;
        let current_payload_sha256 = sha256_hex(&current_payload_bytes);
        let finalized_payload_sha256 = sha256_hex(&updated_payload_bytes);
        let statement = RingReshareUpdateStatement {
            domain: RING_RESHARE_UPDATE_DOMAIN.to_string(),
            session_id,
            chain_id: bulletin.chain_id(),
            namespace: BULLETIN_RING_NAMESPACE.to_string(),
            ring_pk: ring_pk_hex,
            bulletin_post_id: bulletin_post_id.clone(),
            current_payload_sha256: current_payload_sha256.clone(),
            finalized_payload_sha256: finalized_payload_sha256.clone(),
            block_number_nonce,
        };
        let ready_key = ReshareSignatureReadyKey {
            ring_key,
            session_id,
            bulletin_post_id,
            current_payload_sha256,
            updated_payload_sha256: finalized_payload_sha256,
        };

        (
            bulletin,
            SessionStateManager::<DkgImpl>::new(),
            statement,
            ready_key,
        )
    }

    #[tokio::test]
    async fn validate_accepts_current_payload_fallback_with_ready_marker() {
        let (bulletin, state, statement, ready_key) = fixture(None, None).await;
        state.mark_reshare_signature_ready(ready_key).await;

        let ring_pk = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect("ready marker should authorize validation with current payload fallback");

        assert_eq!(ring_pk, statement.ring_pk);
    }

    #[tokio::test]
    async fn validate_rejects_pending_reshare_without_ready_marker() {
        let (bulletin, state, statement, _ready_key) = fixture(
            Some(vec!["new-a".to_string(), "new-b".to_string()]),
            Some(2),
        )
        .await;

        let err = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect_err("missing local ready marker should be retryable");

        assert!(matches!(err, SignError::ReshareInProgress));
    }

    #[tokio::test]
    async fn validate_accepts_pending_reshare_with_ready_marker() {
        let (bulletin, state, statement, ready_key) = fixture(
            Some(vec!["new-a".to_string(), "new-b".to_string()]),
            Some(2),
        )
        .await;
        state.mark_reshare_signature_ready(ready_key).await;

        let ring_pk = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect("ready marker should authorize validation");

        assert_eq!(ring_pk, statement.ring_pk);
    }

    #[tokio::test]
    async fn validate_rejects_non_ring_namespace() {
        let (bulletin, state, mut statement, ready_key) = fixture(
            Some(vec!["new-a".to_string(), "new-b".to_string()]),
            Some(2),
        )
        .await;
        state.mark_reshare_signature_ready(ready_key).await;
        statement.namespace = "other".to_string();

        let err = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect_err("non-ring namespace should be rejected");

        match err {
            SignError::InvalidInput(message) => {
                assert!(message.contains("namespace"));
                assert!(message.contains(BULLETIN_RING_NAMESPACE));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_rejects_nonce_mismatch() {
        let (bulletin, state, mut statement, ready_key) = fixture(
            Some(vec!["new-a".to_string(), "new-b".to_string()]),
            Some(2),
        )
        .await;
        state.mark_reshare_signature_ready(ready_key).await;
        statement.block_number_nonce += 1;

        let err = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect_err("mismatched nonce should be rejected");

        match err {
            SignError::Unauthorized(message) => {
                assert!(message.contains("block_number_nonce"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_accepts_committee_only_reshare() {
        let (bulletin, state, statement, ready_key) =
            fixture(Some(vec!["new-a".to_string(), "new-b".to_string()]), None).await;
        state.mark_reshare_signature_ready(ready_key).await;

        let ring_pk = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect("committee-only reshare should use current threshold fallback");

        assert_eq!(ring_pk, statement.ring_pk);
    }

    #[tokio::test]
    async fn validate_accepts_threshold_only_reshare() {
        let (bulletin, state, statement, ready_key) = fixture(None, Some(1)).await;
        state.mark_reshare_signature_ready(ready_key).await;

        let ring_pk = validate_ring_reshare_update_statement(&bulletin, &state, &statement, None)
            .await
            .expect("threshold-only reshare should use current committee fallback");

        assert_eq!(ring_pk, statement.ring_pk);
    }

    #[test]
    fn ring_reshare_update_message_matches_sourcehub_vector() {
        let statement = RingReshareUpdateStatement {
            domain: RING_RESHARE_UPDATE_DOMAIN.to_string(),
            session_id: 77,
            chain_id: "sourcehub-test".to_string(),
            namespace: "orbis/rings/ring1".to_string(),
            bulletin_post_id: "ring1-post".to_string(),
            ring_pk: "b2c05c1059dadae32a7092a4323977796c521fa5e241ee7fe34283b3595935b2b80fad135e3f91bf7307382017869c51".to_string(),
            current_payload_sha256:
                "b6684a86125e08eb7cba4298c336ea98ea674a62de3714e76bcd2135a7526b44"
                    .to_string(),
            finalized_payload_sha256:
                "11683bb4da93f949f0a1803cc062f1d7933d1fa2ec201f2ab6867058708df9c1"
                    .to_string(),
            block_number_nonce: 0,
        };

        let sign_bytes = ring_reshare_update_message(&statement).expect("sign bytes");

        assert_eq!(
            hex::encode(sign_bytes),
            "0a1b6f726269732d72696e672d726573686172652d66696e616c697a65120e736f757263656875622d746573741a116f726269732f72696e67732f72696e6731220a72696e67312d706f73742a606232633035633130353964616461653332613730393261343332333937373739366335323166613565323431656537666533343238336233353935393335623262383066616431333565336639316266373330373338323031373836396335313220b6684a86125e08eb7cba4298c336ea98ea674a62de3714e76bcd2135a7526b443a2011683bb4da93f949f0a1803cc062f1d7933d1fa2ec201f2ab6867058708df9c1"
        );
    }

    #[test]
    fn ring_reshare_update_message_includes_nonzero_nonce() {
        let statement = RingReshareUpdateStatement {
            domain: RING_RESHARE_UPDATE_DOMAIN.to_string(),
            session_id: 77,
            chain_id: "sourcehub-test".to_string(),
            namespace: "orbis/rings/ring1".to_string(),
            bulletin_post_id: "ring1-post".to_string(),
            ring_pk: "b2c05c1059dadae32a7092a4323977796c521fa5e241ee7fe34283b3595935b2b80fad135e3f91bf7307382017869c51".to_string(),
            current_payload_sha256:
                "b6684a86125e08eb7cba4298c336ea98ea674a62de3714e76bcd2135a7526b44"
                    .to_string(),
            finalized_payload_sha256:
                "11683bb4da93f949f0a1803cc062f1d7933d1fa2ec201f2ab6867058708df9c1"
                    .to_string(),
            block_number_nonce: 7,
        };

        let sign_bytes = ring_reshare_update_message(&statement).expect("sign bytes");

        assert!(
            hex::encode(sign_bytes).ends_with("4007"),
            "field 8 should encode block_number_nonce"
        );
    }
}
