//! Shared "build, sign, and store" step for the `pre_share_endpoints` delivery mode.
//!
//! Given a completed `ReencryptReply`, builds the same `PreReencryptResponseStatement`
//! shape the direct-mode responder already signs (`handlers.rs`), wraps it in a signed
//! [`pre_share::StoredShareEnvelope`], uploads it to the ring's configured Defra
//! endpoint, and returns a signed `StoredShareAck`. Used by both the responder side
//! (`handlers.rs::handle_reencrypt_request`) and the local-contribution path
//! (`initiator.rs::compute_local_stored_contribution`) — the one piece of real
//! duplication between those two call sites, factored out once.

use std::time::{SystemTime, UNIX_EPOCH};

use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{CryptoSerialize, Dkg, ReencryptReply, ThresholdDealer};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use pre_share::{PreShareFields, StoredShareEnvelope, PRE_SHARE_COLLECTION};
use sha2::{Digest, Sha256};

use crate::app_state::AppState;
use crate::constants::PRE_COLLECTION_TIMEOUT;
use crate::pre::v0::error::{PreError, Result};
use crate::pre::v0::messages::StoredShareAck;
use crate::reporting::v0::types::{PreReencryptResponseStatement, PRE_REENCRYPT_RESPONSE_DOMAIN};

/// Loads this node's own hex-encoded node signing key from local storage. Shared by
/// the direct-mode `response_signature` path (`handlers.rs`) and this module's own
/// envelope/ack signing — identical lookup, used by both.
pub(super) fn load_node_signing_key_hex<D>(app_state: &AppState<D>) -> Result<String>
where
    D: Dkg + Clone + 'static,
{
    let signing_key = app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .map_err(|e| PreError::Storage(format!("Failed to read node signing key: {}", e)))?
        .ok_or_else(|| PreError::Storage("Node signing key is not configured".to_string()))?;
    String::from_utf8(signing_key.to_vec())
        .map_err(|e| PreError::Storage(format!("Stored node signing key is not UTF-8: {}", e)))
}

/// Everything `build_and_store_envelope` needs beyond `reply` itself and this node's
/// own identity/signing key (read directly from `app_state`).
pub(super) struct StoredShareParams<'a> {
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: &'a str,
    pub object_id: &'a str,
    pub rdr_pk_bytes: &'a [u8],
    pub derivation: Option<&'a [u8]>,
    pub document_inline: bool,
    pub timestamp: Option<u64>,
    pub pinned_public_polynomial: String,
    /// The one endpoint this call uploads to — callers pick
    /// `ring.pre_share_endpoints[0]`; see that field's doc comment for why there's no
    /// per-request failover across multiple configured endpoints yet.
    pub endpoint: &'a str,
}

pub(super) async fn build_and_store_envelope<D, T>(
    app_state: &AppState<D>,
    reply: &ReencryptReply<Fr, G1Affine>,
    params: StoredShareParams<'_>,
) -> Result<StoredShareAck>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer<ShareValue = Fr, PublicKey = G1Affine>,
{
    let share_bytes = CryptoSerialize::to_bytes(&reply.share.v)
        .map_err(|e| PreError::Serialization(format!("Failed to serialize share: {}", e)))?;
    let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge)
        .map_err(|e| PreError::Serialization(format!("Failed to serialize challenge: {}", e)))?;
    let proof_bytes = CryptoSerialize::to_bytes(&reply.proof)
        .map_err(|e| PreError::Serialization(format!("Failed to serialize proof: {}", e)))?;

    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PreError::SystemTime(format!("Failed to get timestamp: {}", e)))?
        .as_secs();

    let request_id = params.request_id.to_string();
    let ring_id = params.ring_id.clone();

    let statement = PreReencryptResponseStatement {
        domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: params.chain_id,
        ring_id: params.ring_id,
        ring_pk: params.ring_pk,
        ring_state_sha256: params.ring_state_sha256,
        protocol_version: params.protocol_version,
        request_id: request_id.clone(),
        signed_at,
        responder_node_key: app_state.node_key.clone(),
        origin_protocol: "pre".to_string(),
        object_id: params.object_id.to_string(),
        rdr_pk: params.rdr_pk_bytes.to_vec(),
        derivation: params.derivation.map(<[u8]>::to_vec),
        from_node_id: reply.share.i,
        share: share_bytes,
        challenge: challenge_bytes,
        proof: proof_bytes,
        crypto_backend: T::name(),
        timestamp: params.timestamp,
        document_inline: params.document_inline,
    };

    let signing_key_hex = load_node_signing_key_hex(app_state)?;

    let envelope = StoredShareEnvelope::new(statement, params.pinned_public_polynomial.clone())
        .sign(&signing_key_hex)
        .map_err(|e| PreError::Crypto(format!("Failed to sign stored share envelope: {}", e)))?;

    let envelope_bytes = serde_json::to_vec(&envelope)
        .map_err(|e| PreError::Serialization(format!("Failed to serialize envelope: {}", e)))?;
    let envelope_sha256 = Sha256::digest(&envelope_bytes).to_vec();

    let client = app_state
        .defra
        .client_for(params.endpoint, &signing_key_hex, &app_state.node_key)
        .await?;
    let deadline = std::time::Instant::now() + PRE_COLLECTION_TIMEOUT;
    let defra_locator = client
        .store_envelope(
            PRE_SHARE_COLLECTION,
            PreShareFields {
                request_id: request_id.clone(),
                ring_id,
                participant: app_state.node_key.clone(),
            },
            &envelope,
            deadline,
        )
        .await
        .map_err(|e| PreError::DefraStorage(e.to_string()))?;

    let ack_signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PreError::SystemTime(format!("Failed to get timestamp: {}", e)))?
        .as_secs();
    let mut ack = StoredShareAck {
        request_id,
        from_node_id: reply.share.i,
        defra_locator,
        envelope_sha256,
        pinned_public_polynomial: params.pinned_public_polynomial,
        signed_at: ack_signed_at,
        ack_signature: Vec::new(),
    };
    ack.ack_signature = sign_node_message_with_hex_key(&signing_key_hex, &ack.canonical_bytes())
        .map_err(|e| PreError::Crypto(format!("Failed to sign stored share ack: {}", e)))?;

    Ok(ack)
}
