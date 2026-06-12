//! x/orbis module types and operations.
//!
//! This module provides types and methods for interacting with SourceHub's orbis module,
//! which manages typed ring, document, and key derivation state.

use crate::blockchain::{BlockchainError, Result};
use k256::sha2::{Digest, Sha256};
use prost::Message;

use super::bulletin::{PageRequest, PageResponse};

pub const RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN: &str = "orbis-ring-reshare-finalize";

// ============================================================================
// Domain Types (on-chain state)
// ============================================================================

/// Ring state stored in x/orbis.
#[derive(Clone, Message)]
pub struct Ring {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub creator_did: String,
    #[prost(string, tag = "3")]
    pub ring_pk: String,
    #[prost(string, repeated, tag = "4")]
    pub peer_node_keys: Vec<String>,
    #[prost(uint32, tag = "5")]
    pub threshold: u32,
    #[prost(string, repeated, tag = "6")]
    pub new_peer_node_keys: Vec<String>,
    #[prost(uint32, optional, tag = "7")]
    pub new_threshold: Option<u32>,
    #[prost(uint64, optional, tag = "8")]
    pub pss_interval: Option<u64>,
    #[prost(uint64, tag = "9")]
    pub block_number_nonce: u64,
    #[prost(string, tag = "10")]
    pub policy_id: String,
    #[prost(message, repeated, tag = "11")]
    pub confirmations: Vec<RingConfirmation>,
    #[prost(message, optional, tag = "12")]
    pub upgrade_info: Option<UpgradeInfo>,
}

#[derive(Clone, Message)]
pub struct UpgradeInfo {
    #[prost(uint64, tag = "1")]
    pub current_version: u64,
    #[prost(uint64, optional, tag = "2")]
    pub next_version: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub activation_time: Option<u64>,
}

/// Fresh-DKG confirmation stored on an unfinalized ring.
#[derive(Clone, Message)]
pub struct RingConfirmation {
    #[prost(string, tag = "1")]
    pub node_key: String,
    #[prost(string, tag = "2")]
    pub ring_pk: String,
}

/// Document state stored in x/orbis.
#[derive(Clone, Message)]
pub struct Document {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub creator_did: String,
    #[prost(string, tag = "3")]
    pub ring_id: String,
    #[prost(string, tag = "4")]
    pub document: String,
    #[prost(string, tag = "5")]
    pub proof: String,
    #[prost(string, tag = "6")]
    pub policy_id: String,
    #[prost(string, tag = "7")]
    pub resource: String,
    #[prost(string, tag = "8")]
    pub permission: String,
    #[prost(string, optional, tag = "9")]
    pub tier: Option<String>,
    #[prost(uint64, optional, tag = "10")]
    pub timestamp: Option<u64>,
}

/// Key derivation state stored in x/orbis.
#[derive(Clone, Message)]
pub struct KeyDerivation {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub creator_did: String,
    #[prost(string, tag = "3")]
    pub ring_id: String,
    #[prost(string, tag = "4")]
    pub derivation: String,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, tag = "6")]
    pub resource: String,
    #[prost(string, tag = "7")]
    pub permission: String,
}

/// Node info stored in x/orbis.
#[derive(Clone, Message)]
pub struct NodeInfo {
    #[prost(string, tag = "1")]
    pub peer_id: String,
    #[prost(string, tag = "2")]
    pub controller_key: String,
    #[prost(string, repeated, tag = "3")]
    pub whitelisted_policy_ids: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub whitelisted_ring_ids: Vec<String>,
}

// ============================================================================
// Transaction Message Types
// ============================================================================

#[derive(Clone, Message)]
pub struct MsgCreateRing {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, repeated, tag = "2")]
    pub peer_node_keys: Vec<String>,
    #[prost(uint32, tag = "3")]
    pub threshold: u32,
    #[prost(uint64, optional, tag = "4")]
    pub pss_interval: Option<u64>,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, optional, tag = "6")]
    pub nonce: Option<String>,
    #[prost(uint64, tag = "7")]
    pub current_version: u64,
}

impl MsgCreateRing {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgCreateRing";

    pub fn new(
        creator: &str,
        peer_node_keys: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        nonce: Option<String>,
        current_version: u64,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            peer_node_keys,
            threshold,
            pss_interval,
            policy_id: policy_id.to_string(),
            nonce,
            current_version,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgCreateRingResponse {
    #[prost(string, tag = "1")]
    pub ring_id: String,
}

#[derive(Clone, Message)]
pub struct MsgUpdateRingByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, repeated, tag = "3")]
    pub new_peer_node_keys: Vec<String>,
    #[prost(uint32, optional, tag = "4")]
    pub new_threshold: Option<u32>,
    #[prost(uint64, optional, tag = "5")]
    pub pss_interval: Option<u64>,
    #[prost(uint64, optional, tag = "6")]
    pub next_version: Option<u64>,
    #[prost(uint64, optional, tag = "7")]
    pub activation_time: Option<u64>,
    #[prost(bool, tag = "8")]
    pub clear_upgrade: bool,
}

impl MsgUpdateRingByAcp {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgUpdateRingByAcp";

    pub fn new(
        creator: &str,
        ring_id: &str,
        new_peer_node_keys: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
        next_version: Option<u64>,
        activation_time: Option<u64>,
        clear_upgrade: bool,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            new_peer_node_keys,
            new_threshold,
            pss_interval,
            next_version,
            activation_time,
            clear_upgrade,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgFinalizeRing {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub ring_pk: String,
}

impl MsgFinalizeRing {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgFinalizeRing";

    pub fn new(creator: &str, ring_id: &str, ring_pk: &str) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            ring_pk: ring_pk.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgFinalizeRingResponse {}

#[derive(Clone, Message)]
pub struct MsgFinalizeRingReshareByThresholdSignature {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub signature_scheme: String,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
}

impl MsgFinalizeRingReshareByThresholdSignature {
    pub const TYPE_URL: &'static str =
        "/sourcehub.orbis.MsgFinalizeRingReshareByThresholdSignature";

    pub fn new(creator: &str, ring_id: &str, signature_scheme: &str, signature: Vec<u8>) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            signature_scheme: signature_scheme.to_string(),
            signature,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgStoreDocument {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub document: String,
    #[prost(string, tag = "4")]
    pub proof: String,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, tag = "6")]
    pub resource: String,
    #[prost(string, tag = "7")]
    pub permission: String,
    #[prost(string, optional, tag = "8")]
    pub tier: Option<String>,
    #[prost(uint64, optional, tag = "9")]
    pub timestamp: Option<u64>,
}

impl MsgStoreDocument {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgStoreDocument";
}

#[derive(Clone, Message)]
pub struct MsgStoreDocumentResponse {
    #[prost(string, tag = "1")]
    pub document_id: String,
}

#[derive(Clone, Message)]
pub struct MsgStoreKeyDerivation {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub derivation: String,
    #[prost(string, tag = "4")]
    pub policy_id: String,
    #[prost(string, tag = "5")]
    pub resource: String,
    #[prost(string, tag = "6")]
    pub permission: String,
}

impl MsgStoreKeyDerivation {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgStoreKeyDerivation";
}

#[derive(Clone, Message)]
pub struct MsgStoreKeyDerivationResponse {
    #[prost(string, tag = "1")]
    pub key_derivation_id: String,
}

#[derive(Clone, Message)]
pub struct MsgCreateNodeInfo {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub peer_id: String,
    #[prost(string, tag = "3")]
    pub controller_key: String,
    #[prost(string, repeated, tag = "4")]
    pub whitelisted_policy_ids: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub whitelisted_ring_ids: Vec<String>,
}

impl MsgCreateNodeInfo {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgCreateNodeInfo";
}

#[derive(Clone, Message)]
pub struct MsgCreateNodeInfoResponse {}

#[derive(Clone, Message)]
pub struct MsgUpdateNodeInfo {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub node_key: String,
    #[prost(string, optional, tag = "3")]
    pub peer_id: Option<String>,
    #[prost(string, repeated, tag = "4")]
    pub whitelisted_policy_ids: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub whitelisted_ring_ids: Vec<String>,
    #[prost(string, optional, tag = "6")]
    pub controller_key: Option<String>,
}

impl MsgUpdateNodeInfo {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgUpdateNodeInfo";
}

#[derive(Clone, Message)]
pub struct MsgUpdateNodeInfoResponse {}

// ============================================================================
// Query Request/Response Types
// ============================================================================

#[derive(Clone, Message)]
pub struct QueryRingRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryRingResponse {
    #[prost(message, optional, tag = "1")]
    pub ring: Option<Ring>,
}

#[derive(Clone, Message)]
pub struct QueryRingsRequest {
    #[prost(message, optional, tag = "1")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryRingsResponse {
    #[prost(message, repeated, tag = "1")]
    pub rings: Vec<Ring>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryDocumentResponse {
    #[prost(message, optional, tag = "1")]
    pub document: Option<Document>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentsRequest {
    #[prost(message, optional, tag = "1")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentsResponse {
    #[prost(message, repeated, tag = "1")]
    pub documents: Vec<Document>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationResponse {
    #[prost(message, optional, tag = "1")]
    pub key_derivation: Option<KeyDerivation>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationsRequest {
    #[prost(message, optional, tag = "1")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationsResponse {
    #[prost(message, repeated, tag = "1")]
    pub key_derivations: Vec<KeyDerivation>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

#[derive(Clone, Message)]
pub struct QueryNodeInfoRequest {
    #[prost(string, tag = "1")]
    pub node_key: String,
}

#[derive(Clone, Message)]
pub struct QueryNodeInfoResponse {
    #[prost(message, optional, tag = "1")]
    pub node_info: Option<NodeInfo>,
}

// ============================================================================
// Reshare Sign Doc
// ============================================================================

/// Canonical sign document for finalizing a ring reshare via threshold signature.
#[derive(Clone, Message)]
pub struct RingReshareFinalizeSignDoc {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(string, tag = "2")]
    pub chain_id: String,
    #[prost(string, tag = "3")]
    pub ring_id: String,
    #[prost(string, tag = "4")]
    pub ring_pk: String,
    #[prost(bytes = "vec", tag = "5")]
    pub current_ring_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub finalized_ring_sha256: Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub block_number_nonce: u64,
}

/// Canonical Orbis protocol state hashed into reshare finalization sign docs.
///
/// This intentionally excludes SourceHub storage-only fields such as creator DID,
/// fresh-DKG confirmations, and operational scheduling metadata such as PSS
/// interval. Participant lists must be sorted before hashing.
#[derive(Clone, Message)]
pub struct RingReshareSignState {
    #[prost(string, tag = "1")]
    pub ring_pk: String,
    #[prost(string, repeated, tag = "2")]
    pub peer_node_keys: Vec<String>,
    #[prost(uint32, tag = "3")]
    pub threshold: u32,
    #[prost(string, repeated, tag = "4")]
    pub new_peer_node_keys: Vec<String>,
    #[prost(uint32, optional, tag = "5")]
    pub new_threshold: Option<u32>,
    #[prost(uint64, optional, tag = "6")]
    pub pss_interval: Option<u64>,
    #[prost(uint64, tag = "7")]
    pub block_number_nonce: u64,
    #[prost(string, tag = "8")]
    pub policy_id: String,
}

/// Build SourceHub-compatible sign bytes for a ring reshare finalization.
/// `current_ring_sha256` and `finalized_ring_sha256` must each be exactly 32 bytes —
/// SHA-256 of the canonical Orbis reshare sign-state for the current and finalized states.
pub fn ring_reshare_finalize_sign_bytes(
    chain_id: &str,
    ring_id: &str,
    ring_pk: &str,
    current_ring_sha256: Vec<u8>,
    finalized_ring_sha256: Vec<u8>,
    block_number_nonce: u64,
) -> Result<Vec<u8>> {
    if current_ring_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "current_ring_sha256 must be 32 bytes, got {}",
            current_ring_sha256.len()
        )));
    }
    if finalized_ring_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "finalized_ring_sha256 must be 32 bytes, got {}",
            finalized_ring_sha256.len()
        )));
    }

    Ok(RingReshareFinalizeSignDoc {
        domain: RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN.to_string(),
        chain_id: chain_id.to_string(),
        ring_id: ring_id.to_string(),
        ring_pk: ring_pk.to_string(),
        current_ring_sha256,
        finalized_ring_sha256,
        block_number_nonce,
    }
    .encode_to_vec())
}

/// Hash a canonicalized reshare sign-state for use in reshare sign docs.
pub fn ring_reshare_sign_state_hash(state: &RingReshareSignState) -> [u8; 32] {
    let mut canonical = state.clone();
    canonical.peer_node_keys.sort();
    canonical.new_peer_node_keys.sort();
    canonical.pss_interval = None;
    Sha256::digest(canonical.encode_to_vec()).into()
}

/// Compute the deterministic document ID matching SourceHub's on-chain `GenerateDocumentID`.
pub fn generate_document_id(
    ring_id: &str,
    document: &str,
    proof: &str,
    policy_id: &str,
    resource: &str,
    permission: &str,
    tier: Option<&str>,
    timestamp: Option<u64>,
) -> String {
    let mut h = Sha256::new();

    write_string(&mut h, "orbis/document/v1");
    write_string(&mut h, ring_id);
    write_string(&mut h, document);
    write_string(&mut h, proof);
    write_string(&mut h, policy_id);
    write_string(&mut h, resource);
    write_string(&mut h, permission);
    write_optional_string(&mut h, tier);
    write_optional_u64(&mut h, timestamp);

    hex::encode(h.finalize())
}

/// Compute the deterministic key derivation ID matching SourceHub's on-chain `GenerateKeyDerivationID`.
pub fn generate_key_derivation_id(
    ring_id: &str,
    derivation: &str,
    policy_id: &str,
    resource: &str,
    permission: &str,
) -> String {
    let mut h = Sha256::new();

    write_string(&mut h, "orbis/key_derivation/v1");
    write_string(&mut h, ring_id);
    write_string(&mut h, derivation);
    write_string(&mut h, policy_id);
    write_string(&mut h, resource);
    write_string(&mut h, permission);

    hex::encode(h.finalize())
}

fn write_string(h: &mut Sha256, s: &str) {
    h.update((s.len() as u32).to_be_bytes());
    h.update(s.as_bytes());
}

fn write_optional_string(h: &mut Sha256, value: Option<&str>) {
    match value {
        None => h.update([0u8]),
        Some(v) => {
            h.update([1u8]);
            write_string(h, v);
        }
    }
}

fn write_optional_u64(h: &mut Sha256, value: Option<u64>) {
    match value {
        None => h.update([0u8]),
        Some(v) => {
            h.update([1u8]);
            h.update(v.to_be_bytes());
        }
    }
}

// ============================================================================
// Cosmos SDK ABCI response decoding
// ============================================================================

/// Minimal representation of google.protobuf.Any for decoding TxMsgData.
#[derive(Clone, prost::Message)]
struct AnyProto {
    #[prost(string, tag = "1")]
    pub type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// Cosmos SDK TxMsgData: wrapper around per-message ABCI responses.
/// Field 2 (msg_responses) is the modern SDK 0.46+ format.
/// Field 1 (data) is the legacy format; each entry's value bytes are
/// the raw-encoded response message.
#[derive(Clone, prost::Message)]
struct TxMsgData {
    #[prost(message, repeated, tag = "2")]
    pub msg_responses: Vec<AnyProto>,
}

/// Extract `MsgCreateRingResponse.ring_id` from a broadcast result.
///
/// Tries the modern Cosmos SDK format (TxMsgData.msg_responses) first,
/// then falls back to interpreting the raw data as `MsgCreateRingResponse`
/// directly. Returns `None` if decoding fails or the ring_id is empty.
pub fn decode_create_ring_id(data: Option<&Vec<u8>>) -> Option<String> {
    decode_tx_response_id::<MsgCreateRingResponse, _>(data, |resp| &resp.ring_id)
}

/// Extract `MsgStoreDocumentResponse.document_id` from a broadcast result.
pub fn decode_store_document_id(data: Option<&Vec<u8>>) -> Option<String> {
    decode_tx_response_id::<MsgStoreDocumentResponse, _>(data, |resp| &resp.document_id)
}

/// Extract `MsgStoreKeyDerivationResponse.key_derivation_id` from a broadcast result.
pub fn decode_store_key_derivation_id(data: Option<&Vec<u8>>) -> Option<String> {
    decode_tx_response_id::<MsgStoreKeyDerivationResponse, _>(data, |resp| &resp.key_derivation_id)
}

fn decode_tx_response_id<T, F>(data: Option<&Vec<u8>>, extract_id: F) -> Option<String>
where
    T: Message + Default,
    F: Fn(&T) -> &str,
{
    let bytes = data?;
    if bytes.is_empty() {
        return None;
    }

    // Try modern Cosmos SDK 0.46+ format: TxMsgData.msg_responses[0].value
    if let Ok(tx_data) = TxMsgData::decode(bytes.as_slice()) {
        for any in &tx_data.msg_responses {
            if let Ok(resp) = T::decode(any.value.as_slice()) {
                let id = extract_id(&resp);
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }

    // Fallback: try decoding the bytes directly as the response message.
    if let Ok(resp) = T::decode(bytes.as_slice()) {
        let id = extract_id(&resp);
        if !id.is_empty() {
            return Some(id.to_string());
        }
    }

    None
}

// ============================================================================
// SourceHubClient extension methods
// ============================================================================

use crate::blockchain::{BroadcastResult, SourceHubClient};

impl SourceHubClient {
    pub async fn orbis_create_ring(
        &self,
        peer_node_keys: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        nonce: Option<String>,
        current_version: u64,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgCreateRing::new(
            &signer.address(),
            peer_node_keys,
            threshold,
            pss_interval,
            policy_id,
            nonce,
            current_version,
        );
        self.broadcast_proto_msg_with_gas(
            MsgCreateRing::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Create a ring and return the chain-assigned ring_id alongside the broadcast result.
    ///
    /// The ring_id is decoded from `MsgCreateRingResponse` in the ABCI response data.
    pub async fn orbis_create_ring_get_id(
        &self,
        peer_node_keys: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        nonce: Option<String>,
        current_version: u64,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_create_ring(
                peer_node_keys,
                threshold,
                pss_interval,
                policy_id,
                nonce,
                current_version,
            )
            .await?;

        if result.code != 0 {
            return Err(BlockchainError::TxFailed {
                code: result.code,
                log: result.log.clone(),
            });
        }

        let ring_id = decode_create_ring_id(result.data.as_ref()).ok_or_else(|| {
            BlockchainError::Serialization(format!(
                "Failed to decode ring_id from create ring response for tx {}",
                result.tx_hash
            ))
        })?;

        Ok((result, ring_id))
    }

    pub async fn orbis_store_document(
        &self,
        ring_id: &str,
        document: &str,
        proof: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        tier: Option<String>,
        timestamp: Option<u64>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgStoreDocument {
            creator: signer.address(),
            ring_id: ring_id.to_string(),
            document: document.to_string(),
            proof: proof.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            tier,
            timestamp,
        };
        self.broadcast_proto_msg_with_gas(
            MsgStoreDocument::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Store a document and return the chain-assigned document_id alongside the broadcast result.
    pub async fn orbis_store_document_get_id(
        &self,
        ring_id: &str,
        document: &str,
        proof: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        tier: Option<String>,
        timestamp: Option<u64>,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_store_document(
                ring_id, document, proof, policy_id, resource, permission, tier, timestamp,
            )
            .await?;

        if result.code != 0 {
            return Err(BlockchainError::TxFailed {
                code: result.code,
                log: result.log.clone(),
            });
        }

        let document_id = decode_store_document_id(result.data.as_ref()).ok_or_else(|| {
            BlockchainError::Serialization(format!(
                "Failed to decode document_id from store document response for tx {}",
                result.tx_hash
            ))
        })?;

        Ok((result, document_id))
    }

    pub async fn orbis_store_key_derivation(
        &self,
        ring_id: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgStoreKeyDerivation {
            creator: signer.address(),
            ring_id: ring_id.to_string(),
            derivation: derivation.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        };
        self.broadcast_proto_msg_with_gas(
            MsgStoreKeyDerivation::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Store a key derivation and return the chain-assigned key_derivation_id alongside the broadcast result.
    pub async fn orbis_store_key_derivation_get_id(
        &self,
        ring_id: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_store_key_derivation(ring_id, derivation, policy_id, resource, permission)
            .await?;

        if result.code != 0 {
            return Err(BlockchainError::TxFailed {
                code: result.code,
                log: result.log.clone(),
            });
        }

        let key_derivation_id =
            decode_store_key_derivation_id(result.data.as_ref()).ok_or_else(|| {
                BlockchainError::Serialization(format!(
                    "Failed to decode key_derivation_id from store key derivation response for tx {}",
                    result.tx_hash
                ))
            })?;

        Ok((result, key_derivation_id))
    }

    pub async fn orbis_create_node_info(
        &self,
        peer_id: &str,
        controller_key: &str,
        whitelisted_policy_ids: Vec<String>,
        whitelisted_ring_ids: Vec<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgCreateNodeInfo {
            creator: signer.address(),
            peer_id: peer_id.to_string(),
            controller_key: controller_key.to_string(),
            whitelisted_policy_ids,
            whitelisted_ring_ids,
        };
        self.broadcast_proto_msg_with_gas(
            MsgCreateNodeInfo::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_update_node_info(
        &self,
        node_key: &str,
        peer_id: Option<String>,
        whitelisted_policy_ids: Vec<String>,
        whitelisted_ring_ids: Vec<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgUpdateNodeInfo {
            creator: signer.address(),
            node_key: node_key.to_string(),
            peer_id,
            whitelisted_policy_ids,
            whitelisted_ring_ids,
            controller_key: None,
        };
        self.broadcast_proto_msg_with_gas(
            MsgUpdateNodeInfo::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_update_ring_by_acp(
        &self,
        ring_id: &str,
        new_peer_node_keys: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
        next_version: Option<u64>,
        activation_time: Option<u64>,
        clear_upgrade: bool,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgUpdateRingByAcp::new(
            &signer.address(),
            ring_id,
            new_peer_node_keys,
            new_threshold,
            pss_interval,
            next_version,
            activation_time,
            clear_upgrade,
        );
        self.broadcast_proto_msg_with_gas(
            MsgUpdateRingByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_finalize_ring(
        &self,
        ring_id: &str,
        ring_pk: &str,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgFinalizeRing::new(&signer.address(), ring_id, ring_pk);
        self.broadcast_proto_msg_with_gas(
            MsgFinalizeRing::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_finalize_ring_reshare(
        &self,
        ring_id: &str,
        signature_scheme: &str,
        signature: Vec<u8>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgFinalizeRingReshareByThresholdSignature::new(
            &signer.address(),
            ring_id,
            signature_scheme,
            signature,
        );
        self.broadcast_proto_msg_with_gas(
            MsgFinalizeRingReshareByThresholdSignature::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_read_ring(&self, ring_id: &str) -> Result<Option<Ring>> {
        let request = QueryRingRequest {
            id: ring_id.to_string(),
        };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/sourcehub.orbis.Query/Ring",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response = QueryRingResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode ring response: {}", e))
        })?;
        Ok(response.ring)
    }

    pub async fn orbis_read_document(&self, id: &str) -> Result<Option<Document>> {
        let request = QueryDocumentRequest { id: id.to_string() };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/sourcehub.orbis.Query/Document",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response = QueryDocumentResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode document response: {}", e))
        })?;
        Ok(response.document)
    }

    pub async fn orbis_read_key_derivation(&self, id: &str) -> Result<Option<KeyDerivation>> {
        let request = QueryKeyDerivationRequest { id: id.to_string() };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/sourcehub.orbis.Query/KeyDerivation",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response =
            QueryKeyDerivationResponse::decode(response_bytes.as_slice()).map_err(|e| {
                BlockchainError::Serialization(format!(
                    "Failed to decode key derivation response: {}",
                    e
                ))
            })?;
        Ok(response.key_derivation)
    }

    pub async fn orbis_read_node_info(&self, node_key: &str) -> Result<Option<NodeInfo>> {
        let request = QueryNodeInfoRequest {
            node_key: node_key.to_string(),
        };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/sourcehub.orbis.Query/NodeInfo",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response = QueryNodeInfoResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode node info response: {}", e))
        })?;
        Ok(response.node_info)
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::{
        decode_store_document_id, decode_store_key_derivation_id, ring_reshare_sign_state_hash,
        MsgCreateRing, MsgFinalizeRing, MsgFinalizeRingReshareByThresholdSignature,
        MsgStoreDocumentResponse, MsgStoreKeyDerivationResponse, MsgUpdateRingByAcp, Ring,
        RingReshareSignState, UpgradeInfo,
    };

    #[test]
    fn create_ring_preserves_present_zero_pss_interval_on_wire() {
        let msg = MsgCreateRing::new("c", vec!["p1".to_string()], 1, Some(0), "policy", None, 0);
        let bytes = msg.encode_to_vec();

        assert!(
            bytes.windows(2).any(|window| window == [0x20, 0x00]),
            "encoded MsgCreateRing should include optional field 4 with value 0: {}",
            hex::encode(&bytes)
        );

        let decoded = MsgCreateRing::decode(bytes.as_slice()).expect("decode MsgCreateRing");
        assert_eq!(decoded.pss_interval, Some(0));
    }

    #[test]
    fn update_ring_by_acp_wire_fields_match_sourcehub_proto() {
        let msg = MsgUpdateRingByAcp::new(
            "c",
            "r",
            vec!["p1".to_string(), "p2".to_string()],
            Some(2),
            Some(10),
            Some(1),
            Some(1000),
            true,
        );

        assert_eq!(
            hex::encode(msg.encode_to_vec()),
            "0a01631201721a0270311a0270322002280a300138e8074001"
        );
    }

    #[test]
    fn finalize_ring_wire_fields_match_sourcehub_proto() {
        let msg = MsgFinalizeRing::new("c", "r", "pk");

        assert_eq!(hex::encode(msg.encode_to_vec()), "0a01631201721a02706b");
    }

    #[test]
    fn finalize_ring_reshare_wire_fields_match_sourcehub_proto() {
        let msg = MsgFinalizeRingReshareByThresholdSignature::new("c", "r", "s", vec![1, 2]);

        assert_eq!(
            hex::encode(msg.encode_to_vec()),
            "0a01631201721a017322020102"
        );
    }

    #[test]
    fn ring_reshare_sign_state_hash_sorts_participant_lists() {
        let state = RingReshareSignState {
            ring_pk: "pk".to_string(),
            peer_node_keys: vec!["node-b".to_string(), "node-a".to_string()],
            threshold: 2,
            new_peer_node_keys: vec!["node-d".to_string(), "node-c".to_string()],
            new_threshold: Some(1),
            pss_interval: Some(30),
            block_number_nonce: 9,
            policy_id: "policy".to_string(),
        };
        let reordered = RingReshareSignState {
            peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
            new_peer_node_keys: vec!["node-c".to_string(), "node-d".to_string()],
            ..state.clone()
        };

        assert_eq!(
            ring_reshare_sign_state_hash(&state),
            ring_reshare_sign_state_hash(&reordered)
        );
    }

    #[test]
    fn ring_reshare_sign_state_hash_ignores_pss_interval() {
        let state = RingReshareSignState {
            ring_pk: "pk".to_string(),
            peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
            threshold: 2,
            new_peer_node_keys: vec!["node-c".to_string(), "node-d".to_string()],
            new_threshold: Some(1),
            pss_interval: None,
            block_number_nonce: 9,
            policy_id: "policy".to_string(),
        };
        let with_pss_interval = RingReshareSignState {
            pss_interval: Some(30),
            ..state.clone()
        };

        assert_eq!(
            ring_reshare_sign_state_hash(&state),
            ring_reshare_sign_state_hash(&with_pss_interval)
        );
    }

    #[test]
    fn decode_store_document_id_from_direct_response() {
        let response = MsgStoreDocumentResponse {
            document_id: "doc-id".to_string(),
        };
        let bytes = response.encode_to_vec();

        assert_eq!(
            decode_store_document_id(Some(&bytes)),
            Some("doc-id".to_string())
        );
    }

    #[test]
    fn decode_store_key_derivation_id_from_direct_response() {
        let response = MsgStoreKeyDerivationResponse {
            key_derivation_id: "key-derivation-id".to_string(),
        };
        let bytes = response.encode_to_vec();

        assert_eq!(
            decode_store_key_derivation_id(Some(&bytes)),
            Some("key-derivation-id".to_string())
        );
    }

    #[test]
    fn ring_upgrade_info_round_trips() {
        let ring = Ring {
            id: "ring-1".to_string(),
            upgrade_info: Some(UpgradeInfo {
                current_version: 0,
                next_version: Some(1),
                activation_time: Some(100),
            }),
            ..Default::default()
        };
        let bytes = ring.encode_to_vec();
        let decoded = Ring::decode(bytes.as_slice()).expect("decode");
        let info = decoded.upgrade_info.expect("upgrade_info");
        assert_eq!(info.current_version, 0);
        assert_eq!(info.next_version, Some(1));
        assert_eq!(info.activation_time, Some(100));
    }
}
