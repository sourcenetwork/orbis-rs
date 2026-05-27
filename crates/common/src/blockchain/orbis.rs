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
    pub peer_ids: Vec<String>,
    #[prost(uint32, tag = "5")]
    pub threshold: u32,
    #[prost(string, repeated, tag = "6")]
    pub new_peer_ids: Vec<String>,
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
    pub peer_ids: Vec<String>,
    #[prost(uint32, tag = "3")]
    pub threshold: u32,
    #[prost(uint64, optional, tag = "4")]
    pub pss_interval: Option<u64>,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, tag = "6")]
    pub artifact: String,
    #[prost(string, optional, tag = "7")]
    pub nonce: Option<String>,
}

impl MsgCreateRing {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgCreateRing";

    pub fn new(
        creator: &str,
        peer_ids: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        artifact: Option<String>,
        nonce: Option<String>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            peer_ids,
            threshold,
            pss_interval,
            policy_id: policy_id.to_string(),
            artifact: artifact.unwrap_or_default(),
            nonce,
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
    pub new_peer_ids: Vec<String>,
    #[prost(uint32, optional, tag = "4")]
    pub new_threshold: Option<u32>,
    #[prost(uint64, optional, tag = "5")]
    pub pss_interval: Option<u64>,
}

impl MsgUpdateRingByAcp {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgUpdateRingByAcp";

    pub fn new(
        creator: &str,
        ring_id: &str,
        new_peer_ids: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            new_peer_ids,
            new_threshold,
            pss_interval,
        }
    }
}

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

/// Build SourceHub-compatible sign bytes for a ring reshare finalization.
/// `current_ring_sha256` and `finalized_ring_sha256` must each be exactly 32 bytes —
/// SHA-256 of the cosmos-proto-encoded `Ring` structs for the current and finalized states.
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

/// Hash a proto-encoded `Ring` for use in reshare sign docs.
pub fn ring_state_hash(ring: &Ring) -> [u8; 32] {
    Sha256::digest(ring.encode_to_vec()).into()
}

// ============================================================================
// Ring ID generation (mirrors SourceHub's GenerateRingID)
// ============================================================================

/// Compute the deterministic ring ID matching SourceHub's on-chain `GenerateRingID`.
///
/// Encoding: each string is 4-byte big-endian length + UTF-8 bytes; string slices
/// have a 4-byte big-endian count prefix; uint32 is 4-byte big-endian;
/// optional uint64 is a 1-byte presence flag followed by 8-byte big-endian if present.
pub fn generate_ring_id(
    peer_ids: &[String],
    threshold: u32,
    pss_interval: Option<u64>,
    policy_id: &str,
    nonce: Option<&str>,
) -> String {
    let mut h = Sha256::new();

    write_string(&mut h, "orbis/ring/v1");
    write_string_slice(&mut h, peer_ids);
    h.update(threshold.to_be_bytes());
    write_optional_u64(&mut h, pss_interval);
    write_string(&mut h, policy_id);
    write_optional_string(&mut h, nonce);

    hex::encode(h.finalize())
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

fn write_string_slice(h: &mut Sha256, slice: &[String]) {
    h.update((slice.len() as u32).to_be_bytes());
    for s in slice {
        write_string(h, s);
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
    let bytes = data?;
    if bytes.is_empty() {
        return None;
    }

    // Try modern Cosmos SDK 0.46+ format: TxMsgData.msg_responses[0].value
    if let Ok(tx_data) = TxMsgData::decode(bytes.as_slice()) {
        for any in &tx_data.msg_responses {
            if let Ok(resp) = MsgCreateRingResponse::decode(any.value.as_slice()) {
                if !resp.ring_id.is_empty() {
                    return Some(resp.ring_id);
                }
            }
        }
    }

    // Fallback: try decoding the bytes directly as MsgCreateRingResponse
    if let Ok(resp) = MsgCreateRingResponse::decode(bytes.as_slice()) {
        if !resp.ring_id.is_empty() {
            return Some(resp.ring_id);
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
        peer_ids: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        artifact: Option<String>,
        nonce: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgCreateRing::new(
            &signer.address(),
            peer_ids,
            threshold,
            pss_interval,
            policy_id,
            artifact,
            nonce,
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
        peer_ids: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        artifact: Option<String>,
        nonce: Option<String>,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_create_ring(
                peer_ids,
                threshold,
                pss_interval,
                policy_id,
                artifact,
                nonce,
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

    pub async fn orbis_update_ring_by_acp(
        &self,
        ring_id: &str,
        new_peer_ids: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgUpdateRingByAcp::new(
            &signer.address(),
            ring_id,
            new_peer_ids,
            new_threshold,
            pss_interval,
        );
        self.broadcast_proto_msg_with_gas(
            MsgUpdateRingByAcp::TYPE_URL,
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
        let response_bytes = match self
            .abci_query(
                "/sourcehub.orbis.Query/Ring",
                request.encode_to_vec(),
                None,
                false,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(BlockchainError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let response = QueryRingResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode ring response: {}", e))
        })?;
        Ok(response.ring)
    }

    pub async fn orbis_read_document(&self, id: &str) -> Result<Option<Document>> {
        let request = QueryDocumentRequest { id: id.to_string() };
        let response_bytes = match self
            .abci_query(
                "/sourcehub.orbis.Query/Document",
                request.encode_to_vec(),
                None,
                false,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(BlockchainError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let response = QueryDocumentResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode document response: {}", e))
        })?;
        Ok(response.document)
    }

    pub async fn orbis_read_key_derivation(&self, id: &str) -> Result<Option<KeyDerivation>> {
        let request = QueryKeyDerivationRequest { id: id.to_string() };
        let response_bytes = match self
            .abci_query(
                "/sourcehub.orbis.Query/KeyDerivation",
                request.encode_to_vec(),
                None,
                false,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(BlockchainError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
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
        let response_bytes = match self
            .abci_query(
                "/sourcehub.orbis.Query/NodeInfo",
                request.encode_to_vec(),
                None,
                false,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(BlockchainError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
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

    use super::{MsgCreateRing, MsgFinalizeRingReshareByThresholdSignature, MsgUpdateRingByAcp};

    #[test]
    fn create_ring_preserves_present_zero_pss_interval_on_wire() {
        let msg = MsgCreateRing::new(
            "c",
            vec!["p1".to_string()],
            1,
            Some(0),
            "policy",
            None,
            None,
        );
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
        );

        assert_eq!(
            hex::encode(msg.encode_to_vec()),
            "0a01631201721a0270311a0270322002280a"
        );
    }

    #[test]
    fn finalize_ring_reshare_wire_fields_match_sourcehub_proto() {
        let msg = MsgFinalizeRingReshareByThresholdSignature::new("c", "r", "s", vec![1, 2]);

        assert_eq!(
            hex::encode(msg.encode_to_vec()),
            "0a01631201721a017322020102"
        );
    }
}
