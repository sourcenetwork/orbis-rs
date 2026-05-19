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
    pub namespace: String,
    #[prost(string, tag = "3")]
    pub creator_did: String,
    #[prost(string, tag = "4")]
    pub ring_pk: String,
    #[prost(string, repeated, tag = "5")]
    pub peer_ids: Vec<String>,
    #[prost(uint32, tag = "6")]
    pub threshold: u32,
    #[prost(string, repeated, tag = "7")]
    pub new_peer_ids: Vec<String>,
    #[prost(uint32, tag = "8")]
    pub new_threshold: u32,
    #[prost(bool, tag = "9")]
    pub has_new_threshold: bool,
    #[prost(uint64, tag = "10")]
    pub pss_interval: u64,
    #[prost(bool, tag = "11")]
    pub has_pss_interval: bool,
    #[prost(uint64, tag = "12")]
    pub block_number_nonce: u64,
    #[prost(string, tag = "13")]
    pub policy_id: String,
}

/// Document state stored in x/orbis.
#[derive(Clone, Message)]
pub struct Document {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(string, tag = "3")]
    pub creator_did: String,
    #[prost(string, tag = "4")]
    pub ring_id: String,
    #[prost(string, tag = "5")]
    pub document: String,
    #[prost(string, tag = "6")]
    pub proof: String,
    #[prost(string, tag = "7")]
    pub policy_id: String,
    #[prost(string, tag = "8")]
    pub resource: String,
    #[prost(string, tag = "9")]
    pub permission: String,
    #[prost(string, tag = "10")]
    pub tier: String,
    #[prost(bool, tag = "11")]
    pub has_tier: bool,
    #[prost(uint64, tag = "12")]
    pub timestamp: u64,
    #[prost(bool, tag = "13")]
    pub has_timestamp: bool,
}

/// Key derivation state stored in x/orbis.
#[derive(Clone, Message)]
pub struct KeyDerivation {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(string, tag = "3")]
    pub creator_did: String,
    #[prost(string, tag = "4")]
    pub ring_id: String,
    #[prost(string, tag = "5")]
    pub derivation: String,
    #[prost(string, tag = "6")]
    pub policy_id: String,
    #[prost(string, tag = "7")]
    pub resource: String,
    #[prost(string, tag = "8")]
    pub permission: String,
}

// ============================================================================
// Transaction Message Types
// ============================================================================

#[derive(Clone, Message)]
pub struct MsgCreateRing {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(string, tag = "3")]
    pub ring_pk: String,
    #[prost(string, repeated, tag = "4")]
    pub peer_ids: Vec<String>,
    #[prost(uint32, tag = "5")]
    pub threshold: u32,
    #[prost(uint64, tag = "6")]
    pub pss_interval: u64,
    #[prost(bool, tag = "7")]
    pub has_pss_interval: bool,
    #[prost(string, tag = "8")]
    pub policy_id: String,
    #[prost(string, tag = "9")]
    pub artifact: String,
}

impl MsgCreateRing {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgCreateRing";

    pub fn new(
        creator: &str,
        namespace: &str,
        ring_pk: &str,
        peer_ids: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        artifact: Option<String>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
            ring_pk: ring_pk.to_string(),
            peer_ids,
            threshold,
            pss_interval: pss_interval.unwrap_or(0),
            has_pss_interval: pss_interval.is_some(),
            policy_id: policy_id.to_string(),
            artifact: artifact.unwrap_or_default(),
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
    #[prost(string, tag = "3")]
    pub artifact: String,
    #[prost(string, repeated, tag = "4")]
    pub new_peer_ids: Vec<String>,
    #[prost(uint32, tag = "5")]
    pub new_threshold: u32,
    #[prost(bool, tag = "6")]
    pub has_new_threshold: bool,
    #[prost(uint64, tag = "7")]
    pub pss_interval: u64,
    #[prost(bool, tag = "8")]
    pub has_pss_interval: bool,
}

impl MsgUpdateRingByAcp {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgUpdateRingByAcp";

    pub fn new(
        creator: &str,
        ring_id: &str,
        artifact: Option<String>,
        new_peer_ids: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            artifact: artifact.unwrap_or_default(),
            new_peer_ids,
            new_threshold: new_threshold.unwrap_or(0),
            has_new_threshold: new_threshold.is_some(),
            pss_interval: pss_interval.unwrap_or(0),
            has_pss_interval: pss_interval.is_some(),
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
    pub artifact: String,
    #[prost(string, tag = "4")]
    pub signature_scheme: String,
    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
}

impl MsgFinalizeRingReshareByThresholdSignature {
    pub const TYPE_URL: &'static str =
        "/sourcehub.orbis.MsgFinalizeRingReshareByThresholdSignature";

    pub fn new(
        creator: &str,
        ring_id: &str,
        artifact: Option<String>,
        signature_scheme: &str,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            artifact: artifact.unwrap_or_default(),
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
    pub namespace: String,
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
    #[prost(string, tag = "9")]
    pub tier: String,
    #[prost(bool, tag = "10")]
    pub has_tier: bool,
    #[prost(uint64, tag = "11")]
    pub timestamp: u64,
    #[prost(bool, tag = "12")]
    pub has_timestamp: bool,
    #[prost(string, tag = "13")]
    pub artifact: String,
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
    pub namespace: String,
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
    #[prost(string, tag = "8")]
    pub artifact: String,
}

impl MsgStoreKeyDerivation {
    pub const TYPE_URL: &'static str = "/sourcehub.orbis.MsgStoreKeyDerivation";
}

#[derive(Clone, Message)]
pub struct MsgStoreKeyDerivationResponse {
    #[prost(string, tag = "1")]
    pub key_derivation_id: String,
}

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
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(message, optional, tag = "2")]
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
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryDocumentResponse {
    #[prost(message, optional, tag = "1")]
    pub document: Option<Document>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentsRequest {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(message, optional, tag = "2")]
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
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationResponse {
    #[prost(message, optional, tag = "1")]
    pub key_derivation: Option<KeyDerivation>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationsRequest {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationsResponse {
    #[prost(message, repeated, tag = "1")]
    pub key_derivations: Vec<KeyDerivation>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
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
    pub namespace: String,
    #[prost(string, tag = "4")]
    pub ring_id: String,
    #[prost(string, tag = "5")]
    pub ring_pk: String,
    #[prost(bytes = "vec", tag = "6")]
    pub current_ring_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub finalized_ring_sha256: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub block_number_nonce: u64,
}

/// Build SourceHub-compatible sign bytes for a ring reshare finalization.
/// `current_ring_sha256` and `finalized_ring_sha256` must each be exactly 32 bytes —
/// SHA-256 of the cosmos-proto-encoded `Ring` structs for the current and finalized states.
pub fn ring_reshare_finalize_sign_bytes(
    chain_id: &str,
    namespace: &str,
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
        namespace: namespace.to_string(),
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
    namespace: &str,
    ring_pk: &str,
    peer_ids: &[String],
    threshold: u32,
    pss_interval: Option<u64>,
    policy_id: &str,
) -> String {
    let mut h = Sha256::new();

    write_string(&mut h, "orbis/ring/v1");
    write_string(&mut h, namespace);
    write_string(&mut h, ring_pk);
    write_string_slice(&mut h, peer_ids);
    h.update(threshold.to_be_bytes());
    write_optional_u64(&mut h, pss_interval);
    write_string(&mut h, policy_id);

    hex::encode(h.finalize())
}

fn write_string(h: &mut Sha256, s: &str) {
    h.update((s.len() as u32).to_be_bytes());
    h.update(s.as_bytes());
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
// SourceHubClient extension methods
// ============================================================================

use crate::blockchain::{BroadcastResult, SourceHubClient};

impl SourceHubClient {
    pub async fn orbis_create_ring(
        &self,
        namespace: &str,
        ring_pk: &str,
        peer_ids: Vec<String>,
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        artifact: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgCreateRing::new(
            &signer.address(),
            namespace,
            ring_pk,
            peer_ids,
            threshold,
            pss_interval,
            policy_id,
            artifact,
        );
        self.broadcast_proto_msg_with_gas(
            MsgCreateRing::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_store_document(
        &self,
        namespace: &str,
        ring_id: &str,
        document: &str,
        proof: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        tier: Option<String>,
        timestamp: Option<u64>,
        artifact: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgStoreDocument {
            creator: signer.address(),
            namespace: namespace.to_string(),
            ring_id: ring_id.to_string(),
            document: document.to_string(),
            proof: proof.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            tier: tier.clone().unwrap_or_default(),
            has_tier: tier.is_some(),
            timestamp: timestamp.unwrap_or(0),
            has_timestamp: timestamp.is_some(),
            artifact: artifact.unwrap_or_default(),
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
        namespace: &str,
        ring_id: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        artifact: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgStoreKeyDerivation {
            creator: signer.address(),
            namespace: namespace.to_string(),
            ring_id: ring_id.to_string(),
            derivation: derivation.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            artifact: artifact.unwrap_or_default(),
        };
        self.broadcast_proto_msg_with_gas(
            MsgStoreKeyDerivation::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_finalize_ring_reshare(
        &self,
        ring_id: &str,
        artifact: Option<String>,
        signature_scheme: &str,
        signature: Vec<u8>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let msg = MsgFinalizeRingReshareByThresholdSignature::new(
            &signer.address(),
            ring_id,
            artifact,
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

    pub async fn orbis_read_document(&self, namespace: &str, id: &str) -> Result<Option<Document>> {
        let request = QueryDocumentRequest {
            namespace: namespace.to_string(),
            id: id.to_string(),
        };
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

    pub async fn orbis_read_key_derivation(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<KeyDerivation>> {
        let request = QueryKeyDerivationRequest {
            namespace: namespace.to_string(),
            id: id.to_string(),
        };
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
}
