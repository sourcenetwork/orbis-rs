use crate::error::{BulletinError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulletinKind {
    Ring,
    Document,
    KeyDerivation,
    NodeInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulletinWriteKind {
    Finalize,
    Document,
    KeyDerivation,
    NodeInfo,
}

/// Struct for posting to the Bulletin
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct BulletinPost {
    pub id: String,
    pub payload: Vec<u8>,
}

/// Payload for storing a secret on bulletin document_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct DocumentPayload {
    /// Id of the Ring to find other information about the ring
    pub ring_id: String,
    /// Encrypted document
    pub document: String,
    /// Chaum-Pedersen NIZK proof of correct encryption (binds policy info to encryption)
    pub proof: String,
    /// Id of the policy associated with document
    pub policy_id: String,
    /// Resource type on said policy
    pub resource: String,
    /// Does the DID have this permission on the policy (the policy expected with this document)
    pub permission: String,
    /// Optional tier for acp check
    pub tier: Option<String>,
    /// Optional timestamp for acp check
    pub timestamp: Option<u64>,
}
/// Payload for ring information ring_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct RingPayload {
    /// Public key of ring
    pub ring_pk: String,
    /// New peer ids to reshare into.
    /// When set, a reshare `SessionInit` is only accepted if its proposed peers match
    /// this field (order-independent).  `None` means the bulletin does not constrain the next
    /// committee — **nodes may still require this field** (e.g. orbis-node enforces a
    /// pre-announced committee for reshare).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_peer_node_keys: Option<Vec<String>>,
    /// Threshold for the new committee announced by `new_peer_node_keys`.
    /// Validated against `SessionKind::Reshare::new_threshold` when present.
    /// `None` means the bulletin does not constrain the new threshold — **nodes may still
    /// require this field** (e.g. orbis-node enforces a pre-announced threshold for reshare).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_threshold: Option<u32>,
    /// Network ids of peers in ring
    pub peer_node_keys: Vec<String>,
    /// Threshold of ring
    pub threshold: u32,
    /// Seconds between automatic PSS refresh ceremonies.
    /// `None` (or absent in JSON) means automatic refresh is disabled for this ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pss_interval: Option<u64>,
    /// Block number of the last threshold-signature update.
    /// Each threshold signature uses this as a nonce. The chain updates it to
    /// the current block number after accepting the signature.
    #[serde(default)]
    pub block_number_nonce: u64,
    /// If set, the ring is updated externally governed by this policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

/// Payload for confirming a completed fresh DKG ring.
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct RingFinalizationPayload {
    /// Id of the pending ring to finalize.
    pub ring_id: String,
    /// Aggregate public key computed by DKG participants.
    pub ring_pk: String,
}

/// Payload for derivation information derivation_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct KeyDerivation {
    /// Id of the Ring to find other information about the ring
    pub ring_id: String,
    /// Derivation to be added with policy infomratio to create derivation
    pub derivation: String,
    /// Id of the policy associated with document
    pub policy_id: String,
    /// Resource type on said policy
    pub resource: String,
    /// Does the DID have this permission on the policy (the policy expected with this document)
    pub permission: String,
}

#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct NodeInfo {
    /// Network id of peers in ring
    pub peer_id: String,
    /// Key stored externally from node to control ring participants
    pub controller_key: String,
    /// whitelisted policy IDs that will complete DKG with
    pub whitelisted_policy_ids: Vec<String>,
    /// whitelisted ring_ids to complete DKG with
    pub whitelisted_ring_ids: Vec<String>,
}

impl TryFrom<BulletinPost> for DocumentPayload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<Vec<u8>> for BulletinPost {
    type Error = BulletinError;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        serde_json::from_slice(&bytes).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::to_vec(&post).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<DocumentPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: DocumentPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for RingPayload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<RingPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: RingPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for RingFinalizationPayload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<RingFinalizationPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: RingFinalizationPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for KeyDerivation {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<KeyDerivation> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: KeyDerivation) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for NodeInfo {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<NodeInfo> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: NodeInfo) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

#[async_trait]
pub trait Bulletin {
    /// Post a typed Orbis object.
    async fn post(&self, kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String>;
    /// Finalize an existing typed Orbis object update while preserving its ID.
    async fn update(&self, id: String, signature_scheme: String, signature: Vec<u8>) -> Result<()>;
    /// Read a typed Orbis object.
    async fn read(&self, id: String, kind: BulletinKind) -> Result<BulletinPost>;
    /// Chain ID used when building chain-bound signing statements.
    fn chain_id(&self) -> String;
    /// Serialize the canonical sign bytes for a ring reshare finalization sign doc.
    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        block_number_nonce: u64,
    ) -> Result<Vec<u8>>;
}
