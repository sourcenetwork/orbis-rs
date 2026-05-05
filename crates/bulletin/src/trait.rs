use crate::error::{BulletinError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Struct for posting to the Bulletin
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct BulletinPost {
    pub id: String,
    pub namespace: String,
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
    #[serde(
        default,
        alias = "next_peer_ids",
        skip_serializing_if = "Option::is_none"
    )]
    pub new_peer_ids: Option<Vec<String>>,
    /// Threshold for the new committee announced by `new_peer_ids`.
    /// Validated against `SessionKind::Reshare::new_threshold` when present.
    /// `None` means the bulletin does not constrain the new threshold — **nodes may still
    /// require this field** (e.g. orbis-node enforces a pre-announced threshold for reshare).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_threshold: Option<u32>,
    /// Network ids of peers in ring
    pub peer_ids: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::RingPayload;

    #[test]
    fn ring_payload_serializes_new_peer_ids_and_accepts_legacy_next_peer_ids() {
        let payload = RingPayload {
            ring_pk: "ring".to_string(),
            new_peer_ids: Some(vec!["peer-b".to_string(), "peer-c".to_string()]),
            new_threshold: Some(2),
            peer_ids: vec!["peer-a".to_string()],
            threshold: 1,
            pss_interval: None,
            block_number_nonce: 9,
        };

        let value = serde_json::to_value(&payload).expect("serialize RingPayload");
        assert_eq!(
            value
                .get("new_peer_ids")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(2)
        );
        assert!(value.get("next_peer_ids").is_none());

        let legacy = serde_json::json!({
            "ring_pk": "ring",
            "next_peer_ids": ["peer-b", "peer-c"],
            "new_threshold": 2,
            "peer_ids": ["peer-a"],
            "threshold": 1,
            "block_number_nonce": 9
        });
        let parsed: RingPayload =
            serde_json::from_value(legacy).expect("deserialize legacy RingPayload");

        assert_eq!(
            parsed.new_peer_ids,
            Some(vec!["peer-b".to_string(), "peer-c".to_string()])
        );
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

#[async_trait]
pub trait Bulletin {
    /// Register a bulletin instance
    async fn register(&self, namespace: String) -> Result<()>;
    /// Post a message to the bulletin namespace
    async fn post(
        &self,
        namespace: String,
        payload: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<()>;
    /// Finalize an existing message update in the bulletin namespace while preserving its ID.
    async fn update(&self, namespace: String, id: String, artifact: Option<String>) -> Result<()>;
    /// Read a message from the bulletin namespace
    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost>;
    /// Chain ID used when building chain-bound signing statements.
    fn chain_id(&self) -> String;
    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String>;
}
