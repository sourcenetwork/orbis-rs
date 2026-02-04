use crate::error::{BulletinError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Struct for posting to the Bulletin
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct BulletinPost {
    pub id: String,
    pub namespace: String,
    pub payload: Vec<u8>,
    pub proof: Vec<u8>,
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
    /// does the DID have this permission on the policy (the policy expected with this document)
    pub permission: String,
}
/// Payload for ring information ring_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct RingPayload {
    /// Public key of ring
    pub ring_pk: String,
    /// Network ids of peers in ring
    pub peer_ids: Vec<String>,
    /// Threshold of ring
    pub threshold: u32,
    /// Public polynomial of ring
    pub public_polynomial: String,
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

#[async_trait]
pub trait Bulletin {
    /// Register a bulletin instance
    async fn register(&self, namespace: String) -> Result<()>;
    /// Post a message to the bulletin namespace
    async fn post(
        &self,
        namespace: String,
        payload: Vec<u8>,
        proof: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<()>;
    /// Read a message from the bulletin namespace
    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost>;
    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String>;
}
