use crate::error::{BulletinError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Struct for posting to the Bulletin
#[derive(Clone, Default)]
pub struct BulletinPost {
    pub id: String,
    pub namespace: String,
    pub payload: Vec<u8>,
    pub proof: Vec<u8>,
}

/// Payload for storing a secret on bulletin
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct Payload {
    pub ring_pk: String,
    pub secret: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String, // does the DID have the permission on the policy
    pub peer_ids: Vec<String>, // TODO: store in a seperate blob for the ring itself
}

impl TryFrom<BulletinPost> for Payload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<Payload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: Payload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

#[async_trait]
pub trait Bulletin {
    /// Register a bulletin instance
    async fn register(&self, namespace: String) -> Result<()>;
    /// Post a message to the bulletin namespace
    async fn post(&self, namespace: String, id: String, message: Vec<u8>) -> Result<()>;
    /// Read a message from the bulletin namespace
    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost>;
}
