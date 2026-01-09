use crate::error::{BulletinError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
    ring_pk: String,
    secret: String,
    policy_id: String,
    resource: String,
    permission: String,
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
