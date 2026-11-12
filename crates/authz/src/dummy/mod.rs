use crate::{
    error::Result,
    r#trait::{Authz, VerifiedEvidence},
};
use async_trait::async_trait;

pub struct DummyAuthZ;

#[async_trait]
impl Authz for DummyAuthZ {
    async fn check(&self, _permission: Vec<u8>, _subject: &str) -> Result<bool> {
        Ok(true)
    }

    async fn capture_evidence(&self, _permission: Vec<u8>, _subject: &str) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn verify_evidence(
        &self,
        _evidence: &[u8],
        _permission: Vec<u8>,
        _subject: &str,
    ) -> Result<VerifiedEvidence> {
        Ok(VerifiedEvidence {
            captured_at: 0,
            allowed: true,
        })
    }
}

impl DummyAuthZ {
    pub fn name() -> String {
        "authz/dummy".to_string()
    }

    pub async fn new() -> Result<Self> {
        Ok(DummyAuthZ)
    }
}

/// `DummyAuthZ`'s opposite: always denies. For a test that needs to prove a
/// caller actually rejects on an unauthorized ACP decision — `DummyAuthZ`
/// alone can only ever exercise the accept path, since it's permissive by
/// construction.
pub struct DenyingAuthZ;

#[async_trait]
impl Authz for DenyingAuthZ {
    async fn check(&self, _permission: Vec<u8>, _subject: &str) -> Result<bool> {
        Ok(false)
    }

    async fn capture_evidence(&self, _permission: Vec<u8>, _subject: &str) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn verify_evidence(
        &self,
        _evidence: &[u8],
        _permission: Vec<u8>,
        _subject: &str,
    ) -> Result<VerifiedEvidence> {
        Ok(VerifiedEvidence {
            captured_at: 0,
            allowed: false,
        })
    }
}
