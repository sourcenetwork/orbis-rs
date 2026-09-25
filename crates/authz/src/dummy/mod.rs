use crate::{error::Result, r#trait::Authz};
use async_trait::async_trait;

pub struct DummyAuthZ;

#[async_trait]
impl Authz for DummyAuthZ {
    async fn check(&self, _permission: Vec<u8>, _subject: &str) -> Result<bool> {
        Ok(true)
    }

    async fn check_at(&self, _permission: Vec<u8>, _subject: &str, _anchor: &str) -> Result<bool> {
        Ok(true)
    }

    async fn current_anchor(&self) -> Result<String> {
        Ok("0".to_string())
    }

    async fn anchor_time(&self, _anchor: &str) -> Result<u64> {
        Ok(0)
    }

    /// Deterministic stand-in for tests: the object_id itself is the resolved
    /// owner identifier, so a test can construct a PET tag for a known owner
    /// without needing to seed a real ACP relationship.
    async fn resolve_relation_subject(
        &self,
        _policy_id: &str,
        _resource: &str,
        object_id: &str,
        _relation: &str,
    ) -> Result<String> {
        Ok(object_id.to_string())
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
