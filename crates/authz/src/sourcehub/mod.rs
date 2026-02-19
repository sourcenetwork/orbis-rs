use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
};
use async_trait::async_trait;
use common::blockchain::{acp::Policy, ChainConfigBuilder, SourceHubClient};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Request structure for access checks, serialized to Vec<u8> for the generic trait.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckRequest {
    /// Policy ID to check against
    pub policy_id: String,
    /// Resource type (e.g., "document")
    pub resource: String,
    /// Object ID within the resource
    pub object_id: String,
    /// Relationship needed to check this document
    pub relationship: String,
}

impl AccessCheckRequest {
    pub fn new(
        policy_id: impl Into<String>,
        resource: impl Into<String>,
        object_id: impl Into<String>,
        relationship: impl Into<String>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            resource: resource.into(),
            object_id: object_id.into(),
            relationship: relationship.into(),
        }
    }

    /// Encode the request to bytes for the generic Authz trait.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            AuthZError::InvalidRequest(format!("Failed to serialize AccessCheckRequest: {}", e))
        })
    }

    /// Decode from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| AuthZError::InvalidRequest(format!("Failed to parse request: {}", e)))
    }
}

pub struct SourceHubAuth {
    pub chain_client: SourceHubClient,
}

#[async_trait]
impl Authz for SourceHubAuth {
    async fn check(&self, permission: Vec<u8>, subject: &String) -> Result<bool> {
        // Decode the access check request from bytes
        let request = AccessCheckRequest::from_bytes(&permission)?;

        // Check if the actor has any of the relations that grant the permission
        let is_authorized = self
            .chain_client
            .acp_has_relationship(
                &request.policy_id,
                &subject,
                &request.resource,
                &request.object_id,
                &request.relationship,
            )
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?;

        Ok(is_authorized)
    }
}

impl SourceHubAuth {
    pub fn name() -> String {
        "authz/sourcehub".to_string()
    }

    pub async fn new(chain_config_builder: ChainConfigBuilder) -> Result<Self> {
        Ok(SourceHubAuth {
            chain_client: SourceHubClient::new(chain_config_builder.build())
                .await
                .map_err(|e| AuthZError::ChainError(e.to_string()))?,
        })
    }

    pub async fn get_policy(&self, policy_id: String) -> Result<Policy> {
        Ok(self
            .chain_client
            .acp_query_policy(&policy_id)
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?
            .record
            .ok_or_else(|| AuthZError::NotFound("Policy record not found".to_string()))?
            .policy
            .ok_or_else(|| AuthZError::NotFound("Policy not found".to_string()))?)
    }
}
