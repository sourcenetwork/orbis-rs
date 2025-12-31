use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
};
use async_trait::async_trait;
use common::blockchain::{acp::Policy, ChainConfig, SourceHubClient};
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
    /// Permission to check (e.g., "read", "write")
    pub permission: String,
}

impl AccessCheckRequest {
    pub fn new(
        policy_id: impl Into<String>,
        resource: impl Into<String>,
        object_id: impl Into<String>,
        permission: impl Into<String>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            resource: resource.into(),
            object_id: object_id.into(),
            permission: permission.into(),
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
    chain_client: SourceHubClient,
}

#[async_trait]
impl Authz for SourceHubAuth {
    async fn check(&self, permission: Vec<u8>, subject: String) -> Result<bool> {
        // Decode the access check request from bytes
        let request = AccessCheckRequest::from_bytes(&permission)?;

        // Query the policy to get the permission expression
        let policy = self.get_policy(request.policy_id.clone()).await?;

        // Get the relations that grant this permission from the policy definition
        let relations_to_check = policy
            .get_relations_for_permission(&request.resource, &request.permission)
            .ok_or_else(|| {
                AuthZError::NotFound(format!(
                    "Permission '{}' not found for resource '{}' in policy",
                    request.permission, request.resource
                ))
            })?;

        // Check if the actor has any of the relations that grant the permission
        for relation in relations_to_check {
            let has_relation = self
                .chain_client
                .acp_has_relationship(
                    &request.policy_id,
                    &subject,
                    &request.resource,
                    &request.object_id,
                    &relation,
                )
                .await
                .map_err(|e| AuthZError::ChainError(e.to_string()))?;

            if has_relation {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl SourceHubAuth {
    pub async fn new() -> Self {
        // TODO just for testing for now
        SourceHubAuth {
            chain_client: SourceHubClient::new(ChainConfig::local()).await.unwrap(),
        }
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
