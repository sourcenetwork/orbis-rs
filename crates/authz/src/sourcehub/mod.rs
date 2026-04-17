use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
};
use async_trait::async_trait;
use common::blockchain::{
    acp::{AccessRequest, Actor, Object, Operation, Policy},
    ChainConfigBuilder, SourceHubClient,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Unix timestamp range (inclusive) for access validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidWindow {
    pub start: u64,
    pub end: u64,
}

/// Request structure for access checks, serialized to Vec<u8> for the generic trait.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckRequest {
    /// Policy ID to check against
    pub policy_id: String,
    /// Resource type (e.g., "document")
    pub resource: String,
    /// Object ID within the resource
    pub object_id: String,
    /// Permission needed to check this document
    pub permission: String,
    /// Optional tier for acp check
    pub tier: Option<String>,
    /// Optional timestamp for acp check
    pub timestamp: Option<u64>,
    /// Optional timestamp range for validity window
    pub valid_window: Option<ValidWindow>,
}

impl AccessCheckRequest {
    pub fn new(
        policy_id: String,
        resource: String,
        object_id: String,
        permission: String,
        tier: Option<String>,
        timestamp: Option<u64>,
        valid_window: Option<ValidWindow>,
    ) -> Self {
        Self {
            policy_id,
            resource,
            object_id,
            permission,
            timestamp,
            tier,
            valid_window,
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

        // Validate that valid_window and timestamp are either both present or both absent
        match (&request.valid_window, &request.timestamp) {
            (Some(window), Some(ts)) => {
                if ts < &window.start || ts > &window.end {
                    return Ok(false);
                }
            }
            (Some(_), None) => {
                return Err(AuthZError::InvalidRequest(
                    "valid_window provided but timestamp is missing".to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(AuthZError::InvalidRequest(
                    "timestamp provided but valid_window is missing".to_string(),
                ));
            }
            (None, None) => {}
        }

        // Verify the permission using the policy expression (e.g. "read = creator + reader").
        // This mirrors the Go implementation which uses QueryVerifyAccessRequest with a permission name.
        let access_request = AccessRequest {
            operations: vec![Operation {
                object: Some(Object {
                    resource: request.resource.clone(),
                    id: request.object_id.clone(),
                }),
                permission: request.permission.clone(),
            }],
            actor: Some(Actor {
                id: subject.clone(),
            }),
        };

        let is_authorized = self
            .chain_client
            .acp_verify_access(&request.policy_id, &access_request)
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
        self.chain_client
            .acp_query_policy(&policy_id)
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?
            .record
            .ok_or_else(|| AuthZError::NotFound("Policy record not found".to_string()))?
            .policy
            .ok_or_else(|| AuthZError::NotFound("Policy not found".to_string()))
    }
}
