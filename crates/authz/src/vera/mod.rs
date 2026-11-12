//! Vera-backed authorization implementation.

use crate::{
    error::{AuthZError, Result},
    r#trait::{Authz, VerifiedEvidence},
};
use async_trait::async_trait;
use common::blockchain::{
    acp::{AccessRequest, Actor, Object, Operation, Policy},
    ChainConfigBuilder, VeraClient,
};

#[cfg(feature = "startup")]
pub mod startup;
#[cfg(test)]
mod tests;

pub use crate::request::{AccessCheckRequest, ValidWindow};

pub struct VeraAuth {
    pub chain_client: VeraClient,
}

#[async_trait]
impl Authz for VeraAuth {
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool> {
        self.verify_at(permission, subject, None).await
    }

    /// The evidence bundle is a decimal block height, same as the old opaque anchor. Cosmos's
    /// historical ABCI query already works reliably at a specific height, so this stays a
    /// cheap pointer rather than adopting native's self-contained bundle.
    async fn capture_evidence(&self, _permission: Vec<u8>, _subject: &str) -> Result<Vec<u8>> {
        let height = self
            .chain_client
            .get_latest_height()
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?;
        Ok(height.to_string().into_bytes())
    }

    async fn verify_evidence(
        &self,
        evidence: &[u8],
        permission: Vec<u8>,
        subject: &str,
    ) -> Result<VerifiedEvidence> {
        let anchor = std::str::from_utf8(evidence).map_err(|e| {
            AuthZError::InvalidRequest(format!("evidence is not a valid anchor string: {e}"))
        })?;
        let height = parse_anchor_height(anchor)?;
        let captured_at = self
            .chain_client
            .get_block_time(height)
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?;
        let allowed = self.verify_at(permission, subject, Some(height)).await?;
        Ok(VerifiedEvidence {
            captured_at,
            allowed,
        })
    }
}

/// Parse a Vera opaque anchor (a decimal block height).
fn parse_anchor_height(anchor: &str) -> Result<u64> {
    let height = anchor.parse::<u64>().map_err(|e| {
        AuthZError::InvalidRequest(format!("invalid block-height anchor {anchor:?}: {e}"))
    })?;
    if height == 0 {
        return Err(AuthZError::InvalidRequest(
            "block-height anchor must be greater than zero".to_string(),
        ));
    }
    Ok(height)
}

impl VeraAuth {
    async fn verify_at(
        &self,
        permission: Vec<u8>,
        subject: &str,
        height: Option<u64>,
    ) -> Result<bool> {
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
                id: subject.to_owned(),
            }),
        };

        let is_authorized = self
            .chain_client
            .acp_verify_access(&request.policy_id, &access_request, height)
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?;

        Ok(is_authorized)
    }
}

impl VeraAuth {
    pub fn name() -> String {
        "authz/vera".to_string()
    }

    pub async fn new(chain_config_builder: ChainConfigBuilder) -> Result<Self> {
        Ok(VeraAuth {
            chain_client: VeraClient::new(chain_config_builder.build())
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
