//! Vera-backed authorization implementation.

use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
};
use async_trait::async_trait;
use common::blockchain::{
    acp::{
        AccessRequest, Actor, Object, ObjectSelector, ObjectSelectorKind, Operation, Policy,
        RelationSelector, RelationSelectorKind, RelationshipSelector, SubjectKind, SubjectSelector,
        SubjectSelectorKind, WildcardSelector,
    },
    ChainConfigBuilder, VeraClient,
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

pub struct VeraAuth {
    pub chain_client: VeraClient,
}

#[async_trait]
impl Authz for VeraAuth {
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool> {
        self.verify_at(permission, subject, None).await
    }

    /// For Vera the opaque anchor is a decimal block height.
    async fn check_at(&self, permission: Vec<u8>, subject: &str, anchor: &str) -> Result<bool> {
        let height = parse_anchor_height(anchor)?;
        self.verify_at(permission, subject, Some(height)).await
    }

    async fn current_anchor(&self) -> Result<String> {
        let height = self
            .chain_client
            .get_latest_height()
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?;
        Ok(height.to_string())
    }

    async fn anchor_time(&self, anchor: &str) -> Result<u64> {
        let height = parse_anchor_height(anchor)?;
        self.chain_client
            .get_block_time(height)
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))
    }

    async fn resolve_relation_subject(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<String> {
        let selector = RelationshipSelector {
            object_selector: Some(ObjectSelector {
                selector: Some(ObjectSelectorKind::Object(Object {
                    resource: resource.to_string(),
                    id: object_id.to_string(),
                })),
            }),
            relation_selector: Some(RelationSelector {
                selector: Some(RelationSelectorKind::Relation(relation.to_string())),
            }),
            subject_selector: Some(SubjectSelector {
                selector: Some(SubjectSelectorKind::Wildcard(WildcardSelector {})),
            }),
        };

        let response = self
            .chain_client
            .acp_filter_relationships(policy_id, &selector)
            .await
            .map_err(|e| AuthZError::ChainError(e.to_string()))?;

        let mut actor_ids = response
            .records
            .into_iter()
            .filter(|record| !record.archived)
            .filter_map(|record| record.relationship)
            .filter_map(|relationship| match relationship.subject?.kind? {
                SubjectKind::Actor(actor) => Some(actor.id),
                SubjectKind::Object(_) => None,
            });

        let Some(actor_id) = actor_ids.next() else {
            return Err(AuthZError::NotFound(format!(
                "no actor holds relation {relation:?} on {resource}/{object_id}"
            )));
        };
        if actor_ids.next().is_some() {
            return Err(AuthZError::InvalidRequest(format!(
                "ambiguous relation {relation:?} on {resource}/{object_id}: more than one actor holds it"
            )));
        }
        Ok(actor_id)
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
