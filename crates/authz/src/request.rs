use crate::error::{AuthZError, Result};
use serde::{Deserialize, Serialize};

/// Unix timestamp range (inclusive) for access validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidWindow {
    pub start: u64,
    pub end: u64,
}

/// Request structure for access checks, serialized to Vec<u8> for the generic trait.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
