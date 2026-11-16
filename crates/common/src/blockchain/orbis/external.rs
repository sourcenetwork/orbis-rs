//! Configuration for application-validated, inline Jubjub documents.
use serde::{Deserialize, Serialize};

/// The pinned policy must reserve effective document grants for the admitting
/// authority. Registering an object must not let a reader authorize itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRing {
    pub ring_id: String,
    pub document_policy_id: String,
    pub allow_unconditional_read: bool,
}

impl ExternalRing {
    pub fn permission(&self, target: Option<&str>) -> Option<&'static str> {
        match target {
            Some(target) if !target.is_empty() => Some("read"),
            None if self.allow_unconditional_read => Some("read_all"),
            _ => None,
        }
    }
}
