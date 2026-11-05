//! The relayer's own bookkeeping record of where each participant's signed
//! [`crate::SignedStoredShareEnvelope`] landed, handed to the caller once
//! ack-threshold is reached on a Defra-backed PRE delivery.
//!
//! Deliberately unsigned and not itself trusted: a reader fetches each
//! entry's envelope from Defra and independently verifies it (signature
//! plus the underlying PRE proof) against the *pinned* fields carried here,
//! never against current live ring state. If the manifest lies about an
//! entry, that entry's envelope simply fails verification on retrieval —
//! the manifest is a shopping list, not evidence.

use crypto::context::CiphertextContext;
use crypto::r#trait::Secret;
use serde::{Deserialize, Serialize};

pub const PRE_SHARE_MANIFEST_VERSION: u8 = 1;

/// Opaque Defra document locator for one stored envelope. Step 3 (the Defra
/// storage client) decides the real addressing scheme — this stays a thin
/// newtype so that decision doesn't require touching every type that
/// carries a locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefraLocator(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreShareManifestEntry {
    pub from_node_id: u32,
    pub responder_node_key: String,
    pub defra_locator: DefraLocator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreShareRetrievalManifest {
    pub manifest_version: u8,
    pub request_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub threshold: usize,
    /// The generation snapshot every entry in this manifest was pinned to
    /// — must match each fetched envelope's own
    /// `StoredShareEnvelope::pinned_public_polynomial`.
    pub pinned_public_polynomial: String,
    pub rdr_pk_bytes: Vec<u8>,
    pub object_id: String,
    pub secret: Secret,
    pub context: CiphertextContext,
    pub entries: Vec<PreShareManifestEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips_through_serde() {
        let manifest = PreShareRetrievalManifest {
            manifest_version: PRE_SHARE_MANIFEST_VERSION,
            request_id: "req-1".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "ring-pk".to_string(),
            threshold: 2,
            pinned_public_polynomial: "poly-gen-1".to_string(),
            rdr_pk_bytes: vec![1, 2, 3],
            object_id: "object-1".to_string(),
            secret: Secret {
                enc_cmt: vec![4, 5, 6],
                encrypted_data: vec![7, 8, 9],
                nonce: vec![10, 11, 12],
            },
            context: CiphertextContext {
                ring_pk: vec![1, 2, 3],
                policy_id: "policy-1".to_string(),
                resource: "resource".to_string(),
                permission: "read".to_string(),
                tier: None,
                timestamp: Some(1_700_000_000),
                salt: None,
                pet_tag: None,
            },
            entries: vec![PreShareManifestEntry {
                from_node_id: 1,
                responder_node_key: "node-key".to_string(),
                defra_locator: DefraLocator("doc-1".to_string()),
            }],
        };

        let bytes = serde_json::to_vec(&manifest).expect("serialize");
        let decoded: PreShareRetrievalManifest =
            serde_json::from_slice(&bytes).expect("deserialize");

        assert_eq!(decoded.request_id, manifest.request_id);
        assert_eq!(
            decoded.pinned_public_polynomial,
            manifest.pinned_public_polynomial
        );
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(
            decoded.entries[0].defra_locator,
            manifest.entries[0].defra_locator
        );
    }
}
