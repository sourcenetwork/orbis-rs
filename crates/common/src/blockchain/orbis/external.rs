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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::orbis::generate_external_document_id;

    #[test]
    fn opaque_identity_matches_independent_framing() {
        let secret = serde_json::json!({"enc_cmt": vec![1u8; 32], "encrypted_data": vec![2u8; 32], "nonce": vec![0u8; 12]}).to_string();
        let tag = serde_json::json!({"ephemeral_point": vec![3u8; 32], "masked_fingerprint": vec![4u8; 32]}).to_string();
        // Python hashlib reference: SHA256(concat(u32be(len(field)), field)).
        let expected = "238aff3968885739bfb3e758f347329916f60f914cca354745a0f8e92b6f6fc4";
        assert_eq!(
            generate_external_document_id("ring", "policy", &secret, &tag).unwrap(),
            expected
        );
        for (ring, policy) in [("other", "policy"), ("ring", "other")] {
            assert_ne!(
                generate_external_document_id(ring, policy, &secret, &tag).unwrap(),
                expected
            );
        }
        let mut changed: serde_json::Value = serde_json::from_str(&secret).unwrap();
        changed["encrypted_data"][0] = 9.into();
        assert_ne!(
            generate_external_document_id("ring", "policy", &changed.to_string(), &tag).unwrap(),
            expected
        );
        changed["nonce"][0] = 1.into();
        assert!(
            generate_external_document_id("ring", "policy", &changed.to_string(), &tag).is_err()
        );
        assert!(generate_external_document_id("ring", "policy", "{}", &tag).is_err());
    }

    #[test]
    fn target_and_unconditional_permissions_are_distinct() {
        let mut ring = ExternalRing {
            ring_id: "ring".into(),
            document_policy_id: "policy".into(),
            allow_unconditional_read: false,
        };
        assert_eq!(ring.permission(None), None);
        assert_eq!(ring.permission(Some("target")), Some("read"));
        assert_eq!(ring.permission(Some("")), None);
        ring.allow_unconditional_read = true;
        assert_eq!(ring.permission(None), Some("read_all"));
        assert_eq!(ring.permission(Some("target")), Some("read"));
        assert_eq!(ring.permission(Some("")), None);
    }
}
