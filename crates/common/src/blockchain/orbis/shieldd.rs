//! Inline documents admitted by the Shieldd authority from accepted history.
//!
//! These types do not attest chain acceptance. The authority authenticates the
//! source before granting access to the exact object under the configured policy.
//! Native documents and their Vera identifiers are unchanged.

use k256::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

pub const SHIELDD_PROFILE: &str = "shieldd-jubjub-pari-v9-poseidon-scalar-v1";

/// Canonical accepted location, attached after transaction acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptedSource {
    Transaction {
        chain: String,
        tx_id: [u8; 32],
        action: u32,
        slot: u32,
    },
    HostOperation {
        chain: String,
        height: u64,
        operation: Vec<u8>,
        output: u32,
    },
}

/// Fixed purpose; callers cannot substitute an arbitrary ACP resource/permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShielddPurpose {
    SenderCore,
    SenderExt,
    OutputCore,
    OutputExt,
    NoteRecovery,
    Withdrawal,
}

impl ShielddPurpose {
    pub const fn tier(self) -> &'static str {
        match self {
            Self::SenderCore => "sender_core",
            Self::SenderExt => "sender_ext",
            Self::OutputCore => "output_core",
            Self::OutputExt => "output_ext",
            Self::NoteRecovery => "recovery",
            Self::Withdrawal => "withdrawal",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::SenderCore => 0,
            Self::SenderExt => 1,
            Self::OutputCore => 2,
            Self::OutputExt => 3,
            Self::NoteRecovery => 4,
            Self::Withdrawal => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShielddTag {
    pub ephemeral_point: [u8; 32],
    pub masked_fingerprint: [u8; 32],
}

/// Proof-free document. Curve validation is performed by the crypto consumer;
/// fixed-width fields here provide one unambiguous authorization identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShielddDocument {
    pub profile: String,
    pub ring_id: String,
    pub ring_key: [u8; 32],
    pub checking_key: [u8; 32],
    pub policy_id: String,
    pub purpose: ShielddPurpose,
    pub source: AcceptedSource,
    pub epk: [u8; 32],
    pub payload_commitment: [u8; 32],
    pub tag: ShielddTag,
    /// Authenticated creation metadata, never an authorization expiry clock.
    pub timestamp: u64,
}

impl ShielddDocument {
    /// Blind-PET transcript binding in place of the native opening-proof digest.
    pub fn pet_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"orbis/shieldd-pet/v1")
            .chain_update(self.id().as_bytes())
            .finalize()
            .into()
    }
    /// Domain-separated, explicitly framed ID; independent of JSON formatting.
    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        fn bytes(h: &mut Sha256, value: &[u8]) {
            h.update((value.len() as u64).to_be_bytes());
            h.update(value);
        }
        bytes(&mut h, b"orbis/shieldd-document/v1");
        bytes(&mut h, self.profile.as_bytes());
        bytes(&mut h, self.ring_id.as_bytes());
        h.update(self.ring_key);
        h.update(self.checking_key);
        bytes(&mut h, self.policy_id.as_bytes());
        h.update([self.purpose.code()]);
        match &self.source {
            AcceptedSource::Transaction {
                chain,
                tx_id,
                action,
                slot,
            } => {
                h.update([0]);
                bytes(&mut h, chain.as_bytes());
                h.update(tx_id);
                h.update(action.to_be_bytes());
                h.update(slot.to_be_bytes());
            }
            AcceptedSource::HostOperation {
                chain,
                height,
                operation,
                output,
            } => {
                h.update([1]);
                bytes(&mut h, chain.as_bytes());
                h.update(height.to_be_bytes());
                bytes(&mut h, operation);
                h.update(output.to_be_bytes());
            }
        }
        h.update(self.epk);
        h.update(self.payload_commitment);
        h.update(self.tag.ephemeral_point);
        h.update(self.tag.masked_fingerprint);
        h.update(self.timestamp.to_be_bytes());
        hex::encode(h.finalize())
    }
}

/// Included in the authenticated reader request, not the document identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReleaseScope {
    AssetWide,
    NamedPerson { target: String },
    NoteRecovery { target: String },
}

impl ReleaseScope {
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::AssetWide => None,
            Self::NamedPerson { target } | Self::NoteRecovery { target } => Some(target),
        }
    }

    /// Reject scope/purpose mismatches before consulting ACP. A successful
    /// result still requires live exact-document and (when present) target grants.
    pub fn permission(&self, purpose: ShielddPurpose) -> Option<&'static str> {
        match (self, purpose) {
            (Self::AssetWide, ShielddPurpose::NoteRecovery) => None,
            (Self::AssetWide, _) => Some("read_all"),
            (Self::NamedPerson { .. }, ShielddPurpose::NoteRecovery) => None,
            (Self::NamedPerson { target }, _) if !target.is_empty() => Some("read"),
            (Self::NoteRecovery { target }, ShielddPurpose::NoteRecovery) if !target.is_empty() => {
                Some("read")
            }
            _ => None,
        }
    }
}

/// Trusted deployment configuration; never populated from an incoming document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShielddRing {
    pub profile: String,
    pub ring_id: String,
    pub ring_key: [u8; 32],
    pub checking_key: [u8; 32],
    pub policy_id: String,
    pub recovery: bool,
}

impl ShielddRing {
    pub fn accepts(&self, document: &ShielddDocument) -> bool {
        !self.profile.is_empty()
            && !self.ring_id.is_empty()
            && !self.policy_id.is_empty()
            && self.profile == document.profile
            && self.ring_id == document.ring_id
            && self.ring_key == document.ring_key
            && self.checking_key == document.checking_key
            && self.policy_id == document.policy_id
            && self.recovery == (document.purpose == ShielddPurpose::NoteRecovery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> ShielddDocument {
        ShielddDocument {
            profile: "test-profile".into(),
            ring_id: "ring".into(),
            ring_key: [1; 32],
            checking_key: [2; 32],
            policy_id: "policy".into(),
            purpose: ShielddPurpose::SenderCore,
            source: AcceptedSource::Transaction {
                chain: "chain".into(),
                tx_id: [3; 32],
                action: 4,
                slot: 5,
            },
            epk: [6; 32],
            payload_commitment: [7; 32],
            tag: ShielddTag {
                ephemeral_point: [8; 32],
                masked_fingerprint: [9; 32],
            },
            timestamp: 10,
        }
    }

    #[test]
    fn identity_binds_every_document_field() {
        let original = document();
        // Independent Python hashlib/struct reference with explicit field framing.
        assert_eq!(
            original.id(),
            "89a1b028104177b5ac3ac804be5ad7ea3dfccb92f70118cdead931d180a6ca15"
        );
        let mutations: &[fn(&mut ShielddDocument)] = &[
            |d| d.profile.push('x'),
            |d| d.ring_id.push('x'),
            |d| d.ring_key[0] ^= 1,
            |d| d.checking_key[0] ^= 1,
            |d| d.policy_id.push('x'),
            |d| d.purpose = ShielddPurpose::OutputCore,
            |d| {
                if let AcceptedSource::Transaction { chain, .. } = &mut d.source {
                    chain.push('x');
                }
            },
            |d| {
                if let AcceptedSource::Transaction { tx_id, .. } = &mut d.source {
                    tx_id[0] ^= 1;
                }
            },
            |d| {
                if let AcceptedSource::Transaction { action, .. } = &mut d.source {
                    *action += 1;
                }
            },
            |d| {
                if let AcceptedSource::Transaction { slot, .. } = &mut d.source {
                    *slot += 1;
                }
            },
            |d| d.epk[0] ^= 1,
            |d| d.payload_commitment[0] ^= 1,
            |d| d.tag.ephemeral_point[0] ^= 1,
            |d| d.tag.masked_fingerprint[0] ^= 1,
            |d| d.timestamp += 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(original.id(), changed.id());
        }
    }

    #[test]
    fn scope_cannot_downgrade_recovery_or_omit_person() {
        assert_eq!(
            ReleaseScope::AssetWide.permission(ShielddPurpose::SenderCore),
            Some("read_all")
        );
        assert_eq!(
            ReleaseScope::AssetWide.permission(ShielddPurpose::NoteRecovery),
            None
        );
        assert_eq!(
            ReleaseScope::NamedPerson {
                target: String::new()
            }
            .permission(ShielddPurpose::SenderCore),
            None
        );
        assert_eq!(
            ReleaseScope::NamedPerson {
                target: "alice".into()
            }
            .permission(ShielddPurpose::SenderCore),
            Some("read")
        );
        assert_eq!(
            ReleaseScope::NoteRecovery {
                target: "alice".into()
            }
            .permission(ShielddPurpose::OutputCore),
            None
        );
    }

    #[test]
    fn configuration_pins_policy_keys_and_purpose() {
        let d = document();
        let ring = ShielddRing {
            profile: d.profile.clone(),
            ring_id: d.ring_id.clone(),
            ring_key: d.ring_key,
            checking_key: d.checking_key,
            policy_id: d.policy_id.clone(),
            recovery: false,
        };
        assert!(ring.accepts(&d));
        let mutations: &[fn(&mut ShielddDocument)] = &[
            |d| d.profile.push('x'),
            |d| d.ring_id.push('x'),
            |d| d.ring_key[0] ^= 1,
            |d| d.checking_key[0] ^= 1,
            |d| d.policy_id.push('x'),
            |d| d.purpose = ShielddPurpose::NoteRecovery,
        ];
        for mutate in mutations {
            let mut changed = d.clone();
            mutate(&mut changed);
            assert!(!ring.accepts(&changed));
        }
    }
}
