//! The signed envelope stored as Defra document content for a Defra-backed
//! PRE delivery (ring `pre_share_endpoints`).
//!
//! Wraps [`PreReencryptResponseStatement`] unchanged — that statement is
//! already used as invalid-crypto reporting evidence, so its fields and
//! `canonical_bytes()` encoding must not shift. The envelope only adds what
//! the statement doesn't already carry: a version tag and the generation
//! snapshot ([`StoredShareEnvelope::pinned_public_polynomial`]) the
//! responder pinned this share to, so a reader verifying long after the
//! fact can confirm which generation produced it without trusting current
//! live ring state. "Reader public key" and "protocol/crypto suite tag"
//! from the original design doc need no new field — the statement already
//! carries `rdr_pk`, `protocol_version`, and `crypto_backend`.
//!
//! Deliberately excludes the Defra document locator: Defra assigns the
//! docID on write, so a signed envelope can't reference its own storage
//! address without a chicken-and-egg problem. The locator lives on the
//! stored-delivery acknowledgement (`PreMessage::ReencryptStored`, a P2P
//! wire message in `orbis-node`'s `pre::v0::messages`) and on
//! [`crate::PreShareManifestEntry`] instead.

use orbis_reporting::codec::{write_bytes, write_string};
use orbis_reporting::PreReencryptResponseStatement;
use serde::{Deserialize, Serialize};

use crate::error::{PreShareError, Result};

pub const STORED_SHARE_ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredShareEnvelope {
    pub envelope_version: u8,
    pub statement: PreReencryptResponseStatement,
    /// Hex-encoded public polynomial of the PSS generation this share was
    /// produced under — the same snapshot pinned into the request
    /// (`PreRequestContext::pinned_public_polynomial`), carried here so
    /// retrieval doesn't need the original request's pin out of band.
    pub pinned_public_polynomial: String,
}

impl StoredShareEnvelope {
    pub fn new(statement: PreReencryptResponseStatement, pinned_public_polynomial: String) -> Self {
        Self {
            envelope_version: STORED_SHARE_ENVELOPE_VERSION,
            statement,
            pinned_public_polynomial,
        }
    }

    /// Field order is the canonical wire contract for the envelope
    /// signature — nests the inner statement's own canonical bytes
    /// length-prefixed, mirroring how `ReportEnvelope.payload` already
    /// nests an opaque inner statement (`orbis_reporting::ReportEnvelope`).
    /// Only valid for [`STORED_SHARE_ENVELOPE_VERSION`]; a future version
    /// bump gets its own layout rather than trying to stay backward
    /// compatible with this one (nothing built on this is live yet).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.envelope_version);
        write_bytes(&mut out, &self.statement.canonical_bytes());
        write_string(&mut out, &self.pinned_public_polynomial);
        out
    }

    /// Signs the envelope with the responder's node signing key (same
    /// hex-encoded secp256k1 key `handlers.rs` already uses for
    /// `response_signature` on the direct-delivery path). Signs the whole
    /// envelope, not just the inner statement, so `pinned_public_polynomial`
    /// is covered too — a bare statement signature would let a tamperer
    /// swap in a different generation after the fact without invalidating
    /// it.
    pub fn sign(self, signing_key_hex: &str) -> Result<SignedStoredShareEnvelope> {
        let envelope_signature = common::blockchain::sign_node_message_with_hex_key(
            signing_key_hex,
            &self.canonical_bytes(),
        )
        .map_err(|error| PreShareError::Signing(error.to_string()))?;
        Ok(SignedStoredShareEnvelope {
            envelope: self,
            envelope_signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStoredShareEnvelope {
    pub envelope: StoredShareEnvelope,
    pub envelope_signature: Vec<u8>,
}

impl SignedStoredShareEnvelope {
    /// Rejects an envelope version this reader doesn't understand before
    /// attempting to verify anything else, then verifies
    /// `envelope_signature` against `responder_node_key_hex` (the
    /// compressed secp256k1 public key hex of the node that's claimed to
    /// have produced it — callers resolve this from the stored-delivery
    /// acknowledgement or the ring's `peer_node_keys`, never from the
    /// envelope itself).
    pub fn verify(&self, responder_node_key_hex: &str) -> Result<()> {
        if self.envelope.envelope_version != STORED_SHARE_ENVELOPE_VERSION {
            return Err(PreShareError::UnsupportedVersion(
                self.envelope.envelope_version,
            ));
        }
        common::blockchain::verify_node_message(
            responder_node_key_hex,
            &self.envelope.canonical_bytes(),
            &self.envelope_signature,
        )
        .map_err(|error| PreShareError::SignatureInvalid(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{sample_statement, signed_envelope, PUBLIC_KEY_HEX, SIGNING_KEY_HEX};
    use common::blockchain::sign_node_message_with_hex_key;

    #[test]
    fn envelope_round_trips_through_serde() {
        let signed = signed_envelope();
        let bytes = serde_json::to_vec(&signed).expect("serialize");
        let decoded: SignedStoredShareEnvelope =
            serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, signed);
        decoded
            .verify(PUBLIC_KEY_HEX)
            .expect("verify round-tripped envelope");
    }

    #[test]
    fn verify_rejects_tampered_pinned_polynomial() {
        let mut signed = signed_envelope();
        signed.envelope.pinned_public_polynomial = "poly-gen-2".to_string();
        assert!(signed.verify(PUBLIC_KEY_HEX).is_err());
    }

    #[test]
    fn verify_rejects_tampered_statement_field() {
        let mut signed = signed_envelope();
        signed.envelope.statement.request_id = "req-evil".to_string();
        assert!(signed.verify(PUBLIC_KEY_HEX).is_err());
    }

    #[test]
    fn verify_rejects_signature_from_wrong_key() {
        let envelope = StoredShareEnvelope::new(sample_statement(), "poly-gen-1".to_string());
        let other_signature =
            sign_node_message_with_hex_key(SIGNING_KEY_HEX, b"not the envelope bytes").unwrap();
        let signed = SignedStoredShareEnvelope {
            envelope,
            envelope_signature: other_signature,
        };
        assert!(signed.verify(PUBLIC_KEY_HEX).is_err());
    }

    #[test]
    fn verify_rejects_unsupported_envelope_version() {
        let mut signed = signed_envelope();
        signed.envelope.envelope_version = STORED_SHARE_ENVELOPE_VERSION + 1;
        let error = signed.verify(PUBLIC_KEY_HEX).unwrap_err();
        assert!(
            matches!(error, PreShareError::UnsupportedVersion(v) if v == STORED_SHARE_ENVELOPE_VERSION + 1)
        );
    }
}
