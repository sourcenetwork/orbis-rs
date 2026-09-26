//! The PET per-share check-response evidence statement.
//!
//! Mirrors [`super::pre_sign::PreReencryptResponseStatement`] almost exactly
//! — same canonical shape, same reconstruct-from-context discipline — but
//! for a PET threshold-check contribution instead of a PRE reencryption
//! share. One canonical statement, signed once by the responder, is reused
//! everywhere: the live wire signature (`PetMessage::CheckResponse`), the
//! portable `PetShareAttestation` forwarded to PRE peers, and this same
//! statement's bytes as `invalid_crypto_response`/`Pet` report evidence —
//! see `pet::v0::attestation`'s module doc comment for why unifying these
//! into one signed message matters.

use serde::{Deserialize, Serialize};

use crate::reporting::v0::error::Result;

use super::codec::{
    write_bool, write_bytes, write_optional_string, write_optional_u64, write_string, write_u32,
    write_u64, Decoder,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetCheckResponseStatement {
    pub domain: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    /// Unix seconds at which the responder produced and signed this statement.
    /// Evidence older than `REPORT_TTL_SECS` is unreportable — this is what
    /// stops one signed bad response from being re-reported indefinitely.
    pub signed_at: u64,
    pub responder_node_key: String,
    pub origin_protocol: String,
    /// The PET-gated document's bulletin object id — lets a verifier that
    /// never saw the live request (a report co-signer) locate the same
    /// `pet_tag`/`pet_tag_proof` this contribution was computed against,
    /// either by reading the bulletin or, when `document_inline` is set, via
    /// the out-of-band `ReportedDocumentEvidence` every `invalid_crypto_response`
    /// observation already carries.
    pub object_id: String,
    /// Needed, together with the resolved document, to rebuild the exact
    /// `CiphertextContext`/tag-transcript digest this contribution's tag was
    /// bound to — mirrors `PetCheckContext::salt`.
    pub salt: Option<String>,
    pub from_node_id: u32,
    /// Serialized `Pet::PublicKey` — this node's `share_i * R`.
    pub partial: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the per-share DLEQ proof's Fiat-Shamir
    /// challenge.
    pub challenge: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the per-share DLEQ proof's response.
    pub proof: Vec<u8>,
    pub crypto_backend: String,
    /// The document's ACP timestamp (`DocumentPayload.timestamp`) — not the
    /// same thing as `signed_at` above. Not needed for the crypto
    /// re-verification itself, but required to recompute the *document's*
    /// content id via `generate_document_id` when resolving out-of-band
    /// inline evidence for a report (`require_inline_document_evidence`
    /// hashes it in whenever the original document had one) — mirrors
    /// `PreReencryptResponseStatement::timestamp` exactly, and for the same
    /// reason: omitting it made every timestamped inline PET document's
    /// report fail id reconstruction.
    pub timestamp: Option<u64>,
    /// `true` when the request's document was supplied inline rather than
    /// read from the bulletin — mirrors `PreReencryptResponseStatement`'s
    /// field of the same name exactly.
    pub document_inline: bool,
}

impl PetCheckResponseStatement {
    /// Field order is the canonical wire contract — the chain-side (Go)
    /// decoder must read fields in exactly this order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, &self.domain);
        write_string(&mut out, &self.chain_id);
        write_string(&mut out, &self.ring_id);
        write_string(&mut out, &self.ring_pk);
        write_string(&mut out, &self.ring_state_sha256);
        write_u64(&mut out, self.protocol_version);
        write_string(&mut out, &self.request_id);
        write_u64(&mut out, self.signed_at);
        write_string(&mut out, &self.responder_node_key);
        write_string(&mut out, &self.origin_protocol);
        write_string(&mut out, &self.object_id);
        write_optional_string(&mut out, self.salt.as_deref());
        write_u32(&mut out, self.from_node_id);
        write_bytes(&mut out, &self.partial);
        write_bytes(&mut out, &self.challenge);
        write_bytes(&mut out, &self.proof);
        write_string(&mut out, &self.crypto_backend);
        write_optional_u64(&mut out, self.timestamp);
        write_bool(&mut out, self.document_inline);
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let domain = decoder.read_string("domain")?;
        let chain_id = decoder.read_string("chain_id")?;
        let ring_id = decoder.read_string("ring_id")?;
        let ring_pk = decoder.read_string("ring_pk")?;
        let ring_state_sha256 = decoder.read_string("ring_state_sha256")?;
        let protocol_version = decoder.read_u64("protocol_version")?;
        let request_id = decoder.read_string("request_id")?;
        let signed_at = decoder.read_u64("signed_at")?;
        let responder_node_key = decoder.read_string("responder_node_key")?;
        let origin_protocol = decoder.read_string("origin_protocol")?;
        let object_id = decoder.read_string("object_id")?;
        let salt = decoder.read_optional_string("salt")?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let partial = decoder.read_bytes("partial")?;
        let challenge = decoder.read_bytes("challenge")?;
        let proof = decoder.read_bytes("proof")?;
        let crypto_backend = decoder.read_string("crypto_backend")?;
        let timestamp = decoder.read_optional_u64("timestamp")?;
        let document_inline = decoder.read_bool("document_inline")?;
        decoder.finish()?;
        Ok(Self {
            domain,
            chain_id,
            ring_id,
            ring_pk,
            ring_state_sha256,
            protocol_version,
            request_id,
            signed_at,
            responder_node_key,
            origin_protocol,
            object_id,
            salt,
            from_node_id,
            partial,
            challenge,
            proof,
            crypto_backend,
            timestamp,
            document_inline,
        })
    }
}
