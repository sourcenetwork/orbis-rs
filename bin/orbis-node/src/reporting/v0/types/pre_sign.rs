//! The two non-DKG invalid-crypto evidence statements: a PRE re-encrypt
//! response and a Sign response.

use serde::{Deserialize, Serialize};

use crate::reporting::v0::error::Result;

use super::codec::{
    write_bool, write_bytes, write_optional_bytes, write_optional_u64, write_string, write_u32,
    write_u64, Decoder,
};
use super::CommitteeScope;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreReencryptResponseStatement {
    pub domain: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    /// Unix seconds at which the responder produced and signed this statement.
    /// Evidence older than [`REPORT_TTL_SECS`] is unreportable — this is what
    /// stops one signed bad response from being re-reported indefinitely.
    pub signed_at: u64,
    pub responder_node_key: String,
    pub origin_protocol: String,
    pub object_id: String,
    pub rdr_pk: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub from_node_id: u32,
    pub share: Vec<u8>,
    pub challenge: Vec<u8>,
    pub proof: Vec<u8>,
    pub crypto_backend: String,
    /// The document's ACP timestamp (`DocumentPayload.timestamp`). Not needed for the crypto
    /// re-verification itself — carried so the out-of-band [`ReportedDocumentEvidence`], when
    /// `document_inline` is set, can be recomputed against `object_id` via `generate_document_id`.
    pub timestamp: Option<u64>,
    /// `true` when the request's document was supplied inline rather than read from the bulletin.
    /// The evidence itself is not here (see [`ReportedDocumentEvidence`]) — this only tells a
    /// validator to expect it out-of-band in [`ReportSigningContext`] and to skip the bulletin
    /// read.
    pub document_inline: bool,
}

impl PreReencryptResponseStatement {
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
        write_bytes(&mut out, &self.rdr_pk);
        write_optional_bytes(&mut out, self.derivation.as_deref());
        write_u32(&mut out, self.from_node_id);
        write_bytes(&mut out, &self.share);
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
        let rdr_pk = decoder.read_bytes("rdr_pk")?;
        let derivation = decoder.read_optional_bytes("derivation")?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let share = decoder.read_bytes("share")?;
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
            rdr_pk,
            derivation,
            from_node_id,
            share,
            challenge,
            proof,
            crypto_backend,
            timestamp,
            document_inline,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResponseStatement {
    pub domain: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    /// Unix seconds at which the responder produced and signed this statement.
    pub signed_at: u64,
    pub responder_node_key: String,
    pub origin_protocol: String,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub from_node_id: u32,
    pub message: Vec<u8>,
    pub signing_commitments: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub metadata: Option<Vec<u8>>,
    pub sig_share: Vec<u8>,
    pub crypto_backend: String,
}

impl SignResponseStatement {
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
        out.push(self.accused_committee_scope.tag());
        out.push(self.signing_committee_scope.tag());
        write_u32(&mut out, self.from_node_id);
        write_bytes(&mut out, &self.message);
        write_bytes(&mut out, &self.signing_commitments);
        write_optional_bytes(&mut out, self.derivation.as_deref());
        write_optional_bytes(&mut out, self.metadata.as_deref());
        write_bytes(&mut out, &self.sig_share);
        write_string(&mut out, &self.crypto_backend);
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
        let accused_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("accused_committee_scope")?)?;
        let signing_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("signing_committee_scope")?)?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let message = decoder.read_bytes("message")?;
        let signing_commitments = decoder.read_bytes("signing_commitments")?;
        let derivation = decoder.read_optional_bytes("derivation")?;
        let metadata = decoder.read_optional_bytes("metadata")?;
        let sig_share = decoder.read_bytes("sig_share")?;
        let crypto_backend = decoder.read_string("crypto_backend")?;
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
            accused_committee_scope,
            signing_committee_scope,
            from_node_id,
            message,
            signing_commitments,
            derivation,
            metadata,
            sig_share,
            crypto_backend,
        })
    }
}
