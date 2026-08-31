//! The `unauthorized_request` wire types: a relayer's signed record of a
//! forwarded request, and the full report payload wrapping it.

use serde::{Deserialize, Serialize};

use crate::reporting::v0::error::Result;

use super::codec::{
    write_bool, write_bytes, write_optional_u64, write_string, write_u32, write_u64, Decoder,
};
use super::CommitteeScope;

/// A relaying node's signed record of a Sign/PRE request it forwarded to a peer. If the peer's
/// ACP re-check fails, this statement is the on-chain-verifiable evidence attributing the relayer.
/// The document-derived ACP inputs (policy_id, resource, permission, tier) are NOT carried — for a
/// bulletin-sourced request they are re-fetched from the bulletin during the refutation; for an
/// inline-sourced request (`document_inline`) they come from the out-of-band
/// [`ReportedDocumentEvidence`] in [`ReportSigningContext`], re-bound to `object_id`. Either way
/// the statement stays lean and the re-check reproducible. `valid_window_*` and `timestamp` are
/// the relayer's own ACP-check inputs (both window bounds present-or-both-absent), used verbatim
/// so the refutation is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRequestStatement {
    pub domain: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    /// Unix seconds at which the relayer produced and signed this statement (its ACP-check time).
    pub signed_at: u64,
    /// The caller's JWT `iat`. The relayer must have forwarded promptly after the caller signed
    /// (`|signed_at - user_signed_at| <= RELAY_CHECK_MAX_DRIFT_SECS`).
    pub user_signed_at: u64,
    /// The relaying node's chain key — the accused.
    pub relayer_node_key: String,
    /// `"pre"` or `"sign"`.
    pub origin_protocol: String,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub from_node_id: u32,
    /// The JWT issuer whose access is being checked (the ACP subject/actor).
    pub actor_id: String,
    /// PRE object id, or Sign derivation id — the ACP object.
    pub object_id: String,
    pub valid_window_start: Option<u64>,
    pub valid_window_end: Option<u64>,
    pub timestamp: Option<u64>,
    /// `true` when the relayed request's document was supplied inline rather than read from the
    /// bulletin. The evidence itself is not here — it travels out-of-band in
    /// [`ReportSigningContext`]; this only tells a validator to expect it and to skip the
    /// bulletin read.
    pub document_inline: bool,
}

impl RelayRequestStatement {
    /// Field order is the canonical wire contract — the chain-side (Go) decoder must read fields
    /// in exactly this order.
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
        write_u64(&mut out, self.user_signed_at);
        write_string(&mut out, &self.relayer_node_key);
        write_string(&mut out, &self.origin_protocol);
        out.push(self.accused_committee_scope.tag());
        out.push(self.signing_committee_scope.tag());
        write_u32(&mut out, self.from_node_id);
        write_string(&mut out, &self.actor_id);
        write_string(&mut out, &self.object_id);
        write_optional_u64(&mut out, self.valid_window_start);
        write_optional_u64(&mut out, self.valid_window_end);
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
        let user_signed_at = decoder.read_u64("user_signed_at")?;
        let relayer_node_key = decoder.read_string("relayer_node_key")?;
        let origin_protocol = decoder.read_string("origin_protocol")?;
        let accused_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("accused_committee_scope")?)?;
        let signing_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("signing_committee_scope")?)?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let actor_id = decoder.read_string("actor_id")?;
        let object_id = decoder.read_string("object_id")?;
        let valid_window_start = decoder.read_optional_u64("valid_window_start")?;
        let valid_window_end = decoder.read_optional_u64("valid_window_end")?;
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
            user_signed_at,
            relayer_node_key,
            origin_protocol,
            accused_committee_scope,
            signing_committee_scope,
            from_node_id,
            actor_id,
            object_id,
            valid_window_start,
            valid_window_end,
            timestamp,
            document_inline,
        })
    }
}

/// The full `unauthorized_request` report payload: the relayer's signed statement, its signature
/// over `statement.canonical_bytes()`, and the **opaque anchor** the acceptor captured when it saw
/// the failure (`Authz::current_anchor()` — a block height, timestamp, … depending on backend). The
/// refutation re-runs ACP at this anchor and bounds `Authz::anchor_time(anchor) ≈ statement.signed_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnauthorizedRequestPayload {
    pub statement: RelayRequestStatement,
    pub relay_signature: Vec<u8>,
    pub checked_at_anchor: String,
}

impl UnauthorizedRequestPayload {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_bytes(&mut out, &self.statement.canonical_bytes());
        write_bytes(&mut out, &self.relay_signature);
        write_string(&mut out, &self.checked_at_anchor);
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let statement_bytes = decoder.read_bytes("statement")?;
        let relay_signature = decoder.read_bytes("relay_signature")?;
        let checked_at_anchor = decoder.read_string("checked_at_anchor")?;
        decoder.finish()?;
        Ok(Self {
            statement: RelayRequestStatement::from_canonical_bytes(&statement_bytes)?,
            relay_signature,
            checked_at_anchor,
        })
    }
}
