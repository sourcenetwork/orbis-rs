use crate::dkg::v0::messages::SignedDkgCommitment;
use crate::reporting::v0::error::{ReportingError, Result};
use bulletin::r#trait::RingPayload;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_DOMAIN: &str = "orbis-mpc-fault-report";
pub const NODE_OFFLINE_REPORT_TYPE: &str = "node_offline";
pub const INVALID_CRYPTO_RESPONSE_REPORT_TYPE: &str = "invalid_crypto_response";
pub const UNAUTHORIZED_REQUEST_REPORT_TYPE: &str = "unauthorized_request";
pub const PRE_REENCRYPT_RESPONSE_DOMAIN: &str = "orbis-pre-reencrypt-response-v1";
pub const SIGN_RESPONSE_DOMAIN: &str = "orbis-sign-response-v1";
pub const DKG_COMMITMENT_DOMAIN: &str = "orbis-dkg-commitment-v1";
pub const DKG_SHARE_DOMAIN: &str = "orbis-dkg-share-v1";
pub const RELAY_REQUEST_DOMAIN: &str = "orbis-relay-request-v1";
pub const REPORT_TTL_SECS: u64 = 120;
/// Reporters backdate `observed_at` by this so the `observed_at <= block_time`
/// check passes gas simulation against ~5s blocks. invalid_crypto_response
/// envelopes are pinned to their evidence via
/// `observed_at == signed_at - CHAIN_BLOCK_GRACE_SECS`, which makes the
/// envelope's fixed `observed_at + REPORT_TTL_SECS` expiry double as the
/// evidence expiry — a plain TTL dedupe record on chain then always outlives
/// any resubmission of the same evidence.
pub const CHAIN_BLOCK_GRACE_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeScope {
    Current,
    PendingNew,
}

impl CommitteeScope {
    fn tag(self) -> u8 {
        match self {
            Self::Current => 1,
            Self::PendingNew => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Current),
            2 => Ok(Self::PendingNew),
            value => Err(ReportingError::InvalidReport(format!(
                "unknown committee scope {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeOffline {
    pub origin_protocol: String,
    pub origin_protocol_version: u64,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
}

impl NodeOffline {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, &self.origin_protocol);
        write_u64(&mut out, self.origin_protocol_version);
        out.push(self.accused_committee_scope.tag());
        out.push(self.signing_committee_scope.tag());
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let origin_protocol = decoder.read_string("origin_protocol")?;
        let origin_protocol_version = decoder.read_u64("origin_protocol_version")?;
        let accused_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("accused_committee_scope")?)?;
        let signing_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("signing_committee_scope")?)?;
        decoder.finish()?;
        Ok(Self {
            origin_protocol,
            origin_protocol_version,
            accused_committee_scope,
            signing_committee_scope,
        })
    }
}

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

/// A relaying node's signed record of a Sign/PRE request it forwarded to a peer. If the peer's
/// ACP re-check fails, this statement is the on-chain-verifiable evidence attributing the relayer.
/// The document-derived ACP inputs (policy_id, resource, permission, tier) are NOT carried — they
/// are re-fetched from the bulletin during the refutation — so the statement stays lean and the
/// re-check reproducible. `valid_window_*` and `timestamp` are the relayer's own ACP-check inputs
/// (both window bounds present-or-both-absent), used verbatim so the refutation is deterministic.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgCommitmentStatement {
    pub domain: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub signed_at: u64,
    pub responder_node_key: String,
    pub origin_protocol: String,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub from_node_id: u32,
    pub commitment: Vec<u8>,
    /// Per-session-instance nonce the dealer generates once and signs into every
    /// commitment it broadcasts for this attempt. Equivocation = same dealer signing
    /// two commitments with the SAME nonce but different bytes; an honest retry uses a
    /// fresh nonce, so it cannot be framed as equivocation. Opaque to receivers.
    pub session_nonce: [u8; 16],
    pub crypto_backend: String,
}

impl DkgCommitmentStatement {
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
        write_bytes(&mut out, &self.commitment);
        write_bytes(&mut out, &self.session_nonce);
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
        let commitment = decoder.read_bytes("commitment")?;
        let session_nonce_bytes = decoder.read_bytes("session_nonce")?;
        let session_nonce = session_nonce_bytes.try_into().map_err(|bytes: Vec<u8>| {
            ReportingError::InvalidReport(format!(
                "DKG commitment session_nonce must be 16 bytes, got {}",
                bytes.len()
            ))
        })?;
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
            commitment,
            session_nonce,
            crypto_backend,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgShareStatement {
    pub domain: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub signed_at: u64,
    pub responder_node_key: String,
    pub receiver_node_key: String,
    pub origin_protocol: String,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub from_node_id: u32,
    pub to_node_id: u32,
    pub commitment_statement: DkgCommitmentStatement,
    pub commitment_signature: Vec<u8>,
    pub share_value: Vec<u8>,
    pub nonce: [u8; 16],
    pub crypto_backend: String,
}

impl DkgShareStatement {
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
        write_string(&mut out, &self.receiver_node_key);
        write_string(&mut out, &self.origin_protocol);
        out.push(self.accused_committee_scope.tag());
        out.push(self.signing_committee_scope.tag());
        write_u32(&mut out, self.from_node_id);
        write_u32(&mut out, self.to_node_id);
        write_bytes(&mut out, &self.commitment_statement.canonical_bytes());
        write_bytes(&mut out, &self.commitment_signature);
        write_bytes(&mut out, &self.share_value);
        write_bytes(&mut out, &self.nonce);
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
        let receiver_node_key = decoder.read_string("receiver_node_key")?;
        let origin_protocol = decoder.read_string("origin_protocol")?;
        let accused_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("accused_committee_scope")?)?;
        let signing_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("signing_committee_scope")?)?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let to_node_id = decoder.read_u32("to_node_id")?;
        let commitment_statement = DkgCommitmentStatement::from_canonical_bytes(
            &decoder.read_bytes("commitment_statement")?,
        )?;
        let commitment_signature = decoder.read_bytes("commitment_signature")?;
        let share_value = decoder.read_bytes("share_value")?;
        let nonce_bytes = decoder.read_bytes("nonce")?;
        let nonce = nonce_bytes.try_into().map_err(|bytes: Vec<u8>| {
            ReportingError::InvalidReport(format!(
                "DKG share nonce must be 16 bytes, got {}",
                bytes.len()
            ))
        })?;
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
            receiver_node_key,
            origin_protocol,
            accused_committee_scope,
            signing_committee_scope,
            from_node_id,
            to_node_id,
            commitment_statement,
            commitment_signature,
            share_value,
            nonce,
            crypto_backend,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidCryptoResponse {
    Pre {
        statement: PreReencryptResponseStatement,
        response_signature: Vec<u8>,
    },
    Sign {
        statement: SignResponseStatement,
        response_signature: Vec<u8>,
    },
    DkgShare {
        statement: Box<DkgShareStatement>,
        response_signature: Vec<u8>,
    },
    /// A refresh dealer's signed commitment whose constant term is NOT the group identity.
    /// A refresh delta polynomial must have `P(0) = O`; a non-identity constant would shift
    /// the ring key. Single self-incriminating statement, like `DkgShare`.
    DkgInvalidRefreshCommitment {
        statement: Box<DkgCommitmentStatement>,
        response_signature: Vec<u8>,
    },
    /// DKG commitment equivocation: two conflicting commitments, each validly signed by
    /// the same dealer (same ring/session/nonce, different bytes). Unlike the other kinds,
    /// the fault is the *conflict between two signed statements*, not one statement failing.
    DkgEquivocation {
        commitment_a: Box<SignedDkgCommitment>,
        commitment_b: Box<SignedDkgCommitment>,
    },
}

impl InvalidCryptoResponse {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Pre {
                statement,
                response_signature,
            } => {
                write_string(&mut out, "pre");
                write_bytes(&mut out, &statement.canonical_bytes());
                write_bytes(&mut out, response_signature);
            }
            Self::Sign {
                statement,
                response_signature,
            } => {
                write_string(&mut out, "sign");
                write_bytes(&mut out, &statement.canonical_bytes());
                write_bytes(&mut out, response_signature);
            }
            Self::DkgShare {
                statement,
                response_signature,
            } => {
                write_string(&mut out, "dkg_share");
                write_bytes(&mut out, &statement.canonical_bytes());
                write_bytes(&mut out, response_signature);
            }
            Self::DkgInvalidRefreshCommitment {
                statement,
                response_signature,
            } => {
                write_string(&mut out, "dkg_invalid_refresh_commitment");
                write_bytes(&mut out, &statement.canonical_bytes());
                write_bytes(&mut out, response_signature);
            }
            Self::DkgEquivocation {
                commitment_a,
                commitment_b,
            } => {
                write_string(&mut out, "dkg_equivocation");
                write_bytes(&mut out, &commitment_a.statement.canonical_bytes());
                write_bytes(&mut out, &commitment_a.signature);
                write_bytes(&mut out, &commitment_b.statement.canonical_bytes());
                write_bytes(&mut out, &commitment_b.signature);
            }
        }
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let evidence_kind = decoder.read_string("evidence_kind")?;
        // The single-statement kinds share a (statement, signature) tail; the two-statement
        // equivocation kind has its own layout, so branch the decode on the kind.
        let evidence = match evidence_kind.as_str() {
            "pre" => {
                let statement_bytes = decoder.read_bytes("statement")?;
                let response_signature = decoder.read_bytes("response_signature")?;
                Self::Pre {
                    statement: PreReencryptResponseStatement::from_canonical_bytes(
                        &statement_bytes,
                    )?,
                    response_signature,
                }
            }
            "sign" => {
                let statement_bytes = decoder.read_bytes("statement")?;
                let response_signature = decoder.read_bytes("response_signature")?;
                Self::Sign {
                    statement: SignResponseStatement::from_canonical_bytes(&statement_bytes)?,
                    response_signature,
                }
            }
            "dkg_share" => {
                let statement_bytes = decoder.read_bytes("statement")?;
                let response_signature = decoder.read_bytes("response_signature")?;
                Self::DkgShare {
                    statement: Box::new(DkgShareStatement::from_canonical_bytes(&statement_bytes)?),
                    response_signature,
                }
            }
            "dkg_invalid_refresh_commitment" => {
                let statement_bytes = decoder.read_bytes("statement")?;
                let response_signature = decoder.read_bytes("response_signature")?;
                Self::DkgInvalidRefreshCommitment {
                    statement: Box::new(DkgCommitmentStatement::from_canonical_bytes(
                        &statement_bytes,
                    )?),
                    response_signature,
                }
            }
            "dkg_equivocation" => {
                let statement_a = decoder.read_bytes("commitment_a_statement")?;
                let signature_a = decoder.read_bytes("commitment_a_signature")?;
                let statement_b = decoder.read_bytes("commitment_b_statement")?;
                let signature_b = decoder.read_bytes("commitment_b_signature")?;
                Self::DkgEquivocation {
                    commitment_a: Box::new(SignedDkgCommitment {
                        statement: DkgCommitmentStatement::from_canonical_bytes(&statement_a)?,
                        signature: signature_a,
                    }),
                    commitment_b: Box::new(SignedDkgCommitment {
                        statement: DkgCommitmentStatement::from_canonical_bytes(&statement_b)?,
                        signature: signature_b,
                    }),
                }
            }
            value => {
                return Err(ReportingError::InvalidReport(format!(
                    "unsupported invalid crypto evidence kind {value}"
                )))
            }
        };
        decoder.finish()?;
        Ok(evidence)
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::Pre { statement, .. } => &statement.request_id,
            Self::Sign { statement, .. } => &statement.request_id,
            Self::DkgShare { statement, .. } => &statement.request_id,
            Self::DkgInvalidRefreshCommitment { statement, .. } => &statement.request_id,
            Self::DkgEquivocation { commitment_a, .. } => &commitment_a.statement.request_id,
        }
    }

    pub fn signing_committee_scope(&self) -> CommitteeScope {
        match self {
            Self::Pre { .. } => CommitteeScope::Current,
            Self::Sign { statement, .. } => statement.signing_committee_scope,
            Self::DkgShare { statement, .. } => statement.signing_committee_scope,
            Self::DkgInvalidRefreshCommitment { statement, .. } => {
                statement.signing_committee_scope
            }
            Self::DkgEquivocation { .. } => CommitteeScope::Current,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEnvelope {
    pub domain: String,
    pub report_type: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub reporter_node_key: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub payload: Vec<u8>,
    pub session_id: String,
}

impl ReportEnvelope {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, &self.domain);
        write_string(&mut out, &self.report_type);
        write_string(&mut out, &self.chain_id);
        write_string(&mut out, &self.ring_id);
        write_string(&mut out, &self.ring_pk);
        write_string(&mut out, &self.ring_state_sha256);
        write_string(&mut out, &self.reporter_node_key);
        write_string(&mut out, &self.accused_node_key);
        write_string(&mut out, &self.accused_peer_id);
        write_u64(&mut out, self.observed_at);
        write_u64(&mut out, self.expires_at);
        write_bytes(&mut out, &self.payload);
        write_string(&mut out, &self.session_id);
        out
    }

    pub fn report_id(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    pub fn validate_shape(&self, now: u64) -> Result<()> {
        if self.domain != REPORT_DOMAIN {
            return Err(ReportingError::InvalidReport(format!(
                "unexpected domain {}",
                self.domain
            )));
        }

        if self.observed_at > now {
            return Err(ReportingError::InvalidReport(
                "observed_at cannot be in the future".to_string(),
            ));
        }

        if self.observed_at > self.expires_at
            || self.expires_at.saturating_sub(self.observed_at) != REPORT_TTL_SECS
        {
            return Err(ReportingError::InvalidReport(
                "invalid report validity window".to_string(),
            ));
        }
        if now > self.expires_at {
            return Err(ReportingError::Expired);
        }
        for (label, value) in [
            ("report_type", self.report_type.as_str()),
            ("chain_id", self.chain_id.as_str()),
            ("ring_id", self.ring_id.as_str()),
            ("ring_pk", self.ring_pk.as_str()),
            ("ring_state_sha256", self.ring_state_sha256.as_str()),
            ("reporter_node_key", self.reporter_node_key.as_str()),
            ("accused_node_key", self.accused_node_key.as_str()),
            ("accused_peer_id", self.accused_peer_id.as_str()),
            ("session_id", self.session_id.as_str()),
        ] {
            if value.is_empty() {
                return Err(ReportingError::InvalidReport(format!(
                    "{label} cannot be empty"
                )));
            }
        }
        if self.reporter_node_key == self.accused_node_key {
            return Err(ReportingError::InvalidReport(
                "reporter and accused node must differ".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSigningContext {
    pub envelope: ReportEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReport {
    pub report: ReportEnvelope,
    pub report_id: String,
    pub signature_scheme: String,
    pub signature: String,
}

pub fn ring_state_sha256(payload: &RingPayload) -> String {
    hex::encode(Sha256::digest(canonical_ring_state_bytes(payload)))
}

pub fn canonical_ring_state_bytes(payload: &RingPayload) -> Vec<u8> {
    let mut out = Vec::new();
    write_string(&mut out, &payload.ring_pk);
    write_string_vec(&mut out, &payload.peer_node_keys);
    write_u32(&mut out, payload.threshold);

    write_optional_string_vec(&mut out, payload.new_peer_node_keys.as_deref());
    write_optional_u32(&mut out, payload.new_threshold);
    write_u64(&mut out, payload.pss_interval);
    write_u64(&mut out, payload.block_number_nonce);
    write_optional_string(&mut out, payload.policy_id.as_deref());
    write_u64(&mut out, payload.upgrade_info.current_version);
    write_optional_u64(&mut out, payload.upgrade_info.next_version);
    write_optional_u64(&mut out, payload.upgrade_info.activation_time);
    write_reporting_config(&mut out, &payload.reporting);
    out
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_bytes(out, value.as_bytes());
}

fn write_string_vec(out: &mut Vec<u8>, values: &[String]) {
    write_u32(out, values.len() as u32);
    for value in values {
        write_string(out, value);
    }
}

/// Field order is the canonical wire contract — the chain-side (Go)
/// decoder must read fields in exactly this order.
fn write_demerit_config(out: &mut Vec<u8>, value: &bulletin::r#trait::DemeritConfig) {
    write_u64(out, value.node_offline_demerits);
    write_u64(out, value.invalid_crypto_response_demerits);
    write_u64(out, value.reset_interval_seconds);
    write_u64(out, value.unauthorized_request_demerits);
}

fn write_reporting_config(out: &mut Vec<u8>, value: &bulletin::r#trait::ReportingConfig) {
    write_demerit_config(out, &value.demerit_config);
    write_string_vec(out, &value.backup_node_keys);
    write_u64(out, value.kick_threshold);
}

fn write_optional_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            write_string(out, value);
        }
        None => out.push(0),
    }
}

fn write_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            out.push(1);
            write_bytes(out, value);
        }
        None => out.push(0),
    }
}

fn write_optional_string_vec(out: &mut Vec<u8>, value: Option<&[String]>) {
    match value {
        Some(value) => {
            out.push(1);
            write_string_vec(out, value);
        }
        None => out.push(0),
    }
}

fn write_optional_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u32(out, value);
        }
        None => out.push(0),
    }
}

fn write_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u64(out, value);
        }
        None => out.push(0),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_u8(&mut self, label: &str) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor += 1;
        Ok(value)
    }

    fn read_u32(&mut self, label: &str) -> Result<u32> {
        let end = self.cursor.saturating_add(4);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor = end;
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            ReportingError::InvalidReport(format!("invalid {label}"))
        })?))
    }

    fn read_u64(&mut self, label: &str) -> Result<u64> {
        let end = self.cursor.saturating_add(8);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("missing {label}")))?;
        self.cursor = end;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            ReportingError::InvalidReport(format!("invalid {label}"))
        })?))
    }

    fn read_string(&mut self, label: &str) -> Result<String> {
        let len = self.read_u32(&format!("{label}_length"))? as usize;
        let end = self.cursor.saturating_add(len);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("truncated {label}")))?;
        self.cursor = end;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| ReportingError::InvalidReport(format!("{label} is not utf-8")))
    }

    fn read_bytes(&mut self, label: &str) -> Result<Vec<u8>> {
        let len = self.read_u32(&format!("{label}_length"))? as usize;
        let end = self.cursor.saturating_add(len);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ReportingError::InvalidReport(format!("truncated {label}")))?;
        self.cursor = end;
        Ok(bytes.to_vec())
    }

    fn read_optional_bytes(&mut self, label: &str) -> Result<Option<Vec<u8>>> {
        match self.read_u8(&format!("{label}_present"))? {
            0 => Ok(None),
            1 => self.read_bytes(label).map(Some),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid optional {label} tag {value}"
            ))),
        }
    }

    fn read_optional_u64(&mut self, label: &str) -> Result<Option<u64>> {
        match self.read_u8(&format!("{label}_present"))? {
            0 => Ok(None),
            1 => self.read_u64(label).map(Some),
            value => Err(ReportingError::InvalidReport(format!(
                "invalid optional {label} tag {value}"
            ))),
        }
    }

    fn finish(&self) -> Result<()> {
        if self.cursor != self.bytes.len() {
            return Err(ReportingError::InvalidReport(
                "trailing payload bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletin::r#trait::UpgradeInfo;

    fn envelope() -> ReportEnvelope {
        ReportEnvelope {
            domain: REPORT_DOMAIN.to_string(),
            report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
            chain_id: "sourcehub-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            reporter_node_key: "reporter".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "22".repeat(32),
            observed_at: 1_700_000_000,
            expires_at: 1_700_000_120,
            payload: NodeOffline {
                origin_protocol: "pre".to_string(),
                origin_protocol_version: 0,
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
            }
            .canonical_bytes(),
            session_id: "pre-request-1".to_string(),
        }
    }

    fn relay_request_statement() -> RelayRequestStatement {
        RelayRequestStatement {
            domain: RELAY_REQUEST_DOMAIN.to_string(),
            chain_id: "sourcehub-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            protocol_version: 0,
            request_id: "sign-request-1".to_string(),
            signed_at: 1_700_000_000,
            user_signed_at: 1_699_999_995,
            relayer_node_key: "relayer".to_string(),
            origin_protocol: "sign".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            actor_id: "did:key:z6Mkactor".to_string(),
            object_id: "derivation-1".to_string(),
            valid_window_start: Some(1_699_999_000),
            valid_window_end: Some(1_700_001_000),
            timestamp: Some(1_700_000_000),
        }
    }

    #[test]
    fn relay_request_statement_round_trips() {
        let statement = relay_request_statement();
        assert_eq!(
            RelayRequestStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
            statement
        );
    }

    #[test]
    fn unauthorized_request_payload_round_trips() {
        let payload = UnauthorizedRequestPayload {
            statement: relay_request_statement(),
            relay_signature: vec![7; 64],
            checked_at_anchor: "42000".to_string(),
        };
        assert_eq!(
            UnauthorizedRequestPayload::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
        // A statement with no window/timestamp (unbounded auth) also round-trips.
        let mut unbounded = payload.clone();
        unbounded.statement.valid_window_start = None;
        unbounded.statement.valid_window_end = None;
        unbounded.statement.timestamp = None;
        assert_eq!(
            UnauthorizedRequestPayload::from_canonical_bytes(&unbounded.canonical_bytes()).unwrap(),
            unbounded
        );
    }

    #[test]
    fn offline_payload_round_trips() {
        let payload = NodeOffline {
            origin_protocol: "pre".to_string(),
            origin_protocol_version: 7,
            accused_committee_scope: CommitteeScope::PendingNew,
            signing_committee_scope: CommitteeScope::Current,
        };
        assert_eq!(
            NodeOffline::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
    }

    fn pre_statement() -> PreReencryptResponseStatement {
        PreReencryptResponseStatement {
            domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: "sourcehub-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            protocol_version: 7,
            request_id: "pre-request-1".to_string(),
            signed_at: 1_700_000_000 + CHAIN_BLOCK_GRACE_SECS,
            responder_node_key: "accused".to_string(),
            origin_protocol: "pre".to_string(),
            object_id: "object-1".to_string(),
            rdr_pk: vec![1, 2, 3],
            derivation: Some(vec![4, 5, 6]),
            from_node_id: 2,
            share: vec![7, 8],
            challenge: vec![9, 10],
            proof: vec![11, 12],
            crypto_backend: "elgamal/test".to_string(),
        }
    }

    fn dkg_commitment_statement() -> DkgCommitmentStatement {
        DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "sourcehub-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            protocol_version: 7,
            request_id: "dkg-session-1".to_string(),
            signed_at: 1_700_000_000,
            responder_node_key: "accused".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            commitment: vec![1, 2, 3],
            session_nonce: [0u8; 16],
            crypto_backend: "dkg/test".to_string(),
        }
    }

    fn dkg_share_statement() -> DkgShareStatement {
        DkgShareStatement {
            domain: DKG_SHARE_DOMAIN.to_string(),
            chain_id: "sourcehub-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            protocol_version: 7,
            request_id: "dkg-session-1".to_string(),
            signed_at: 1_700_000_000 + CHAIN_BLOCK_GRACE_SECS,
            responder_node_key: "accused".to_string(),
            receiver_node_key: "receiver".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            to_node_id: 1,
            commitment_statement: dkg_commitment_statement(),
            commitment_signature: vec![41; 64],
            share_value: vec![7, 8],
            nonce: [9; 16],
            crypto_backend: "dkg/test".to_string(),
        }
    }

    #[test]
    fn pre_response_statement_round_trips_and_is_domain_separated() {
        let statement = pre_statement();
        assert_eq!(
            PreReencryptResponseStatement::from_canonical_bytes(&statement.canonical_bytes())
                .unwrap(),
            statement
        );

        let mut changed = pre_statement();
        changed.domain = "other".to_string();
        assert_ne!(pre_statement().canonical_bytes(), changed.canonical_bytes());
    }

    #[test]
    fn invalid_crypto_response_pre_payload_round_trips() {
        let payload = InvalidCryptoResponse::Pre {
            statement: pre_statement(),
            response_signature: vec![42; 64],
        };

        assert_eq!(
            InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
    }

    #[test]
    fn invalid_crypto_response_sign_payload_round_trips() {
        let payload = InvalidCryptoResponse::Sign {
            statement: SignResponseStatement {
                domain: SIGN_RESPONSE_DOMAIN.to_string(),
                chain_id: "sourcehub-test".to_string(),
                ring_id: "ring-1".to_string(),
                ring_pk: "aabb".to_string(),
                ring_state_sha256: "11".repeat(32),
                protocol_version: 7,
                request_id: "sign-request-1".to_string(),
                signed_at: 1_700_000_000 + CHAIN_BLOCK_GRACE_SECS,
                responder_node_key: "accused".to_string(),
                origin_protocol: "sign".to_string(),
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
                from_node_id: 2,
                message: vec![1, 2, 3],
                signing_commitments: vec![4, 5],
                derivation: None,
                metadata: Some(vec![6, 7]),
                sig_share: vec![8, 9],
                crypto_backend: "threshold-bls-g2".to_string(),
            },
            response_signature: vec![42; 64],
        };

        assert_eq!(
            InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
    }

    #[test]
    fn dkg_share_statement_round_trips_and_binds_nested_commitment() {
        let statement = dkg_share_statement();
        assert_eq!(
            DkgShareStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
            statement
        );

        let mut changed = dkg_share_statement();
        changed.commitment_statement.commitment.push(99);
        assert_ne!(
            dkg_share_statement().canonical_bytes(),
            changed.canonical_bytes()
        );
    }

    #[test]
    fn dkg_commitment_statement_round_trips_and_binds_session_nonce() {
        let statement = dkg_commitment_statement();
        assert_eq!(
            DkgCommitmentStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
            statement
        );

        // The per-attempt nonce is part of the signed bytes — changing it changes them.
        let mut changed = dkg_commitment_statement();
        changed.session_nonce = [7u8; 16];
        assert_ne!(
            dkg_commitment_statement().canonical_bytes(),
            changed.canonical_bytes()
        );
    }

    #[test]
    fn invalid_crypto_response_dkg_share_payload_round_trips() {
        let payload = InvalidCryptoResponse::DkgShare {
            statement: Box::new(dkg_share_statement()),
            response_signature: vec![42; 64],
        };

        assert_eq!(
            InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
        assert_eq!(payload.signing_committee_scope(), CommitteeScope::Current);
    }

    #[test]
    fn invalid_crypto_response_dkg_invalid_refresh_commitment_payload_round_trips() {
        let mut statement = dkg_commitment_statement();
        statement.origin_protocol = "pss_refresh".to_string();
        let payload = InvalidCryptoResponse::DkgInvalidRefreshCommitment {
            statement: Box::new(statement.clone()),
            response_signature: vec![42; 64],
        };

        assert_eq!(
            InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
        assert_eq!(payload.request_id(), statement.request_id);
        assert_eq!(payload.signing_committee_scope(), CommitteeScope::Current);
    }

    #[test]
    fn invalid_crypto_response_dkg_equivocation_payload_round_trips() {
        let mut statement_a = dkg_commitment_statement();
        statement_a.session_nonce = [3u8; 16];
        let mut statement_b = statement_a.clone();
        statement_b.commitment = vec![9, 9, 9]; // conflicting bytes, same nonce
        let payload = InvalidCryptoResponse::DkgEquivocation {
            commitment_a: Box::new(SignedDkgCommitment {
                statement: statement_a.clone(),
                signature: vec![1; 64],
            }),
            commitment_b: Box::new(SignedDkgCommitment {
                statement: statement_b,
                signature: vec![2; 64],
            }),
        };

        assert_eq!(
            InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
        assert_eq!(payload.request_id(), statement_a.request_id);
        assert_eq!(payload.signing_committee_scope(), CommitteeScope::Current);
    }

    #[test]
    fn report_id_is_deterministic_and_domain_separated() {
        let report = envelope();
        assert_eq!(report.report_id(), report.report_id());
        let mut changed = report.clone();
        changed.domain = "different-domain".to_string();
        assert_ne!(report.report_id(), changed.report_id());

        let mut changed = report.clone();
        changed.session_id = "pre-request-2".to_string();
        assert_ne!(report.report_id(), changed.report_id());
    }

    #[test]
    fn report_validity_window_is_fixed() {
        let report = envelope();
        report.validate_shape(report.observed_at).unwrap();
        assert!(matches!(
            report.validate_shape(report.expires_at + 1),
            Err(ReportingError::Expired)
        ));
    }

    #[test]
    fn self_reporting_is_rejected() {
        let mut report = envelope();
        report.accused_node_key = report.reporter_node_key.clone();
        assert!(report.validate_shape(report.observed_at).is_err());
    }

    #[test]
    fn report_validity_window_must_be_exactly_ttl() {
        let mut report = envelope();
        report.expires_at = report.observed_at + REPORT_TTL_SECS + 1;
        assert!(report.validate_shape(report.observed_at).is_err());
        let mut report = envelope();
        report.expires_at = report.observed_at + REPORT_TTL_SECS - 1;
        assert!(report.validate_shape(report.observed_at).is_err());
    }

    #[test]
    fn ring_state_digest_commits_to_committee_order() {
        let mut a = RingPayload {
            ring_pk: "pk".into(),
            peer_node_keys: vec!["b".into(), "a".into()],
            threshold: 2,
            pss_interval: 86_400,
            upgrade_info: UpgradeInfo {
                current_version: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut b = a.clone();
        b.peer_node_keys.reverse();
        assert_ne!(ring_state_sha256(&a), ring_state_sha256(&b));
        assert_eq!(
            ring_state_sha256(&a),
            "ad10dfb463d1d3aeca03644e200aa192c49d6689300e90fe243d710e645aba18"
        );

        a.threshold = 1;
        assert_ne!(ring_state_sha256(&a), ring_state_sha256(&b));
    }

    #[test]
    fn report_encoding_golden_vector() {
        assert_eq!(
            envelope().report_id(),
            "80b0f43ae215dd88a6e635de00207cd549c2492bb2086b22ceceda73a4de65f3"
        );
    }
}
