//! Every DKG-ceremony fault evidence wire type: dealer commitments and
//! shares, endpoint-signed public contributions, and the leader / control
//! -message fault statements.

use serde::{Deserialize, Serialize};

use crate::reporting::v0::error::{ReportingError, Result};

use super::codec::{write_bytes, write_string, write_u32, write_u64, Decoder};
use super::CommitteeScope;

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
    /// two commitments for the SAME attempt with the SAME nonce but different bytes;
    /// an honest retry has a different attempt ID and uses a fresh nonce, so it cannot
    /// be framed as equivocation. Opaque to receivers.
    ///
    /// NOT used for dedupe scoping: it's self-chosen by the dealer (part of what
    /// they sign, but not assigned by the protocol), so a dealer could reuse the
    /// same nonce across attempts to blunt its own demerit exposure. `attempt_id`
    /// below is the network-assigned identity used for that instead.
    pub session_nonce: [u8; 16],
    /// The live attempt this commitment was signed for. Chain-side dedupe folds
    /// this into `sessionDedupeID` so independent faults across retries of the
    /// same `CeremonyId` (which is intentionally reusable) each get independent
    /// demerits, rather than colliding on one dedupe record for the whole
    /// ceremony. Tamper-proof the same way every other field here is: it's
    /// covered by the responder's own signature, not asserted by whoever
    /// assembles the report.
    pub attempt_id: [u8; 32],
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
        write_bytes(&mut out, &self.attempt_id);
        write_string(&mut out, &self.crypto_backend);
        out
    }

    /// Returns true when two statements contain the conflicting commitment
    /// pair required to prove dealer equivocation. Callers remain responsible
    /// for validating the statements' signatures and surrounding bindings.
    pub(crate) fn proves_equivocation_with(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.session_nonce == other.session_nonce
            && self.from_node_id == other.from_node_id
            && self.commitment != other.commitment
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
        let attempt_id_bytes = decoder.read_bytes("attempt_id")?;
        let attempt_id = attempt_id_bytes.try_into().map_err(|bytes: Vec<u8>| {
            ReportingError::InvalidReport(format!(
                "DKG commitment attempt_id must be 32 bytes, got {}",
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
            attempt_id,
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

/// Exact endpoint-authenticated public-contribution envelope carried as fault
/// evidence. These bytes are deliberately not decoded by the canonical codec:
/// independent Orbis signers verify the endpoint signature and decode the
/// transport contribution under the active wire implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSignedContribution {
    pub origin: Vec<u8>,
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
}

impl EndpointSignedContribution {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        write_bytes(out, &self.origin);
        write_bytes(out, &self.signature);
        write_bytes(out, &self.data);
    }

    fn read_canonical(decoder: &mut Decoder<'_>, prefix: &str) -> Result<Self> {
        Ok(Self {
            origin: decoder.read_bytes(&format!("{prefix}_origin"))?,
            signature: decoder.read_bytes(&format!("{prefix}_signature"))?,
            data: decoder.read_bytes(&format!("{prefix}_data"))?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgPublicOriginFaultKind {
    InvalidPayload,
    OriginEquivocation,
}

impl DkgPublicOriginFaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPayload => "invalid_payload",
            Self::OriginEquivocation => "origin_equivocation",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "invalid_payload" => Ok(Self::InvalidPayload),
            "origin_equivocation" => Ok(Self::OriginEquivocation),
            _ => Err(ReportingError::InvalidReport(format!(
                "unknown DKG public-origin fault kind {value}"
            ))),
        }
    }
}

/// Normalized bindings plus the exact endpoint-signed public contribution(s).
/// The normalized fields are threshold-attested report metadata; each Orbis
/// co-signer must prove they match the embedded transport contribution before
/// signing the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgPublicOriginFaultStatement {
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
    pub attempt_id: [u8; 32],
    pub phase: String,
    pub fault_kind: DkgPublicOriginFaultKind,
    pub contribution_a: EndpointSignedContribution,
    pub contribution_b: Option<EndpointSignedContribution>,
}

impl DkgPublicOriginFaultStatement {
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
        write_bytes(&mut out, &self.attempt_id);
        write_string(&mut out, &self.phase);
        write_string(&mut out, self.fault_kind.as_str());
        self.contribution_a.write_canonical(&mut out);
        match &self.contribution_b {
            Some(contribution) => {
                out.push(1);
                contribution.write_canonical(&mut out);
            }
            None => out.push(0),
        }
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
        let attempt_id =
            decoder
                .read_bytes("attempt_id")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG public-origin attempt_id must be 32 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let phase = decoder.read_string("phase")?;
        let fault_kind = DkgPublicOriginFaultKind::from_str(&decoder.read_string("fault_kind")?)?;
        let contribution_a =
            EndpointSignedContribution::read_canonical(&mut decoder, "contribution_a")?;
        let contribution_b = match decoder.read_u8("contribution_b_present")? {
            0 => None,
            1 => Some(EndpointSignedContribution::read_canonical(
                &mut decoder,
                "contribution_b",
            )?),
            value => {
                return Err(ReportingError::InvalidReport(format!(
                    "invalid optional contribution_b tag {value}"
                )))
            }
        };
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
            attempt_id,
            phase,
            fault_kind,
            contribution_a,
            contribution_b,
        })
    }
}

/// Normalized bindings plus two conflicting Gossip-authenticated deliveries
/// from the same canonical leader for the same phase/coordinate (a manifest,
/// or a chunk at the same index). `delivery_a`/`delivery_b` carry the exact
/// endpoint-signed broadcast bytes; each co-signer independently
/// re-verifies both signatures under the accused leader's registered
/// endpoint identity rather than trusting the reporter's characterization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgLeaderEquivocationStatement {
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
    pub attempt_id: [u8; 32],
    pub phase: String,
    pub delivery_id_a: [u8; 16],
    pub delivery_a: EndpointSignedContribution,
    pub delivery_id_b: [u8; 16],
    pub delivery_b: EndpointSignedContribution,
}

impl DkgLeaderEquivocationStatement {
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
        write_bytes(&mut out, &self.attempt_id);
        write_string(&mut out, &self.phase);
        write_bytes(&mut out, &self.delivery_id_a);
        self.delivery_a.write_canonical(&mut out);
        write_bytes(&mut out, &self.delivery_id_b);
        self.delivery_b.write_canonical(&mut out);
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
        let attempt_id =
            decoder
                .read_bytes("attempt_id")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG leader-equivocation attempt_id must be 32 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let phase = decoder.read_string("phase")?;
        let delivery_id_a =
            decoder
                .read_bytes("delivery_id_a")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG leader-equivocation delivery_id_a must be 16 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let delivery_a = EndpointSignedContribution::read_canonical(&mut decoder, "delivery_a")?;
        let delivery_id_b =
            decoder
                .read_bytes("delivery_id_b")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG leader-equivocation delivery_id_b must be 16 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let delivery_b = EndpointSignedContribution::read_canonical(&mut decoder, "delivery_b")?;
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
            attempt_id,
            phase,
            delivery_id_a,
            delivery_a,
            delivery_id_b,
            delivery_b,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgLeaderPublicFaultKind {
    /// A single leader-signed Manifest that fails `PhaseManifest::validate`
    /// (origins don't match the phase's expected committee, or the
    /// self-consistency/root-recomputation check fails), or whose
    /// `complete` flag contradicts the phase's Complete/Incremental mode.
    /// Independently provable from the one signed delivery plus the
    /// phase's committee-derived expected-origins set — no conflicting
    /// counterpart needed, unlike `DkgLeaderEquivocationStatement`.
    InvalidManifest,
    /// A single leader-signed Chunk whose `index` is outside the phase's
    /// valid range (`index >= expected_origin_count`). Independently
    /// provable from the one signed delivery plus the same committee-derived
    /// bound `InvalidManifest` uses.
    ChunkIndexOutOfRange,
    /// A single leader-signed Chunk whose encoded size exceeds
    /// `MAX_PUBLIC_CHUNK_BYTES`. Independently provable from the one signed
    /// delivery's own byte length against a fixed protocol constant — no
    /// committee/ring lookup needed at all.
    OversizedChunk,
    /// A single leader-signed Chunk that names the same origin more than
    /// once among its own contributions. Independently provable from the
    /// one signed delivery alone — a chunk is built from a
    /// `BTreeMap<ParticipantRef, SignedPayload>`, which cannot contain the
    /// same key twice, so any duplicate can only come from the leader's own
    /// packaging, honest or not. No committee/ring lookup needed, so (like
    /// `oversized_chunk`) this is provable even for the Reshare
    /// `Commitments` phase. Additive alongside origin-side equivocation
    /// evidence — a duplicate with conflicting content still separately
    /// proves the origin double-signed (`commitment_equivocation`/
    /// `public_origin_fault`), but the leader's packaging fault is
    /// provable either way, matching or conflicting content alike.
    DuplicateChunkOrigin,
}

impl DkgLeaderPublicFaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidManifest => "invalid_manifest",
            Self::ChunkIndexOutOfRange => "chunk_index_out_of_range",
            Self::OversizedChunk => "oversized_chunk",
            Self::DuplicateChunkOrigin => "duplicate_chunk_origin",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "invalid_manifest" => Ok(Self::InvalidManifest),
            "chunk_index_out_of_range" => Ok(Self::ChunkIndexOutOfRange),
            "oversized_chunk" => Ok(Self::OversizedChunk),
            "duplicate_chunk_origin" => Ok(Self::DuplicateChunkOrigin),
            _ => Err(ReportingError::InvalidReport(format!(
                "unknown DKG leader public-fault kind {value}"
            ))),
        }
    }
}

/// A single leader-signed Gossip broadcast (manifest or chunk) that is
/// independently provable as invalid on its own, without a conflicting
/// counterpart — e.g. a manifest naming the wrong origin set for its phase,
/// or whose `complete` flag contradicts the phase's publication mode.
/// Reuses the same endpoint-authenticated delivery shape as
/// `DkgLeaderEquivocationStatement`, just with one delivery instead of two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgLeaderPublicFaultStatement {
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
    pub attempt_id: [u8; 32],
    pub phase: String,
    pub fault_kind: DkgLeaderPublicFaultKind,
    pub delivery_id: [u8; 16],
    pub delivery: EndpointSignedContribution,
}

impl DkgLeaderPublicFaultStatement {
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
        write_bytes(&mut out, &self.attempt_id);
        write_string(&mut out, &self.phase);
        write_string(&mut out, self.fault_kind.as_str());
        write_bytes(&mut out, &self.delivery_id);
        self.delivery.write_canonical(&mut out);
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
        let attempt_id =
            decoder
                .read_bytes("attempt_id")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG leader public-fault attempt_id must be 32 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let phase = decoder.read_string("phase")?;
        let fault_kind = DkgLeaderPublicFaultKind::from_str(&decoder.read_string("fault_kind")?)?;
        let delivery_id =
            decoder
                .read_bytes("delivery_id")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG leader public-fault delivery_id must be 16 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let delivery = EndpointSignedContribution::read_canonical(&mut decoder, "delivery")?;
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
            attempt_id,
            phase,
            fault_kind,
            delivery_id,
            delivery,
        })
    }
}

/// One node-key-signed control-handshake artifact
/// (`Prepare`/`Prepared`/`Activate`/`Activated`/`Begin`/`Begun`). `data` is
/// whatever content that message kind's signature actually covers: the
/// canonically-encoded `PrepareSession` for `prepare` (so a verifier can
/// recompute `config_digest` and inspect `leader_node_key`/`committees`
/// directly), or the raw 32-byte `config_digest`/`activation_digest` for the
/// ack kinds (already bound to ceremony/attempt/message_kind by the
/// signature itself, so nothing else needs duplicating). `signed_at` is the
/// signer's own claimed timestamp, bound into the signature by
/// `control_ack_signing_bytes` — carried here explicitly (rather than only
/// recovered by decoding `data`) because the ack kinds' `data` is just a
/// bare digest with no embedded timestamp to recover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlMessageArtifact {
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
    pub signed_at: u64,
}

impl ControlMessageArtifact {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        write_bytes(out, &self.signature);
        write_bytes(out, &self.data);
        write_u64(out, self.signed_at);
    }

    fn read_canonical(decoder: &mut Decoder<'_>, prefix: &str) -> Result<Self> {
        Ok(Self {
            signature: decoder.read_bytes(&format!("{prefix}_signature"))?,
            data: decoder.read_bytes(&format!("{prefix}_data"))?,
            signed_at: decoder.read_u64(&format!("{prefix}_signed_at"))?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgControlMessageFaultKind {
    /// One signed `Prepare`, independently provable as invalid: sent by a
    /// noncanonical leader, or naming committee routes/digests that
    /// contradict current Vera `NodeInfo`/ring state.
    LeaderPrepareFault,
    /// Two conflicting signed acks (`Prepared`/`Activated`/`Begun`) from the
    /// same follower for the identical (ceremony, attempt, message_kind)
    /// request — a single wrong/stale-looking ack is not enough on its own,
    /// since that can happen honestly on a retry race.
    AckEquivocation,
    /// One signed `PublicPhaseResponse` (a direct-QUIC repair-page reply)
    /// whose encoded size exceeds `MAX_PUBLIC_REPAIR_PAGE_BYTES` — a pure
    /// byte-length check against a fixed protocol constant, independently
    /// provable the same way `dkg_leader_public_fault`'s `oversized_chunk`
    /// is, just for the direct-QUIC repair path instead of Gossip.
    OversizedRepairPage,
}

impl DkgControlMessageFaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeaderPrepareFault => "leader_prepare_fault",
            Self::AckEquivocation => "ack_equivocation",
            Self::OversizedRepairPage => "oversized_repair_page",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "leader_prepare_fault" => Ok(Self::LeaderPrepareFault),
            "ack_equivocation" => Ok(Self::AckEquivocation),
            "oversized_repair_page" => Ok(Self::OversizedRepairPage),
            _ => Err(ReportingError::InvalidReport(format!(
                "unknown DKG control-message fault kind {value}"
            ))),
        }
    }
}

/// Normalized bindings plus the exact node-key-signed control-handshake
/// artifact(s). Unlike `DkgPublicOriginFaultStatement`/
/// `DkgLeaderEquivocationStatement` (endpoint-signed), these are signed with
/// the accused's chain node key directly, since direct-QUIC control
/// messages carry no reclaimable transport-layer signature the way Gossip
/// broadcasts do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgControlMessageFaultStatement {
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
    pub attempt_id: [u8; 32],
    pub message_kind: String,
    pub fault_kind: DkgControlMessageFaultKind,
    pub artifact_a: ControlMessageArtifact,
    pub artifact_b: Option<ControlMessageArtifact>,
}

impl DkgControlMessageFaultStatement {
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
        write_bytes(&mut out, &self.attempt_id);
        write_string(&mut out, &self.message_kind);
        write_string(&mut out, self.fault_kind.as_str());
        self.artifact_a.write_canonical(&mut out);
        match &self.artifact_b {
            Some(artifact) => {
                out.push(1);
                artifact.write_canonical(&mut out);
            }
            None => out.push(0),
        }
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
        let attempt_id =
            decoder
                .read_bytes("attempt_id")?
                .try_into()
                .map_err(|bytes: Vec<u8>| {
                    ReportingError::InvalidReport(format!(
                        "DKG control-message fault attempt_id must be 32 bytes, got {}",
                        bytes.len()
                    ))
                })?;
        let message_kind = decoder.read_string("message_kind")?;
        let fault_kind = DkgControlMessageFaultKind::from_str(&decoder.read_string("fault_kind")?)?;
        let artifact_a = ControlMessageArtifact::read_canonical(&mut decoder, "artifact_a")?;
        let artifact_b = match decoder.read_u8("artifact_b_present")? {
            0 => None,
            1 => Some(ControlMessageArtifact::read_canonical(
                &mut decoder,
                "artifact_b",
            )?),
            value => {
                return Err(ReportingError::InvalidReport(format!(
                    "invalid optional artifact_b tag {value}"
                )))
            }
        };
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
            attempt_id,
            message_kind,
            fault_kind,
            artifact_a,
            artifact_b,
        })
    }
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
