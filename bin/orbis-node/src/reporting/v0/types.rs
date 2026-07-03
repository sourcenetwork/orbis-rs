use crate::reporting::v0::error::{ReportingError, Result};
use bulletin::r#trait::RingPayload;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_DOMAIN: &str = "orbis-mpc-fault-report";
pub const NODE_OFFLINE_REPORT_TYPE: &str = "node_offline";
pub const PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE: &str = "pre_invalid_reencryption_proof";
pub const PRE_REENCRYPT_RESPONSE_DOMAIN: &str = "orbis-pre-reencrypt-response-v1";
pub const REPORT_TTL_SECS: u64 = 120;
/// Forward tolerance when checking `PreReencryptResponseStatement::signed_at`
/// against a local clock — a statement timestamped further in the future than
/// this is rejected.
pub const PRE_RESPONSE_MAX_CLOCK_SKEW_SECS: u64 = 60;
/// Maximum |observed_at - signed_at| allowed between a report envelope and the
/// evidence statement it carries. Anchoring the envelope to the evidence makes
/// the envelope's fixed `observed_at + REPORT_TTL_SECS` expiry double as the
/// evidence expiry, so the chain's existing expiry check bounds how long the
/// evidence stays submittable. Covers observed_at backdating (10s), responder
/// handling time, and clock skew.
pub const PRE_RESPONSE_OBSERVED_AT_SLACK_SECS: u64 = 90;

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
pub struct PreInvalidReencryptionProof {
    pub statement: PreReencryptResponseStatement,
    pub response_signature: Vec<u8>,
}

impl PreInvalidReencryptionProof {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_bytes(&mut out, &self.statement.canonical_bytes());
        write_bytes(&mut out, &self.response_signature);
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let statement_bytes = decoder.read_bytes("statement")?;
        let response_signature = decoder.read_bytes("response_signature")?;
        decoder.finish()?;
        let statement = PreReencryptResponseStatement::from_canonical_bytes(&statement_bytes)?;
        Ok(Self {
            statement,
            response_signature,
        })
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

fn write_demerit_config(out: &mut Vec<u8>, value: &bulletin::r#trait::DemeritConfig) {
    write_u64(out, value.node_offline_demerits);
    write_u64(out, value.reset_interval_seconds);
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
            signed_at: 1_700_000_000,
            responder_node_key: "accused".to_string(),
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
    fn pre_invalid_proof_payload_round_trips() {
        let payload = PreInvalidReencryptionProof {
            statement: pre_statement(),
            response_signature: vec![42; 64],
        };

        assert_eq!(
            PreInvalidReencryptionProof::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
            payload
        );
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
            "7da44e690e8cb8c223ee4ce80d35b12c7f41e92bbac5a114f89c26657b4148db"
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
