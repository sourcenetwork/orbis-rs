//! The generic, backend-agnostic report container and its out-of-band
//! inline-document evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reporting::v0::error::{ReportingError, Result};

use super::codec::{write_bytes, write_string, write_u64};
use super::{REPORT_DOMAIN, REPORT_TTL_SECS};

/// The document fields needed to independently re-derive `object_id` via
/// `generate_document_id`, so a co-signer can verify a report's evidence is genuinely bound to
/// `object_id` without reading it from the bulletin — and, for the PRE proof refutation, to
/// recover `enc_cmt` via `deserialize_secret`. Populated only for requests whose document was
/// supplied inline (never posted to the bulletin) — see `PreRequestContext::document`.
///
/// This is **never** part of any canonical (threshold-signed, on-chain) encoding: the ciphertext
/// would otherwise be persisted on chain for no functional reason (the chain discards it). It
/// travels to co-signers out-of-band in [`ReportSigningContext`] instead; the signed statement
/// keeps only `object_id` (already a SHA-256 commitment to every field here) plus a
/// `document_inline` bool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedDocumentEvidence {
    pub document: String,
    pub proof: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
    pub tier: Option<String>,
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
    /// Out-of-band evidence for a report whose PRE request carried its document inline (the
    /// statement's `document_inline` is set). Carried here rather than in the threshold-signed,
    /// on-chain envelope so the document ciphertext is never persisted on chain — co-signers use
    /// it to re-derive `object_id` and recover `enc_cmt`, then discard it. `None` for every
    /// bulletin-sourced report.
    #[serde(default)]
    pub inline_document: Option<ReportedDocumentEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReport {
    pub report: ReportEnvelope,
    pub report_id: String,
    pub signature_scheme: String,
    pub signature: String,
}
