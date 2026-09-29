//! Canonical digests, signed statements, and the blinding certificate for
//! the PET blind equality test — see
//! `docs/plans/pet-blind-equality-test-design.md` for the full protocol and
//! `docs/plans/lazy-gliding-gosling.md`'s Stage 2 scope for what this file
//! covers. This replaces `pet.rs`'s single-round `PetCheckResponseStatement`
//! protocol rather than extending it: a genuine `Z·R` decryption proof would
//! not verify against that statement's shape, and must not be coerced into
//! it.
//!
//! Three digests bind the protocol together:
//! - `context_digest` ([`PetBlindContext::context_digest`]) — every
//!   participant recomputes this from independently verified inputs; it is
//!   never trusted from the coordinator. Mirrors the role
//!   `pet::v0::attestation::PetCheckStatementContext` plays for the old
//!   protocol, but lives here since every other Stage 2 type does too.
//! - `selection_digest` ([`pet_blind_selection_digest`]) — binds the exact
//!   selected `threshold`-sized commitment list every reveal endorses.
//! - `certificate_digest` ([`PetBlindCertificate::certificate_digest`]) —
//!   covers the complete certificate; decrypt responses bind this plus both
//!   reconstructed aggregate points.
//!
//! Digests are `[u8; 32]`, not hex strings — unlike `ring_state_sha256`
//! elsewhere in this module, these travel inside canonically-encoded signed
//! statements (`PetBlindRevealStatement`/`PetBlindDecryptStatement`), where
//! a fixed-width encoding removes any hex-case or round-trip ambiguity.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reporting::v0::error::Result;

use super::{
    PET_BLIND_CERTIFICATE_DOMAIN, PET_BLIND_COMMIT_DOMAIN, PET_BLIND_CONTEXT_DOMAIN,
    PET_BLIND_PROOF_TRANSCRIPT_DOMAIN, PET_BLIND_SELECTION_DOMAIN,
};

use super::codec::{
    write_bytes, write_fixed_32, write_optional_string, write_optional_u64, write_string,
    write_u32, write_u64, Decoder,
};

/// Everything the `context_digest` binds, per the design doc: "at least the
/// chain, protocol version/crypto suite, ring identity/state, authoritative
/// PET checking key and share-generation/public-polynomial identifier,
/// validated document/tag digest (including the existing document
/// salt/timestamp binding), exact audit target, and authenticated audit
/// scope... the authenticated coordinator identity and attempt as well."
///
/// `pet_pk` alone serves as both the checking key and the
/// share-generation/public-polynomial identifier: PET keys have no
/// refresh/reshare path (see `RingShareBundle::save_by_pet_ring_key`'s doc
/// comment), so a ring never has more than one PET key generation to
/// disambiguate. `object_id`/`salt`/`timestamp`/`document_inline` mirror
/// `PetCheckStatementContext`'s existing document/tag locator fields
/// exactly, and `actor_id`/`valid_window_start`/`valid_window_end` mirror
/// `RelayRequestStatement`'s existing authorized-scope binding.
///
/// This struct never itself travels on the wire — only its digest does
/// (e.g. `CommitResponse::context_digest`). Building one from a live
/// `PetCheckContext` and ring state is a later stage's concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetBlindContext {
    pub chain_id: String,
    pub protocol_version: u64,
    pub crypto_backend: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub pet_pk: String,
    pub object_id: String,
    pub salt: Option<String>,
    pub timestamp: Option<u64>,
    pub document_inline: bool,
    pub audit_target_object_id: String,
    pub actor_id: String,
    pub valid_window_start: Option<u64>,
    pub valid_window_end: Option<u64>,
    pub coordinator_node_key: String,
    pub attempt_id: String,
}

impl PetBlindContext {
    pub fn context_digest(&self) -> [u8; 32] {
        let mut out = Vec::new();
        write_string(&mut out, PET_BLIND_CONTEXT_DOMAIN);
        out.extend_from_slice(&self.canonical_bytes());
        Sha256::digest(&out).into()
    }

    /// Field order only needs to be stable for `context_digest`'s own hash to be
    /// deterministic — unlike every other canonical-bytes method in this file, this one's output
    /// never itself travels on the wire or on chain. `PetBlindContext` values travel out-of-band
    /// (via `ReportSigningContext`/`ReportValidationContext`, serde-encoded) exactly like
    /// `ReportedDocumentEvidence`, precisely so the audit target and every other context field
    /// are never published on chain — see `reporting::v0::types::invalid_crypto`'s
    /// `PetBlindReveal`/`PetBlindDecrypt` doc comments.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, &self.chain_id);
        write_u64(&mut out, self.protocol_version);
        write_string(&mut out, &self.crypto_backend);
        write_string(&mut out, &self.ring_id);
        write_string(&mut out, &self.ring_pk);
        write_string(&mut out, &self.ring_state_sha256);
        write_string(&mut out, &self.pet_pk);
        write_string(&mut out, &self.object_id);
        write_optional_string(&mut out, self.salt.as_deref());
        write_optional_u64(&mut out, self.timestamp);
        out.push(u8::from(self.document_inline));
        write_string(&mut out, &self.audit_target_object_id);
        write_string(&mut out, &self.actor_id);
        write_optional_u64(&mut out, self.valid_window_start);
        write_optional_u64(&mut out, self.valid_window_end);
        write_string(&mut out, &self.coordinator_node_key);
        write_string(&mut out, &self.attempt_id);
        out
    }
}

/// `C_i = H(encode(COMMIT_DOMAIN, attempt_id, context_digest, i,
/// commit_salt_i, A_i, B_i))` — the commit-phase commitment hash a
/// responder publishes in `CommitResponse` and later opens in
/// `RevealResponse`. `blinded_r`/`blinded_diff` are the serialized
/// `A_i = z_i·R`/`B_i = z_i·(T-Y)` points.
pub fn pet_blind_commit_hash(
    attempt_id: &str,
    context_digest: &[u8; 32],
    node_id: u32,
    commit_salt: &[u8; 32],
    blinded_r: &[u8],
    blinded_diff: &[u8],
) -> [u8; 32] {
    let mut out = Vec::new();
    write_string(&mut out, PET_BLIND_COMMIT_DOMAIN);
    write_string(&mut out, attempt_id);
    write_fixed_32(&mut out, context_digest);
    write_u32(&mut out, node_id);
    write_fixed_32(&mut out, commit_salt);
    write_bytes(&mut out, blinded_r);
    write_bytes(&mut out, blinded_diff);
    Sha256::digest(&out).into()
}

/// `selection_digest = H(encode(SELECTION_DOMAIN, attempt_id,
/// context_digest, sorted_selected_commitments))` — binds the exact
/// `threshold`-sized selected list every reveal endorses. `commitments` is
/// sorted by node id internally, so callers need not agree on input order
/// to agree on the digest — only on the selected set and its `C_i` values.
pub fn pet_blind_selection_digest(
    attempt_id: &str,
    context_digest: &[u8; 32],
    commitments: &[(u32, [u8; 32])],
) -> [u8; 32] {
    let mut sorted = commitments.to_vec();
    sorted.sort_by_key(|(node_id, _)| *node_id);

    let mut out = Vec::new();
    write_string(&mut out, PET_BLIND_SELECTION_DOMAIN);
    write_string(&mut out, attempt_id);
    write_fixed_32(&mut out, context_digest);
    write_u32(&mut out, sorted.len() as u32);
    for (node_id, commitment) in &sorted {
        write_u32(&mut out, *node_id);
        write_fixed_32(&mut out, commitment);
    }
    Sha256::digest(&out).into()
}

/// The digest fed into `Pet::prove_blinding_correctness`/
/// `verify_blinding_correctness`'s `blind_transcript_digest` parameter —
/// binds the attempt, context, selection, claimed participant, and that
/// participant's own commitment. Computed only once the selected list (and
/// hence `selection_digest`) is known, i.e. at reveal time, never at commit
/// time — see `pending_blind`'s module doc comment for why the crypto-level
/// proof itself cannot be generated any earlier.
pub fn pet_blind_proof_transcript_digest(
    attempt_id: &str,
    context_digest: &[u8; 32],
    selection_digest: &[u8; 32],
    node_id: u32,
    commitment: &[u8; 32],
) -> [u8; 32] {
    let mut out = Vec::new();
    write_string(&mut out, PET_BLIND_PROOF_TRANSCRIPT_DOMAIN);
    write_string(&mut out, attempt_id);
    write_fixed_32(&mut out, context_digest);
    write_fixed_32(&mut out, selection_digest);
    write_u32(&mut out, node_id);
    write_fixed_32(&mut out, commitment);
    Sha256::digest(&out).into()
}

/// The canonical, signed content of a round-2 `RevealResponse` — everything
/// but the transport-level `request_id` and the `response_signature` itself.
/// Endorses both this node's own commitment opening and the entire selected
/// list (`selection_digest`), so a non-opening reveal is attributable
/// without a separate signature on the commit-phase response, and a
/// coordinator cannot forge a signed, inconsistent reveal — see the design
/// doc's "Round 2 — Reveal" section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetBlindRevealStatement {
    pub domain: String,
    /// `chain_id`/`ring_id`/`ring_pk`/`ring_state_sha256`/`protocol_version` bind this statement
    /// to its report envelope the same way `PreReencryptResponseStatement`'s own copies do — the
    /// chain-side validator (`validateInvalidCryptoResponseStatement` in Vera's `report.go`) has
    /// no access to `PetBlindContext` (it travels out-of-band, never on chain) and can only bind
    /// evidence to the envelope using fields the statement itself carries. None of these four
    /// leak anything: they're already plaintext, top-level `ReportEnvelope` fields on the same
    /// submission.
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub attempt_id: String,
    pub context_digest: [u8; 32],
    pub selection_digest: [u8; 32],
    pub responder_node_key: String,
    pub from_node_id: u32,
    /// This node's own `C_i`, re-endorsed (not just claimed via
    /// `from_node_id`/`responder_node_key`).
    pub commitment: Vec<u8>,
    /// Serialized `A_i = z_i·R`.
    pub blinded_r: Vec<u8>,
    /// Serialized `B_i = z_i·(T-Y)` — may legitimately be the identity
    /// point (an exact pre-blinding match); only `blinded_r` is guaranteed
    /// nonidentity.
    pub blinded_diff: Vec<u8>,
    /// Opens `commitment`; never `z_i` itself.
    pub commit_salt: [u8; 32],
    /// Serialized `Pet::ShareValue` — the blinding-correctness proof's
    /// Fiat-Shamir challenge.
    pub challenge: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the blinding-correctness proof's
    /// response.
    pub proof: Vec<u8>,
    pub signed_at: u64,
}

impl PetBlindRevealStatement {
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
        write_string(&mut out, &self.attempt_id);
        write_fixed_32(&mut out, &self.context_digest);
        write_fixed_32(&mut out, &self.selection_digest);
        write_string(&mut out, &self.responder_node_key);
        write_u32(&mut out, self.from_node_id);
        write_bytes(&mut out, &self.commitment);
        write_bytes(&mut out, &self.blinded_r);
        write_bytes(&mut out, &self.blinded_diff);
        write_fixed_32(&mut out, &self.commit_salt);
        write_bytes(&mut out, &self.challenge);
        write_bytes(&mut out, &self.proof);
        write_u64(&mut out, self.signed_at);
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
        let attempt_id = decoder.read_string("attempt_id")?;
        let context_digest = decoder.read_fixed_32("context_digest")?;
        let selection_digest = decoder.read_fixed_32("selection_digest")?;
        let responder_node_key = decoder.read_string("responder_node_key")?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let commitment = decoder.read_bytes("commitment")?;
        let blinded_r = decoder.read_bytes("blinded_r")?;
        let blinded_diff = decoder.read_bytes("blinded_diff")?;
        let commit_salt = decoder.read_fixed_32("commit_salt")?;
        let challenge = decoder.read_bytes("challenge")?;
        let proof = decoder.read_bytes("proof")?;
        let signed_at = decoder.read_u64("signed_at")?;
        decoder.finish()?;
        Ok(Self {
            domain,
            chain_id,
            ring_id,
            ring_pk,
            ring_state_sha256,
            protocol_version,
            attempt_id,
            context_digest,
            selection_digest,
            responder_node_key,
            from_node_id,
            commitment,
            blinded_r,
            blinded_diff,
            commit_salt,
            challenge,
            proof,
            signed_at,
        })
    }
}

/// A [`PetBlindRevealStatement`] paired with the signature over its
/// `canonical_bytes()` — the unit a [`PetBlindCertificate`] collects one of
/// per selected node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetBlindSignedReveal {
    pub statement: PetBlindRevealStatement,
    pub response_signature: Vec<u8>,
}

/// A [`PetBlindDecryptStatement`] paired with the signature over its
/// `canonical_bytes()` — the portable unit forwarded to PRE peers (alongside
/// the [`PetBlindCertificate`] itself) so each one can independently
/// reconstruct and check the final equality without trusting the
/// initiator's word. Mirrors [`PetBlindSignedReveal`]'s exact shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetBlindSignedDecrypt {
    pub statement: PetBlindDecryptStatement,
    pub response_signature: Vec<u8>,
}

/// The canonical, signed content of a round-3 `DecryptResponse`. Binds
/// `certificate_digest` plus both reconstructed aggregate points, since the
/// reusable decryption DLEQ arithmetic alone (unchanged from today's
/// single-round protocol) does not express which certificate/attempt this
/// decryption share belongs to — see the design doc's "Round 3 — Decrypt"
/// section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetBlindDecryptStatement {
    pub domain: String,
    /// See [`PetBlindRevealStatement`]'s matching fields' doc comment — same rationale, same
    /// chain-side consumer.
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub attempt_id: String,
    pub context_digest: [u8; 32],
    pub certificate_digest: [u8; 32],
    pub responder_node_key: String,
    pub from_node_id: u32,
    /// Serialized reconstructed `Z·R`.
    pub aggregate_r: Vec<u8>,
    /// Serialized reconstructed `Z·(T-Y)`.
    pub aggregate_diff: Vec<u8>,
    /// Serialized `Pet::PublicKey` — this node's `share_i·(Z·R)`.
    pub partial: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the existing per-share decryption
    /// DLEQ's Fiat-Shamir challenge, unchanged, run against `Z·R` in place
    /// of today's `R`.
    pub challenge: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the decryption DLEQ's response.
    pub proof: Vec<u8>,
    pub signed_at: u64,
}

impl PetBlindDecryptStatement {
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
        write_string(&mut out, &self.attempt_id);
        write_fixed_32(&mut out, &self.context_digest);
        write_fixed_32(&mut out, &self.certificate_digest);
        write_string(&mut out, &self.responder_node_key);
        write_u32(&mut out, self.from_node_id);
        write_bytes(&mut out, &self.aggregate_r);
        write_bytes(&mut out, &self.aggregate_diff);
        write_bytes(&mut out, &self.partial);
        write_bytes(&mut out, &self.challenge);
        write_bytes(&mut out, &self.proof);
        write_u64(&mut out, self.signed_at);
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
        let attempt_id = decoder.read_string("attempt_id")?;
        let context_digest = decoder.read_fixed_32("context_digest")?;
        let certificate_digest = decoder.read_fixed_32("certificate_digest")?;
        let responder_node_key = decoder.read_string("responder_node_key")?;
        let from_node_id = decoder.read_u32("from_node_id")?;
        let aggregate_r = decoder.read_bytes("aggregate_r")?;
        let aggregate_diff = decoder.read_bytes("aggregate_diff")?;
        let partial = decoder.read_bytes("partial")?;
        let challenge = decoder.read_bytes("challenge")?;
        let proof = decoder.read_bytes("proof")?;
        let signed_at = decoder.read_u64("signed_at")?;
        decoder.finish()?;
        Ok(Self {
            domain,
            chain_id,
            ring_id,
            ring_pk,
            ring_state_sha256,
            protocol_version,
            attempt_id,
            context_digest,
            certificate_digest,
            responder_node_key,
            from_node_id,
            aggregate_r,
            aggregate_diff,
            partial,
            challenge,
            proof,
            signed_at,
        })
    }
}

/// The complete round-2 output: the exact selected commitment list and
/// every selected node's signed reveal, opening, and proof. A verifier
/// (the initiator, any decryptor, PRE admission, or a reporting validator)
/// must reject missing, duplicate, extra, mixed-context, or
/// mixed-selection entries — see `verify_pet_blind_certificate` (a later
/// stage) for that shared check. This struct only carries the data and
/// computes its own digest; it does not validate itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetBlindCertificate {
    pub attempt_id: String,
    pub context_digest: [u8; 32],
    /// The exact selected list, in canonical (node-id-sorted) order — not
    /// every over-asked candidate from round 1.
    pub all_commitments: Vec<(u32, Vec<u8>)>,
    /// One complete signed reveal from each selected node.
    pub reveals: Vec<PetBlindSignedReveal>,
}

impl PetBlindCertificate {
    /// Covers the entire public certificate. Decrypt responses bind this
    /// digest plus both reconstructed aggregate points.
    pub fn certificate_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Field order is the canonical wire contract — the chain-side (Go)
    /// decoder must read fields in exactly this order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, PET_BLIND_CERTIFICATE_DOMAIN);
        write_string(&mut out, &self.attempt_id);
        write_fixed_32(&mut out, &self.context_digest);
        write_u32(&mut out, self.all_commitments.len() as u32);
        for (node_id, commitment) in &self.all_commitments {
            write_u32(&mut out, *node_id);
            write_bytes(&mut out, commitment);
        }
        write_u32(&mut out, self.reveals.len() as u32);
        for reveal in &self.reveals {
            write_bytes(&mut out, &reveal.statement.canonical_bytes());
            write_bytes(&mut out, &reveal.response_signature);
        }
        out
    }

    /// Kept for API symmetry with every other canonical type in this file
    /// (and exercised by this file's own round-trip tests) even though no
    /// production caller decodes a certificate from raw canonical bytes
    /// today — a certificate travels over the wire via ordinary serde
    /// (de)serialization; only `certificate_digest()`/`canonical_bytes()`
    /// are called in production, to compute and check the digest.
    #[allow(dead_code)]
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let _domain = decoder.read_string("domain")?;
        let attempt_id = decoder.read_string("attempt_id")?;
        let context_digest = decoder.read_fixed_32("context_digest")?;

        let commitment_count = decoder.read_u32("all_commitments_count")? as usize;
        let mut all_commitments = Vec::with_capacity(commitment_count);
        for _ in 0..commitment_count {
            let node_id = decoder.read_u32("all_commitments_node_id")?;
            let commitment = decoder.read_bytes("all_commitments_commitment")?;
            all_commitments.push((node_id, commitment));
        }

        let reveal_count = decoder.read_u32("reveals_count")? as usize;
        let mut reveals = Vec::with_capacity(reveal_count);
        for _ in 0..reveal_count {
            let statement_bytes = decoder.read_bytes("reveals_statement")?;
            let statement = PetBlindRevealStatement::from_canonical_bytes(&statement_bytes)?;
            let response_signature = decoder.read_bytes("reveals_response_signature")?;
            reveals.push(PetBlindSignedReveal {
                statement,
                response_signature,
            });
        }

        decoder.finish()?;
        Ok(Self {
            attempt_id,
            context_digest,
            all_commitments,
            reveals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PET_BLIND_DECRYPT_RESPONSE_DOMAIN, PET_BLIND_REVEAL_RESPONSE_DOMAIN};
    use super::*;

    fn context() -> PetBlindContext {
        PetBlindContext {
            chain_id: "vera-test".to_string(),
            protocol_version: 0,
            crypto_backend: "bls12_381".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            pet_pk: "ccdd".to_string(),
            object_id: "derivation-1".to_string(),
            salt: Some("salt-1".to_string()),
            timestamp: Some(1_700_000_000),
            document_inline: false,
            audit_target_object_id: "target-1".to_string(),
            actor_id: "did:key:z6Mkactor".to_string(),
            valid_window_start: Some(1_699_999_000),
            valid_window_end: Some(1_700_001_000),
            coordinator_node_key: "coordinator".to_string(),
            attempt_id: "attempt-1".to_string(),
        }
    }

    #[test]
    fn context_digest_is_deterministic() {
        assert_eq!(context().context_digest(), context().context_digest());
    }

    #[test]
    fn context_digest_changes_with_every_field() {
        let base = context().context_digest();

        let mut chain = context();
        chain.chain_id = "vera-other".to_string();
        assert_ne!(chain.context_digest(), base);

        let mut protocol_version = context();
        protocol_version.protocol_version = 1;
        assert_ne!(protocol_version.context_digest(), base);

        let mut backend = context();
        backend.crypto_backend = "decaf377".to_string();
        assert_ne!(backend.context_digest(), base);

        let mut ring_id = context();
        ring_id.ring_id = "ring-2".to_string();
        assert_ne!(ring_id.context_digest(), base);

        let mut ring_pk = context();
        ring_pk.ring_pk = "eeff".to_string();
        assert_ne!(ring_pk.context_digest(), base);

        let mut ring_state = context();
        ring_state.ring_state_sha256 = "22".repeat(32);
        assert_ne!(ring_state.context_digest(), base);

        let mut pet_pk = context();
        pet_pk.pet_pk = "ffff".to_string();
        assert_ne!(pet_pk.context_digest(), base);

        let mut object_id = context();
        object_id.object_id = "derivation-2".to_string();
        assert_ne!(object_id.context_digest(), base);

        let mut salt = context();
        salt.salt = None;
        assert_ne!(salt.context_digest(), base);

        let mut timestamp = context();
        timestamp.timestamp = None;
        assert_ne!(timestamp.context_digest(), base);

        let mut inline = context();
        inline.document_inline = true;
        assert_ne!(inline.context_digest(), base);

        let mut target = context();
        target.audit_target_object_id = "target-2".to_string();
        assert_ne!(target.context_digest(), base);

        let mut actor = context();
        actor.actor_id = "did:key:z6Mkother".to_string();
        assert_ne!(actor.context_digest(), base);

        let mut window_start = context();
        window_start.valid_window_start = None;
        assert_ne!(window_start.context_digest(), base);

        let mut window_end = context();
        window_end.valid_window_end = None;
        assert_ne!(window_end.context_digest(), base);

        let mut coordinator = context();
        coordinator.coordinator_node_key = "other-coordinator".to_string();
        assert_ne!(coordinator.context_digest(), base);

        let mut attempt = context();
        attempt.attempt_id = "attempt-2".to_string();
        assert_ne!(attempt.context_digest(), base);
    }

    #[test]
    fn commit_hash_changes_with_every_field() {
        let attempt_id = "attempt-1";
        let ctx_digest = [1u8; 32];
        let salt = [2u8; 32];
        let base = pet_blind_commit_hash(attempt_id, &ctx_digest, 3, &salt, &[4, 5], &[6, 7]);

        assert_ne!(
            base,
            pet_blind_commit_hash("attempt-2", &ctx_digest, 3, &salt, &[4, 5], &[6, 7])
        );
        assert_ne!(
            base,
            pet_blind_commit_hash(attempt_id, &[9u8; 32], 3, &salt, &[4, 5], &[6, 7])
        );
        assert_ne!(
            base,
            pet_blind_commit_hash(attempt_id, &ctx_digest, 4, &salt, &[4, 5], &[6, 7])
        );
        assert_ne!(
            base,
            pet_blind_commit_hash(attempt_id, &ctx_digest, 3, &[9u8; 32], &[4, 5], &[6, 7])
        );
        assert_ne!(
            base,
            pet_blind_commit_hash(attempt_id, &ctx_digest, 3, &salt, &[9, 9], &[6, 7])
        );
        assert_ne!(
            base,
            pet_blind_commit_hash(attempt_id, &ctx_digest, 3, &salt, &[4, 5], &[9, 9])
        );
    }

    #[test]
    fn selection_digest_is_order_independent() {
        let attempt_id = "attempt-1";
        let ctx_digest = [1u8; 32];
        let forward = [(1u32, [2u8; 32]), (2u32, [3u8; 32]), (3u32, [4u8; 32])];
        let mut shuffled = forward;
        shuffled.reverse();

        assert_eq!(
            pet_blind_selection_digest(attempt_id, &ctx_digest, &forward),
            pet_blind_selection_digest(attempt_id, &ctx_digest, &shuffled)
        );
    }

    #[test]
    fn selection_digest_changes_with_the_selected_set() {
        let attempt_id = "attempt-1";
        let ctx_digest = [1u8; 32];
        let base = [(1u32, [2u8; 32]), (2u32, [3u8; 32])];
        let different_commitment = [(1u32, [2u8; 32]), (2u32, [9u8; 32])];
        let different_membership = [(1u32, [2u8; 32]), (3u32, [3u8; 32])];

        let base_digest = pet_blind_selection_digest(attempt_id, &ctx_digest, &base);
        assert_ne!(
            base_digest,
            pet_blind_selection_digest(attempt_id, &ctx_digest, &different_commitment)
        );
        assert_ne!(
            base_digest,
            pet_blind_selection_digest(attempt_id, &ctx_digest, &different_membership)
        );
        assert_ne!(
            base_digest,
            pet_blind_selection_digest("attempt-2", &ctx_digest, &base)
        );
    }

    #[test]
    fn proof_transcript_digest_changes_with_every_field() {
        let base =
            pet_blind_proof_transcript_digest("attempt-1", &[1u8; 32], &[2u8; 32], 3, &[4u8; 32]);
        assert_ne!(
            base,
            pet_blind_proof_transcript_digest("attempt-2", &[1u8; 32], &[2u8; 32], 3, &[4u8; 32])
        );
        assert_ne!(
            base,
            pet_blind_proof_transcript_digest("attempt-1", &[9u8; 32], &[2u8; 32], 3, &[4u8; 32])
        );
        assert_ne!(
            base,
            pet_blind_proof_transcript_digest("attempt-1", &[1u8; 32], &[9u8; 32], 3, &[4u8; 32])
        );
        assert_ne!(
            base,
            pet_blind_proof_transcript_digest("attempt-1", &[1u8; 32], &[2u8; 32], 4, &[4u8; 32])
        );
        assert_ne!(
            base,
            pet_blind_proof_transcript_digest("attempt-1", &[1u8; 32], &[2u8; 32], 3, &[9u8; 32])
        );
    }

    fn reveal_statement() -> PetBlindRevealStatement {
        PetBlindRevealStatement {
            domain: PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            attempt_id: "attempt-1".to_string(),
            context_digest: [1u8; 32],
            selection_digest: [2u8; 32],
            responder_node_key: "responder-1".to_string(),
            from_node_id: 3,
            commitment: vec![4, 5, 6],
            blinded_r: vec![7, 8],
            blinded_diff: vec![],
            commit_salt: [9u8; 32],
            challenge: vec![10, 11],
            proof: vec![12, 13],
            signed_at: 1_700_000_000,
        }
    }

    #[test]
    fn reveal_statement_round_trips() {
        let statement = reveal_statement();
        assert_eq!(
            PetBlindRevealStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
            statement
        );
    }

    #[test]
    fn reveal_statement_with_identity_diff_round_trips() {
        // blinded_diff may legitimately be an empty/identity encoding (an
        // exact pre-blinding match) — this must still round-trip cleanly,
        // not be treated as a missing field.
        let mut statement = reveal_statement();
        statement.blinded_diff = vec![];
        assert_eq!(
            PetBlindRevealStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
            statement
        );
    }

    fn decrypt_statement() -> PetBlindDecryptStatement {
        PetBlindDecryptStatement {
            domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            attempt_id: "attempt-1".to_string(),
            context_digest: [1u8; 32],
            certificate_digest: [2u8; 32],
            responder_node_key: "responder-1".to_string(),
            from_node_id: 3,
            aggregate_r: vec![4, 5],
            aggregate_diff: vec![6, 7],
            partial: vec![8, 9],
            challenge: vec![10, 11],
            proof: vec![12, 13],
            signed_at: 1_700_000_000,
        }
    }

    #[test]
    fn decrypt_statement_round_trips() {
        let statement = decrypt_statement();
        assert_eq!(
            PetBlindDecryptStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
            statement
        );
    }

    fn certificate() -> PetBlindCertificate {
        PetBlindCertificate {
            attempt_id: "attempt-1".to_string(),
            context_digest: [1u8; 32],
            all_commitments: vec![(1, vec![2, 3]), (2, vec![4, 5])],
            reveals: vec![
                PetBlindSignedReveal {
                    statement: reveal_statement(),
                    response_signature: vec![14, 15],
                },
                PetBlindSignedReveal {
                    statement: PetBlindRevealStatement {
                        from_node_id: 4,
                        responder_node_key: "responder-2".to_string(),
                        ..reveal_statement()
                    },
                    response_signature: vec![16, 17],
                },
            ],
        }
    }

    #[test]
    fn certificate_round_trips() {
        let cert = certificate();
        assert_eq!(
            PetBlindCertificate::from_canonical_bytes(&cert.canonical_bytes()).unwrap(),
            cert
        );
    }

    #[test]
    fn certificate_with_no_reveals_round_trips() {
        let mut cert = certificate();
        cert.reveals.clear();
        assert_eq!(
            PetBlindCertificate::from_canonical_bytes(&cert.canonical_bytes()).unwrap(),
            cert
        );
    }

    #[test]
    fn certificate_digest_changes_when_a_reveal_changes() {
        let base = certificate();
        let base_digest = base.certificate_digest();

        let mut different_reveal = base.clone();
        different_reveal.reveals[0].response_signature = vec![99];
        assert_ne!(different_reveal.certificate_digest(), base_digest);

        let mut different_commitments = base.clone();
        different_commitments.all_commitments[0].1 = vec![99];
        assert_ne!(different_commitments.certificate_digest(), base_digest);

        let mut different_attempt = base.clone();
        different_attempt.attempt_id = "attempt-2".to_string();
        assert_ne!(different_attempt.certificate_digest(), base_digest);

        let mut different_context = base.clone();
        different_context.context_digest = [9u8; 32];
        assert_ne!(different_context.certificate_digest(), base_digest);
    }

    #[test]
    fn certificate_digest_is_deterministic() {
        assert_eq!(
            certificate().certificate_digest(),
            certificate().certificate_digest()
        );
    }
}
