//! The `invalid_crypto_response` umbrella: one enum folding every PRE /
//! Sign / DKG evidence kind into a single canonical payload.

use serde::{Deserialize, Serialize};

use crate::dkg::v0::messages::SignedDkgCommitment;
use crate::reporting::v0::error::{ReportingError, Result};

use super::codec::{write_bytes, write_string, Decoder};
use super::dkg::{
    DkgCommitmentStatement, DkgControlMessageFaultStatement, DkgLeaderEquivocationStatement,
    DkgLeaderPublicFaultStatement, DkgPublicOriginFaultStatement, DkgShareStatement,
};
use super::pre_sign::{PreReencryptResponseStatement, SignResponseStatement};
use super::CommitteeScope;

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
    /// the same dealer (same ring/session/attempt/nonce, different bytes). Unlike the other
    /// kinds, the fault is the *conflict between two signed statements*, not one statement
    /// failing.
    DkgEquivocation {
        commitment_a: Box<SignedDkgCommitment>,
        commitment_b: Box<SignedDkgCommitment>,
    },
    /// An endpoint-authenticated Refresh/Reshare public contribution whose
    /// payload is independently provable as invalid, or a pair of conflicting
    /// non-Commitment contributions from the same origin.
    DkgPublicOriginFault {
        statement: Box<DkgPublicOriginFaultStatement>,
    },
    /// The canonical leader of a public-plane batch signed two conflicting
    /// Gossip broadcasts (a manifest, or a chunk) for the same phase and
    /// coordinate. Unlike `DkgPublicOriginFault`, the fault is the leader's
    /// own packaging act, not any origin's contribution content.
    DkgLeaderEquivocation {
        statement: Box<DkgLeaderEquivocationStatement>,
    },
    /// A single leader-signed Gossip broadcast that is independently
    /// provable as invalid on its own — e.g. a manifest naming the wrong
    /// origin set for its phase. Unlike `DkgLeaderEquivocation`, there is no
    /// conflicting counterpart; the one delivery self-condemns.
    DkgLeaderPublicFault {
        statement: Box<DkgLeaderPublicFaultStatement>,
    },
    /// Two leader-signed Gossip broadcasts (any combination of manifest and
    /// chunk) that each reference the same origin (same `ParticipantRef`,
    /// same `MessageId`) under two *different* phase roots. Reuses
    /// `DkgLeaderEquivocationStatement`'s shape (it's the same "two signed
    /// deliveries, same phase" wire format) under a distinct domain/kind —
    /// the fault predicate differs from `DkgLeaderEquivocation` (different
    /// coordinate, shared origin, rather than same coordinate, different
    /// content).
    DkgLeaderBatchMismatch {
        statement: Box<DkgLeaderEquivocationStatement>,
    },
    /// A direct-QUIC control-handshake fault: a noncanonical leader's
    /// `Prepare`, a `Prepare` whose routes/digests contradict Vera, or
    /// a follower equivocating on a `Prepared`/`Activated`/`Begun` ack.
    DkgControlMessageFault {
        statement: Box<DkgControlMessageFaultStatement>,
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
            Self::DkgPublicOriginFault { statement } => {
                write_string(&mut out, "dkg_public_origin_fault");
                write_bytes(&mut out, &statement.canonical_bytes());
            }
            Self::DkgLeaderEquivocation { statement } => {
                write_string(&mut out, "dkg_leader_equivocation");
                write_bytes(&mut out, &statement.canonical_bytes());
            }
            Self::DkgLeaderPublicFault { statement } => {
                write_string(&mut out, "dkg_leader_public_fault");
                write_bytes(&mut out, &statement.canonical_bytes());
            }
            Self::DkgLeaderBatchMismatch { statement } => {
                write_string(&mut out, "dkg_leader_batch_mismatch");
                write_bytes(&mut out, &statement.canonical_bytes());
            }
            Self::DkgControlMessageFault { statement } => {
                write_string(&mut out, "dkg_control_message_fault");
                write_bytes(&mut out, &statement.canonical_bytes());
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
            "dkg_public_origin_fault" => {
                let statement = decoder.read_bytes("statement")?;
                Self::DkgPublicOriginFault {
                    statement: Box::new(DkgPublicOriginFaultStatement::from_canonical_bytes(
                        &statement,
                    )?),
                }
            }
            "dkg_leader_equivocation" => {
                let statement = decoder.read_bytes("statement")?;
                Self::DkgLeaderEquivocation {
                    statement: Box::new(DkgLeaderEquivocationStatement::from_canonical_bytes(
                        &statement,
                    )?),
                }
            }
            "dkg_leader_public_fault" => {
                let statement = decoder.read_bytes("statement")?;
                Self::DkgLeaderPublicFault {
                    statement: Box::new(DkgLeaderPublicFaultStatement::from_canonical_bytes(
                        &statement,
                    )?),
                }
            }
            "dkg_leader_batch_mismatch" => {
                let statement = decoder.read_bytes("statement")?;
                Self::DkgLeaderBatchMismatch {
                    statement: Box::new(DkgLeaderEquivocationStatement::from_canonical_bytes(
                        &statement,
                    )?),
                }
            }
            "dkg_control_message_fault" => {
                let statement = decoder.read_bytes("statement")?;
                Self::DkgControlMessageFault {
                    statement: Box::new(DkgControlMessageFaultStatement::from_canonical_bytes(
                        &statement,
                    )?),
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
            Self::DkgPublicOriginFault { statement } => &statement.request_id,
            Self::DkgLeaderEquivocation { statement } => &statement.request_id,
            Self::DkgLeaderPublicFault { statement } => &statement.request_id,
            Self::DkgLeaderBatchMismatch { statement } => &statement.request_id,
            Self::DkgControlMessageFault { statement } => &statement.request_id,
        }
    }

    /// The DKG attempt this evidence targets, or `None` for `Pre`/`Sign` —
    /// those aren't DKG-ceremony-scoped and have no `attempt_id` field at
    /// all (matches RPT-16's chain-side dedupe key, which folds this in for
    /// exactly the same set of DKG evidence kinds and leaves PRE/Sign
    /// ceremony-scoped by `request_id` alone).
    pub fn attempt_id(&self) -> Option<[u8; 32]> {
        match self {
            Self::Pre { .. } => None,
            Self::Sign { .. } => None,
            Self::DkgShare { statement, .. } => Some(statement.commitment_statement.attempt_id),
            Self::DkgInvalidRefreshCommitment { statement, .. } => Some(statement.attempt_id),
            Self::DkgEquivocation { commitment_a, .. } => Some(commitment_a.statement.attempt_id),
            Self::DkgPublicOriginFault { statement } => Some(statement.attempt_id),
            Self::DkgLeaderEquivocation { statement } => Some(statement.attempt_id),
            Self::DkgLeaderPublicFault { statement } => Some(statement.attempt_id),
            Self::DkgLeaderBatchMismatch { statement } => Some(statement.attempt_id),
            Self::DkgControlMessageFault { statement } => Some(statement.attempt_id),
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
            Self::DkgPublicOriginFault { statement } => statement.signing_committee_scope,
            Self::DkgLeaderEquivocation { statement } => statement.signing_committee_scope,
            Self::DkgLeaderPublicFault { statement } => statement.signing_committee_scope,
            Self::DkgLeaderBatchMismatch { statement } => statement.signing_committee_scope,
            Self::DkgControlMessageFault { statement } => statement.signing_committee_scope,
        }
    }
}
