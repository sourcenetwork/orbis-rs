use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicViolationAccused {
    Leader,
    Origin(ParticipantRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicProtocolViolationKind {
    MalformedLeaderMessage,
    MalformedOriginMessage,
    InvalidManifest,
    ConflictingManifest,
    InvalidChunk,
    ConflictingChunk,
    InvalidContribution,
    BatchMismatch,
    OriginEquivocation,
    BufferLimit,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct PublicProtocolViolation {
    pub(super) kind: PublicProtocolViolationKind,
    pub(super) accused: PublicViolationAccused,
    pub(super) phase: Option<PublicPhase>,
    // Boxed to keep this error type under clippy's `result_large_err`
    // threshold now that every `Option<Box<...>>` evidence field is in
    // play — this is otherwise a plain `[u8; 32]`, not "large" on its own.
    pub(super) root: Option<Box<[u8; 32]>>,
    pub(super) message_ids: Vec<MessageId>,
    pub(super) detail: String,
    pub(super) commitment_equivocation: Option<Box<PublicCommitmentEquivocation>>,
    pub(super) public_origin_fault: Option<Box<PublicOriginFaultEvidence>>,
    pub(super) leader_equivocation: Option<Box<LeaderDeliveryEquivocation>>,
    /// A single leader-signed delivery that is independently provable as
    /// invalid on its own (no conflicting counterpart needed) — see
    /// `DkgLeaderPublicFaultKind` for the covered fault kinds. `None`
    /// whenever the violating delivery wasn't retained (best-effort, same
    /// caveat as `leader_equivocation`) or the phase isn't independently
    /// reportable (Reshare's `Commitments` phase — see
    /// `reporting/v0/registry.rs`'s `expected_leader_manifest_shape`).
    pub(super) leader_public_fault: Option<Box<LeaderPublicFaultEvidence>>,
    /// Two leader deliveries (any combination of manifest/chunk) that each
    /// reference the same origin under two *different* phase roots — the
    /// leader's own packaging contradiction, distinct from
    /// `leader_equivocation` (same coordinate, different content). Reuses
    /// `LeaderDeliveryEquivocation`'s shape (it's the same "two signed
    /// deliveries" pair, just a different violation predicate). See
    /// `claim_origins`.
    pub(super) leader_batch_mismatch: Option<Box<LeaderDeliveryEquivocation>>,
    /// A single leader-signed `PublicPhaseResponse` (direct-QUIC repair-page
    /// reply) that is independently provable as invalid on its own — reuses
    /// `dkg_control_message_fault`'s `ControlMessageArtifact` shape (a
    /// `ControlSignature`, not a Gossip envelope, backs this one) rather than
    /// `LeaderPublicFaultEvidence`, which is Gossip-delivery-shaped. `None`
    /// whenever the leader response wasn't signed (Fresh DKG — no ring to
    /// bind evidence to) or the violation is a different kind entirely.
    pub(super) control_message_fault: Option<Box<ControlMessageArtifact>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct LeaderPublicFaultEvidence {
    pub(super) fault_kind: DkgLeaderPublicFaultKind,
    pub(super) delivery: PublicLeaderDelivery,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct PublicCommitmentEquivocation {
    pub(super) origin: ParticipantRef,
    pub(super) retained: SignedPayload,
    pub(super) conflicting: SignedPayload,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct PublicOriginFaultEvidence {
    pub(super) fault_kind: DkgPublicOriginFaultKind,
    pub(super) contribution_a: SignedPayload,
    pub(super) contribution_b: Option<SignedPayload>,
}

/// The raw endpoint-authenticated bytes of one canonical-leader Gossip
/// broadcast (a Manifest or a Chunk), retained so an equivocating leader can
/// be proven to a third party who never witnessed the live topic exchange.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PublicLeaderDelivery {
    pub(super) origin: Vec<u8>,
    pub(super) delivery_id: [u8; 16],
    pub(super) signature: Vec<u8>,
    pub(super) data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct LeaderDeliveryEquivocation {
    pub(super) retained: PublicLeaderDelivery,
    pub(super) conflicting: PublicLeaderDelivery,
}

/// `delivery_id` is only `None` for a message verified via a standalone
/// `PubSub::verify` call, never for one delivered over a topic subscription
/// — but retention here is best-effort by design, so a missing ID just
/// means this particular delivery can't back a future equivocation report,
/// not that the message is rejected.
pub(super) fn public_leader_delivery_from_message(
    message: &network::AuthenticatedMessage,
) -> Option<PublicLeaderDelivery> {
    Some(PublicLeaderDelivery {
        origin: message.origin.as_bytes().to_vec(),
        delivery_id: message.delivery_id?,
        signature: message.signature.clone(),
        data: message.data.clone().into(),
    })
}

/// Retention is best-effort (see `PublicLeaderDelivery`'s callers): a
/// conflict is still rejected even when one side's raw delivery wasn't
/// captured, but evidence can only be attached when both sides are present.
pub(super) fn leader_delivery_equivocation(
    retained: Option<&PublicLeaderDelivery>,
    conflicting: Option<&PublicLeaderDelivery>,
) -> Option<LeaderDeliveryEquivocation> {
    Some(LeaderDeliveryEquivocation {
        retained: retained?.clone(),
        conflicting: conflicting?.clone(),
    })
}

impl PublicProtocolViolation {
    pub(super) fn leader(
        kind: PublicProtocolViolationKind,
        phase: Option<PublicPhase>,
        root: Option<[u8; 32]>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            accused: PublicViolationAccused::Leader,
            phase,
            root: root.map(Box::new),
            message_ids: Vec::new(),
            detail: detail.into(),
            commitment_equivocation: None,
            public_origin_fault: None,
            leader_equivocation: None,
            leader_public_fault: None,
            leader_batch_mismatch: None,
            control_message_fault: None,
        }
    }

    pub(super) fn origin(
        phase: PublicPhase,
        root: Option<[u8; 32]>,
        origin: ParticipantRef,
        detail: impl Into<String>,
    ) -> Self {
        Self::origin_with_kind(
            PublicProtocolViolationKind::OriginEquivocation,
            phase,
            root,
            origin,
            detail,
        )
    }

    pub(super) fn origin_with_kind(
        kind: PublicProtocolViolationKind,
        phase: PublicPhase,
        root: Option<[u8; 32]>,
        origin: ParticipantRef,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            accused: PublicViolationAccused::Origin(origin),
            phase: Some(phase),
            root: root.map(Box::new),
            message_ids: Vec::new(),
            detail: detail.into(),
            commitment_equivocation: None,
            public_origin_fault: None,
            leader_equivocation: None,
            leader_public_fault: None,
            leader_batch_mismatch: None,
            control_message_fault: None,
        }
    }

    pub(super) fn with_message_ids(mut self, first: MessageId, second: MessageId) -> Self {
        self.message_ids = vec![first, second];
        self
    }

    pub(super) fn with_message_id(mut self, message_id: MessageId) -> Self {
        self.message_ids = vec![message_id];
        self
    }

    pub(super) fn with_commitment_equivocation(
        mut self,
        evidence: Option<PublicCommitmentEquivocation>,
    ) -> Self {
        self.commitment_equivocation = evidence.map(Box::new);
        self
    }

    pub(super) fn with_public_origin_fault(
        mut self,
        evidence: Option<PublicOriginFaultEvidence>,
    ) -> Self {
        self.public_origin_fault = evidence.map(Box::new);
        self
    }

    pub(super) fn with_leader_equivocation(
        mut self,
        evidence: Option<LeaderDeliveryEquivocation>,
    ) -> Self {
        self.leader_equivocation = evidence.map(Box::new);
        self
    }

    pub(super) fn with_leader_public_fault(
        mut self,
        fault_kind: DkgLeaderPublicFaultKind,
        delivery: Option<PublicLeaderDelivery>,
    ) -> Self {
        self.leader_public_fault = delivery.map(|delivery| {
            Box::new(LeaderPublicFaultEvidence {
                fault_kind,
                delivery,
            })
        });
        self
    }

    pub(super) fn with_leader_batch_mismatch(
        mut self,
        evidence: Option<LeaderDeliveryEquivocation>,
    ) -> Self {
        self.leader_batch_mismatch = evidence.map(Box::new);
        self
    }

    pub(super) fn with_control_message_fault(
        mut self,
        evidence: Option<ControlMessageArtifact>,
    ) -> Self {
        self.control_message_fault = evidence.map(Box::new);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct VerifiedPublicContribution {
    pub(super) signed: SignedPayload,
    pub(super) contribution: DkgPublicContribution,
}

#[derive(Default)]
pub(super) struct PendingPublicBatch {
    pub(super) manifest: Option<ReceivedPublicManifest>,
    pub(super) chunks: BTreeMap<u32, ReceivedPublicChunk>,
}

pub(super) struct ReceivedPublicManifest {
    pub(super) manifest: PhaseManifest,
    pub(super) event_digest: [u8; 32],
    pub(super) delivery: Option<PublicLeaderDelivery>,
}

pub(super) struct ReceivedPublicChunk {
    pub(super) contributions: Vec<VerifiedPublicContribution>,
    pub(super) event_digest: [u8; 32],
    pub(super) delivery: Option<PublicLeaderDelivery>,
}

pub(super) struct CompletedPublicBatch {
    pub(super) manifest_event_digest: [u8; 32],
    pub(super) manifest_delivery: Option<PublicLeaderDelivery>,
    pub(super) chunk_digests: BTreeMap<u32, [u8; 32]>,
    pub(super) chunk_deliveries: BTreeMap<u32, PublicLeaderDelivery>,
}

#[derive(Debug, Clone)]
pub(super) struct ObservedPublicOrigin {
    pub(super) message_id: MessageId,
    pub(super) root: [u8; 32],
    pub(super) signed_envelope: SignedPayload,
}

/// Which root the leader has packaged a given origin under so far, and the
/// leader's own delivery (manifest or chunk) that first did so — separate
/// from `ObservedPublicOrigin` (which tracks the *origin's own* signed
/// content, for detecting the origin double-signing). This tracks the
/// *leader's* packaging choice instead, populated by both `insert_manifest`
/// and `insert_chunk`, so a leader claiming the same origin under two
/// different roots (via any combination of manifests/chunks) is
/// attributable — see `claim_origins`.
#[derive(Debug, Clone)]
pub(super) struct LeaderOriginClaim {
    pub(super) root: [u8; 32],
    pub(super) message_id: MessageId,
    pub(super) delivery: Option<PublicLeaderDelivery>,
}

#[derive(Debug)]
pub(super) enum PublicBatchAssembly {
    Pending {
        manifest_added: bool,
    },
    Duplicate,
    Complete {
        phase: PublicPhase,
        root: [u8; 32],
        contributions: Vec<VerifiedPublicContribution>,
    },
}

#[derive(Default)]
pub(super) struct ManifestRepairSchedule {
    pub(super) deadlines: BTreeMap<PublicPhase, Instant>,
}

impl ManifestRepairSchedule {
    /// Arm one delayed repair per phase. Existing deadlines are deliberately
    /// not extended: a leader cannot postpone repair by dripping manifests.
    pub(super) fn arm(&mut self, phase: PublicPhase, deadline: Instant) -> bool {
        if self.deadlines.contains_key(&phase) {
            return false;
        }
        self.deadlines.insert(phase, deadline);
        true
    }

    pub(super) fn cancel(&mut self, phase: PublicPhase) -> bool {
        self.deadlines.remove(&phase).is_some()
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.values().copied().min()
    }

    pub(super) fn take_due(&mut self, now: Instant) -> Vec<PublicPhase> {
        let due: Vec<_> = self
            .deadlines
            .iter()
            .filter_map(|(phase, deadline)| (*deadline <= now).then_some(*phase))
            .collect();
        for phase in &due {
            self.deadlines.remove(phase);
        }
        due
    }
}

pub(super) struct CompletePhaseRootClaim {
    pub(super) root: [u8; 32],
    pub(super) delivery: Option<PublicLeaderDelivery>,
}

#[derive(Default)]
pub(super) struct PublicBatchAssembler {
    pub(super) pending: HashMap<(PublicPhase, [u8; 32]), PendingPublicBatch>,
    pub(super) completed: HashMap<(PublicPhase, [u8; 32]), CompletedPublicBatch>,
    pub(super) complete_phase_roots: HashMap<PublicPhase, CompletePhaseRootClaim>,
    pub(super) observed_origins: HashMap<(PublicPhase, ParticipantRef), ObservedPublicOrigin>,
    pub(super) origin_claims: HashMap<(PublicPhase, ParticipantRef), LeaderOriginClaim>,
}

impl PublicBatchAssembler {
    pub(super) fn insert_manifest(
        &mut self,
        mode: PublicBatchMode,
        manifest: PhaseManifest,
        event_digest: [u8; 32],
        expected_origins: &BTreeSet<ParticipantRef>,
        delivery: Option<PublicLeaderDelivery>,
    ) -> std::result::Result<PublicBatchAssembly, PublicProtocolViolation> {
        let phase = manifest.phase;
        let root = manifest.phase_root;
        manifest.validate(expected_origins).map_err(|detail| {
            PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidManifest,
                Some(phase),
                Some(root),
                detail,
            )
            .with_leader_public_fault(DkgLeaderPublicFaultKind::InvalidManifest, delivery.clone())
        })?;
        let expected_complete = mode == PublicBatchMode::Complete;
        if manifest.complete != expected_complete {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidManifest,
                Some(phase),
                Some(root),
                format!(
                    "manifest complete={} does not match {mode:?} phase publication",
                    manifest.complete
                ),
            )
            .with_leader_public_fault(
                DkgLeaderPublicFaultKind::InvalidManifest,
                delivery.clone(),
            ));
        }

        let key = (phase, root);
        if let Some(completed) = self.completed.get(&key) {
            return if completed.manifest_event_digest == event_digest {
                Ok(PublicBatchAssembly::Duplicate)
            } else {
                Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingManifest,
                    Some(phase),
                    Some(root),
                    "manifest metadata conflicts with a completed batch",
                )
                .with_leader_equivocation(leader_delivery_equivocation(
                    completed.manifest_delivery.as_ref(),
                    delivery.as_ref(),
                )))
            };
        }
        if let Some(existing) = self
            .pending
            .get(&key)
            .and_then(|batch| batch.manifest.as_ref())
        {
            return if existing.manifest == manifest && existing.event_digest == event_digest {
                Ok(PublicBatchAssembly::Duplicate)
            } else {
                Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingManifest,
                    Some(phase),
                    Some(root),
                    "manifest metadata conflicts for the same phase root",
                )
                .with_leader_equivocation(leader_delivery_equivocation(
                    existing.delivery.as_ref(),
                    delivery.as_ref(),
                )))
            };
        }

        self.claim_phase_root(mode, phase, root, expected_origins.len(), delivery.as_ref())?;
        self.claim_origins(
            phase,
            root,
            manifest
                .contribution_ids
                .iter()
                .map(|(&origin, &message_id)| (origin, message_id)),
            delivery.as_ref(),
        )?;
        let buffered_manifest_entries: usize = self
            .pending
            .iter()
            .filter(|((candidate_phase, _), _)| *candidate_phase == phase)
            .filter_map(|(_, batch)| batch.manifest.as_ref())
            .map(|received| received.manifest.contribution_ids.len())
            .sum();
        if buffered_manifest_entries.saturating_add(manifest.contribution_ids.len())
            > expected_origins.len()
        {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "pending manifest entries exceed the expected origin count {}",
                    expected_origins.len()
                ),
            ));
        }
        self.pending.entry(key).or_default().manifest = Some(ReceivedPublicManifest {
            manifest,
            event_digest,
            delivery,
        });
        self.try_complete(key, true)
    }

    pub(super) fn insert_chunk(
        &mut self,
        mode: PublicBatchMode,
        phase: PublicPhase,
        root: [u8; 32],
        index: u32,
        contributions: Vec<VerifiedPublicContribution>,
        event_digest: [u8; 32],
        expected_origin_count: usize,
        delivery: Option<PublicLeaderDelivery>,
    ) -> std::result::Result<PublicBatchAssembly, PublicProtocolViolation> {
        if contributions.is_empty() {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidChunk,
                Some(phase),
                Some(root),
                "public batch chunk is empty",
            ));
        }
        if index as usize >= expected_origin_count {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "chunk index {index} exceeds the maximum {} chunks for this phase",
                    expected_origin_count
                ),
            )
            .with_leader_public_fault(
                DkgLeaderPublicFaultKind::ChunkIndexOutOfRange,
                delivery.clone(),
            ));
        }

        let key = (phase, root);
        let commitment_equivocation =
            self.find_commitment_origin_equivocation(phase, &contributions);
        let public_origin_fault = self.find_public_origin_equivocation(phase, &contributions);
        // A chunk is built from a `BTreeMap<ParticipantRef, SignedPayload>`
        // (`chunk_public_contributions_with_limit`), which cannot contain the
        // same key twice — so any duplicate origin among a chunk's own
        // contributions can only be the leader's own packaging, honest or
        // not, independent of whether the two entries also happen to
        // conflict in content (that's `commitment_equivocation`/
        // `public_origin_fault`'s separate, additive finding above). This is
        // the only case `claim_origins` doesn't cover — it only compares
        // against already-recorded claims from *earlier* deliveries, not
        // duplicates within the batch currently being validated — so without
        // this, a same-content duplicate silently falls through to the
        // aggregate `BufferLimit` checks below with no evidence at all.
        let duplicate_chunk_origin_evidence = {
            let mut seen_origins = BTreeSet::new();
            let has_duplicate = contributions
                .iter()
                .any(|verified| !seen_origins.insert(verified.contribution.origin));
            has_duplicate.then(|| delivery.clone()).flatten()
        };
        if let Some(completed) = self.completed.get(&key) {
            return match completed.chunk_digests.get(&index) {
                Some(existing) if existing == &event_digest => Ok(PublicBatchAssembly::Duplicate),
                Some(_) => Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingChunk,
                    Some(phase),
                    Some(root),
                    format!("chunk {index} conflicts with the completed batch"),
                )
                .with_commitment_equivocation(commitment_equivocation)
                .with_public_origin_fault(public_origin_fault)
                .with_leader_public_fault(
                    DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                    duplicate_chunk_origin_evidence,
                )
                .with_leader_equivocation(leader_delivery_equivocation(
                    completed.chunk_deliveries.get(&index),
                    delivery.as_ref(),
                ))),
                None => Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::InvalidChunk,
                    Some(phase),
                    Some(root),
                    format!("extra chunk {index} follows the completed batch"),
                )
                .with_commitment_equivocation(commitment_equivocation)
                .with_public_origin_fault(public_origin_fault)
                .with_leader_public_fault(
                    DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                    duplicate_chunk_origin_evidence,
                )),
            };
        }
        // For incremental publications, attribute a proven origin contradiction
        // before enforcing the root-count bound. For complete publications, claim
        // the single allowed root first so a second root remains an attributable
        // leader contradiction even when it contains an origin equivocation.
        // `claim_origins` runs first in both cases — it's what makes the
        // aggregate BufferLimit checks below structurally unreachable (see its
        // doc comment) — so it should attribute a cross-root packaging
        // contradiction before `ensure_no_origin_equivocation`'s own (weaker,
        // message-id-only-evidenced) fallback for the same situation.
        if mode == PublicBatchMode::Incremental {
            if let Err(violation) = self.claim_origins(
                phase,
                root,
                contributions.iter().map(|verified| {
                    (
                        verified.contribution.origin,
                        verified.contribution.message_id,
                    )
                }),
                delivery.as_ref(),
            ) {
                return Err(violation
                    .with_commitment_equivocation(commitment_equivocation)
                    .with_public_origin_fault(public_origin_fault)
                    .with_leader_public_fault(
                        DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                        duplicate_chunk_origin_evidence,
                    ));
            }
            self.ensure_no_origin_equivocation(phase, root, &contributions)?;
        }
        if let Err(violation) =
            self.claim_phase_root(mode, phase, root, expected_origin_count, delivery.as_ref())
        {
            return Err(violation
                .with_commitment_equivocation(commitment_equivocation)
                .with_public_origin_fault(public_origin_fault)
                .with_leader_public_fault(
                    DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                    duplicate_chunk_origin_evidence,
                ));
        }
        if let Some(existing) = self
            .pending
            .get(&key)
            .and_then(|batch| batch.chunks.get(&index))
        {
            return if existing.event_digest == event_digest
                && existing.contributions == contributions
            {
                Ok(PublicBatchAssembly::Duplicate)
            } else {
                Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingChunk,
                    Some(phase),
                    Some(root),
                    format!("leader published different contents for chunk {index}"),
                )
                .with_commitment_equivocation(commitment_equivocation)
                .with_public_origin_fault(public_origin_fault)
                .with_leader_public_fault(
                    DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                    duplicate_chunk_origin_evidence,
                )
                .with_leader_equivocation(leader_delivery_equivocation(
                    existing.delivery.as_ref(),
                    delivery.as_ref(),
                )))
            };
        }
        if mode == PublicBatchMode::Complete {
            if let Err(violation) = self.claim_origins(
                phase,
                root,
                contributions.iter().map(|verified| {
                    (
                        verified.contribution.origin,
                        verified.contribution.message_id,
                    )
                }),
                delivery.as_ref(),
            ) {
                return Err(violation
                    .with_commitment_equivocation(commitment_equivocation)
                    .with_public_origin_fault(public_origin_fault)
                    .with_leader_public_fault(
                        DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                        duplicate_chunk_origin_evidence,
                    ));
            }
            self.ensure_no_origin_equivocation(phase, root, &contributions)?;
        }
        let buffered_for_root: usize = self
            .pending
            .get(&key)
            .into_iter()
            .flat_map(|batch| batch.chunks.values())
            .map(|chunk| chunk.contributions.len())
            .sum();
        if buffered_for_root.saturating_add(contributions.len()) > expected_origin_count {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "buffered contributions exceed the expected origin count {expected_origin_count}"
                ),
            )
            .with_commitment_equivocation(commitment_equivocation)
            .with_public_origin_fault(public_origin_fault)
            .with_leader_public_fault(
                DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                duplicate_chunk_origin_evidence,
            ));
        }
        let buffered_for_phase: usize = self
            .pending
            .iter()
            .filter(|((candidate_phase, _), _)| *candidate_phase == phase)
            .flat_map(|(_, batch)| batch.chunks.values())
            .map(|chunk| chunk.contributions.len())
            .sum();
        if buffered_for_phase.saturating_add(contributions.len()) > expected_origin_count {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "pending contributions exceed the expected origin count {expected_origin_count}"
                ),
            )
            .with_commitment_equivocation(commitment_equivocation)
            .with_public_origin_fault(public_origin_fault)
            .with_leader_public_fault(
                DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
                duplicate_chunk_origin_evidence,
            ));
        }
        for verified in &contributions {
            let contribution = &verified.contribution;
            self.observed_origins
                .entry((phase, contribution.origin))
                .or_insert_with(|| ObservedPublicOrigin {
                    message_id: contribution.message_id,
                    root,
                    signed_envelope: verified.signed.clone(),
                });
        }
        self.pending.entry(key).or_default().chunks.insert(
            index,
            ReceivedPublicChunk {
                contributions,
                event_digest,
                delivery,
            },
        );
        self.try_complete(key, false)
    }

    /// Record that the leader packaged each `(origin, message_id)` pair
    /// under `root` for `phase`, rejecting any origin already packaged
    /// under a *different* root by an earlier manifest or chunk — but only
    /// when it's the *same* `message_id` both times. A differing
    /// `message_id` means the origin itself signed two different messages,
    /// which is the origin's own fault (`ensure_no_origin_equivocation`'s
    /// `OriginEquivocation` case), not the leader's packaging choice; this
    /// check only fires when the leader is unambiguously the one at fault —
    /// it received one canonical signed message from this origin, yet chose
    /// to package that exact message under two different roots.
    ///
    /// This is what makes the aggregate `BufferLimit` checks (buffered
    /// entries/contributions exceeding the committee size, too many
    /// distinct incremental roots) structurally unreachable in the cases
    /// that matter: pairwise-disjoint non-empty origin subsets of an
    /// N-member committee can never sum past N, so exceeding any of those
    /// bounds would always require some origin to have been claimed under
    /// two different roots first — which this check catches earlier, with
    /// real two-delivery evidence, before the aggregate ever accumulates
    /// that high. The one case this does *not* cover (and where the
    /// aggregate checks remain the active, still-needed mechanism): the
    /// same origin appearing twice *within a single delivery's own
    /// contributions* — this check only compares against already-recorded
    /// claims from *earlier* deliveries, not duplicates within the batch
    /// currently being validated.
    ///
    /// Mutating eagerly (before every other check in the caller has passed)
    /// is safe: any rejection here or later is terminal for the whole
    /// ceremony attempt, so there is no scenario where a premature record
    /// could be queried again.
    pub(super) fn claim_origins(
        &mut self,
        phase: PublicPhase,
        root: [u8; 32],
        origins: impl IntoIterator<Item = (ParticipantRef, MessageId)>,
        delivery: Option<&PublicLeaderDelivery>,
    ) -> std::result::Result<(), PublicProtocolViolation> {
        let origins: Vec<(ParticipantRef, MessageId)> = origins.into_iter().collect();
        for &(origin, message_id) in &origins {
            if let Some(existing) = self.origin_claims.get(&(phase, origin)) {
                if existing.message_id == message_id && existing.root != root {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::BatchMismatch,
                        Some(phase),
                        Some(root),
                        format!("origin {origin:?} was packaged under two different phase roots"),
                    )
                    .with_leader_batch_mismatch(leader_delivery_equivocation(
                        existing.delivery.as_ref(),
                        delivery,
                    )));
                }
            }
        }
        for (origin, message_id) in origins {
            self.origin_claims
                .entry((phase, origin))
                .or_insert_with(|| LeaderOriginClaim {
                    root,
                    message_id,
                    delivery: delivery.cloned(),
                });
        }
        Ok(())
    }

    pub(super) fn ensure_no_origin_equivocation(
        &self,
        phase: PublicPhase,
        root: [u8; 32],
        contributions: &[VerifiedPublicContribution],
    ) -> std::result::Result<(), PublicProtocolViolation> {
        for verified in contributions {
            let contribution = &verified.contribution;
            let origin_key = (phase, contribution.origin);
            if let Some(existing) = self.observed_origins.get(&origin_key) {
                if existing.message_id != contribution.message_id {
                    return Err(PublicProtocolViolation::origin(
                        phase,
                        Some(root),
                        contribution.origin,
                        "origin signed different messages for the same attempt and phase",
                    )
                    .with_message_ids(existing.message_id, contribution.message_id)
                    .with_commitment_equivocation(
                        self.commitment_origin_equivocation(existing, verified),
                    )
                    .with_public_origin_fault(
                        self.public_origin_equivocation(existing, verified),
                    ));
                }
                if existing.root != root {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::BatchMismatch,
                        Some(phase),
                        Some(root),
                        format!(
                            "origin {:?} was repeated across incremental batch roots",
                            contribution.origin
                        ),
                    )
                    .with_message_id(contribution.message_id));
                }
            }
        }
        Ok(())
    }

    pub(super) fn find_commitment_origin_equivocation(
        &self,
        phase: PublicPhase,
        contributions: &[VerifiedPublicContribution],
    ) -> Option<PublicCommitmentEquivocation> {
        if phase != PublicPhase::Commitments {
            return None;
        }
        let mut seen = HashMap::<ParticipantRef, &VerifiedPublicContribution>::new();
        for verified in contributions {
            let contribution = &verified.contribution;
            if let Some(existing) = self.observed_origins.get(&(phase, contribution.origin)) {
                if existing.message_id != contribution.message_id {
                    return self.commitment_origin_equivocation(existing, verified);
                }
            }
            if let Some(existing) = seen.insert(contribution.origin, verified) {
                if existing.contribution.message_id != contribution.message_id {
                    return Some(PublicCommitmentEquivocation {
                        origin: contribution.origin,
                        retained: existing.signed.clone(),
                        conflicting: verified.signed.clone(),
                    });
                }
            }
        }
        None
    }

    pub(super) fn find_public_origin_equivocation(
        &self,
        phase: PublicPhase,
        contributions: &[VerifiedPublicContribution],
    ) -> Option<PublicOriginFaultEvidence> {
        if phase == PublicPhase::Commitments {
            return None;
        }
        let mut seen = HashMap::<ParticipantRef, &VerifiedPublicContribution>::new();
        for verified in contributions {
            let contribution = &verified.contribution;
            if let Some(existing) = self.observed_origins.get(&(phase, contribution.origin)) {
                if let Some(evidence) = self.public_origin_equivocation(existing, verified) {
                    return Some(evidence);
                }
            }
            if let Some(existing) = seen.insert(contribution.origin, verified) {
                if existing.contribution.payload != contribution.payload {
                    return Some(PublicOriginFaultEvidence {
                        fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
                        contribution_a: existing.signed.clone(),
                        contribution_b: Some(verified.signed.clone()),
                    });
                }
            }
        }
        None
    }

    pub(super) fn public_origin_equivocation(
        &self,
        existing: &ObservedPublicOrigin,
        conflicting: &VerifiedPublicContribution,
    ) -> Option<PublicOriginFaultEvidence> {
        if conflicting.contribution.payload.phase() == PublicPhase::Commitments {
            return None;
        }
        let retained: DkgPublicContribution = transport::decode(
            &existing.signed_envelope.data,
            transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
        )
        .ok()?;
        if retained.payload == conflicting.contribution.payload {
            return None;
        }
        Some(PublicOriginFaultEvidence {
            fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
            contribution_a: existing.signed_envelope.clone(),
            contribution_b: Some(conflicting.signed.clone()),
        })
    }

    pub(super) fn commitment_origin_equivocation(
        &self,
        existing: &ObservedPublicOrigin,
        conflicting: &VerifiedPublicContribution,
    ) -> Option<PublicCommitmentEquivocation> {
        if conflicting.contribution.payload.phase() != PublicPhase::Commitments {
            return None;
        }
        Some(PublicCommitmentEquivocation {
            origin: conflicting.contribution.origin,
            retained: existing.signed_envelope.clone(),
            conflicting: conflicting.signed.clone(),
        })
    }

    pub(super) fn claim_phase_root(
        &mut self,
        mode: PublicBatchMode,
        phase: PublicPhase,
        root: [u8; 32],
        expected_origin_count: usize,
        delivery: Option<&PublicLeaderDelivery>,
    ) -> std::result::Result<(), PublicProtocolViolation> {
        if mode == PublicBatchMode::Complete {
            if let Some(existing) = self.complete_phase_roots.get(&phase) {
                if existing.root != root {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::ConflictingManifest,
                        Some(phase),
                        Some(root),
                        format!(
                            "complete phase already committed to root {}",
                            hex::encode(existing.root)
                        ),
                    )
                    .with_leader_equivocation(leader_delivery_equivocation(
                        existing.delivery.as_ref(),
                        delivery,
                    )));
                }
            } else {
                self.complete_phase_roots.insert(
                    phase,
                    CompletePhaseRootClaim {
                        root,
                        delivery: delivery.cloned(),
                    },
                );
            }
            return Ok(());
        }

        let root_known = self.pending.contains_key(&(phase, root))
            || self.completed.contains_key(&(phase, root));
        if !root_known {
            let roots = self
                .pending
                .keys()
                .chain(self.completed.keys())
                .filter(|(candidate_phase, _)| *candidate_phase == phase)
                .count();
            if roots >= expected_origin_count {
                return Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BufferLimit,
                    Some(phase),
                    Some(root),
                    format!(
                        "incremental phase exceeds its maximum {expected_origin_count} batch roots"
                    ),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn try_complete(
        &mut self,
        key: (PublicPhase, [u8; 32]),
        manifest_added: bool,
    ) -> std::result::Result<PublicBatchAssembly, PublicProtocolViolation> {
        let Some(batch) = self.pending.get(&key) else {
            return Ok(PublicBatchAssembly::Pending { manifest_added });
        };
        let Some(received_manifest) = batch.manifest.as_ref() else {
            return Ok(PublicBatchAssembly::Pending { manifest_added });
        };
        let manifest = &received_manifest.manifest;
        let chunk_count = manifest.chunk_count;
        if let Some(index) = batch
            .chunks
            .keys()
            .find(|index| **index >= chunk_count)
            .copied()
        {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidChunk,
                Some(key.0),
                Some(key.1),
                format!("chunk index {index} is outside manifest chunk count {chunk_count}"),
            ));
        }
        if batch.chunks.len() < chunk_count as usize {
            return Ok(PublicBatchAssembly::Pending { manifest_added });
        }

        let batch = self
            .pending
            .remove(&key)
            .expect("the complete pending batch was checked above");
        let received_manifest = batch
            .manifest
            .expect("the complete pending batch has a manifest");
        let manifest = received_manifest.manifest;
        let mut contributions = Vec::new();
        let mut chunk_digests = BTreeMap::new();
        let mut chunk_deliveries = BTreeMap::new();
        for index in 0..manifest.chunk_count {
            let chunk = batch.chunks.get(&index).ok_or_else(|| {
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::InvalidChunk,
                    Some(key.0),
                    Some(key.1),
                    format!("manifest batch is missing chunk {index}"),
                )
            })?;
            chunk_digests.insert(index, chunk.event_digest);
            if let Some(delivery) = &chunk.delivery {
                chunk_deliveries.insert(index, delivery.clone());
            }
            contributions.extend(chunk.contributions.iter().cloned());
        }

        let canonical_origins: Vec<_> = manifest.contribution_ids.keys().copied().collect();
        let actual_origins: Vec<_> = contributions
            .iter()
            .map(|verified| verified.contribution.origin)
            .collect();
        let commitment_equivocation =
            self.find_commitment_origin_equivocation(key.0, &contributions);
        let public_origin_fault = self.find_public_origin_equivocation(key.0, &contributions);
        if actual_origins != canonical_origins {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BatchMismatch,
                Some(key.0),
                Some(key.1),
                "chunk contributions are not in the manifest's canonical origin order",
            )
            .with_commitment_equivocation(commitment_equivocation)
            .with_public_origin_fault(public_origin_fault));
        }
        let actual_ids: BTreeMap<_, _> = contributions
            .iter()
            .map(|verified| {
                (
                    verified.contribution.origin,
                    verified.contribution.message_id,
                )
            })
            .collect();
        if actual_ids.len() != contributions.len() || actual_ids != manifest.contribution_ids {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BatchMismatch,
                Some(key.0),
                Some(key.1),
                "chunk contribution IDs do not match the manifest",
            )
            .with_commitment_equivocation(commitment_equivocation)
            .with_public_origin_fault(public_origin_fault));
        }

        self.completed.insert(
            key,
            CompletedPublicBatch {
                manifest_event_digest: received_manifest.event_digest,
                manifest_delivery: received_manifest.delivery,
                chunk_digests,
                chunk_deliveries,
            },
        );
        Ok(PublicBatchAssembly::Complete {
            phase: key.0,
            root: key.1,
            contributions,
        })
    }
}
