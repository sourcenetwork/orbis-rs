#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn public_batch_waits_for_manifest_and_every_chunk() {
    let first = assembled_contribution(ParticipantRef::current(1), 1);
    let second = assembled_contribution(ParticipantRef::current(2), 2);
    let manifest = assembled_manifest(&[first.clone(), second.clone()], 2, true);
    let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
    let mut assembler = PublicBatchAssembler::default();

    assert!(matches!(
        assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                manifest.phase_root,
                1,
                vec![second],
                [2; 32],
                expected.len(),
                None,
            )
            .unwrap(),
        PublicBatchAssembly::Pending { .. }
    ));
    assert!(matches!(
        assembler
            .insert_manifest(
                PublicBatchMode::Complete,
                manifest.clone(),
                [3; 32],
                &expected,
                None,
            )
            .unwrap(),
        PublicBatchAssembly::Pending {
            manifest_added: true
        }
    ));
    let complete = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            manifest.phase_root,
            0,
            vec![first],
            [1; 32],
            expected.len(),
            None,
        )
        .unwrap();
    let PublicBatchAssembly::Complete { contributions, .. } = complete else {
        panic!("batch must complete only after manifest and both chunks");
    };
    assert_eq!(
        contributions
            .iter()
            .map(|verified| verified.contribution.origin)
            .collect::<Vec<_>>(),
        vec![ParticipantRef::current(1), ParticipantRef::current(2)]
    );
}

#[test]
fn manifest_repair_schedule_coalesces_without_extending_deadline() {
    let now = Instant::now();
    let first_deadline = now + DKG_REPAIR_STALL_INTERVAL;
    let later_deadline = first_deadline + DKG_REPAIR_STALL_INTERVAL;
    let mut schedule = ManifestRepairSchedule::default();

    assert!(schedule.arm(PublicPhase::Commitments, first_deadline));
    assert!(
        !schedule.arm(PublicPhase::Commitments, later_deadline),
        "another incremental root must not create work or postpone repair"
    );
    assert_eq!(schedule.next_deadline(), Some(first_deadline));
    assert!(schedule
        .take_due(first_deadline - Duration::from_nanos(1))
        .is_empty());
    assert_eq!(
        schedule.take_due(first_deadline),
        vec![PublicPhase::Commitments]
    );
    assert_eq!(schedule.next_deadline(), None);
}

#[test]
fn manifest_repair_schedule_tracks_phases_independently_and_cancels_complete_phase() {
    let now = Instant::now();
    let first_deadline = now + DKG_REPAIR_STALL_INTERVAL;
    let second_deadline = first_deadline + Duration::from_secs(1);
    let mut schedule = ManifestRepairSchedule::default();

    assert!(schedule.arm(PublicPhase::Commitments, second_deadline));
    assert!(schedule.arm(PublicPhase::CommitmentHashes, first_deadline));
    assert_eq!(schedule.next_deadline(), Some(first_deadline));
    assert_eq!(
        schedule.take_due(first_deadline),
        vec![PublicPhase::CommitmentHashes]
    );
    assert_eq!(schedule.next_deadline(), Some(second_deadline));

    assert!(schedule.cancel(PublicPhase::Commitments));
    assert!(!schedule.cancel(PublicPhase::Commitments));
    assert_eq!(schedule.next_deadline(), None);
}

#[test]
fn public_batch_accepts_only_identical_retransmissions() {
    let contribution = assembled_contribution(ParticipantRef::current(1), 1);
    let manifest = assembled_manifest(std::slice::from_ref(&contribution), 1, true);
    let expected = BTreeSet::from([ParticipantRef::current(1)]);
    let mut assembler = PublicBatchAssembler::default();
    let manifest_delivery_a = sample_leader_delivery(1);
    let manifest_delivery_b = sample_leader_delivery(2);
    assert!(matches!(
        assembler
            .insert_manifest(
                PublicBatchMode::Complete,
                manifest.clone(),
                [1; 32],
                &expected,
                Some(manifest_delivery_a.clone()),
            )
            .unwrap(),
        PublicBatchAssembly::Pending { .. }
    ));
    assert!(matches!(
        assembler
            .insert_manifest(
                PublicBatchMode::Complete,
                manifest.clone(),
                [1; 32],
                &expected,
                Some(manifest_delivery_a.clone()),
            )
            .unwrap(),
        PublicBatchAssembly::Duplicate
    ));
    let error = assembler
        .insert_manifest(
            PublicBatchMode::Complete,
            manifest.clone(),
            [9; 32],
            &expected,
            Some(manifest_delivery_b.clone()),
        )
        .expect_err("a semantically equal manifest with different bytes must conflict");
    assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingManifest);
    assert_eq!(
        error.leader_equivocation.as_deref(),
        Some(&LeaderDeliveryEquivocation {
            retained: manifest_delivery_a,
            conflicting: manifest_delivery_b,
        }),
        "conflicting manifest must retain both signed leader deliveries"
    );
    assert!(matches!(
        assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                manifest.phase_root,
                0,
                vec![contribution.clone()],
                [2; 32],
                expected.len(),
                None,
            )
            .unwrap(),
        PublicBatchAssembly::Complete { .. }
    ));
    assert!(matches!(
        assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                manifest.phase_root,
                0,
                vec![contribution],
                [2; 32],
                expected.len(),
                None,
            )
            .unwrap(),
        PublicBatchAssembly::Duplicate
    ));
    let chunk_delivery = sample_leader_delivery(3);
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            manifest.phase_root,
            0,
            vec![assembled_contribution(ParticipantRef::current(1), 1)],
            [8; 32],
            expected.len(),
            Some(chunk_delivery),
        )
        .expect_err("a semantically equal chunk with different bytes must conflict");
    assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingChunk);
    assert!(
        error.leader_equivocation.is_none(),
        "the completed chunk's own delivery was never retained, so evidence stays best-effort"
    );
}

#[test]
fn public_batch_rejects_invalid_or_conflicting_complete_roots() {
    let contribution = assembled_contribution(ParticipantRef::current(1), 1);
    let mut invalid = assembled_manifest(std::slice::from_ref(&contribution), 1, true);
    invalid.phase_root = [99; 32];
    let expected = BTreeSet::from([ParticipantRef::current(1)]);
    let mut assembler = PublicBatchAssembler::default();
    let error = assembler
        .insert_manifest(PublicBatchMode::Complete, invalid, [1; 32], &expected, None)
        .expect_err("an internally invalid root must fail");
    assert_eq!(error.kind, PublicProtocolViolationKind::InvalidManifest);

    let first_root = [1; 32];
    let second_root = [2; 32];
    let conflicting = assembled_contribution(ParticipantRef::current(1), 2);
    let first_chunk_delivery = sample_leader_delivery(1);
    let second_chunk_delivery = sample_leader_delivery(2);
    assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            first_root,
            0,
            vec![contribution.clone()],
            [2; 32],
            expected.len(),
            Some(first_chunk_delivery.clone()),
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            second_root,
            0,
            vec![conflicting.clone()],
            [3; 32],
            expected.len(),
            Some(second_chunk_delivery.clone()),
        )
        .expect_err("a complete phase cannot advertise two roots");
    assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingManifest);
    assert_eq!(error.accused, PublicViolationAccused::Leader);
    assert_eq!(
        error.commitment_equivocation.as_deref(),
        Some(&PublicCommitmentEquivocation {
            origin: ParticipantRef::current(1),
            retained: contribution.signed,
            conflicting: conflicting.signed,
        }),
        "leader-first attribution must still preserve provable dealer equivocation"
    );
    assert_eq!(
        error.leader_equivocation.as_deref(),
        Some(&LeaderDeliveryEquivocation {
            retained: first_chunk_delivery,
            conflicting: second_chunk_delivery,
        }),
        "a leader claiming two different complete-phase roots must be provably attributable"
    );
}

#[test]
fn public_batch_rejects_manifest_naming_the_wrong_origin_set_with_leader_public_fault_evidence() {
    // A Complete-mode manifest must name every expected origin. This one
    // names only origin 1, but the phase's committee has two members —
    // a genuine `PhaseManifest::validate` failure, not an equivocation
    // (no earlier manifest exists to conflict with).
    let contribution = assembled_contribution(ParticipantRef::current(1), 1);
    let manifest = assembled_manifest(std::slice::from_ref(&contribution), 1, true);
    let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
    let mut assembler = PublicBatchAssembler::default();
    let delivery = sample_leader_delivery(1);
    let error = assembler
        .insert_manifest(
            PublicBatchMode::Complete,
            manifest,
            [1; 32],
            &expected,
            Some(delivery.clone()),
        )
        .expect_err("a manifest naming an incomplete origin set must be rejected");
    assert_eq!(error.kind, PublicProtocolViolationKind::InvalidManifest);
    assert_eq!(error.accused, PublicViolationAccused::Leader);
    assert_eq!(
        error.leader_public_fault.as_deref(),
        Some(&LeaderPublicFaultEvidence {
            fault_kind: DkgLeaderPublicFaultKind::InvalidManifest,
            delivery,
        }),
        "an invalid manifest must retain the leader's signed delivery as evidence, \
             independently provable without any conflicting counterpart"
    );
}

#[test]
fn public_batch_rejects_chunk_index_out_of_range_with_leader_public_fault_evidence() {
    // The phase's committee has one member, so any chunk index other
    // than 0 is out of range — a genuine, single-artifact-provable
    // `BufferLimit` fault, distinct from `InvalidManifest`.
    let contribution = assembled_contribution(ParticipantRef::current(1), 1);
    let mut assembler = PublicBatchAssembler::default();
    let delivery = sample_leader_delivery(1);
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [1; 32],
            1,
            vec![contribution],
            [2; 32],
            1,
            Some(delivery.clone()),
        )
        .expect_err("a chunk index at or beyond the expected origin count must be rejected");
    assert_eq!(error.kind, PublicProtocolViolationKind::BufferLimit);
    assert_eq!(error.accused, PublicViolationAccused::Leader);
    assert_eq!(
        error.leader_public_fault.as_deref(),
        Some(&LeaderPublicFaultEvidence {
            fault_kind: DkgLeaderPublicFaultKind::ChunkIndexOutOfRange,
            delivery,
        }),
        "an out-of-range chunk index must retain the leader's signed delivery as evidence"
    );
}

#[test]
fn public_batch_rejects_oversized_chunk_bytes_with_leader_public_fault_evidence() {
    let mut oversized = sample_leader_delivery(1);
    oversized.data = vec![0u8; transport::MAX_PUBLIC_CHUNK_BYTES + 1];
    let violation = PublicProtocolViolation::leader(
        PublicProtocolViolationKind::BufferLimit,
        Some(PublicPhase::Commitments),
        Some([1; 32]),
        "encoded chunk exceeds the byte limit",
    )
    .with_leader_public_fault(
        DkgLeaderPublicFaultKind::OversizedChunk,
        Some(oversized.clone()),
    );
    assert_eq!(violation.kind, PublicProtocolViolationKind::BufferLimit);
    assert_eq!(
        violation.leader_public_fault.as_deref(),
        Some(&LeaderPublicFaultEvidence {
            fault_kind: DkgLeaderPublicFaultKind::OversizedChunk,
            delivery: oversized,
        }),
        "an oversized chunk must retain the leader's signed delivery as evidence"
    );
}

#[test]
fn public_batch_rejects_duplicate_chunk_origin_with_leader_public_fault_evidence() {
    // Same origin twice in one chunk, matching content both times — no
    // equivocation to attribute to the origin, so without dedicated
    // detection this would fall through to the aggregate `BufferLimit`
    // check with zero evidence.
    let first = assembled_contribution(ParticipantRef::current(1), 1);
    let duplicate = assembled_contribution(ParticipantRef::current(1), 1);
    let delivery = sample_leader_delivery(1);
    let error = PublicBatchAssembler::default()
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [1; 32],
            0,
            vec![first, duplicate],
            [1; 32],
            1,
            Some(delivery.clone()),
        )
        .expect_err("a chunk cannot name the same origin twice");
    assert_eq!(error.kind, PublicProtocolViolationKind::BufferLimit);
    assert_eq!(error.accused, PublicViolationAccused::Leader);
    assert_eq!(
        error.leader_public_fault.as_deref(),
        Some(&LeaderPublicFaultEvidence {
            fault_kind: DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
            delivery,
        }),
        "a duplicate origin within one chunk must retain the leader's signed delivery as evidence"
    );
    assert_eq!(
        error.commitment_equivocation, None,
        "matching content both times is not origin equivocation"
    );
}

#[test]
fn public_batch_rejects_conflicting_chunks_and_noncanonical_contents() {
    let first = assembled_contribution(ParticipantRef::current(1), 1);
    let second = assembled_contribution(ParticipantRef::current(2), 2);
    let manifest = assembled_manifest(&[first.clone(), second.clone()], 1, true);
    let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
    let mut assembler = PublicBatchAssembler::default();
    assembler
        .insert_manifest(
            PublicBatchMode::Complete,
            manifest.clone(),
            [1; 32],
            &expected,
            None,
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            manifest.phase_root,
            0,
            vec![second, first],
            [2; 32],
            expected.len(),
            None,
        )
        .expect_err("manifest contents must retain canonical origin order");
    assert_eq!(error.kind, PublicProtocolViolationKind::BatchMismatch);

    let contribution = assembled_contribution(ParticipantRef::current(1), 3);
    let mut assembler = PublicBatchAssembler::default();
    assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [3; 32],
            0,
            vec![contribution.clone()],
            [3; 32],
            2,
            None,
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [3; 32],
            0,
            vec![assembled_contribution(ParticipantRef::current(2), 4)],
            [4; 32],
            2,
            None,
        )
        .expect_err("the same chunk index cannot change contents");
    assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingChunk);

    let retained = assembled_contribution(ParticipantRef::current(1), 5);
    let conflicting = assembled_contribution(ParticipantRef::current(1), 6);
    let retained_delivery = sample_leader_delivery(5);
    let conflicting_delivery = sample_leader_delivery(6);
    let mut assembler = PublicBatchAssembler::default();
    assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [5; 32],
            0,
            vec![retained.clone()],
            [5; 32],
            1,
            Some(retained_delivery.clone()),
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [5; 32],
            0,
            vec![conflicting.clone()],
            [6; 32],
            1,
            Some(conflicting_delivery.clone()),
        )
        .expect_err("complete chunk conflict must remain attributable to the leader");
    assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingChunk);
    assert_eq!(error.accused, PublicViolationAccused::Leader);
    assert_eq!(
        error.leader_equivocation.as_deref(),
        Some(&LeaderDeliveryEquivocation {
            retained: retained_delivery,
            conflicting: conflicting_delivery,
        }),
        "conflicting chunk must retain both signed leader deliveries"
    );
    assert_eq!(
        error.commitment_equivocation.as_deref(),
        Some(&PublicCommitmentEquivocation {
            origin: ParticipantRef::current(1),
            retained: retained.signed,
            conflicting: conflicting.signed,
        })
    );

    let retained = assembled_contribution(ParticipantRef::current(1), 7);
    let conflicting = assembled_contribution(ParticipantRef::current(1), 8);
    let error = PublicBatchAssembler::default()
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::Commitments,
            [7; 32],
            0,
            vec![retained.clone(), conflicting.clone()],
            [7; 32],
            1,
            None,
        )
        .expect_err("one chunk cannot contain two messages from the same origin");
    assert_eq!(error.kind, PublicProtocolViolationKind::BufferLimit);
    assert_eq!(error.accused, PublicViolationAccused::Leader);
    assert_eq!(
        error.commitment_equivocation.as_deref(),
        Some(&PublicCommitmentEquivocation {
            origin: ParticipantRef::current(1),
            retained: retained.signed,
            conflicting: conflicting.signed,
        })
    );
}

#[test]
fn incremental_batches_allow_multiple_roots_but_reject_origin_equivocation() {
    let first = assembled_contribution(ParticipantRef::current(1), 1);
    let second = assembled_contribution(ParticipantRef::current(2), 2);
    let first_manifest = assembled_manifest(std::slice::from_ref(&first), 1, false);
    let second_manifest = assembled_manifest(std::slice::from_ref(&second), 1, false);
    let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
    let mut assembler = PublicBatchAssembler::default();
    for (manifest, contribution) in [(first_manifest, first.clone()), (second_manifest, second)] {
        assembler
            .insert_manifest(
                PublicBatchMode::Incremental,
                manifest.clone(),
                [contribution.contribution.origin.node_id as u8; 32],
                &expected,
                None,
            )
            .unwrap();
        assert!(matches!(
            assembler
                .insert_chunk(
                    PublicBatchMode::Incremental,
                    PublicPhase::Commitments,
                    manifest.phase_root,
                    0,
                    vec![contribution],
                    [manifest.contribution_ids.len() as u8; 32],
                    expected.len(),
                    None,
                )
                .unwrap(),
            PublicBatchAssembly::Complete { .. }
        ));
    }

    let conflicting = assembled_contribution(ParticipantRef::current(1), 9);
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Incremental,
            PublicPhase::Commitments,
            [7; 32],
            0,
            vec![conflicting.clone()],
            [9; 32],
            expected.len(),
            None,
        )
        .expect_err("one origin cannot sign two messages for a public phase");
    assert_eq!(error.kind, PublicProtocolViolationKind::OriginEquivocation);
    assert_eq!(
        error.accused,
        PublicViolationAccused::Origin(ParticipantRef::current(1))
    );
    assert_eq!(
        error.commitment_equivocation.as_deref(),
        Some(&PublicCommitmentEquivocation {
            origin: ParticipantRef::current(1),
            retained: first.signed,
            conflicting: conflicting.signed,
        })
    );
}

#[test]
fn non_commitment_origin_conflicts_do_not_carry_dkg_equivocation_evidence() {
    let origin = ParticipantRef::current(1);
    let mut first = assembled_contribution(origin, 1);
    first.contribution.payload = refresh_health_payload(900);
    first.signed.data = transport::encode(&first.contribution).unwrap();
    let mut conflicting = assembled_contribution(origin, 2);
    conflicting.contribution.payload = refresh_health_payload(900);
    let DkgPublicPayload::RefreshHealthCheckResult { statement, .. } =
        &mut conflicting.contribution.payload
    else {
        unreachable!("refresh-health test helper returned a different phase");
    };
    statement.public_polynomial_sha256 = "22".repeat(32);
    conflicting.signed.data = transport::encode(&conflicting.contribution).unwrap();
    let expected = BTreeSet::from([origin]);
    let mut assembler = PublicBatchAssembler::default();
    let retained_envelope = first.signed.clone();
    let conflicting_envelope = conflicting.signed.clone();
    assembler
        .insert_chunk(
            PublicBatchMode::Incremental,
            PublicPhase::RefreshHealthCheck,
            [1; 32],
            0,
            vec![first],
            [1; 32],
            expected.len(),
            None,
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Incremental,
            PublicPhase::RefreshHealthCheck,
            [2; 32],
            0,
            vec![conflicting],
            [2; 32],
            expected.len(),
            None,
        )
        .expect_err("non-Commitment origin conflict must still abort");
    assert_eq!(error.kind, PublicProtocolViolationKind::OriginEquivocation);
    assert!(error.commitment_equivocation.is_none());
    assert_eq!(
        error.public_origin_fault.as_deref(),
        Some(&PublicOriginFaultEvidence {
            fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
            contribution_a: retained_envelope,
            contribution_b: Some(conflicting_envelope),
        }),
        "non-Commitment conflicts must preserve both exact endpoint envelopes"
    );
}

#[test]
fn reshare_participant_set_origin_conflicts_do_not_carry_dkg_equivocation_evidence() {
    // ReshareParticipantSet is Complete-mode with a single legitimate
    // origin (next-committee node 1), so a genuinely different root the
    // second time is a leader-attributed ConflictingManifest, not origin
    // equivocation. Origin equivocation instead shows up as the same
    // origin appearing again at a different index under the one
    // canonical root the phase already committed to.
    let origin = ParticipantRef::next(1);
    let mut first = assembled_contribution(origin, 1);
    first.contribution.payload = reshare_participant_set_payload(&[1, 2]);
    first.signed.data = transport::encode(&first.contribution).unwrap();
    let mut conflicting = assembled_contribution(origin, 2);
    conflicting.contribution.payload = reshare_participant_set_payload(&[1, 3]);
    conflicting.signed.data = transport::encode(&conflicting.contribution).unwrap();
    let mut assembler = PublicBatchAssembler::default();
    let retained_envelope = first.signed.clone();
    let conflicting_envelope = conflicting.signed.clone();
    assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::ReshareParticipantSet,
            [1; 32],
            0,
            vec![first],
            [1; 32],
            2,
            None,
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Complete,
            PublicPhase::ReshareParticipantSet,
            [1; 32],
            1,
            vec![conflicting],
            [2; 32],
            2,
            None,
        )
        .expect_err("reshare participant-set origin conflict must still abort");
    assert_eq!(error.kind, PublicProtocolViolationKind::OriginEquivocation);
    assert!(error.commitment_equivocation.is_none());
    assert_eq!(
        error.public_origin_fault.as_deref(),
        Some(&PublicOriginFaultEvidence {
            fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
            contribution_a: retained_envelope,
            contribution_b: Some(conflicting_envelope),
        }),
        "reshare participant-set conflicts must preserve both exact endpoint envelopes"
    );
}

#[test]
fn incremental_batch_buffers_are_origin_bounded() {
    let first = assembled_contribution(ParticipantRef::current(1), 1);
    let second = assembled_contribution(ParticipantRef::current(2), 2);
    let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
    let mut assembler = PublicBatchAssembler::default();
    let first_chunk_delivery = sample_leader_delivery(1);
    let second_chunk_delivery = sample_leader_delivery(2);

    assembler
        .insert_chunk(
            PublicBatchMode::Incremental,
            PublicPhase::Commitments,
            [1; 32],
            0,
            vec![first.clone()],
            [1; 32],
            expected.len(),
            Some(first_chunk_delivery.clone()),
        )
        .unwrap();
    let error = assembler
        .insert_chunk(
            PublicBatchMode::Incremental,
            PublicPhase::Commitments,
            [2; 32],
            0,
            vec![first],
            [2; 32],
            expected.len(),
            Some(second_chunk_delivery.clone()),
        )
        .expect_err("a leader cannot retain one contribution under multiple roots");
    assert_eq!(error.kind, PublicProtocolViolationKind::BatchMismatch);
    assert_eq!(
        error.leader_batch_mismatch.as_deref(),
        Some(&LeaderDeliveryEquivocation {
            retained: first_chunk_delivery,
            conflicting: second_chunk_delivery,
        }),
        "a leader repackaging one origin under two different roots must be provably \
             attributable via claim_origins, not just the weaker message-id-only evidence \
             ensure_no_origin_equivocation's own fallback branch would have attached"
    );

    // The same cross-root duplication, but detected at the *manifest*
    // level (no chunks involved at all) — this is what `insert_manifest`
    // had no equivalent check for before `claim_origins`, so this
    // scenario used to only be caught by the much weaker aggregate
    // `BufferLimit` bound (see the pigeonhole argument on
    // `claim_origins`'s doc comment).
    let mut assembler = PublicBatchAssembler::default();
    let first = assembled_contribution(ParticipantRef::current(1), 1);
    let one_origin = assembled_manifest(std::slice::from_ref(&first), 1, false);
    let overlapping = assembled_manifest(&[first, second], 1, false);
    let one_origin_delivery = sample_leader_delivery(3);
    let overlapping_delivery = sample_leader_delivery(4);
    assembler
        .insert_manifest(
            PublicBatchMode::Incremental,
            one_origin,
            [3; 32],
            &expected,
            Some(one_origin_delivery.clone()),
        )
        .unwrap();
    let error = assembler
        .insert_manifest(
            PublicBatchMode::Incremental,
            overlapping,
            [4; 32],
            &expected,
            Some(overlapping_delivery.clone()),
        )
        .expect_err("pending manifest entries must remain committee-bounded");
    assert_eq!(error.kind, PublicProtocolViolationKind::BatchMismatch);
    assert_eq!(
        error.leader_batch_mismatch.as_deref(),
        Some(&LeaderDeliveryEquivocation {
            retained: one_origin_delivery,
            conflicting: overlapping_delivery,
        }),
        "a leader repackaging one origin across two different manifests must be provably \
             attributable, not just caught by the aggregate BufferLimit backstop"
    );
}
