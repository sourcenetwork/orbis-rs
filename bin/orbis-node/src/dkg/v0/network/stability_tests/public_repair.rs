#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn public_repair_control_errors_separate_availability_from_malformed_bytes() {
    assert!(retryable_public_repair_control_error(
        &DkgError::NetworkConnection("offline".into())
    ));
    assert!(retryable_public_repair_control_error(
        &DkgError::NetworkCommunication("stream reset".into())
    ));
    assert!(retryable_public_repair_control_error(
        &DkgError::ProtocolError("explicit peer error".into())
    ));
    assert!(!retryable_public_repair_control_error(
        &DkgError::Deserialization("malformed peer bytes".into())
    ));
    assert!(!retryable_public_repair_control_error(
        &DkgError::Serialization("local encoding failure".into())
    ));
}

#[tokio::test]
async fn leader_unavailability_enters_direct_origin_repair() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "leader_unavailability_enters_origin_repair",
        4250,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        origin,
    )
    .await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 1);
    let signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        refresh_health_payload(ceremony_id.0),
    )
    .await;
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
        "repair-route-1".to_string(),
        std::collections::VecDeque::from([
            Err(DkgError::NetworkConnection("leader unavailable".into())),
            Ok(DkgControlMessage::PublicContributionResponse {
                ceremony_id,
                attempt_id,
                contribution: Some(signed),
            }),
        ]),
    )]));

    repair_public_phase_claimed(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::RefreshHealthCheck,
    )
    .await
    .expect("origin repair should replace the unavailable leader repair path");

    let retained = state
        .dkg_session_state
        .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck)
        .await
        .expect("active repair attempt");
    assert_eq!(retained.keys().copied().collect::<Vec<_>>(), vec![origin]);
    assert_eq!(
        state.dkg_session_state.offline_candidate_claim_count(),
        1,
        "leader fallback must retain its terminal liveness observation"
    );
    assert_eq!(
        requester.requests.lock().await.as_slice(),
        [
            ("repair-route-1".to_string(), "get_public_phase"),
            ("repair-route-1".to_string(), "get_public_contribution"),
        ]
    );
}

#[tokio::test]
async fn commitment_audit_leader_failure_does_not_create_origin_fanout() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, _, _guard) = contribution_test_state(
        "commitment_audit_repair_remains_best_effort",
        4255,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        origin,
    )
    .await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
        "repair-route-1".to_string(),
        std::collections::VecDeque::from([Err(DkgError::ProtocolError(
            "leader no longer retains diagnostic audits".into(),
        ))]),
    )]));

    repair_public_phase_claimed(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::CommitmentAudit,
    )
    .await
    .expect("commitment-audit repair is optional diagnostics");

    assert_eq!(
        requester.requests.lock().await.as_slice(),
        [("repair-route-1".to_string(), "get_public_phase")]
    );
    assert!(
        state.dkg_session_state.offline_candidate_claim_count() == 0,
        "a reachable protocol rejection must not create an offline candidate"
    );
}

#[tokio::test]
async fn later_leader_page_failure_preserves_pages_then_uses_origins() {
    let first = ParticipantRef::current(1);
    let second = ParticipantRef::current(2);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "later_leader_page_failure_uses_origins",
        4251,
        SessionKind::Fresh,
        Vec::new(),
        first,
    )
    .await;
    bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
    let first_signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        first,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [1; 32],
        },
    )
    .await;
    let second_signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        second,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [2; 32],
        },
    )
    .await;
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([
        (
            "repair-route-1".to_string(),
            std::collections::VecDeque::from([
                Ok(DkgControlMessage::PublicPhaseResponse {
                    ceremony_id,
                    attempt_id,
                    phase: PublicPhase::CommitmentHashes,
                    contributions: vec![first_signed],
                    next_cursor: Some(first),
                    page_digest: [0; 32],
                    report_signature: None,
                }),
                Err(DkgError::NetworkCommunication(
                    "leader failed on the second page".into(),
                )),
            ]),
        ),
        (
            "repair-route-2".to_string(),
            std::collections::VecDeque::from([Ok(DkgControlMessage::PublicContributionResponse {
                ceremony_id,
                attempt_id,
                contribution: Some(second_signed),
            })]),
        ),
    ]));
    let expected = BTreeSet::from([first, second]);

    let outcome = collect_public_phase_from_leader(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::CommitmentHashes,
        &expected,
    )
    .await
    .expect("a later leader availability failure must be recoverable");
    assert!(matches!(
        outcome,
        LeaderPublicRepairOutcome::Unavailable { retained: 1, .. }
    ));
    collect_public_phase_from_origins(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::CommitmentHashes,
        &expected,
    )
    .await
    .expect("the missing second origin should complete repair");

    let retained = state
        .dkg_session_state
        .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::CommitmentHashes)
        .await
        .expect("active repair attempt");
    assert_eq!(
        retained.keys().copied().collect::<Vec<_>>(),
        vec![first, second]
    );
}

#[tokio::test]
async fn unavailable_origin_does_not_block_other_origin_responses() {
    let first = ParticipantRef::current(1);
    let second = ParticipantRef::current(2);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "unavailable_origin_does_not_block_others",
        4252,
        SessionKind::Fresh,
        Vec::new(),
        first,
    )
    .await;
    bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
    let second_signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        second,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [2; 32],
        },
    )
    .await;
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([
        (
            "repair-route-1".to_string(),
            std::collections::VecDeque::from([Err(DkgError::NetworkConnection(
                "first origin unavailable".into(),
            ))]),
        ),
        (
            "repair-route-2".to_string(),
            std::collections::VecDeque::from([Ok(DkgControlMessage::PublicContributionResponse {
                ceremony_id,
                attempt_id,
                contribution: Some(second_signed),
            })]),
        ),
    ]));

    collect_public_phase_from_origins(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::CommitmentHashes,
        &BTreeSet::from([first, second]),
    )
    .await
    .expect("one unavailable origin must not short-circuit the repair round");

    let retained = state
        .dkg_session_state
        .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::CommitmentHashes)
        .await
        .expect("active repair attempt");
    assert!(!retained.contains_key(&first));
    assert!(retained.contains_key(&second));
}

#[tokio::test]
async fn malformed_origin_response_preflights_before_any_origin_is_applied() {
    let first = ParticipantRef::current(1);
    let second = ParticipantRef::current(2);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "malformed_origin_response_is_atomic",
        4253,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        first,
    )
    .await;
    bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
    let second_signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        second,
        refresh_health_payload(ceremony_id.0),
    )
    .await;
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([
        (
            "repair-route-1".to_string(),
            std::collections::VecDeque::from([Ok(DkgControlMessage::Begun {
                ceremony_id,
                attempt_id,
                activation_digest: [8; 32],
                report_signature: None,
            })]),
        ),
        (
            "repair-route-2".to_string(),
            std::collections::VecDeque::from([Ok(DkgControlMessage::PublicContributionResponse {
                ceremony_id,
                attempt_id,
                contribution: Some(second_signed),
            })]),
        ),
    ]));

    let error = collect_public_phase_from_origins(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::RefreshHealthCheck,
        &BTreeSet::from([first, second]),
    )
    .await
    .expect_err("an authenticated malformed origin response must fail fast");
    assert!(matches!(
        error,
        PublicRepairFailure::Violation(PublicProtocolViolation {
            kind: PublicProtocolViolationKind::MalformedOriginMessage,
            accused: PublicViolationAccused::Origin(origin),
            ..
        }) if origin == first
    ));
    assert!(
        state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck,)
            .await
            .expect("active repair attempt")
            .is_empty(),
        "origin responses must be preflighted before any valid subset is recorded"
    );
}

#[tokio::test]
async fn repair_payload_preflight_is_atomic_before_retention_or_crypto_mutation() {
    let first = ParticipantRef::current(2);
    let second = ParticipantRef::current(3);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "repair_payload_preflight_is_atomic",
        4255,
        SessionKind::Fresh,
        Vec::new(),
        first,
    )
    .await;
    bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 3);

    let valid_commitment = fresh_commitment_bytes(first.node_id, ceremony_id.0);
    let mut invalid_commitment = fresh_commitment_bytes(second.node_id, ceremony_id.0);
    invalid_commitment[..crypto::GROUP_POINT_SIZE].fill(0xff);
    {
        let mut states = state.dkg_session_state.states.write().await;
        let session = states.get_mut(&ceremony_id.0).expect("repair test session");
        session.commit_reveal.received_hashes.insert(
            first.node_id,
            crate::dkg::v0::helpers::fresh_commitment_hash(
                ceremony_id.0,
                first.node_id,
                &valid_commitment,
            ),
        );
        session.commit_reveal.received_hashes.insert(
            second.node_id,
            crate::dkg::v0::helpers::fresh_commitment_hash(
                ceremony_id.0,
                second.node_id,
                &invalid_commitment,
            ),
        );
    }

    let valid = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        first,
        DkgPublicPayload::Commitment {
            commitment: valid_commitment,
            report_evidence: None,
        },
    );
    let invalid = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        second,
        DkgPublicPayload::Commitment {
            commitment: invalid_commitment,
            report_evidence: None,
        },
    );

    let error = apply_repair_contributions(
        &state,
        &network::V0,
        &prepare,
        PublicPhase::Commitments,
        vec![valid, invalid],
        RepairContributionSource::Origin,
    )
    .await
    .expect_err("a crypto-invalid direct-origin contribution must fail preflight");
    assert!(matches!(
        error,
        PublicRepairFailure::Violation(PublicProtocolViolation {
            kind: PublicProtocolViolationKind::InvalidContribution,
            accused: PublicViolationAccused::Origin(origin),
            ..
        }) if origin == second
    ));

    let retained = state
        .dkg_session_state
        .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::Commitments)
        .await
        .expect("active repair attempt");
    assert!(
        retained.is_empty(),
        "a failed payload preflight must retain none of the repair batch"
    );
    assert_eq!(
        state
            .dkg_session_state
            .with_state(&ceremony_id.0, |session| session.commitments_received)
            .await,
        Some(0),
        "a failed payload preflight must not apply the valid batch prefix"
    );
}

#[tokio::test]
async fn direct_repair_conflict_preserves_both_commitment_envelopes() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "direct_repair_conflict_preserves_envelopes",
        4257,
        SessionKind::Fresh,
        Vec::new(),
        origin,
    )
    .await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 3);
    let retained = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: fresh_commitment_bytes(origin.node_id, ceremony_id.0),
            report_evidence: None,
        },
    );
    let mut different = fresh_commitment_bytes(origin.node_id, ceremony_id.0);
    different[crypto::GROUP_POINT_SIZE] ^= 1;
    let conflicting = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: different,
            report_evidence: None,
        },
    );
    assert_eq!(
        state
            .dkg_session_state
            .record_public_contribution(
                &ceremony_id.0,
                attempt_id,
                PublicPhase::Commitments,
                origin,
                retained.signed.clone(),
            )
            .await,
        PublicContributionRecordOutcome::Recorded
    );

    let error = apply_repair_contributions(
        &state,
        &network::V0,
        &prepare,
        PublicPhase::Commitments,
        vec![conflicting.clone()],
        RepairContributionSource::Origin,
    )
    .await
    .expect_err("conflicting direct repair contribution must abort");
    let PublicRepairFailure::Violation(violation) = error else {
        panic!("expected attributable repair violation");
    };
    assert_eq!(
        violation.kind,
        PublicProtocolViolationKind::OriginEquivocation
    );
    assert_eq!(
        violation.commitment_equivocation.as_deref(),
        Some(&PublicCommitmentEquivocation {
            origin,
            retained: retained.signed.clone(),
            conflicting: conflicting.signed,
        })
    );
    assert_eq!(
        state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::Commitments,)
            .await
            .expect("active attempt")
            .get(&origin),
        Some(&retained.signed),
        "the first authenticated envelope must remain authoritative"
    );
}

#[tokio::test]
async fn direct_repair_non_commitment_conflict_preserves_public_origin_evidence() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "direct_repair_non_commitment_conflict_preserves_envelopes",
        4258,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        origin,
    )
    .await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 3);
    let first_payload = refresh_health_payload(ceremony_id.0);
    let mut second_payload = first_payload.clone();
    let DkgPublicPayload::RefreshHealthCheckResult { statement, .. } = &mut second_payload else {
        unreachable!("refresh-health test helper returned a different phase");
    };
    statement.public_polynomial_sha256 = "22".repeat(32);
    let retained = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        first_payload,
    );
    let conflicting = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        second_payload,
    );
    assert_eq!(
        state
            .dkg_session_state
            .record_public_contribution(
                &ceremony_id.0,
                attempt_id,
                PublicPhase::RefreshHealthCheck,
                origin,
                retained.signed.clone(),
            )
            .await,
        PublicContributionRecordOutcome::Recorded
    );

    let error = apply_repair_contributions(
        &state,
        &network::V0,
        &prepare,
        PublicPhase::RefreshHealthCheck,
        vec![conflicting.clone()],
        RepairContributionSource::Origin,
    )
    .await
    .expect_err("conflicting direct repair contribution must abort");
    let PublicRepairFailure::Violation(violation) = error else {
        panic!("expected attributable repair violation");
    };
    assert_eq!(
        violation.kind,
        PublicProtocolViolationKind::OriginEquivocation
    );
    assert!(violation.commitment_equivocation.is_none());
    assert_eq!(
        violation.public_origin_fault.as_deref(),
        Some(&PublicOriginFaultEvidence {
            fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
            contribution_a: retained.signed.clone(),
            contribution_b: Some(conflicting.signed),
        })
    );
    assert_eq!(
        state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck)
            .await
            .expect("active attempt")
            .get(&origin),
        Some(&retained.signed),
        "the first authenticated envelope must remain authoritative"
    );
}

#[tokio::test]
async fn malformed_leader_repair_is_attributable_but_stale_abort_is_attempt_scoped() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, _, _guard) = contribution_test_state(
        "malformed_leader_repair_is_attempt_scoped",
        4254,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        origin,
    )
    .await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 1);
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
        "repair-route-1".to_string(),
        std::collections::VecDeque::from([Ok(DkgControlMessage::Begun {
            ceremony_id,
            attempt_id,
            activation_digest: [7; 32],
            report_signature: None,
        })]),
    )]));

    let violation = match collect_public_phase_from_leader(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::RefreshHealthCheck,
        &BTreeSet::from([origin]),
    )
    .await
    .expect_err("an authenticated unexpected leader response must be attributable")
    {
        PublicRepairFailure::Violation(violation) => violation,
        other => panic!("expected typed protocol violation, got {other:?}"),
    };
    assert_eq!(
        violation.kind,
        PublicProtocolViolationKind::MalformedLeaderMessage
    );
    assert_eq!(violation.accused, PublicViolationAccused::Leader);

    let newer_attempt = AttemptId([attempt_id.0[0].wrapping_add(1); 32]);
    {
        let mut states = state.dkg_session_state.states.write().await;
        states
            .get_mut(&ceremony_id.0)
            .expect("repair test session")
            .transport
            .attempt_id = Some(newer_attempt);
    }
    abort_public_protocol_violation(
        &state,
        &network::V0,
        &prepare,
        &violation,
        TopicTaskDisposition::Abort,
    )
    .await;
    assert_eq!(
        state
            .dkg_session_state
            .transport_attempt(&ceremony_id.0)
            .await,
        Some(newer_attempt),
        "a stale attributable response must not remove a newer attempt"
    );
}

#[tokio::test]
async fn oversized_signed_repair_page_is_attributable_with_control_message_fault_evidence() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, _, _guard) = contribution_test_state(
        "oversized_signed_repair_page_is_attributable",
        4255,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        origin,
    )
    .await;
    let prepare = repair_test_prepare(ceremony_id, attempt_id, 1);
    let oversized_contribution = SignedPayload {
        origin: vec![1; 32],
        signature: vec![2; 64],
        data: vec![9; 700_000],
    };
    let report_signature_bytes = vec![3u8; 64];
    let oversized_response = DkgControlMessage::PublicPhaseResponse {
        ceremony_id,
        attempt_id,
        phase: PublicPhase::Commitments,
        contributions: vec![oversized_contribution],
        next_cursor: None,
        page_digest: [4; 32],
        report_signature: Some(ControlSignature {
            signer_node_key: "repair-node-1".to_string(),
            signed_at: 1_700_000_000,
            signature: report_signature_bytes.clone(),
        }),
    };
    let expected_data = transport::encode(&oversized_response).unwrap();
    let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
        "repair-route-1".to_string(),
        std::collections::VecDeque::from([Ok(oversized_response)]),
    )]));

    let violation = match collect_public_phase_from_leader(
        &state,
        &network::V0,
        &requester,
        &prepare,
        PublicPhase::Commitments,
        &BTreeSet::from([origin]),
    )
    .await
    .expect_err("an oversized signed repair page must be attributable")
    {
        PublicRepairFailure::Violation(violation) => violation,
        other => panic!("expected typed protocol violation, got {other:?}"),
    };
    assert_eq!(violation.kind, PublicProtocolViolationKind::BufferLimit);
    assert_eq!(violation.accused, PublicViolationAccused::Leader);
    assert_eq!(
        violation.control_message_fault.as_deref(),
        Some(&ControlMessageArtifact {
            signature: report_signature_bytes,
            data: expected_data,
            signed_at: 1_700_000_000,
        }),
        "an oversized leader-signed repair page must retain the signed artifact as evidence"
    );
}
