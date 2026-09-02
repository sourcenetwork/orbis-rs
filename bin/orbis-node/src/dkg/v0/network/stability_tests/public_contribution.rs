use std::sync::atomic::Ordering;
#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[tokio::test]
async fn direct_origin_payload_is_preflighted_before_leader_relay() {
    let origin = ParticipantRef::current(2);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "direct_origin_preflight_before_relay",
        4256,
        SessionKind::Fresh,
        Vec::new(),
        origin,
    )
    .await;
    let topic = Arc::new(ScriptedBroadcastTopic::new([]));
    let mut invalid_commitment = fresh_commitment_bytes(origin.node_id, ceremony_id.0);
    invalid_commitment[..crypto::GROUP_POINT_SIZE].fill(0xff);
    let signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: invalid_commitment.clone(),
            report_evidence: None,
        },
    )
    .await;

    let first = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        ParticipantRef::current(1),
        DkgPublicPayload::Commitment {
            commitment: fresh_commitment_bytes(1, ceremony_id.0),
            report_evidence: None,
        },
    );
    let third = verified_test_contribution(
        ceremony_id,
        attempt_id,
        committee_digest,
        ParticipantRef::current(3),
        DkgPublicPayload::Commitment {
            commitment: fresh_commitment_bytes(3, ceremony_id.0),
            report_evidence: None,
        },
    );
    {
        let mut states = state.dkg_session_state.states.write().await;
        let session = states
            .get_mut(&ceremony_id.0)
            .expect("direct contribution test session");
        session.transport.leader_node_key = Some(state.node_key.clone());
        session.transport.topic = Some(topic.clone());
        session.transport.hard_deadline =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(30));
        session.transport.public_contributions.insert(
            PublicPhase::Commitments,
            BTreeMap::from([
                (first.contribution.origin, first.signed),
                (third.contribution.origin, third.signed),
            ]),
        );
        session.commit_reveal.received_hashes.insert(
            origin.node_id,
            crate::dkg::v0::helpers::fresh_commitment_hash(
                ceremony_id.0,
                origin.node_id,
                &invalid_commitment,
            ),
        );
    }
    let sender = state.network.local_peer_id().clone();

    let error = handle_control(
        state.clone(),
        &network::V0,
        DkgControlMessage::PublicContribution(signed),
        &sender,
    )
    .await
    .expect_err("the leader must reject a crypto-invalid direct contribution");

    assert!(matches!(error, DkgError::Deserialization(_)));
    assert_eq!(
        topic.calls.load(Ordering::SeqCst),
        0,
        "the invalid contribution must not complete and relay the phase batch"
    );
    assert_eq!(
        state
            .dkg_session_state
            .transport_attempt(&ceremony_id.0)
            .await,
        None,
        "an attributable direct-origin violation must abort the exact attempt"
    );
}

#[tokio::test]
async fn recording_a_stale_public_contribution_is_not_equivocation() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, active_attempt, committee_digest, _guard) = contribution_test_state(
        "record_stale_public_contribution",
        4241,
        SessionKind::Fresh,
        Vec::new(),
        origin,
    )
    .await;
    let stale_attempt = AttemptId([active_attempt.0[0].wrapping_add(1); 32]);
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        stale_attempt,
        "test-ring-post".to_string(),
        committee_digest,
        origin,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [1; 32],
        },
    )
    .unwrap();
    let signed = SignedPayload {
        origin: vec![1; 32],
        signature: vec![2; 64],
        data: vec![3; 16],
    };

    let error = record_public_contribution(&state, &network::V0, signed, &contribution)
        .await
        .expect_err("stale contribution must be rejected");

    assert!(
        matches!(error, DkgError::ProtocolError(ref message) if message.contains("stale attempt"))
    );
}

// =========================================================================
// verify_signed_contribution — per-phase/scope authorization matrix
// =========================================================================

#[tokio::test]
async fn verify_signed_contribution_rejects_reshare_commitment_from_non_dealer() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "verify_signed_contribution_rejects_non_dealer",
        4242,
        SessionKind::Reshare {
            ring_pk_hex: "test-ring".to_string(),
            new_peer_node_keys: vec!["node-a".to_string()],
            new_threshold: 1,
            bulletin_post_id: "test-ring-post".to_string(),
        },
        vec![ParticipantRef::current(2)], // origin (node 1) is deliberately not a dealer
        origin,
    )
    .await;

    let signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: vec![1, 2, 3],
            report_evidence: None,
        },
    )
    .await;

    let error = verify_signed_contribution(&state, &signed)
        .await
        .expect_err(
            "a non-dealer origin must not be allowed to submit a reshare Commitments contribution",
        );
    assert!(matches!(error, DkgError::Unauthorized(_)));
}

#[tokio::test]
async fn verify_signed_contribution_accepts_reshare_commitment_from_active_dealer() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "verify_signed_contribution_accepts_active_dealer",
        4243,
        SessionKind::Reshare {
            ring_pk_hex: "test-ring".to_string(),
            new_peer_node_keys: vec!["node-a".to_string()],
            new_threshold: 1,
            bulletin_post_id: "test-ring-post".to_string(),
        },
        vec![origin], // origin is an active dealer this time
        origin,
    )
    .await;

    let signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: vec![1, 2, 3],
            report_evidence: None,
        },
    )
    .await;

    verify_signed_contribution(&state, &signed)
        .await
        .expect("an active dealer must be allowed to submit a reshare Commitments contribution");
}

#[tokio::test]
async fn verify_signed_contribution_rejects_foreign_ring_id() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "verify_signed_contribution_rejects_foreign_ring",
        4245,
        SessionKind::Fresh,
        Vec::new(),
        origin,
    )
    .await;
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        attempt_id,
        "different-ring".to_string(),
        committee_digest,
        origin,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [7; 32],
        },
    )
    .unwrap();
    let signed = state
        .network
        .pubsub()
        .expect("pubsub enabled")
        .sign(
            PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
            transport::encode(&contribution).unwrap().into(),
        )
        .await
        .unwrap();

    let error = verify_signed_contribution(&state, &signed)
        .await
        .expect_err("the signed contribution must be bound to the active ring");
    assert!(matches!(error, DkgError::Unauthorized(_)));
}

#[tokio::test]
async fn verify_signed_contribution_rejects_next_scope_origin_during_refresh() {
    // Refresh has no "next" committee at all — a contribution whose origin
    // claims `CommitteeScope::Next` must be rejected regardless of phase.
    let origin = ParticipantRef::next(1);
    let (state, ceremony_id, attempt_id, committee_digest, _guard) = contribution_test_state(
        "verify_signed_contribution_rejects_next_scope_refresh",
        4244,
        SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        Vec::new(),
        origin,
    )
    .await;

    let signed = sign_contribution(
        &state,
        ceremony_id,
        attempt_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: vec![1, 2, 3],
            report_evidence: None,
        },
    )
    .await;

    let error = verify_signed_contribution(&state, &signed)
        .await
        .expect_err("a Next-scope origin must never be accepted during a Refresh ceremony");
    assert!(matches!(error, DkgError::Unauthorized(_)));
}
