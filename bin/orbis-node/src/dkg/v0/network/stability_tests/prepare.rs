#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn reshare_preparation_candidates_preserve_committee_scope() {
    let committees = offline_relay_committees();
    let prepare = PrepareSession {
        ceremony_id: CeremonyId(33),
        attempt_id: AttemptId([5; 32]),
        config_digest: [0; 32],
        topic_id: [0; 32],
        leader_node_key: "next-a".into(),
        committees: committees.clone(),
        kind: SessionKind::Reshare {
            ring_pk_hex: "ring-pk".into(),
            new_peer_node_keys: committees.next.as_ref().unwrap().node_keys.clone(),
            new_threshold: 2,
            bulletin_post_id: "ring-id".into(),
        },
        pss_interval: 60,
        policy_id: None,
        ring_id: "ring-id".into(),
        report_signature: None,
    };
    let current_route = extract_node_part(&committees.current.peer_routes[1]).to_lowercase();
    let next_route =
        extract_node_part(&committees.next.as_ref().unwrap().peer_routes[1]).to_lowercase();

    assert_eq!(
        reshare_preparation_candidates(&prepare, [current_route, next_route]),
        [ParticipantRef::current(2), ParticipantRef::next(2)]
    );
}

#[test]
fn reshare_preparation_only_fails_for_nonretryable_next_member_errors() {
    let retryable = DkgError::NetworkCommunication("timed out".into());
    let nonretryable = DkgError::Unauthorized("configuration mismatch".into());

    assert_eq!(
        reshare_preparation_error_action(false, &retryable),
        ResharePreparationErrorAction::Retry
    );
    assert_eq!(
        reshare_preparation_error_action(false, &nonretryable),
        ResharePreparationErrorAction::ExcludeOld
    );
    assert_eq!(
        reshare_preparation_error_action(true, &nonretryable),
        ResharePreparationErrorAction::Fail
    );
}

#[test]
fn missing_topology_members_are_exact_and_prefixes_are_bounded() {
    let expected = BTreeSet::from([
        "aaaaaaaaaaaaaaaa".to_string(),
        "bbbbbbbbbbbbbbbb".to_string(),
        "cccccccccccccccc".to_string(),
    ]);
    let acknowledged = BTreeSet::from([
        "aaaaaaaaaaaaaaaa".to_string(),
        "cccccccccccccccc".to_string(),
    ]);
    let missing = missing_topology_peers(&expected, &acknowledged);
    assert_eq!(missing, vec!["bbbbbbbbbbbbbbbb"]);
    assert_eq!(missing_topology_peer_prefixes(&missing), "bbbbbbbbbbbb");
}

/// Regression test for a fix to `prepare_participant`: a retried `Prepare`
/// for an already-configured attempt must return the cached `Prepared`
/// response *without* re-running `handle_session_init`'s live Vera
/// validation. Proven here by corrupting the Vera ring's threshold
/// between the first and second call — if the retry re-validated against
/// Vera (the bug this guards against), it would fail on the
/// now-mismatched threshold instead of taking the fast idempotent path.
#[tokio::test]
async fn retried_prepare_skips_vera_revalidation_when_already_configured() {
    let db_name = "retried_prepare_skips_vera_revalidation";
    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin.clone(), db_name).await;
    let node_key = app_state.node_key.clone();
    let ring_id = TEST_FRESH_DKG_RING_ID.to_string();

    bulletin
        .set_ring(ring_id.clone(), fresh_test_ring(&node_key, 1))
        .expect("seed fresh ring");

    let state = Arc::new(app_state);
    let ceremony_id = CeremonyId(0xC0FFEE);
    let prepare = fresh_self_prepare(&state, &ring_id, &node_key, ceremony_id).await;
    let self_peer = state.network.local_peer_id();

    match prepare_participant(state.clone(), &network::V0, prepare.clone(), &self_peer)
        .await
        .expect("first Prepare should succeed against the seeded ring")
    {
        DkgControlMessage::Prepared { .. } => {}
        other => panic!("expected Prepared on the first call, got {other:?}"),
    }

    // Corrupt the ring so a fresh `handle_session_init` validation would
    // fail with a threshold mismatch if it ran again.
    bulletin
        .set_ring(ring_id.clone(), fresh_test_ring(&node_key, 99))
        .expect("corrupt ring threshold between the two Prepare calls");

    match prepare_participant(state.clone(), &network::V0, prepare.clone(), &self_peer)
        .await
        .expect(
            "retried Prepare must take the already-configured fast path, \
                 not re-validate against the now-broken Vera ring",
        ) {
        DkgControlMessage::Prepared {
            ceremony_id: got_ceremony,
            attempt_id: got_attempt,
            config_digest: got_digest,
            ..
        } => {
            assert_eq!(got_ceremony, prepare.ceremony_id);
            assert_eq!(got_attempt, prepare.attempt_id);
            assert_eq!(got_digest, prepare.config_digest);
        }
        other => panic!("expected Prepared on the retry, got {other:?}"),
    }
}

/// A `Prepare` that conflicts with an already-configured attempt (same
/// session, different ceremony/attempt/config digest) must still be
/// rejected on retry, even though the rejection is now also detected
/// before the expensive Vera revalidation.
#[tokio::test]
async fn conflicting_prepare_is_rejected_without_vera_revalidation() {
    let db_name = "conflicting_prepare_is_rejected_without_vera_revalidation";
    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin.clone(), db_name).await;
    let node_key = app_state.node_key.clone();
    let ring_id = TEST_FRESH_DKG_RING_ID.to_string();

    bulletin
        .set_ring(ring_id.clone(), fresh_test_ring(&node_key, 1))
        .expect("seed fresh ring");

    let state = Arc::new(app_state);
    let first_ceremony_id = CeremonyId(0xC0FFEE);
    let first = fresh_self_prepare(&state, &ring_id, &node_key, first_ceremony_id).await;
    let self_peer = state.network.local_peer_id();

    prepare_participant(state.clone(), &network::V0, first.clone(), &self_peer)
        .await
        .expect("first Prepare should succeed against the seeded ring");

    // Corrupt the ring; the conflicting retry below must be rejected
    // before this would even be consulted.
    bulletin
        .set_ring(ring_id.clone(), fresh_test_ring(&node_key, 99))
        .expect("corrupt ring threshold before the conflicting retry");

    // Same session (same ring, so same deterministic ceremony ID
    // pattern here is reused directly), different attempt: a fresh
    // `AttemptId` makes this a conflicting attempt for the session
    // `prepare_participant` already configured above.
    let mut conflicting = first.clone();
    conflicting.attempt_id = AttemptId::random();
    conflicting.config_digest = transport::config_digest(&conflicting)
        .expect("compute config digest for conflicting test Prepare");

    let error = prepare_participant(state.clone(), &network::V0, conflicting, &self_peer)
        .await
        .expect_err("a conflicting attempt for an already-configured session must be rejected");
    assert!(matches!(error, DkgError::ProtocolError(_)));
    assert!(error
        .to_string()
        .contains("conflicts with the configured transport attempt"));
}
