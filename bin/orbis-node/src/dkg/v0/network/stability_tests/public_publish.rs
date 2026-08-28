#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[tokio::test]
async fn partial_publication_failure_replays_the_exact_batch_from_manifest() {
    let topic = ScriptedBroadcastTopic::new([2]);
    let batch = PreparedPublicBatch {
        root: [7; 32],
        contribution_count: 1,
        messages: vec![
            Bytes::from_static(b"manifest"),
            Bytes::from_static(b"chunk-0"),
            Bytes::from_static(b"chunk-1"),
        ],
    };

    assert!(
        broadcast_public_batches(&topic, std::slice::from_ref(&batch))
            .await
            .is_err()
    );
    broadcast_public_batches(&topic, &[batch])
        .await
        .expect("the retry should restart with the identical manifest");

    assert_eq!(
        topic.observed.lock().await.as_slice(),
        [
            Bytes::from_static(b"manifest"),
            Bytes::from_static(b"chunk-0"),
            Bytes::from_static(b"manifest"),
            Bytes::from_static(b"chunk-0"),
            Bytes::from_static(b"chunk-1"),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn complete_phase_is_marked_published_only_after_retry_succeeds() {
    let origin = ParticipantRef::current(1);
    let (state, ceremony_id, attempt_id, _, _guard) = contribution_test_state(
        "complete_publication_commits_after_retry",
        4249,
        SessionKind::Fresh,
        Vec::new(),
        origin,
    )
    .await;
    let topic = Arc::new(ScriptedBroadcastTopic::new([2]));
    {
        let mut states = state.dkg_session_state.states.write().await;
        let transport = &mut states
            .get_mut(&ceremony_id.0)
            .expect("publication test session")
            .transport;
        transport.topic = Some(topic.clone());
        transport.hard_deadline =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
        transport.public_contributions.insert(
            PublicPhase::Commitments,
            (1..=3)
                .map(|node_id| {
                    (
                        ParticipantRef::current(node_id),
                        SignedPayload {
                            origin: vec![node_id as u8],
                            signature: vec![node_id as u8; 32],
                            data: vec![node_id as u8; 32],
                        },
                    )
                })
                .collect(),
        );
    }

    publish_phase_if_complete(
        state.clone(),
        &network::V0,
        ceremony_id.0,
        attempt_id,
        PublicPhase::Commitments,
    )
    .await
    .expect("a transient Gossip failure should schedule publication retry");
    assert_eq!(
        state
            .dkg_session_state
            .with_state(&ceremony_id.0, |session| (
                session
                    .transport
                    .publishing_public_phases
                    .contains(&PublicPhase::Commitments),
                session
                    .transport
                    .published_public_phases
                    .contains(&PublicPhase::Commitments),
            ))
            .await,
        Some((true, false)),
        "a partial send must remain in-flight, not published"
    );

    tokio::task::yield_now().await;
    tokio::time::advance(INITIAL_CONTROL_RETRY_BACKOFF).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    assert_eq!(
        state
            .dkg_session_state
            .with_state(&ceremony_id.0, |session| (
                session
                    .transport
                    .publishing_public_phases
                    .contains(&PublicPhase::Commitments),
                session
                    .transport
                    .published_public_phases
                    .contains(&PublicPhase::Commitments),
            ))
            .await,
        Some((false, true)),
        "the full successful retry must atomically commit publication"
    );
    let observed = topic.observed.lock().await;
    assert_eq!(observed.len(), 4, "manifest and chunk should be retried");
    assert_eq!(observed[0], observed[2]);
    assert_eq!(observed[1], observed[3]);
}
