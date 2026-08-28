#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn reshare_start_rejects_stale_ring_key_before_leader_selection() {
    let error = pending_reshare_parameters(&pending_reshare_ring(), "stale-ring-key")
        .expect_err("a stale scheduler observation must not start reshare");
    assert!(matches!(error, DkgError::InvalidState(_)));
    assert!(error.to_string().contains("differs from Vera state"));
}

#[test]
fn threshold_only_reshare_uses_current_committee_as_next() {
    let mut ring = pending_reshare_ring();
    ring.new_peer_node_keys = None;
    ring.new_threshold = Some(1);
    let (next_keys, next_threshold) =
        pending_reshare_parameters(&ring, "authoritative-ring-key").unwrap();
    assert_eq!(next_keys, ring.peer_node_keys);
    assert_eq!(next_threshold, 1);
    assert_eq!(transport::canonical_leader(&next_keys), Some("current-a"));
}

#[tokio::test]
async fn ceremony_start_lock_is_removed_after_the_last_waiter_releases_it() {
    let state = Arc::new(create_test_app_state_default("ceremony_start_lock_cleanup").await);
    let ceremony = CeremonyId(91);
    let first = lock_ceremony_start(&state, ceremony).await;
    assert!(state
        .dkg_session_state
        .ceremony_start_locks()
        .lock()
        .await
        .contains_key(&ceremony.0));

    let waiter_state = state.clone();
    let waiter = tokio::spawn(async move { lock_ceremony_start(&waiter_state, ceremony).await });
    timeout(Duration::from_secs(1), async {
        loop {
            let references = {
                let locks = state.dkg_session_state.ceremony_start_locks();
                let locks = locks.lock().await;
                Arc::strong_count(locks.get(&ceremony.0).expect("lock entry must exist"))
            };
            if references >= 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("waiter should retain the existing lock");

    drop(first);
    let second = waiter.await.expect("waiter task should complete");
    assert!(state
        .dkg_session_state
        .ceremony_start_locks()
        .lock()
        .await
        .contains_key(&ceremony.0));
    drop(second);

    timeout(Duration::from_secs(1), async {
        loop {
            if !state
                .dkg_session_state
                .ceremony_start_locks()
                .lock()
                .await
                .contains_key(&ceremony.0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("last guard should remove the ceremony lock entry");
}
