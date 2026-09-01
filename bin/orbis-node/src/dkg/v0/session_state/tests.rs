use super::*;
use crate::dkg::v0::messages::SessionKind;
use crypto::r#trait::DkgRole;
use crypto::DkgImpl;
use crypto::ScalarField as Fr;
use std::sync::Arc;

/// Create a minimal DkgImpl node for state-manager tests.
/// The state manager stores the node but never calls protocol methods on it,
/// so any valid construction is fine here.
fn make_node(id: u32) -> DkgImpl {
    *DkgImpl::new(id, 2, 3, 0, DkgRole::Standard).expect("DkgImpl::new failed")
}

// =========================================================================
// Session creation
// =========================================================================

#[tokio::test]
async fn test_create_session_success() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ok = mgr.create_session(1, make_node(1), 3, |_| {}).await;
    assert_eq!(
        ok,
        CreateSessionOutcome::Created,
        "first create should succeed"
    );
    assert_eq!(mgr.session_count().await, 1);
}

#[tokio::test]
async fn background_workers_shutdown_cleanly() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    tokio::time::timeout(std::time::Duration::from_millis(250), mgr.shutdown())
        .await
        .expect("background workers should stop promptly");
    assert!(mgr
        .background_tasks
        .lock()
        .expect("background task mutex")
        .is_empty());
}

#[tokio::test]
async fn test_create_session_rejects_duplicate_id() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert_eq!(
        mgr.create_session(42, make_node(1), 3, |_| {}).await,
        CreateSessionOutcome::Created
    );
    let dup = mgr.create_session(42, make_node(2), 3, |_| {}).await;
    assert_eq!(
        dup,
        CreateSessionOutcome::AlreadyExists,
        "duplicate session_id should be rejected"
    );
    assert_eq!(mgr.session_count().await, 1, "count must not increment");
}

#[tokio::test]
async fn test_create_session_rejects_zero_participants() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ok = mgr.create_session(1, make_node(1), 0, |_| {}).await;
    assert_eq!(
        ok,
        CreateSessionOutcome::InvalidParticipantCount,
        "zero participants should be rejected"
    );
    assert_eq!(mgr.session_count().await, 0);
}

#[tokio::test]
async fn test_session_limit_enforcement() {
    let mgr = SessionStateManager::<DkgImpl>::new();

    for i in 0..MAX_DKG_SESSIONS as u128 {
        let ok = mgr.create_session(i, make_node(1), 3, |_| {}).await;
        assert_eq!(
            ok,
            CreateSessionOutcome::Created,
            "create should succeed for session {}",
            i
        );
    }

    // One beyond the limit must be rejected
    let rejected = mgr
        .create_session(MAX_DKG_SESSIONS as u128, make_node(1), 3, |_| {})
        .await;
    assert_eq!(
        rejected,
        CreateSessionOutcome::LimitReached,
        "create should fail at session limit"
    );
    assert_eq!(mgr.session_count().await, MAX_DKG_SESSIONS);
}

// =========================================================================
// Session existence and removal
// =========================================================================

#[tokio::test]
async fn test_session_exists_and_remove() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert!(!mgr.session_exists(&7).await);

    mgr.create_session(7, make_node(1), 3, |_| {}).await;
    assert!(mgr.session_exists(&7).await);

    mgr.remove_session(&7).await;
    assert!(!mgr.session_exists(&7).await);
    assert_eq!(mgr.session_count().await, 0);
}

#[tokio::test]
async fn test_remove_session_clears_reshare_signature_ready_markers() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ready_key = ReshareSignatureReadyKey {
        ring_key: "ring".to_string(),
        session_id: 7,
        attempt_id: AttemptId([1; 32]),
        ring_id: "post".to_string(),
        current_ring_sha256: "current".to_string(),
        finalized_ring_sha256: "updated".to_string(),
    };

    mgr.create_session(7, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(CeremonyId(7));
        state.transport.attempt_id = Some(ready_key.attempt_id);
    })
    .await;
    mgr.mark_reshare_signature_ready(ready_key.clone()).await;
    assert!(mgr.is_reshare_signature_ready(&ready_key).await);

    mgr.remove_session(&7).await;

    assert!(!mgr.is_reshare_signature_ready(&ready_key).await);
}

#[tokio::test]
async fn test_session_count_tracks_multiple() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(1, make_node(1), 3, |_| {}).await;
    mgr.create_session(2, make_node(1), 3, |_| {}).await;
    mgr.create_session(3, make_node(1), 3, |_| {}).await;
    assert_eq!(mgr.session_count().await, 3);

    mgr.remove_session(&2).await;
    assert_eq!(mgr.session_count().await, 2);
}

// =========================================================================
// with_state / with_state_mut
// =========================================================================

#[tokio::test]
async fn test_with_state_returns_none_for_missing_session() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let result = mgr.with_state(&99, |s| s.total_participants).await;
    assert!(
        result.is_none(),
        "should return None for non-existent session"
    );
}

#[tokio::test]
async fn test_with_state_returns_value_for_existing_session() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(5, make_node(1), 7, |_| {}).await;
    let participants = mgr.with_state(&5, |s| s.total_participants).await;
    assert_eq!(participants, Some(7));
}

// =========================================================================
// Phase tracking
// =========================================================================

#[tokio::test]
async fn test_phase_update_changes_phase_and_resets_timer() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(1, make_node(1), 3, |_| {}).await;
    let phase_histogram =
        crate::metrics::DKG_PHASE_DURATION_SECONDS.with_label_values(&["fresh", "initializing"]);
    let observations_before = phase_histogram.get_sample_count();

    // Capture a timestamp just before the update; monotonic time guarantees
    // phase_started_at set inside update_phase will be >= this value.
    let before_update = std::time::Instant::now();
    mgr.update_phase(&1, DkgPhase::Phase1Commitments).await;
    assert_eq!(
        phase_histogram.get_sample_count(),
        observations_before + 1,
        "the phase that was exited must be observed exactly once"
    );
    mgr.update_phase(&1, DkgPhase::Phase1Commitments).await;
    assert_eq!(
        phase_histogram.get_sample_count(),
        observations_before + 1,
        "an idempotent phase update must not emit a second observation"
    );

    let (phase, started_at) = mgr
        .with_state(&1, |s| (s.phase, s.phase_started_at))
        .await
        .expect("session 1 should exist");
    assert_eq!(phase, DkgPhase::Phase1Commitments);
    assert!(
        started_at >= before_update,
        "phase_started_at should be reset to >= the time update_phase was called"
    );
}

// =========================================================================
// Commitment and share counters
// =========================================================================

#[tokio::test]
async fn test_increment_commitment_and_share_counters() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    // 3 participants: need 2 from others (total - 1)
    mgr.create_session(1, make_node(1), 3, |_| {}).await;

    mgr.increment_commitments(&1).await;
    let all = mgr
        .with_state(&1, |s| s.all_commitments_received())
        .await
        .unwrap();
    assert!(!all, "one commitment is not enough for 3 participants");

    mgr.increment_commitments(&1).await;
    let all = mgr
        .with_state(&1, |s| s.all_commitments_received())
        .await
        .unwrap();
    assert!(
        all,
        "two commitments should satisfy 3-participant threshold"
    );

    mgr.increment_shares(&1).await;
    mgr.increment_shares(&1).await;
    let all_shares = mgr
        .with_state(&1, |s| s.all_shares_received())
        .await
        .unwrap();
    assert!(all_shares);
}

// =========================================================================
// Peer IDs
// =========================================================================

#[tokio::test]
async fn test_set_and_get_peer_ids() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(1, make_node(1), 3, |_| {}).await;

    let peers = vec!["peer-a".to_string(), "peer-b".to_string()];
    mgr.set_peer_ids(&1, peers.clone()).await;

    let got = mgr.get_peer_ids(&1).await;
    assert_eq!(got, Some(peers));
}

#[tokio::test]
async fn test_pending_share_waiting_for_commitment_is_drained_once() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(3, make_node(1), 3, |_| {}).await;

    let share = DistributedShare {
        from_id: 2,
        to_id: 1,
        value: Fr::from(42u64),
        nonce: [7u8; 16],
        session_id: 3,
    };

    assert_eq!(
        mgr.store_pending_share_waiting_for_commitment(&3, share.clone(), None)
            .await,
        Some(true)
    );
    assert_eq!(
        mgr.store_pending_share_waiting_for_commitment(&3, share, None)
            .await,
        Some(false),
        "a duplicate early share from the same sender should not replace the first"
    );

    let drained = mgr
        .take_pending_share_waiting_for_commitment(&3, 2)
        .await
        .expect("pending share should be present");
    assert_eq!(drained.share.from_id, 2);
    assert_eq!(drained.share.to_id, 1);
    assert!(
        mgr.take_pending_share_waiting_for_commitment(&3, 2)
            .await
            .is_none(),
        "pending share should only drain once"
    );
}

#[tokio::test]
async fn test_commitment_hash_recording_detects_duplicates_and_mismatches() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(33, make_node(1), 3, |_| {}).await;

    assert_eq!(
        mgr.record_commitment_hash(&33, 2, [1; 32]).await,
        Some(CommitmentHashRecordOutcome::Recorded)
    );
    assert_eq!(mgr.get_commitment_hash(&33, 2).await, Some([1; 32]));
    assert_eq!(
        mgr.record_commitment_hash(&33, 2, [1; 32]).await,
        Some(CommitmentHashRecordOutcome::DuplicateSame)
    );
    assert_eq!(
        mgr.record_commitment_hash(&33, 2, [2; 32]).await,
        Some(CommitmentHashRecordOutcome::Mismatch { existing: [1; 32] })
    );
}

fn signed_commitment(
    dealer_id: u32,
    commitment: Vec<u8>,
    session_nonce: [u8; 16],
) -> SignedDkgCommitment {
    use crate::reporting::v0::types::{
        CommitteeScope as ReportingCommitteeScope, DkgCommitmentStatement, DKG_COMMITMENT_DOMAIN,
    };
    SignedDkgCommitment {
        statement: DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: "1".to_string(),
            signed_at: 100,
            responder_node_key: format!("dealer-{dealer_id}"),
            origin_protocol: "pss_reshare".to_string(),
            accused_committee_scope: ReportingCommitteeScope::Current,
            signing_committee_scope: ReportingCommitteeScope::Current,
            from_node_id: dealer_id,
            commitment,
            session_nonce,
            attempt_id: [9; 32],
            crypto_backend: "dkg/test".to_string(),
        },
        signature: vec![0; 64],
    }
}

#[tokio::test]
async fn missing_dealer_peer_ids_reports_silent_refresh_dealers() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    // Own node_id = 1 in a 3-member refresh committee.
    mgr.create_session(80, make_node(1), 3, |_| {}).await;
    mgr.set_session_kind(
        &80,
        SessionKind::Refresh {
            ring_pk_hex: "rk".to_string(),
        },
    )
    .await;
    mgr.set_peer_node_keys(&80, vec!["k1".into(), "k2".into(), "k3".into()])
        .await;
    mgr.set_node_peer_mappings(
        &80,
        HashMap::from([
            (1, "peer1".to_string()),
            (2, "peer2".to_string()),
            (3, "peer3".to_string()),
        ]),
    )
    .await;

    // Only node 2's commitment arrived; node 3 stayed silent (node 1 is self).
    mgr.store_received_commitment(&80, 2, signed_commitment(2, vec![1, 2, 3], [0u8; 16]))
        .await;
    let missing = mgr
        .with_state(&80, |s| {
            s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
        })
        .await
        .unwrap();
    assert_eq!(missing, vec!["peer3".to_string()]);

    // Once node 3's commitment also arrives, nothing is attributed.
    mgr.store_received_commitment(&80, 3, signed_commitment(3, vec![4, 5, 6], [0u8; 16]))
        .await;
    let missing = mgr
        .with_state(&80, |s| {
            s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
        })
        .await
        .unwrap();
    assert!(missing.is_empty(), "no dealer is silent once all commit");
}

#[tokio::test]
async fn missing_dealer_peer_ids_reports_silent_phase2_share_dealers() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    // Own node_id = 1 in a 3-member refresh committee.
    mgr.create_session(82, make_node(1), 3, |_| {}).await;
    mgr.set_session_kind(
        &82,
        SessionKind::Refresh {
            ring_pk_hex: "rk".to_string(),
        },
    )
    .await;
    mgr.set_peer_node_keys(&82, vec!["k1".into(), "k2".into(), "k3".into()])
        .await;
    mgr.set_node_peer_mappings(
        &82,
        HashMap::from([
            (1, "peer1".to_string()),
            (2, "peer2".to_string()),
            (3, "peer3".to_string()),
        ]),
    )
    .await;

    // Both dealers committed, so a commitment stall would not accuse either peer.
    mgr.store_received_commitment(&82, 2, signed_commitment(2, vec![1, 2, 3], [0u8; 16]))
        .await;
    mgr.store_received_commitment(&82, 3, signed_commitment(3, vec![4, 5, 6], [0u8; 16]))
        .await;
    let missing_commitments = mgr
        .with_state(&82, |s| {
            s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
        })
        .await
        .unwrap();
    assert!(
        missing_commitments.is_empty(),
        "commitment tracking should not accuse a dealer that committed"
    );

    // Node 2's share was accepted; node 3 committed but never sent its Phase 2 share.
    mgr.record_received_share(&82, 2).await;
    let missing_shares = mgr
        .with_state(&82, |s| s.missing_dealer_peer_ids(DkgPhase::Phase2Shares))
        .await
        .unwrap();
    assert_eq!(missing_shares, vec!["peer3".to_string()]);
}

#[tokio::test]
async fn missing_dealer_peer_ids_empty_for_fresh_dkg() {
    // Fresh DKG has no finalized ring to anchor an offline report against, so even a
    // session missing every peer's commitment must not attribute anyone.
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(81, make_node(1), 3, |_| {}).await; // default kind = Fresh
    mgr.set_peer_node_keys(&81, vec!["k1".into(), "k2".into(), "k3".into()])
        .await;
    mgr.set_node_peer_mappings(
        &81,
        HashMap::from([
            (1, "peer1".to_string()),
            (2, "peer2".to_string()),
            (3, "peer3".to_string()),
        ]),
    )
    .await;

    let missing = mgr
        .with_state(&81, |s| {
            s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
        })
        .await
        .unwrap();
    assert!(
        missing.is_empty(),
        "fresh DKG must not produce offline attribution"
    );
}

#[tokio::test]
async fn test_find_conflicting_commitment_pair() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(50, make_node(1), 3, |_| {}).await;

    let nonce_a = [1u8; 16];
    mgr.store_received_commitment(&50, 2, signed_commitment(2, vec![1, 2, 3], nonce_a))
        .await;
    mgr.store_received_commitment(&50, 3, signed_commitment(3, vec![4, 5, 6], nonce_a))
        .await;

    // A reveal matching what we stored → no conflict.
    let matching_reveal = [signed_commitment(2, vec![1, 2, 3], nonce_a)];
    assert_eq!(
        mgr.find_conflicting_commitment_pair(&50, &matching_reveal)
            .await
            .map(|(dealer_id, _, _)| dealer_id),
        None
    );
    // A reveal for a dealer we never received from → ignored.
    let unknown_dealer_reveal = [signed_commitment(9, vec![9, 9], nonce_a)];
    assert_eq!(
        mgr.find_conflicting_commitment_pair(&50, &unknown_dealer_reveal)
            .await
            .map(|(dealer_id, _, _)| dealer_id),
        None
    );
    // Different bytes but a DIFFERENT nonce → honest retry, NOT equivocation (not framed).
    let retry_reveal = [signed_commitment(2, vec![7, 7, 7], [2u8; 16])];
    assert_eq!(
        mgr.find_conflicting_commitment_pair(&50, &retry_reveal)
            .await
            .map(|(dealer_id, _, _)| dealer_id),
        None
    );
    // Different bytes with the SAME nonce for dealer 2 → equivocation; returns the pair.
    let conflicting_reveal = [signed_commitment(2, vec![7, 7, 7], nonce_a)];
    let (dealer_id, ours, reveal) = mgr
        .find_conflicting_commitment_pair(&50, &conflicting_reveal)
        .await
        .expect("equivocation detected");
    assert_eq!(dealer_id, 2);
    assert_eq!(ours.statement.commitment, vec![1, 2, 3]);
    assert_eq!(reveal.statement.commitment, vec![7, 7, 7]);
}

#[tokio::test]
async fn test_pending_commitment_waiting_for_hash_is_drained_once() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(34, make_node(1), 3, |_| {}).await;

    assert_eq!(
        mgr.store_pending_commitment_waiting_for_hash(&34, 2, vec![1, 2, 3], None)
            .await,
        Some(true)
    );
    assert_eq!(
        mgr.store_pending_commitment_waiting_for_hash(&34, 2, vec![4, 5, 6], None)
            .await,
        Some(false),
        "a duplicate early commitment from the same sender should not replace the first"
    );

    let drained = mgr
        .take_pending_commitment_waiting_for_hash(&34, 2)
        .await
        .expect("pending commitment should be present");
    assert_eq!(drained.commitment, vec![1, 2, 3]);
    assert!(
        mgr.take_pending_commitment_waiting_for_hash(&34, 2)
            .await
            .is_none(),
        "pending commitment should only drain once"
    );
}

#[tokio::test]
async fn test_pending_refresh_health_check_result_is_drained_once() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(4, make_node(1), 3, |_| {}).await;

    let result = PendingRefreshHealthCheckResult {
        from_node_id: 1,
        statement: RefreshHealthCheckStatement {
            domain: "health-check".to_string(),
            session_id: 4,
            ring_pk: "ring".to_string(),
            public_polynomial_sha256: "poly".to_string(),
            peer_node_keys_sha256: "peers".to_string(),
            threshold: 2,
            total_participants: 3,
        },
        signature: None,
    };

    assert_eq!(
        mgr.store_pending_refresh_health_check_result(&4, result.clone())
            .await,
        Some(true)
    );
    assert_eq!(
        mgr.store_pending_refresh_health_check_result(&4, result)
            .await,
        Some(false),
        "a duplicate early health-check result should not replace the first"
    );

    let drained = mgr
        .take_pending_refresh_health_check_result(&4)
        .await
        .expect("pending health-check result should be present");
    assert_eq!(drained.from_node_id, 1);
    assert_eq!(drained.statement.session_id, 4);
    assert!(
        mgr.take_pending_refresh_health_check_result(&4)
            .await
            .is_none(),
        "pending health-check result should only drain once"
    );
}

#[tokio::test]
async fn test_create_session_can_publish_routing_maps_atomically() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(5, make_node(1), 3, |state| {
        state.routing.peer_ids = vec!["old-a".to_string(), "old-b".to_string()];
        state.routing.peer_node_keys = vec!["node-a".to_string(), "node-b".to_string()];
        state.routing.ring_id = "ring-id".to_string();
        state.pss_interval = 60;

        state.routing.node_id_to_peer_id =
            HashMap::from([(1, "old-a".to_string()), (2, "old-b".to_string())]);
        state.routing.peer_id_to_node_id =
            HashMap::from([("old-a".to_string(), 1), ("old-b".to_string(), 2)]);
        state.routing.reshare_new_node_id_to_peer_id =
            HashMap::from([(1, "new-a".to_string()), (2, "new-b".to_string())]);
        state.routing.reshare_new_peer_id_to_node_id =
            HashMap::from([("new-a".to_string(), 1), ("new-b".to_string(), 2)]);
    })
    .await;

    let snapshot = mgr
        .with_state(&5, |state| {
            (
                state.routing.peer_ids.clone(),
                state.routing.peer_node_keys.clone(),
                state.routing.ring_id.clone(),
                state.pss_interval,
                state.routing.node_id_to_peer_id.clone(),
                state.routing.peer_id_to_node_id.clone(),
                state.routing.reshare_new_node_id_to_peer_id.clone(),
                state.routing.reshare_new_peer_id_to_node_id.clone(),
            )
        })
        .await
        .expect("session should exist");

    assert_eq!(snapshot.0, vec!["old-a", "old-b"]);
    assert_eq!(snapshot.1, vec!["node-a", "node-b"]);
    assert_eq!(snapshot.2, "ring-id");
    assert_eq!(snapshot.3, 60);
    assert_eq!(snapshot.4.get(&2), Some(&"old-b".to_string()));
    assert_eq!(snapshot.5.get("old-a"), Some(&1));
    assert_eq!(snapshot.6.get(&1), Some(&"new-a".to_string()));
    assert_eq!(snapshot.7.get("new-b"), Some(&2));
}

// =========================================================================
// Concurrent access
// =========================================================================

#[tokio::test]
async fn test_concurrent_create_same_id() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let m1 = mgr.clone();
    let m2 = mgr.clone();
    let node1 = make_node(1);
    let node2 = make_node(2);

    let (r1, r2) = tokio::join!(
        async move { m1.create_session(42, node1, 3, |_| {}).await },
        async move { m2.create_session(42, node2, 3, |_| {}).await },
    );

    // The RwLock serialises the two writes; exactly one must win
    assert_ne!(r1, r2, "exactly one concurrent create should succeed");
    assert_eq!(mgr.session_count().await, 1);
}

// =========================================================================
// Expiration worker    // =========================================================================
// Expiration worker
// =========================================================================

#[tokio::test(start_paused = true)]
async fn test_expiration_worker_removes_sessions_at_hard_deadline() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(20, make_node(1), 3, |_| {}).await;

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&20) {
            s.transport.hard_deadline = Some(Instant::now());
        }
    }

    // Drive the tokio interval timer past the expiration check interval
    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        !mgr.session_exists(&20).await,
        "session at its hard deadline should be removed by the expiration worker"
    );
}

#[tokio::test]
async fn private_retransmission_keeps_exact_cached_bytes() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(21, make_node(1), 3, |_| {}).await;
    let attempt = AttemptId([7; 32]);
    {
        let mut states = mgr.states.write().await;
        let state = states.get_mut(&21).expect("session");
        state.transport.attempt_id = Some(attempt);
    }
    let message_id = MessageId([9; 32]);
    let exact = vec![1, 2, 3, 4, 5];
    assert_eq!(
        mgr.cache_private_message(&21, message_id, exact.clone())
            .await,
        Some(true)
    );
    assert_eq!(
        mgr.cache_private_message(&21, message_id, exact.clone())
            .await,
        Some(true),
        "an identical reconnect must reuse the retained bytes"
    );
    assert_eq!(
        mgr.cache_private_message(&21, message_id, vec![5, 4, 3, 2, 1])
            .await,
        Some(false),
        "the same message ID must reject regenerated or conflicting bytes"
    );
    assert_eq!(mgr.private_message(&21, message_id).await, Some(exact));
}

#[tokio::test]
async fn public_duplicates_are_idempotent_and_conflicts_are_rejected() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(22, make_node(1), 3, |_| {}).await;
    let attempt = AttemptId([7; 32]);
    {
        let mut states = mgr.states.write().await;
        states.get_mut(&22).expect("session").transport.attempt_id = Some(attempt);
    }
    let phase = PublicPhase::Commitments;
    let origin = ParticipantRef::current(2);
    let exact = network::SignedPayload {
        origin: vec![1; 32],
        signature: vec![2; 64],
        data: vec![3; 16],
    };
    assert_eq!(
        mgr.record_public_contribution(&22, attempt, phase, origin, exact.clone())
            .await,
        PublicContributionRecordOutcome::Recorded
    );
    assert_eq!(
        mgr.record_public_contribution(&22, attempt, phase, origin, exact.clone())
            .await,
        PublicContributionRecordOutcome::DuplicateSame
    );
    let mut conflicting = exact.clone();
    conflicting.data[0] ^= 1;
    assert_eq!(
        mgr.record_public_contribution(&22, attempt, phase, origin, conflicting.clone())
            .await,
        PublicContributionRecordOutcome::ConflictingDuplicate {
            retained: exact.clone(),
            conflicting,
        }
    );
    assert_eq!(
        mgr.public_contributions(&22, attempt, phase)
            .await
            .expect("attempt")
            .get(&origin),
        Some(&exact)
    );
    assert_eq!(
        mgr.record_public_contribution(
            &22,
            AttemptId([8; 32]),
            phase,
            ParticipantRef::current(3),
            exact,
        )
        .await,
        PublicContributionRecordOutcome::StaleAttempt,
        "a stale attempt cannot populate the active attempt"
    );
}

#[tokio::test]
async fn topology_acknowledgements_are_scoped_and_idempotent() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(23, make_node(1), 3, |_| {}).await;
    let ceremony = CeremonyId(23);
    let attempt = AttemptId([7; 32]);
    let nonce = [9; 32];
    {
        let mut states = mgr.states.write().await;
        let transport = &mut states.get_mut(&23).expect("session").transport;
        transport.ceremony_id = Some(ceremony);
        transport.attempt_id = Some(attempt);
    }

    mgr.begin_topology_probe(&23, attempt, nonce, "leader".into())
        .await
        .expect("probe state");
    assert_eq!(
        mgr.record_topology_probe_ack(&23, attempt, nonce, "peer-a".into())
            .await,
        TopologyAckRecordOutcome::Recorded
    );
    assert_eq!(
        mgr.record_topology_probe_ack(&23, attempt, nonce, "peer-a".into())
            .await,
        TopologyAckRecordOutcome::Duplicate
    );
    assert_eq!(
        mgr.record_topology_probe_ack(&23, attempt, [8; 32], "peer-b".into())
            .await,
        TopologyAckRecordOutcome::WrongNonce
    );
    assert_eq!(
        mgr.record_topology_probe_ack(&23, AttemptId([6; 32]), nonce, "peer-c".into(),)
            .await,
        TopologyAckRecordOutcome::StaleAttempt
    );
    assert_eq!(
        mgr.topology_probe_acknowledgements(&23, attempt, nonce)
            .await
            .expect("ack set"),
        BTreeSet::from(["leader".to_string(), "peer-a".to_string()])
    );
    assert_eq!(
        mgr.topology_probe_responses(&23, attempt)
            .await
            .expect("response set"),
        BTreeSet::from([
            "leader".to_string(),
            "peer-a".to_string(),
            "peer-b".to_string(),
        ]),
        "a wrong-nonce ACK proves reachability without satisfying the barrier"
    );
}

#[tokio::test]
async fn activation_and_begin_are_idempotent_and_gate_stall_repair() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(24, make_node(1), 3, |_| {}).await;
    let attempt = AttemptId([4; 32]);
    {
        let mut states = mgr.states.write().await;
        states.get_mut(&24).expect("session").transport.attempt_id = Some(attempt);
    }

    assert!(
        !mgr.transport_repair_due(&24, attempt, crate::constants::DKG_REPAIR_STALL_INTERVAL)
            .await
    );
    assert_eq!(
        mgr.begin_transport(&24, attempt, [8; 32]).await,
        TransportBeginOutcome::NotActivated
    );
    assert_eq!(
        mgr.activate_transport(&24, attempt, [8; 32], Vec::new())
            .await,
        TransportActivationOutcome::Activated
    );
    assert_eq!(
        mgr.activate_transport(&24, attempt, [8; 32], Vec::new())
            .await,
        TransportActivationOutcome::AlreadyActivated
    );
    assert_eq!(
        mgr.begin_transport(&24, attempt, [9; 32]).await,
        TransportBeginOutcome::StaleAttempt
    );
    assert_eq!(
        mgr.begin_transport(&24, attempt, [8; 32]).await,
        TransportBeginOutcome::Begun
    );
    assert_eq!(
        mgr.begin_transport(&24, attempt, [8; 32]).await,
        TransportBeginOutcome::AlreadyBegun
    );
    assert_eq!(
        mgr.begin_transport(&24, AttemptId([5; 32]), [8; 32],).await,
        TransportBeginOutcome::StaleAttempt
    );
    assert!(
        !mgr.transport_repair_due(&24, attempt, crate::constants::DKG_REPAIR_STALL_INTERVAL)
            .await
    );

    {
        let mut states = mgr.states.write().await;
        states
            .get_mut(&24)
            .expect("session")
            .transport
            .last_progress_at = Instant::now() - crate::constants::DKG_REPAIR_STALL_INTERVAL;
    }
    assert!(
        mgr.transport_repair_due(&24, attempt, crate::constants::DKG_REPAIR_STALL_INTERVAL)
            .await
    );
}

#[tokio::test]
async fn public_phase_repairs_are_single_flight_and_back_off_without_progress() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(25, make_node(1), 3, |_| {}).await;
    let attempt = AttemptId([5; 32]);
    {
        let mut states = mgr.states.write().await;
        states.get_mut(&25).expect("session").transport.attempt_id = Some(attempt);
    }

    assert_eq!(
        mgr.claim_public_phase_repair(&25, attempt, PublicPhase::Commitments)
            .await,
        PublicRepairClaimOutcome::Claimed
    );
    assert_eq!(
        mgr.claim_public_phase_repair(&25, attempt, PublicPhase::Commitments)
            .await,
        PublicRepairClaimOutcome::InFlight
    );
    assert!(
        mgr.finish_public_phase_repair(
            &25,
            attempt,
            PublicPhase::Commitments,
            false,
            crate::constants::DKG_MAX_REPAIR_BACKOFF,
        )
        .await
    );
    assert_eq!(
        mgr.claim_public_phase_repair(&25, attempt, PublicPhase::Commitments)
            .await,
        PublicRepairClaimOutcome::Backoff
    );
    assert_eq!(
        mgr.record_public_contribution(
            &25,
            attempt,
            PublicPhase::Commitments,
            ParticipantRef::current(1),
            network::SignedPayload {
                origin: vec![1],
                signature: vec![2],
                data: vec![3],
            },
        )
        .await,
        PublicContributionRecordOutcome::Recorded
    );
    assert_eq!(
        mgr.claim_public_phase_repair(&25, attempt, PublicPhase::Commitments)
            .await,
        PublicRepairClaimOutcome::Claimed
    );
    assert!(
        mgr.finish_public_phase_repair(
            &25,
            attempt,
            PublicPhase::Commitments,
            true,
            crate::constants::DKG_MAX_REPAIR_BACKOFF,
        )
        .await
    );
    assert_eq!(
        mgr.claim_public_phase_repair(&25, attempt, PublicPhase::Commitments)
            .await,
        PublicRepairClaimOutcome::Claimed
    );
    assert_eq!(
        mgr.claim_public_phase_repair(&25, AttemptId([6; 32]), PublicPhase::CommitmentHashes,)
            .await,
        PublicRepairClaimOutcome::StaleAttempt
    );
}

#[tokio::test]
async fn complete_publication_claim_commits_only_after_success() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(26, make_node(1), 3, |_| {}).await;
    let attempt = AttemptId([6; 32]);
    let phase = PublicPhase::Commitments;
    {
        let mut states = mgr.states.write().await;
        states.get_mut(&26).expect("session").transport.attempt_id = Some(attempt);
    }
    assert_eq!(
        mgr.record_public_contribution(
            &26,
            attempt,
            phase,
            ParticipantRef::current(1),
            network::SignedPayload {
                origin: vec![1],
                signature: vec![2],
                data: vec![3],
            },
        )
        .await,
        PublicContributionRecordOutcome::Recorded
    );

    assert!(mgr.claim_public_phase_publish(&26, attempt, phase, 1).await);
    assert!(
        !mgr.claim_public_phase_publish(&26, attempt, phase, 1).await,
        "an in-flight publication must remain single-flight"
    );
    assert_eq!(
        mgr.with_state(&26, |state| (
            state.transport.publishing_public_phases.contains(&phase),
            state.transport.published_public_phases.contains(&phase),
        ))
        .await,
        Some((true, false)),
        "claiming must not mark the phase published"
    );

    assert!(
        mgr.finish_public_phase_publish(&26, attempt, phase, false)
            .await
    );
    assert!(
        mgr.claim_public_phase_publish(&26, attempt, phase, 1).await,
        "a failed send must release the phase for retry"
    );
    assert!(
        mgr.finish_public_phase_publish(&26, attempt, phase, true)
            .await
    );
    assert_eq!(
        mgr.with_state(&26, |state| (
            state.transport.publishing_public_phases.contains(&phase),
            state.transport.published_public_phases.contains(&phase),
        ))
        .await,
        Some((false, true))
    );
    assert!(
        !mgr.claim_public_phase_publish(&26, attempt, phase, 1).await,
        "a successfully published phase must remain idempotent"
    );
}

#[tokio::test]
async fn incremental_publication_claim_is_atomic_and_retryable() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(27, make_node(1), 3, |_| {}).await;
    let attempt = AttemptId([7; 32]);
    let first = MessageId([1; 32]);
    let second = MessageId([2; 32]);
    let unclaimed = MessageId([3; 32]);
    {
        let mut states = mgr.states.write().await;
        states.get_mut(&27).expect("session").transport.attempt_id = Some(attempt);
    }

    assert_eq!(
        mgr.claim_public_messages_publish(&27, attempt, &[first, second])
            .await,
        vec![first, second]
    );
    assert!(
        !mgr.finish_public_messages_publish(&27, attempt, &[first, unclaimed], true,)
            .await,
        "a mismatched completion must leave the entire claim untouched"
    );
    assert_eq!(
        mgr.claim_public_messages_publish(&27, attempt, &[first, second])
            .await,
        Vec::<MessageId>::new()
    );
    assert!(
        mgr.finish_public_messages_publish(&27, attempt, &[first, second], false)
            .await
    );
    assert_eq!(
        mgr.claim_public_messages_publish(&27, attempt, &[first, second])
            .await,
        vec![first, second],
        "a failed batch must make every message retryable"
    );
    assert!(
        mgr.finish_public_messages_publish(&27, attempt, &[first, second], true)
            .await
    );
    assert_eq!(
        mgr.with_state(&27, |state| (
            state.transport.publishing_public_messages.is_empty(),
            state.transport.published_public_messages.clone(),
        ))
        .await,
        Some((true, HashSet::from([first, second])))
    );
    assert_eq!(
        mgr.claim_public_messages_publish(&27, attempt, &[first, second, unclaimed])
            .await,
        vec![unclaimed],
        "published IDs stay suppressed while new IDs remain claimable"
    );
}

#[tokio::test]
async fn stale_publication_completion_cannot_mutate_the_active_attempt() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(28, make_node(1), 3, |_| {}).await;
    let stale_attempt = AttemptId([8; 32]);
    let active_attempt = AttemptId([9; 32]);
    let phase = PublicPhase::Commitments;
    let message_id = MessageId([4; 32]);
    {
        let mut states = mgr.states.write().await;
        let transport = &mut states.get_mut(&28).expect("session").transport;
        transport.attempt_id = Some(active_attempt);
        transport.publishing_public_phases.insert(phase);
        transport.publishing_public_messages.insert(message_id);
    }

    assert!(
        !mgr.finish_public_phase_publish(&28, stale_attempt, phase, true)
            .await
    );
    assert!(
        !mgr.finish_public_messages_publish(&28, stale_attempt, &[message_id], true)
            .await
    );
    assert_eq!(
        mgr.with_state(&28, |state| (
            state.transport.publishing_public_phases.contains(&phase),
            state.transport.published_public_phases.contains(&phase),
            state
                .transport
                .publishing_public_messages
                .contains(&message_id),
            state
                .transport
                .published_public_messages
                .contains(&message_id),
        ))
        .await,
        Some((true, false, true, false))
    );
}

#[tokio::test(start_paused = true)]
async fn test_expiration_worker_removes_attempt_at_hard_deadline() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(30, make_node(1), 3, |_| {}).await;

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&30) {
            s.phase = DkgPhase::Phase1Commitments;
            s.transport.hard_deadline = Some(Instant::now());
        }
    }

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        !mgr.session_exists(&30).await,
        "session at the attempt hard deadline should be removed"
    );
}

#[tokio::test(start_paused = true)]
async fn test_expiration_worker_preserves_attempt_before_hard_deadline() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(31, make_node(1), 3, |_| {}).await;

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&31) {
            assert_eq!(s.phase, DkgPhase::Initializing);
            s.phase_started_at = Instant::now()
                - (crate::constants::DKG_PREPARATION_TIMEOUT + std::time::Duration::from_secs(10));
            s.transport.hard_deadline = Some(Instant::now() + DKG_ATTEMPT_TIMEOUT);
        }
    }

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        mgr.session_exists(&31).await,
        "phase age must not override the attempt hard deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn expiration_worker_reports_stall_for_pure_reshare_receiver_stuck_initializing() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let mut stall_rx = mgr
        .take_stall_report_receiver()
        .expect("stall receiver available on a fresh manager");

    let receiver_node = *DkgImpl::new(1, 2, 3, 0, DkgRole::Receiver).expect("DkgImpl::new failed");
    mgr.create_session(90, receiver_node, 3, |_| {}).await;
    mgr.set_session_kind(
        &90,
        SessionKind::Reshare {
            ring_pk_hex: "rk".to_string(),
            new_peer_node_keys: vec!["k1".into(), "k2".into(), "k3".into()],
            new_threshold: 2,
            bulletin_post_id: "post".to_string(),
        },
    )
    .await;
    mgr.set_peer_node_keys(&90, vec!["k1".into(), "k2".into(), "k3".into()])
        .await;
    mgr.set_node_peer_mappings(
        &90,
        HashMap::from([
            (1, "peer1".to_string()),
            (2, "peer2".to_string()),
            (3, "peer3".to_string()),
        ]),
    )
    .await;

    {
        let mut states = mgr.states.write().await;
        let s = states.get_mut(&90).expect("session must exist");
        assert_eq!(
            s.node.role(),
            DkgRole::Receiver,
            "test setup must construct a pure receiver"
        );
        s.reshare.params = Some(ReshareParams {
            old_share: None,
            participating_ids: vec![2, 3],
            new_threshold: 2,
            new_total_nodes: 3,
            new_peer_node_keys: vec!["k1".into(), "k2".into(), "k3".into()],
            new_node_id: Some(1),
            bulletin_post_id: "post".to_string(),
        });
        s.transport.hard_deadline = Some(Instant::now());
    }

    // Only dealer 2 sent its share; dealer 3 stayed silent. A pure
    // receiver never leaves `Initializing` (it has no commitments of its
    // own to generate), so this must not rely on the phase reaching
    // `Phase2Shares`.
    mgr.record_received_share(&90, 2).await;
    assert_eq!(
        mgr.with_state(&90, |s| s.phase).await,
        Some(DkgPhase::Initializing),
        "a pure receiver must stay Initializing before Phase 4"
    );

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        !mgr.session_exists(&90).await,
        "session at the attempt hard deadline should be removed"
    );
    let event = stall_rx
        .try_recv()
        .expect("a stall report must be published for the silent dealer");
    assert_eq!(event.session_id, 90);
    assert_eq!(event.missing_peer_ids, vec!["peer3".to_string()]);
}

#[tokio::test(start_paused = true)]
async fn test_expiration_worker_keeps_recent_completed_sessions() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(40, make_node(1), 3, |_| {}).await;

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&40) {
            s.phase = DkgPhase::Phase4Complete;
            s.phase_started_at =
                Instant::now() - (DKG_COMPLETED_SESSION_TTL - std::time::Duration::from_secs(10));
        }
    }

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        mgr.session_exists(&40).await,
        "recent Phase4Complete sessions should retain their cleanup grace period"
    );
}

#[tokio::test(start_paused = true)]
async fn test_expiration_worker_removes_completed_sessions_past_ttl() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let ready_key = ReshareSignatureReadyKey {
        ring_key: "ring_complete".to_string(),
        session_id: 42,
        attempt_id: AttemptId([2; 32]),
        ring_id: "post".to_string(),
        current_ring_sha256: "current".to_string(),
        finalized_ring_sha256: "updated".to_string(),
    };

    mgr.create_session(42, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(CeremonyId(42));
        state.transport.attempt_id = Some(ready_key.attempt_id);
    })
    .await;
    mgr.set_session_kind(
        &42,
        SessionKind::Reshare {
            ring_pk_hex: "ring_complete".to_string(),
            new_peer_node_keys: vec!["node".to_string()],
            new_threshold: 1,
            bulletin_post_id: "post".to_string(),
        },
    )
    .await;
    let attempt = AttemptKey::new(CeremonyId(42), ready_key.attempt_id);
    assert_eq!(
        mgr.claim_ring_pss_attempt("ring_complete", attempt).await,
        RingPssClaimOutcome::Claimed
    );
    let staged_bundle = RingShareBundle {
        share_bytes: zeroize::Zeroizing::new(vec![1, 2, 3]),
        public_polynomial: "poly".to_string(),
        last_pss: 0,
    };
    assert!(
        mgr.mark_reshare_signature_ready_for_attempt(attempt, ready_key.clone(), staged_bundle)
            .await
    );

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&42) {
            s.phase = DkgPhase::Phase4Complete;
            s.phase_started_at =
                Instant::now() - (DKG_COMPLETED_SESSION_TTL + std::time::Duration::from_secs(10));
        }
    }

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        !mgr.session_exists(&42).await,
        "Phase4Complete sessions must be removed after their maximum TTL"
    );
    assert_eq!(
        mgr.claim_ring_pss_session("ring_complete", 43).await,
        RingPssClaimOutcome::Claimed,
        "completed-session expiration must release the PSS claim"
    );
    assert!(
        !mgr.is_reshare_signature_ready(&ready_key).await,
        "completed-session expiration must remove readiness markers"
    );
}

#[tokio::test(start_paused = true)]
async fn test_expiration_worker_removes_phase4_at_attempt_hard_deadline() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    mgr.create_session(41, make_node(1), 3, |_| {}).await;

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&41) {
            s.phase = DkgPhase::Phase4Completing;
            s.transport.hard_deadline = Some(Instant::now());
        }
    }

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        !mgr.session_exists(&41).await,
        "Phase4Completing sessions must not outlive the attempt hard deadline"
    );
}

// =========================================================================
// rings_pss: claim / unmark
// =========================================================================

#[tokio::test]
async fn test_claim_returns_claimed_first_call() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 11).await,
        RingPssClaimOutcome::Claimed,
        "first claim should succeed (ring not yet in progress)"
    );
}

#[tokio::test]
async fn test_claim_returns_same_session_for_duplicate() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 11).await,
        RingPssClaimOutcome::Claimed
    );
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 11).await,
        RingPssClaimOutcome::AlreadyClaimedBySameSession,
        "duplicate claim for same session should be idempotent"
    );
}

#[tokio::test]
async fn test_claim_returns_conflict_for_different_session() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 11).await,
        RingPssClaimOutcome::Claimed
    );
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 22).await,
        RingPssClaimOutcome::Conflict {
            active_session_id: 11
        },
        "different session should conflict"
    );
    assert_eq!(
        mgr.claim_ring_pss_session("ring_xyz", 22).await,
        RingPssClaimOutcome::Claimed,
        "different ring should be claimable independently"
    );
}

#[tokio::test]
async fn test_unmark_if_matches_preserves_other_session() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 11).await,
        RingPssClaimOutcome::Claimed
    );
    mgr.unmark_ring_pss_if_matches("ring_abc", 22).await;
    assert_eq!(mgr.active_ring_pss_session("ring_abc").await, Some(11));
    mgr.unmark_ring_pss_if_matches("ring_abc", 11).await;
    assert_eq!(mgr.active_ring_pss_session("ring_abc").await, None);
    assert_eq!(
        mgr.claim_ring_pss_session("ring_abc", 33).await,
        RingPssClaimOutcome::Claimed,
        "after matching unmark the ring should be claimable again"
    );
}

#[tokio::test(start_paused = true)]
async fn test_expiration_clears_ring_pss_flag() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());

    // Create a refresh session and mark the ring as in-progress (PSS).
    mgr.create_session(60, make_node(1), 3, |_| {}).await;
    mgr.set_session_kind(
        &60,
        SessionKind::Refresh {
            ring_pk_hex: "ring_expire".to_string(),
        },
    )
    .await;
    assert_eq!(
        mgr.claim_ring_pss_session("ring_expire", 60).await,
        RingPssClaimOutcome::Claimed
    );

    {
        let mut states = mgr.states.write().await;
        if let Some(s) = states.get_mut(&60) {
            s.transport.hard_deadline = Some(Instant::now());
        }
    }

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
        .await;
    tokio::task::yield_now().await;

    assert!(
        !mgr.session_exists(&60).await,
        "expired session should be removed"
    );
    assert_eq!(
        mgr.claim_ring_pss_session("ring_expire", 61).await,
        RingPssClaimOutcome::Claimed,
        "rings_pss claim should be cleared after session expiration"
    );
}

// =========================================================================
// TransportMessageClaimGuard
// =========================================================================

#[tokio::test]
async fn transport_claim_guard_finish_marks_processed() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let session_id = 100u128;
    let attempt = AttemptKey::test(session_id);
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(attempt.ceremony_id);
        state.transport.attempt_id = Some(attempt.attempt_id);
    })
    .await;
    let message_id = MessageId([1u8; 32]);

    assert_eq!(
        mgr.claim_transport_message(attempt, message_id).await,
        MessageProcessingClaim::Claimed
    );
    let guard = TransportMessageClaimGuard::new(mgr.clone(), attempt, message_id);
    guard.finish(true).await;

    assert_eq!(
        mgr.claim_transport_message(attempt, message_id).await,
        MessageProcessingClaim::AlreadyProcessed,
        "finish(true) should mark the message processed, not just release the claim"
    );
}

#[tokio::test]
async fn transport_claim_guard_releases_claim_when_dropped_without_finish() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let session_id = 101u128;
    let attempt = AttemptKey::test(session_id);
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(attempt.ceremony_id);
        state.transport.attempt_id = Some(attempt.attempt_id);
    })
    .await;
    let message_id = MessageId([2u8; 32]);

    assert_eq!(
        mgr.claim_transport_message(attempt, message_id).await,
        MessageProcessingClaim::Claimed
    );
    // A concurrent retry of the exact same message sees it as in-flight.
    assert_eq!(
        mgr.claim_transport_message(attempt, message_id).await,
        MessageProcessingClaim::AlreadyProcessing
    );

    // Simulate the future driving processing being cancelled (e.g. by an
    // outer `tokio::time::timeout`) after the claim succeeded but before
    // `finish` ran: build the guard and drop it without calling `finish`.
    let guard = TransportMessageClaimGuard::new(mgr.clone(), attempt, message_id);
    drop(guard);

    // `Drop` releases the claim via a spawned task rather than
    // synchronously; poll until it lands instead of assuming one yield
    // is enough.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if mgr.claim_transport_message(attempt, message_id).await
                == MessageProcessingClaim::Claimed
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect(
        "a dropped guard must release the claim as failed, not leave the message \
             stuck in AlreadyProcessing for the rest of the attempt",
    );
}

#[tokio::test]
async fn stale_claim_guard_cannot_release_replacement_attempt_claim() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let session_id = 104u128;
    let attempt_a = AttemptKey::new(CeremonyId(session_id), AttemptId([0xA1; 32]));
    let attempt_b = AttemptKey::new(CeremonyId(session_id), AttemptId([0xB2; 32]));
    let message_id = MessageId([0xCC; 32]);

    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(attempt_a.ceremony_id);
        state.transport.attempt_id = Some(attempt_a.attempt_id);
    })
    .await;
    assert_eq!(
        mgr.claim_transport_message(attempt_a, message_id).await,
        MessageProcessingClaim::Claimed
    );
    let stale_guard = TransportMessageClaimGuard::new(mgr.clone(), attempt_a, message_id);

    assert!(
        mgr.abort_transport_attempt(attempt_a, TopicTaskDisposition::DetachCurrent)
            .await
    );
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(attempt_b.ceremony_id);
        state.transport.attempt_id = Some(attempt_b.attempt_id);
    })
    .await;
    assert_eq!(
        mgr.claim_transport_message(attempt_b, message_id).await,
        MessageProcessingClaim::Claimed
    );

    drop(stale_guard);
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    assert_eq!(
        mgr.claim_transport_message(attempt_b, message_id).await,
        MessageProcessingClaim::AlreadyProcessing,
        "attempt A's dropped guard must not release attempt B's claim"
    );
}

#[tokio::test]
async fn stale_attempt_cannot_mutate_or_remove_replacement_session() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let session_id = 105u128;
    let attempt_a = AttemptKey::new(CeremonyId(session_id), AttemptId([0xA3; 32]));
    let attempt_b = AttemptKey::new(CeremonyId(session_id), AttemptId([0xB4; 32]));

    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(attempt_a.ceremony_id);
        state.transport.attempt_id = Some(attempt_a.attempt_id);
    })
    .await;
    assert!(
        mgr.abort_transport_attempt(attempt_a, TopicTaskDisposition::DetachCurrent)
            .await
    );
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.ceremony_id = Some(attempt_b.ceremony_id);
        state.transport.attempt_id = Some(attempt_b.attempt_id);
        state.commitments_received = 7;
    })
    .await;

    assert_eq!(
        mgr.with_attempt_state_mut(attempt_a, |state| {
            state.commitments_received = 99;
        })
        .await,
        Err(AttemptStateError::StaleAttempt)
    );
    assert!(
        !mgr.abort_transport_attempt(attempt_a, TopicTaskDisposition::Abort)
            .await
    );
    assert_eq!(
        mgr.with_attempt_state(attempt_b, |state| state.commitments_received)
            .await,
        Ok(7)
    );
}

#[tokio::test]
async fn stale_pss_cleanup_cannot_clear_replacement_attempt_claim() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ring_key = "attempt-scoped-pss";
    let session_id = 106u128;
    let attempt_a = AttemptKey::new(CeremonyId(session_id), AttemptId([0xA5; 32]));
    let attempt_b = AttemptKey::new(CeremonyId(session_id), AttemptId([0xB6; 32]));

    assert_eq!(
        mgr.claim_ring_pss_attempt(ring_key, attempt_b).await,
        RingPssClaimOutcome::Claimed
    );
    mgr.unmark_ring_pss_for_attempt(ring_key, attempt_a).await;

    assert_eq!(
        mgr.active_ring_pss_session(ring_key).await,
        Some(session_id),
        "attempt A cleanup must leave attempt B's ring ownership intact"
    );
}

fn test_signed_public(byte: u8) -> network::SignedPayload {
    network::SignedPayload {
        origin: vec![byte; 32],
        signature: vec![byte; 64],
        data: vec![byte; 8],
    }
}

#[tokio::test]
async fn public_batch_recording_is_atomic_on_conflict() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let session_id = 102u128;
    let attempt = AttemptId([3; 32]);
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.attempt_id = Some(attempt);
    })
    .await;
    let phase = PublicPhase::Commitments;
    let first = test_signed_public(1);
    assert_eq!(
        mgr.record_public_contribution(
            &session_id,
            attempt,
            phase,
            ParticipantRef::current(1),
            first.clone(),
        )
        .await,
        PublicContributionRecordOutcome::Recorded
    );

    let conflicting_first = test_signed_public(9);
    let conflicting = BTreeMap::from([
        (ParticipantRef::current(1), conflicting_first.clone()),
        (ParticipantRef::current(2), test_signed_public(2)),
    ]);
    assert_eq!(
        mgr.record_public_batch(&session_id, attempt, phase, conflicting)
            .await,
        PublicBatchRecordOutcome::ConflictingDuplicate {
            origin: ParticipantRef::current(1),
            retained: first.clone(),
            conflicting: conflicting_first,
        }
    );
    let retained = mgr
        .public_contributions(&session_id, attempt, phase)
        .await
        .expect("active attempt");
    assert_eq!(retained.len(), 1, "the second origin must not be inserted");
    assert_eq!(retained.get(&ParticipantRef::current(1)), Some(&first));

    let valid = BTreeMap::from([
        (ParticipantRef::current(1), first),
        (ParticipantRef::current(2), test_signed_public(2)),
    ]);
    assert_eq!(
        mgr.record_public_batch(&session_id, attempt, phase, valid)
            .await,
        PublicBatchRecordOutcome::Recorded
    );
    assert_eq!(
        mgr.public_contributions(&session_id, attempt, phase)
            .await
            .expect("active attempt")
            .len(),
        2
    );
}

#[tokio::test]
async fn attempt_scoped_abort_detaches_listener_and_clears_pss_claim() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let session_id = 103u128;
    let attempt = AttemptId([4; 32]);
    let attempt_key = AttemptKey::new(CeremonyId(session_id), attempt);
    let ring_key = "abort-test-ring";
    assert_eq!(
        mgr.claim_ring_pss_attempt(ring_key, attempt_key).await,
        RingPssClaimOutcome::Claimed
    );
    let listener = tokio::spawn(std::future::pending::<()>());
    let listener_abort = listener.abort_handle();
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.kind = SessionKind::Refresh {
            ring_pk_hex: ring_key.to_string(),
        };
        state.transport.ceremony_id = Some(CeremonyId(session_id));
        state.transport.attempt_id = Some(attempt);
        state.transport.topic_task = Some(listener_abort);
    })
    .await;
    let mut cancellation = mgr
        .attempt_cancellation(attempt_key)
        .await
        .expect("active attempt cancellation receiver");

    assert!(
        !mgr.abort_transport_attempt(
            AttemptKey::new(CeremonyId(session_id), AttemptId([5; 32])),
            TopicTaskDisposition::DetachCurrent,
        )
        .await,
        "a stale violation must not remove the active attempt"
    );
    assert!(mgr.session_exists(&session_id).await);
    assert!(!*cancellation.borrow());

    assert!(
        mgr.abort_transport_attempt(attempt_key, TopicTaskDisposition::DetachCurrent,)
            .await
    );
    cancellation
        .changed()
        .await
        .expect("attempt abort must signal cancellation");
    assert!(*cancellation.borrow());
    assert!(!mgr.session_exists(&session_id).await);
    assert_eq!(mgr.active_ring_pss_session(ring_key).await, None);
    assert!(
        !listener.is_finished(),
        "the listener must be allowed to return after detaching its own handle"
    );
    listener.abort();
}

#[tokio::test]
async fn preparation_abort_preserves_a_different_configured_attempt() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let session_id = 104u128;
    let winning_attempt = AttemptId([6; 32]);
    let stale_attempt = AttemptId([7; 32]);
    mgr.create_session(session_id, make_node(1), 3, |state| {
        state.transport.attempt_id = Some(winning_attempt);
    })
    .await;

    assert!(
        !mgr.abort_transport_preparation(&session_id, stale_attempt, TopicTaskDisposition::Abort,)
            .await,
        "a stale preparation failure must not remove the configured winner"
    );
    assert_eq!(
        mgr.transport_attempt(&session_id).await,
        Some(winning_attempt)
    );

    assert!(
        mgr.abort_transport_preparation(&session_id, winning_attempt, TopicTaskDisposition::Abort,)
            .await
    );
    assert!(!mgr.session_exists(&session_id).await);
}

#[tokio::test]
async fn preparation_abort_removes_unconfigured_session() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let session_id = 105u128;
    mgr.create_session(session_id, make_node(1), 3, |_| {})
        .await;

    assert!(
        mgr.abort_transport_preparation(
            &session_id,
            AttemptId([8; 32]),
            TopicTaskDisposition::Abort,
        )
        .await
    );
    assert!(!mgr.session_exists(&session_id).await);
}

// =========================================================================
// Fresh DKG failure attribution / soft-stall detection
// =========================================================================

#[tokio::test]
async fn test_missing_fresh_participants_non_fresh_returns_empty() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(500, make_node(1), 3, |s| {
        s.kind = SessionKind::Refresh {
            ring_pk_hex: "pk".to_string(),
        };
        s.routing.peer_node_keys = vec!["k1".into(), "k2".into(), "k3".into()];
        s.phase = DkgPhase::Phase1Commitments;
    })
    .await;
    let missing = mgr
        .with_state(&500, |s| s.missing_fresh_participants())
        .await
        .unwrap();
    assert!(
        missing.is_empty(),
        "missing_fresh_participants is Fresh-only, mirroring missing_dealer_peer_ids"
    );
}

#[tokio::test]
async fn test_missing_fresh_participants_diffs_each_phase() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(501, make_node(1), 3, |s| {
        s.kind = SessionKind::Fresh;
        s.routing.peer_node_keys = vec!["k1".into(), "k2".into(), "k3".into()];
    })
    .await;

    // Phase0: neither peer 2 nor 3 has hashed in yet.
    mgr.with_state_mut(&501, |s| s.phase = DkgPhase::Phase0CommitmentHashes)
        .await;
    let missing = mgr
        .with_state(&501, |s| s.missing_fresh_participants())
        .await
        .unwrap();
    let missing_ids: BTreeSet<_> = missing.iter().map(|p| p.node_id).collect();
    assert_eq!(missing_ids, BTreeSet::from([2, 3]));

    // Record peer 2's Phase0 hash; only 3 should remain missing.
    mgr.with_state_mut(&501, |s| {
        s.transport
            .public_contributions
            .entry(PublicPhase::CommitmentHashes)
            .or_default()
            .insert(ParticipantRef::current(2), test_signed_public(2));
    })
    .await;
    let missing = mgr
        .with_state(&501, |s| s.missing_fresh_participants())
        .await
        .unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].node_id, 3);
    assert_eq!(missing[0].node_key, "k3");

    // Phase1: commitments tracked independently of Phase0's hashes.
    mgr.with_state_mut(&501, |s| {
        s.phase = DkgPhase::Phase1Commitments;
        s.transport
            .public_contributions
            .entry(PublicPhase::Commitments)
            .or_default()
            .insert(ParticipantRef::current(3), test_signed_public(3));
    })
    .await;
    let missing = mgr
        .with_state(&501, |s| s.missing_fresh_participants())
        .await
        .unwrap();
    assert_eq!(
        missing.len(),
        1,
        "Phase1 must diff PublicPhase::Commitments, not carry over Phase0's map"
    );
    assert_eq!(missing[0].node_id, 2);

    // Phase2: shares tracked via commitment_audit.received_shares, not the public plane.
    mgr.with_state_mut(&501, |s| {
        s.phase = DkgPhase::Phase2Shares;
        s.commitment_audit.received_shares.insert(2);
    })
    .await;
    let missing = mgr
        .with_state(&501, |s| s.missing_fresh_participants())
        .await
        .unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].node_id, 3);
}

#[tokio::test]
async fn test_soft_stalled_peer_ids_gating_and_clear() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ceremony_id = CeremonyId(502);
    let attempt_id = AttemptId([3; 32]);
    mgr.create_session(502, make_node(1), 3, |s| {
        s.transport.ceremony_id = Some(ceremony_id);
        s.transport.attempt_id = Some(attempt_id);
    })
    .await;
    let attempt = AttemptKey::new(ceremony_id, attempt_id);

    mgr.record_peer_no_progress(attempt, 2).await;
    mgr.record_peer_no_progress(attempt, 2).await;

    assert!(
            mgr.with_state(&502, |s| s.soft_stalled_peer_ids(Duration::from_secs(0), 2))
                .await
                .unwrap()
                .contains(&2),
            "2 recorded failures at min_attempts=2 (no elapsed-time requirement) should count as stalled"
        );
    assert!(
        !mgr.with_state(&502, |s| s.soft_stalled_peer_ids(Duration::from_secs(0), 3))
            .await
            .unwrap()
            .contains(&2),
        "below min_attempts should not count as stalled even with no elapsed-time requirement"
    );
    assert!(
            !mgr.with_state(&502, |s| s.soft_stalled_peer_ids(Duration::from_secs(3600), 0))
                .await
                .unwrap()
                .contains(&2),
            "a freshly-recorded streak should not satisfy a large elapsed-time gate, regardless of attempt count"
        );

    mgr.clear_peer_no_progress(attempt, 2).await;
    assert!(
        mgr.with_state(&502, |s| s.soft_stalled_peer_ids(Duration::from_secs(0), 0))
            .await
            .unwrap()
            .is_empty(),
        "clearing should remove the streak entirely"
    );
}

#[tokio::test]
async fn test_record_public_contribution_clears_peer_no_progress() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ceremony_id = CeremonyId(503);
    let attempt_id = AttemptId([4; 32]);
    mgr.create_session(503, make_node(1), 3, |s| {
        s.transport.ceremony_id = Some(ceremony_id);
        s.transport.attempt_id = Some(attempt_id);
    })
    .await;
    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    mgr.record_peer_no_progress(attempt, 2).await;
    assert!(mgr
        .with_state(&503, |s| s.transport.peer_no_progress.contains_key(&2))
        .await
        .unwrap());

    let outcome = mgr
        .record_public_contribution(
            &503,
            attempt_id,
            PublicPhase::Commitments,
            ParticipantRef::current(2),
            test_signed_public(1),
        )
        .await;
    assert_eq!(outcome, PublicContributionRecordOutcome::Recorded);

    assert!(
        !mgr.with_state(&503, |s| s.transport.peer_no_progress.contains_key(&2))
            .await
            .unwrap(),
        "recording a contribution from the peer should clear its no-progress streak"
    );
}

#[tokio::test]
async fn test_record_public_batch_clears_peer_no_progress_only_for_newly_recorded_origins() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    let ceremony_id = CeremonyId(509);
    let attempt_id = AttemptId([6; 32]);
    mgr.create_session(509, make_node(1), 3, |s| {
        s.transport.ceremony_id = Some(ceremony_id);
        s.transport.attempt_id = Some(attempt_id);
    })
    .await;
    let attempt = AttemptKey::new(ceremony_id, attempt_id);

    // Peer 2's contribution is already retained (e.g. a prior direct submission); peer 3's
    // is not. Seed both with a no-progress streak.
    mgr.record_public_contribution(
        &509,
        attempt_id,
        PublicPhase::Commitments,
        ParticipantRef::current(2),
        test_signed_public(2),
    )
    .await;
    mgr.record_peer_no_progress(attempt, 2).await;
    mgr.record_peer_no_progress(attempt, 3).await;

    let mut batch = BTreeMap::new();
    batch.insert(ParticipantRef::current(2), test_signed_public(2)); // same bytes: already retained
    batch.insert(ParticipantRef::current(3), test_signed_public(3)); // newly recorded
    let outcome = mgr
        .record_public_batch(&509, attempt_id, PublicPhase::Commitments, batch)
        .await;
    assert_eq!(outcome, PublicBatchRecordOutcome::Recorded);

    assert!(
        mgr.with_state(&509, |s| s.transport.peer_no_progress.contains_key(&2))
            .await
            .unwrap(),
        "peer 2's contribution was already retained (duplicate-same in the batch), so the \
             batch recorded nothing new from it — its no-progress streak must be left alone"
    );
    assert!(
        !mgr.with_state(&509, |s| s.transport.peer_no_progress.contains_key(&3))
            .await
            .unwrap(),
        "peer 3's contribution was newly recorded by the batch, so its streak must clear"
    );
}

#[tokio::test]
async fn test_is_local_leader() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    mgr.create_session(504, make_node(1), 3, |s| {
        s.routing.peer_node_keys = vec!["k1".into(), "k2".into(), "k3".into()];
        s.transport.leader_node_key = Some("k1".to_string());
    })
    .await;
    assert!(
        mgr.with_state(&504, |s| s.is_local_leader()).await.unwrap(),
        "node_id 1 maps to k1, the recorded leader key"
    );

    mgr.create_session(505, make_node(2), 3, |s| {
        s.routing.peer_node_keys = vec!["k1".into(), "k2".into(), "k3".into()];
        s.transport.leader_node_key = Some("k1".to_string());
    })
    .await;
    assert!(
        !mgr.with_state(&505, |s| s.is_local_leader()).await.unwrap(),
        "node_id 2 maps to k2, not the recorded leader key k1"
    );
}

#[tokio::test]
async fn test_record_and_read_failed_session_round_trip() {
    let mgr = SessionStateManager::<DkgImpl>::new();
    assert!(mgr.failed_session(&600).await.is_none());

    mgr.record_failed_session(FailedDkgSessionRecord {
        session_id: 600,
        ring_id: "ring-600".to_string(),
        attempt_id: Some(AttemptId([5; 32])),
        stage: DkgFailureStage::ShareExchange,
        missing: vec![MissingDkgParticipant {
            node_id: 2,
            node_key: "k2".to_string(),
        }],
        reason: "test failure".to_string(),
        failed_at: SystemTime::now(),
    })
    .await;

    let record = mgr
        .failed_session(&600)
        .await
        .expect("record should be queryable");
    assert_eq!(record.ring_id, "ring-600");
    assert_eq!(record.stage, DkgFailureStage::ShareExchange);
    assert_eq!(record.missing.len(), 1);
    assert_eq!(record.missing[0].node_key, "k2");
}

#[tokio::test(start_paused = true)]
async fn test_failed_sessions_ttl_sweep_ages_out() {
    // `Instant` here is `std::time::Instant`, which `tokio::time::advance` does NOT move
    // (only tokio's own timers respect the paused clock) — so, mirroring
    // `test_expiration_worker_removes_completed_sessions_past_ttl`'s
    // `phase_started_at` backdating above, the record is inserted already past its TTL
    // rather than relying on `advance` to age it there. `advance` below is only to make
    // the tokio `interval` tick that drives the sweep actually fire.
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let record = FailedDkgSessionRecord {
        session_id: 601,
        ring_id: "ring-601".to_string(),
        attempt_id: None,
        stage: DkgFailureStage::Unknown,
        missing: Vec::new(),
        reason: "test".to_string(),
        failed_at: SystemTime::now(),
    };
    let backdated_insert =
        Instant::now() - (DKG_FAILED_SESSION_RECORD_TTL + Duration::from_secs(10));
    mgr.failed_sessions
        .write()
        .await
        .insert(601, (record, backdated_insert));
    assert!(mgr.failed_session(&601).await.is_some());

    tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    assert!(
        mgr.failed_session(&601).await.is_none(),
        "failure record should age out after DKG_FAILED_SESSION_RECORD_TTL"
    );
}

#[tokio::test(start_paused = true)]
async fn test_soft_stall_scan_publishes_event_for_genuinely_stalled_leader() {
    let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
    let mut soft_stall_rx = mgr
        .take_soft_stall_receiver()
        .expect("receiver available exactly once");

    let attempt_id = AttemptId([9; 32]);
    mgr.create_session(602, make_node(1), 3, |s| {
        s.kind = SessionKind::Fresh;
        s.routing.ring_id = "ring-602".to_string();
        s.routing.peer_node_keys = vec!["k1".into(), "k2".into(), "k3".into()];
        s.transport.leader_node_key = Some("k1".to_string());
        s.transport.attempt_id = Some(attempt_id);
        s.phase = DkgPhase::Phase1Commitments;
        // Backdated rather than `Instant::now()` + `tokio::time::advance`: `Instant` here
        // is `std::time::Instant`, unaffected by tokio's paused clock (see the TTL sweep
        // test above for the same reasoning).
        s.transport.peer_no_progress.insert(
            2,
            PeerNoProgressInfo {
                first_failure_at: Instant::now()
                    - (DKG_SOFT_STALL_NO_PROGRESS_THRESHOLD + Duration::from_secs(1)),
                consecutive_failures: DKG_SOFT_STALL_MIN_REPAIR_ATTEMPTS,
            },
        );
        // Peer 3 never sent a commitment either, but with no recorded no-progress streak
        // it must NOT be reported — only a peer repair has actually failed against counts.
    })
    .await;

    // Only needs to cross the soft-stall scan's own tick interval now — the elapsed-time
    // gate is already satisfied by the backdated `first_failure_at` above.
    tokio::time::advance(DKG_SOFT_STALL_CHECK_INTERVAL + Duration::from_secs(1)).await;
    let mut event = None;
    for _ in 0..20 {
        tokio::task::yield_now().await;
        if let Ok(e) = soft_stall_rx.try_recv() {
            event = Some(e);
            break;
        }
    }
    let event = event.expect("a soft-stall event should have been published");

    assert_eq!(event.session_id, 602);
    assert_eq!(event.ring_id, "ring-602");
    assert_eq!(event.stage, DkgFailureStage::Commitments);
    assert_eq!(
        event.missing.len(),
        1,
        "only peer 2 has both a recorded no-progress streak and a missing contribution"
    );
    assert_eq!(event.missing[0].node_id, 2);
    assert_eq!(event.missing[0].node_key, "k2");
}
