use super::*;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
use crypto::r#trait::DkgRole;
use crypto::DkgImpl;
use std::sync::Arc;

/// RPT-13: `spawn_evidence_relay` must return to its caller as soon as the
/// relay task is spawned, never waiting for the relay itself to resolve —
/// the whole point of moving it off the caller's `.await` chain. A
/// channel-gated relay future proves this isn't just true because the
/// current relay implementation happens to be fast: the metric this test
/// observes can only fire once the spawned task actually runs, so seeing
/// it still at zero immediately after the call, then incremented only
/// after the gate is released, demonstrates the call returned without
/// waiting on that future at all.
#[tokio::test]
async fn spawn_evidence_relay_does_not_block_on_relay_completion() {
    let event = "test_relay_kind_relay_exhausted";
    let before = crate::metrics::DKG_TRANSPORT_EVENTS_TOTAL
        .with_label_values(&["private", event])
        .get();

    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    spawn_evidence_relay(1, "test_relay_kind", async move {
        release_rx.await.ok();
        Err(DkgError::Generic("relay never accepted".to_string()))
    });

    // The call above already returned (it's a plain `fn`, not `async fn`),
    // and the gate is still held — the spawned task cannot have completed
    // yet, so the failure metric must still read its pre-call value.
    assert_eq!(
        crate::metrics::DKG_TRANSPORT_EVENTS_TOTAL
            .with_label_values(&["private", event])
            .get(),
        before,
        "relay failure metric must not fire before the relay future resolves"
    );

    release_tx
        .send(())
        .expect("relay task should still be awaiting the gate");
    // Give the spawned task a chance to run now that it's unblocked.
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    assert_eq!(
        crate::metrics::DKG_TRANSPORT_EVENTS_TOTAL
            .with_label_values(&["private", event])
            .get(),
        before + 1.0,
        "relay failure metric should fire once the spawned task completes"
    );
}

fn signed_share_with_origin(origin: &str) -> SignedDkgShare {
    let commitment_statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: "pk".to_string(),
        ring_state_sha256: "00".repeat(32),
        protocol_version: 0,
        request_id: "session".to_string(),
        signed_at: 100,
        responder_node_key: "accused".to_string(),
        origin_protocol: origin.to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        commitment: vec![1],
        session_nonce: [0u8; 16],
        attempt_id: [9; 32],
        crypto_backend: DkgImpl::name(),
    };
    SignedDkgShare {
        statement: DkgShareStatement {
            domain: DKG_SHARE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: "session".to_string(),
            signed_at: 100,
            responder_node_key: "accused".to_string(),
            receiver_node_key: "receiver".to_string(),
            origin_protocol: origin.to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            to_node_id: 1,
            commitment_statement,
            commitment_signature: vec![7; 64],
            share_value: vec![8],
            nonce: [9; 16],
            crypto_backend: DkgImpl::name(),
        },
        signature: vec![5; 64],
    }
}

fn evidence_binding_for_tests() -> DkgReportEvidenceBinding {
    DkgReportEvidenceBinding {
        ring_id: "ring".to_string(),
        ring_pk: "pk".to_string(),
        ring_state_sha256: "00".repeat(32),
        chain_id: "chain".to_string(),
        protocol_version: 0,
        request_id: "session".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        current_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
        receiver_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
    }
}

fn commitment_statement_for_tests(responder_node_key: &str) -> DkgCommitmentStatement {
    DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: "pk".to_string(),
        ring_state_sha256: "00".repeat(32),
        protocol_version: 0,
        request_id: "session".to_string(),
        signed_at: 100,
        responder_node_key: responder_node_key.to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 1,
        commitment: vec![1, 2, 3],
        session_nonce: [0u8; 16],
        attempt_id: [9; 32],
        crypto_backend: DkgImpl::name(),
    }
}

#[test]
fn commitment_evidence_rejects_responder_not_bound_to_from_node_id() {
    let binding = evidence_binding_for_tests();
    let statement = commitment_statement_for_tests("node-b");

    let error =
        validate_commitment_statement::<DkgImpl>(&binding, 1, &[1, 2, 3], &statement).unwrap_err();

    assert!(matches!(error, DkgError::Unauthorized(_)));
}

fn signed_commitment_for_equivocation(
    commitment: Vec<u8>,
    session_nonce: [u8; 16],
) -> SignedDkgCommitment {
    let mut statement = commitment_statement_for_tests("accused");
    statement.commitment = commitment;
    statement.session_nonce = session_nonce;
    SignedDkgCommitment {
        statement,
        signature: vec![1; 64],
    }
}

#[test]
fn commitments_prove_equivocation_requires_same_attempt_nonce_and_different_bytes() {
    let nonce = [5u8; 16];
    let a = signed_commitment_for_equivocation(vec![1, 2, 3], nonce);

    // Same nonce, different bytes → equivocation.
    let b = signed_commitment_for_equivocation(vec![9, 9, 9], nonce);
    assert!(commitments_prove_equivocation(&a, &b));

    // Same nonce, identical bytes → not equivocation.
    let same = signed_commitment_for_equivocation(vec![1, 2, 3], nonce);
    assert!(!commitments_prove_equivocation(&a, &same));

    // Different nonce (honest retry), different bytes → not equivocation.
    let retry = signed_commitment_for_equivocation(vec![9, 9, 9], [6u8; 16]);
    assert!(!commitments_prove_equivocation(&a, &retry));

    // Different attempt, even with a reused nonce and different bytes, is not
    // equivocation within either attempt.
    let mut other_attempt = signed_commitment_for_equivocation(vec![9, 9, 9], nonce);
    other_attempt.statement.attempt_id = [10u8; 32];
    assert!(!commitments_prove_equivocation(&a, &other_attempt));

    // Different dealer → not equivocation.
    let mut other_dealer = signed_commitment_for_equivocation(vec![9, 9, 9], nonce);
    other_dealer.statement.from_node_id += 1;
    assert!(!commitments_prove_equivocation(&a, &other_dealer));
}

#[test]
fn share_evidence_rejects_responder_not_bound_to_from_node_id() {
    let binding = evidence_binding_for_tests();
    let commitment_statement = commitment_statement_for_tests("node-b");
    let statement = DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: "pk".to_string(),
        ring_state_sha256: "00".repeat(32),
        protocol_version: 0,
        request_id: "session".to_string(),
        signed_at: 101,
        responder_node_key: "node-b".to_string(),
        receiver_node_key: "node-a".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 1,
        to_node_id: 1,
        commitment_statement,
        commitment_signature: vec![7; 64],
        share_value: vec![9],
        nonce: [8; 16],
        crypto_backend: DkgImpl::name(),
    };

    let error =
        validate_share_statement::<DkgImpl>(&binding, 1, 1, &[9], [8; 16], &statement).unwrap_err();

    assert!(matches!(error, DkgError::Unauthorized(_)));
}

#[tokio::test]
async fn current_signer_detection_uses_current_route_map_during_reshare() {
    let db_name = "evidence_current_signer_uses_current_routes";
    let db_path = test_db_path(db_name);
    cleanup_db(&db_path);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let session_id = 7;

    coordinator
        .create_session(
            AttemptKey::test(session_id),
            1,
            2,
            3,
            DkgRole::Dealer,
            |state| {
                state.kind = SessionKind::Reshare {
                    ring_pk_hex: "ring-pk".to_string(),
                    new_peer_node_keys: vec!["new-a".to_string(), "new-b".to_string()],
                    new_threshold: 2,
                    bulletin_post_id: "ring-id".to_string(),
                };
                // During reshare this field is the receiver/new committee; it must
                // not be used to decide whether this node can sign current reports.
                state.routing.peer_node_keys = vec!["new-a".to_string(), "new-b".to_string()];
                state
                    .routing
                    .node_id_to_peer_id
                    .insert(1, format!("{local_peer_hex}@127.0.0.1:1234"));
            },
        )
        .await
        .expect("create reshare dealer session");

    assert!(
        local_node_is_current_route_member(&coordinator, AttemptKey::test(session_id))
            .await
            .expect("membership check")
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn pure_new_receiver_is_not_current_report_signer() {
    let db_name = "evidence_pure_new_not_current_signer";
    let db_path = test_db_path(db_name);
    cleanup_db(&db_path);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let local_node_key = app_state.node_key.clone();
    let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let session_id = 8;

    coordinator
        .create_session(
            AttemptKey::test(session_id),
            1,
            1,
            1,
            DkgRole::Receiver,
            |state| {
                state.kind = SessionKind::Reshare {
                    ring_pk_hex: "ring-pk".to_string(),
                    new_peer_node_keys: vec![local_node_key.clone()],
                    new_threshold: 1,
                    bulletin_post_id: "ring-id".to_string(),
                };
                // This simulates the pure-new receiver case that used to be
                // misclassified because `peer_node_keys` names the new committee.
                state.routing.peer_node_keys = vec![local_node_key];
                state.routing.node_id_to_peer_id.insert(1, "a".repeat(64));
                state
                    .routing
                    .reshare_new_node_id_to_peer_id
                    .insert(1, local_peer_hex);
            },
        )
        .await
        .expect("create reshare receiver session");

    assert!(
        !local_node_is_current_route_member(&coordinator, AttemptKey::test(session_id))
            .await
            .expect("membership check")
    );
    cleanup_db(&db_path);
}

/// A relayed report is unauthenticated network input; the handler must reject a
/// non-reshare origin before doing any work, since the relay message only
/// exists for reshare pending-new receivers.
#[tokio::test]
async fn relay_rejects_non_reshare_origin() {
    let db_name = "evidence_relay_rejects_non_reshare_origin";
    let db_path = test_db_path(db_name);
    cleanup_db(&db_path);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let error = handle_invalid_share_evidence_relay(
        &coordinator,
        AttemptKey::test(1),
        signed_share_with_origin("pss_refresh"),
    )
    .await
    .unwrap_err();
    cleanup_db(&db_path);

    assert!(matches!(error, DkgError::Unauthorized(_)));
}

#[tokio::test]
async fn public_origin_relay_rejects_refresh_session() {
    let db_name = "evidence_public_origin_relay_rejects_refresh";
    let db_path = test_db_path(db_name);
    cleanup_db(&db_path);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let attempt = AttemptKey::test(9);
    coordinator
        .create_session(attempt, 1, 2, 3, DkgRole::Standard, |state| {
            state.kind = SessionKind::Refresh {
                ring_pk_hex: "pk".to_string(),
            };
            state.routing.node_id_to_peer_id.insert(1, local_peer_hex);
            state.report_evidence_binding = Some(evidence_binding_for_tests());
        })
        .await
        .expect("create Refresh relay test session");

    let error = handle_public_origin_fault_evidence_relay(
        &coordinator,
        attempt,
        DkgPublicOriginFaultKind::InvalidPayload,
        network::SignedPayload {
            origin: vec![1; 32],
            signature: vec![2; 64],
            data: vec![3],
        },
        None,
    )
    .await
    .expect_err("public-origin relays are Reshare-only");
    cleanup_db(&db_path);

    assert!(matches!(error, DkgError::Unauthorized(_)));
}

/// A reshare-origin relay for a session this node is not currently signing is
/// rejected before the evidence is queued.
#[tokio::test]
async fn relay_rejects_unknown_session() {
    let db_name = "evidence_relay_rejects_unknown_session";
    let db_path = test_db_path(db_name);
    cleanup_db(&db_path);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let error = handle_invalid_share_evidence_relay(
        &coordinator,
        AttemptKey::test(999),
        signed_share_with_origin("pss_reshare"),
    )
    .await
    .unwrap_err();
    cleanup_db(&db_path);

    // No such session exists, so the current-signer check fails before queuing.
    assert!(matches!(
        error,
        DkgError::SessionNotFound(_) | DkgError::StaleAttempt { .. } | DkgError::Unauthorized(_)
    ));
}
