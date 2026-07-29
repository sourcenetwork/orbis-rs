use crate::app_state::AppState;
use crate::dkg::v0::coordinator::message_handlers::{
    handle_commitment_audit_message, handle_commitment_hash_message, handle_commitment_message,
};
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::{fresh_commitment_hash, serialize_commitment_coefficients};
use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment};
use crate::dkg::v0::session_state::DkgPhase;
use crate::dkg::v0::transport::AttemptKey;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
use crypto::r#trait::{Dkg, DkgMode, DkgRole};
use crypto::DkgImpl;
use std::sync::Arc;

const SESSION_ID: u128 = 91_000;
const LOCAL_PEER_HEX: &str = "aabbccdd";
const SENDER_PEER_HEX: &str = "deadbeef";
const THIRD_PEER_HEX: &str = "feedface";

struct FreshFixture {
    app_state: Arc<AppState<DkgImpl>>,
    coordinator: DkgCoordinator<DkgImpl>,
    commitment: Vec<u8>,
    commitment_hash: [u8; 32],
}

async fn fresh_fixture(db_name: &str) -> FreshFixture {
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);

    coordinator
        .create_session(
            AttemptKey::test(SESSION_ID),
            1,
            2,
            3,
            DkgRole::Standard,
            |_| {},
        )
        .await
        .expect("create session");
    app_state
        .dkg_session_state
        .set_peer_ids(
            &SESSION_ID,
            vec![
                LOCAL_PEER_HEX.to_string(),
                SENDER_PEER_HEX.to_string(),
                THIRD_PEER_HEX.to_string(),
            ],
        )
        .await;
    app_state
        .dkg_session_state
        .set_node_peer_mappings(
            &SESSION_ID,
            std::collections::HashMap::from([
                (1u32, LOCAL_PEER_HEX.to_string()),
                (2u32, SENDER_PEER_HEX.to_string()),
                (3u32, THIRD_PEER_HEX.to_string()),
            ]),
        )
        .await;

    // These tests exercise commit/reveal ordering in the coordinator, not the
    // network publisher. Put the fixture at the same local phase-0 boundary a
    // successful typed transport start would establish, without inventing an
    // inactive or partially configured transport attempt.
    app_state
        .dkg_session_state
        .with_state_mut(&SESSION_ID, |state| state.generate_polynomial())
        .await
        .expect("session exists")
        .expect("generate local polynomial");
    app_state
        .dkg_session_state
        .update_phase(&SESSION_ID, DkgPhase::Phase0CommitmentHashes)
        .await;
    app_state
        .dkg_session_state
        .mark_commitment_hash_broadcast_complete(&SESSION_ID)
        .await;

    let mut sender_node =
        *DkgImpl::new(2, 2, 3, SESSION_ID, DkgRole::Standard).expect("create sender node");
    sender_node
        .generate_polynomial(DkgMode::Fresh)
        .expect("sender polynomial");
    let commitment = serialize_commitment_coefficients(&sender_node.commitment().coefficients)
        .expect("serialize commitment");
    let commitment_hash = fresh_commitment_hash(SESSION_ID, 2, &commitment);
    FreshFixture {
        app_state,
        coordinator,
        commitment,
        commitment_hash,
    }
}

#[tokio::test]
async fn hash_before_commitment_accepts_matching_reveal() {
    let db_name = "commit_reveal_hash_before_commitment";
    let db_path = test_db_path(db_name);
    let fixture = fresh_fixture(db_name).await;

    handle_commitment_hash_message(
        &fixture.coordinator,
        AttemptKey::test(SESSION_ID),
        2,
        fixture.commitment_hash,
    )
    .await
    .expect("hash accepted");
    handle_commitment_message(
        &fixture.coordinator,
        AttemptKey::test(SESSION_ID),
        2,
        fixture.commitment.clone(),
        None,
    )
    .await
    .expect("matching commitment accepted");

    let commitments_received = fixture
        .app_state
        .dkg_session_state
        .with_state(&SESSION_ID, |state| state.commitments_received)
        .await
        .expect("session exists");
    assert_eq!(commitments_received, 1);

    cleanup_db(&db_path);
}

#[tokio::test]
async fn commitment_before_hash_is_buffered_and_replayed() {
    let db_name = "commit_reveal_commitment_before_hash";
    let db_path = test_db_path(db_name);
    let fixture = fresh_fixture(db_name).await;

    handle_commitment_message(
        &fixture.coordinator,
        AttemptKey::test(SESSION_ID),
        2,
        fixture.commitment.clone(),
        None,
    )
    .await
    .expect("early commitment buffered");

    let commitments_before_hash = fixture
        .app_state
        .dkg_session_state
        .with_state(&SESSION_ID, |state| state.commitments_received)
        .await
        .expect("session exists");
    assert_eq!(commitments_before_hash, 0);

    handle_commitment_hash_message(
        &fixture.coordinator,
        AttemptKey::test(SESSION_ID),
        2,
        fixture.commitment_hash,
    )
    .await
    .expect("hash accepted and commitment replayed");

    let commitments_after_hash = fixture
        .app_state
        .dkg_session_state
        .with_state(&SESSION_ID, |state| state.commitments_received)
        .await
        .expect("session exists");
    assert_eq!(commitments_after_hash, 1);

    cleanup_db(&db_path);
}

#[tokio::test]
async fn reveal_that_does_not_match_hash_is_rejected() {
    let db_name = "commit_reveal_mismatch";
    let db_path = test_db_path(db_name);
    let fixture = fresh_fixture(db_name).await;

    handle_commitment_hash_message(
        &fixture.coordinator,
        AttemptKey::test(SESSION_ID),
        2,
        [9; 32],
    )
    .await
    .expect("hash accepted");
    let result = handle_commitment_message(
        &fixture.coordinator,
        AttemptKey::test(SESSION_ID),
        2,
        fixture.commitment.clone(),
        None,
    )
    .await;

    assert!(result.is_err(), "mismatched reveal should be rejected");

    cleanup_db(&db_path);
}

#[tokio::test]
async fn commitment_hash_is_rejected_for_non_fresh_session() {
    let db_name = "commit_reveal_rejects_refresh";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    coordinator
        .create_session(
            AttemptKey::test(SESSION_ID),
            1,
            2,
            3,
            DkgRole::Standard,
            |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: "ring".to_string(),
                };
                state.phase = DkgPhase::Phase1Commitments;
            },
        )
        .await
        .expect("create refresh session");
    app_state
        .dkg_session_state
        .set_node_peer_mappings(
            &SESSION_ID,
            std::collections::HashMap::from([
                (1u32, LOCAL_PEER_HEX.to_string()),
                (2u32, SENDER_PEER_HEX.to_string()),
            ]),
        )
        .await;

    let result =
        handle_commitment_hash_message(&coordinator, AttemptKey::test(SESSION_ID), 2, [1; 32])
            .await;

    assert!(result.is_err(), "non-Fresh CommitmentHash should fail");
    assert!(matches!(result, Err(DkgError::ProtocolError(_))));

    cleanup_db(&db_path);
}

fn bogus_signed_commitment(dealer_id: u32, commitment: Vec<u8>) -> SignedDkgCommitment {
    use crate::reporting::v0::types::{
        CommitteeScope, DkgCommitmentStatement, DKG_COMMITMENT_DOMAIN,
    };
    SignedDkgCommitment {
        statement: DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: SESSION_ID.to_string(),
            signed_at: 100,
            responder_node_key: format!("dealer-{dealer_id}"),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: dealer_id,
            commitment,
            session_nonce: [0u8; 16],
            crypto_backend: DkgImpl::name(),
        },
        signature: vec![0; 64],
    }
}

#[tokio::test]
async fn commitment_audit_is_rejected_for_fresh_session() {
    let db_name = "commit_reveal_audit_rejects_fresh";
    let db_path = test_db_path(db_name);
    let fixture = fresh_fixture(db_name).await;

    let result =
        handle_commitment_audit_message(&fixture.coordinator, AttemptKey::test(SESSION_ID), vec![])
            .await;

    assert!(
        result.is_err(),
        "CommitmentAudit on a Fresh session should fail"
    );
    assert!(matches!(result, Err(DkgError::ProtocolError(_))));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn commitment_audit_skips_unverifiable_reveals() {
    // A refresh session whose ring cannot be resolved makes every reveal fail
    // verification; the handler must skip them and return Ok(None) with no attribution
    // and no panic (a lying revealer cannot forge attribution).
    let db_name = "commit_reveal_audit_skips_unverifiable";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    coordinator
        .create_session(
            AttemptKey::test(SESSION_ID),
            1,
            2,
            3,
            DkgRole::Standard,
            |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: "ring".to_string(),
                };
                state.phase = DkgPhase::Phase1Commitments;
            },
        )
        .await
        .expect("create refresh session");

    let result = handle_commitment_audit_message(
        &coordinator,
        AttemptKey::test(SESSION_ID),
        vec![bogus_signed_commitment(2, vec![1, 2, 3])],
    )
    .await;

    assert!(
        matches!(result, Ok(())),
        "unverifiable audit reveals should be skipped, got {result:?}"
    );

    cleanup_db(&db_path);
}
