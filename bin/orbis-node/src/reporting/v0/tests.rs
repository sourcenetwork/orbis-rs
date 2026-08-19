use super::error::Result;
use super::observation::{InvalidCryptoResponseObservation, OfflineObservation, ReportObservation};
use super::types::{
    ring_state_sha256, CommitteeScope, DkgControlMessageFaultKind, DkgPublicOriginFaultKind,
    InvalidCryptoResponse, PreReencryptResponseStatement, RelayRequestStatement, ReportEnvelope,
    CHAIN_BLOCK_GRACE_SECS, INVALID_CRYPTO_RESPONSE_REPORT_TYPE, PRE_REENCRYPT_RESPONSE_DOMAIN,
    RELAY_REQUEST_DOMAIN,
};
#[cfg(feature = "bls12-381")]
use super::types::{SignResponseStatement, SIGN_RESPONSE_DOMAIN};
use super::{
    build_signed_relay_statement, queue_report, validate_relay_request_binding,
    RelayRequestBinding, RelayRequestTimestampBinding, RelayStatementInputs,
};
use crate::dkg::v0::coordinator::evidence::{
    build_commitment_evidence_with_context, evidence_build_context,
    report_leader_prepare_fault_best_effort, sign_control_message,
};
use crate::dkg::v0::coordinator::message_handlers::prepare_commitment_message;
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::serialize_commitment_coefficients;
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::network::{
    handle_control_for_test, queue_public_commitment_equivocation_for_test,
    record_control_ack_best_effort_for_test, record_public_contribution_at_leader_for_test,
};
use crate::dkg::v0::service::DkgServiceImpl;
use crate::dkg::v0::transport::{
    canonical_leader, AttemptId, AttemptKey, CeremonyConfig, CeremonyId, CommitteeConfig,
    DkgControlMessage, DkgPublicContribution, DkgPublicPayload, ParticipantRef, PrepareSession,
    PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
};
use crate::helpers::identity::{determine_session_node_id, extract_node_part};
use crate::helpers::node_routes::resolve_node_routes;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default, get_test_ring_post,
    setup_three_node_network_with_sign, test_db_path, TestKeyPair, TEST_FRESH_DKG_RING_ID,
};
use crate::ring_state::{RingPolyState, RingShareBundle};
use authz::sourcehub::ValidWindow;
use bulletin::r#trait::UpgradeInfo;
use bulletin::r#trait::{Bulletin, BulletinWriteKind, DocumentPayload, RingPayload};
use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, DkgMode, DkgRole, PriShare,
    ThresholdDealer, ThresholdSigner,
};
use crypto::{DkgImpl, PreImpl, ScalarField, SignImpl};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

const RELAY_BINDING_CHAIN_ID: &str = "relay-binding-chain";
const RELAY_BINDING_RING_ID: &str = "relay-binding-ring";
const RELAY_BINDING_REQUEST_ID: &str = "relay-binding-request";
const RELAY_BINDING_ACTOR_ID: &str = "did:key:z6Mkrelayactor";
const RELAY_BINDING_OBJECT_ID: &str = "relay-binding-object";
const RELAY_BINDING_RELAYER_KEY: &str = "accused";
const RELAY_BINDING_FROM_NODE_ID: u32 = 1;
const RELAY_BINDING_SIGNED_AT: u64 = 1_700_000_010;
const RELAY_BINDING_USER_SIGNED_AT: u64 = 1_700_000_000;
const RELAY_BINDING_PRE_TIMESTAMP: u64 = 1_699_999_900;

fn relay_binding_ring() -> RingPayload {
    RingPayload {
        ring_pk: "relay-binding-ring-pk".to_string(),
        peer_node_keys: vec![
            "reporter".to_string(),
            RELAY_BINDING_RELAYER_KEY.to_string(),
            "validator".to_string(),
        ],
        threshold: 2,
        pss_interval: 86_400,
        upgrade_info: UpgradeInfo {
            current_version: network::V0.version,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn relay_binding_window() -> ValidWindow {
    ValidWindow {
        start: RELAY_BINDING_SIGNED_AT - 60,
        end: RELAY_BINDING_SIGNED_AT + 60,
    }
}

fn relay_binding_statement(
    ring: &RingPayload,
    origin_protocol: &str,
    valid_window: Option<ValidWindow>,
    timestamp: Option<u64>,
) -> RelayRequestStatement {
    let (valid_window_start, valid_window_end) = valid_window
        .as_ref()
        .map(|window| (Some(window.start), Some(window.end)))
        .unwrap_or((None, None));
    RelayRequestStatement {
        domain: RELAY_REQUEST_DOMAIN.to_string(),
        chain_id: RELAY_BINDING_CHAIN_ID.to_string(),
        ring_id: RELAY_BINDING_RING_ID.to_string(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id: RELAY_BINDING_REQUEST_ID.to_string(),
        signed_at: RELAY_BINDING_SIGNED_AT,
        user_signed_at: RELAY_BINDING_USER_SIGNED_AT,
        relayer_node_key: RELAY_BINDING_RELAYER_KEY.to_string(),
        origin_protocol: origin_protocol.to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: RELAY_BINDING_FROM_NODE_ID,
        actor_id: RELAY_BINDING_ACTOR_ID.to_string(),
        object_id: RELAY_BINDING_OBJECT_ID.to_string(),
        valid_window_start,
        valid_window_end,
        timestamp,
    }
}

fn relay_binding(
    ring: &RingPayload,
    origin_protocol: &str,
    valid_window: Option<ValidWindow>,
    timestamp: RelayRequestTimestampBinding,
) -> RelayRequestBinding {
    RelayRequestBinding {
        ring: ring.clone(),
        ring_id: RELAY_BINDING_RING_ID.to_string(),
        protocol_version: network::V0.version,
        chain_id: RELAY_BINDING_CHAIN_ID.to_string(),
        request_id: RELAY_BINDING_REQUEST_ID.to_string(),
        origin_protocol: origin_protocol.to_string(),
        actor_id: RELAY_BINDING_ACTOR_ID.to_string(),
        object_id: RELAY_BINDING_OBJECT_ID.to_string(),
        user_signed_at: RELAY_BINDING_USER_SIGNED_AT,
        valid_window,
        timestamp,
        from_node_id: RELAY_BINDING_FROM_NODE_ID,
    }
}

#[test]
fn relay_request_binding_accepts_valid_pre_statement() {
    let ring = relay_binding_ring();
    let window = relay_binding_window();
    let statement = relay_binding_statement(
        &ring,
        "pre",
        Some(window.clone()),
        Some(RELAY_BINDING_PRE_TIMESTAMP),
    );

    validate_relay_request_binding(
        &statement,
        relay_binding(
            &ring,
            "pre",
            Some(window.clone()),
            RelayRequestTimestampBinding::Exact(Some(RELAY_BINDING_PRE_TIMESTAMP)),
        ),
    )
    .unwrap();
}

#[test]
fn relay_request_binding_accepts_valid_sign_statement_timestamp_semantics() {
    let ring = relay_binding_ring();
    let no_window_statement = relay_binding_statement(&ring, "sign", None, None);
    validate_relay_request_binding(
        &no_window_statement,
        relay_binding(
            &ring,
            "sign",
            None,
            RelayRequestTimestampBinding::SignPolicy,
        ),
    )
    .unwrap();

    let window = relay_binding_window();
    let windowed_statement = relay_binding_statement(
        &ring,
        "sign",
        Some(window.clone()),
        Some(RELAY_BINDING_SIGNED_AT + 1),
    );
    validate_relay_request_binding(
        &windowed_statement,
        relay_binding(
            &ring,
            "sign",
            Some(window.clone()),
            RelayRequestTimestampBinding::SignPolicy,
        ),
    )
    .unwrap();

    let mut stale_timestamp = windowed_statement;
    stale_timestamp.timestamp =
        Some(RELAY_BINDING_SIGNED_AT + crate::constants::RELAY_CHECK_MAX_DRIFT_SECS + 1);
    assert!(validate_relay_request_binding(
        &stale_timestamp,
        relay_binding(
            &ring,
            "sign",
            Some(window.clone()),
            RelayRequestTimestampBinding::SignPolicy,
        ),
    )
    .is_err());
}

#[test]
fn relay_request_binding_rejects_unbound_statement_fields() {
    let ring = relay_binding_ring();
    let window = relay_binding_window();
    let valid = relay_binding_statement(
        &ring,
        "pre",
        Some(window.clone()),
        Some(RELAY_BINDING_PRE_TIMESTAMP),
    );
    let window_start = window.start;

    let cases: Vec<(&str, Box<dyn FnOnce(&mut RelayRequestStatement)>)> = vec![
        (
            "request_id",
            Box::new(|statement| statement.request_id = "other-request".to_string()),
        ),
        (
            "origin_protocol",
            Box::new(|statement| statement.origin_protocol = "sign".to_string()),
        ),
        (
            "actor_id",
            Box::new(|statement| statement.actor_id = "did:key:z6Mkother".to_string()),
        ),
        (
            "object_id",
            Box::new(|statement| statement.object_id = "other-object".to_string()),
        ),
        (
            "ring_id",
            Box::new(|statement| statement.ring_id = "other-ring".to_string()),
        ),
        (
            "ring_pk",
            Box::new(|statement| statement.ring_pk = "other-ring-pk".to_string()),
        ),
        (
            "ring_state_sha256",
            Box::new(|statement| statement.ring_state_sha256 = "00".repeat(32)),
        ),
        (
            "protocol_version",
            Box::new(|statement| statement.protocol_version += 1),
        ),
        (
            "from_node_id",
            Box::new(|statement| statement.from_node_id += 1),
        ),
        (
            "user_signed_at",
            Box::new(|statement| statement.user_signed_at += 1),
        ),
        (
            "valid_window",
            Box::new(move |statement| statement.valid_window_start = Some(window_start + 1)),
        ),
        (
            "pre timestamp",
            Box::new(|statement| statement.timestamp = Some(RELAY_BINDING_PRE_TIMESTAMP + 1)),
        ),
    ];

    for (case, mutate) in cases {
        let mut statement = valid.clone();
        mutate(&mut statement);
        assert!(
            validate_relay_request_binding(
                &statement,
                relay_binding(
                    &ring,
                    "pre",
                    Some(window.clone()),
                    RelayRequestTimestampBinding::Exact(Some(RELAY_BINDING_PRE_TIMESTAMP)),
                ),
            )
            .is_err(),
            "{case} should reject"
        );
    }
}

#[tokio::test]
async fn relay_statement_builder_rejects_relayer_key_outside_ring() {
    let db_name = "relay_statement_builder_rejects_relayer_key_outside_ring";
    let db_path = test_db_path(db_name);
    cleanup_db(&db_path);
    let app_state = create_test_app_state_default(db_name).await;
    let ring = relay_binding_ring();

    let error = build_signed_relay_statement(
        RelayStatementInputs {
            ring,
            ring_id: RELAY_BINDING_RING_ID.to_string(),
            protocol_version: network::V0.version,
            chain_id: app_state.bulletin.chain_id(),
            request_id: RELAY_BINDING_REQUEST_ID.to_string(),
            origin_protocol: "pre".to_string(),
            relayer_node_key: app_state.node_key.clone(),
            actor_id: RELAY_BINDING_ACTOR_ID.to_string(),
            object_id: RELAY_BINDING_OBJECT_ID.to_string(),
            user_signed_at: RELAY_BINDING_USER_SIGNED_AT,
            acp_timestamp: Some(RELAY_BINDING_PRE_TIMESTAMP),
            valid_window: None,
        },
        &app_state.local_storage,
    )
    .unwrap_err();

    cleanup_db(&db_path);
    assert!(error.to_string().contains("not in ring"));
}

async fn create_preflight_test_session(
    coordinator: &DkgCoordinator<DkgImpl>,
    attempt: AttemptKey,
    ring_id: &str,
    ring: &RingPayload,
    kind: SessionKind,
) -> u32 {
    let node_id = determine_session_node_id(&coordinator.app_state.node_key, &ring.peer_node_keys)
        .expect("test node must belong to finalized ring");
    let session_ring_id = ring_id.to_string();
    let peer_node_keys = ring.peer_node_keys.clone();
    coordinator
        .create_session(
            attempt,
            node_id,
            ring.threshold as usize,
            ring.peer_node_keys.len(),
            DkgRole::Standard,
            move |state| {
                state.kind = kind;
                state.routing.ring_id = session_ring_id;
                state.routing.peer_node_keys = peer_node_keys;
            },
        )
        .await
        .expect("create explicit preflight test session");
    node_id
}

async fn configure_public_test_session(
    coordinator: &DkgCoordinator<DkgImpl>,
    attempt: AttemptKey,
    committee: CommitteeConfig,
) -> [u8; 32] {
    let committee_digest =
        crate::dkg::v0::transport::ceremony_committee_digest(&committee.node_keys, None);
    let leader_node_key = coordinator.app_state.node_key.clone();
    let leader_peer_route = committee
        .node_keys
        .iter()
        .position(|node_key| node_key == &leader_node_key)
        .and_then(|index| committee.peer_routes.get(index))
        .cloned()
        .expect("test leader must have a committee route");
    let node_id_to_peer_id = committee
        .node_keys
        .iter()
        .zip(&committee.peer_routes)
        .map(|(node_key, route)| {
            (
                *committee
                    .node_id_assignments
                    .get(node_key)
                    .expect("canonical test node ID"),
                route.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let participant_routes = committee.peer_routes.clone();
    let active_dealers = committee
        .node_id_assignments
        .values()
        .copied()
        .map(ParticipantRef::current)
        .collect::<Vec<_>>();
    coordinator
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            state.routing.peer_ids = participant_routes.clone();
            state.routing.node_id_to_peer_id = node_id_to_peer_id;
            state.transport.ceremony_id = Some(attempt.ceremony_id);
            state.transport.attempt_id = Some(attempt.attempt_id);
            state.transport.committee_digest = Some(committee_digest);
            state.transport.leader_node_key = Some(leader_node_key);
            state.transport.leader_peer_route = Some(leader_peer_route);
            state.transport.participant_routes = participant_routes;
            state.transport.committees = Some(CeremonyConfig {
                current: committee,
                next: None,
            });
            state.transport.active_dealers = active_dealers;
            state.transport.activated = true;
        })
        .await
        .expect("configure explicit public transport session");
    committee_digest
}

async fn sign_test_public_contribution(
    app_state: &crate::app_state::AppState<DkgImpl>,
    attempt: AttemptKey,
    ring_id: &str,
    committee_digest: [u8; 32],
    origin: ParticipantRef,
    payload: DkgPublicPayload,
) -> (network::SignedPayload, DkgPublicContribution) {
    let contribution = DkgPublicContribution::new(
        attempt.ceremony_id,
        attempt.attempt_id,
        ring_id.to_string(),
        committee_digest,
        origin,
        payload,
    )
    .expect("construct signed public test contribution");
    let encoded = crate::dkg::v0::transport::encode(&contribution)
        .expect("encode signed public test contribution");
    let signed = app_state
        .network
        .pubsub()
        .expect("test network must support pubsub")
        .sign(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, encoded.into())
        .await
        .expect("sign public contribution with endpoint identity");
    (signed, contribution)
}

#[tokio::test]
#[serial_test::serial]
async fn invalid_refresh_commitment_preflight_queues_report_before_rejection() {
    let db_name = "reporting_invalid_refresh_commitment_preflight";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let alice = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &network::V0,
    );
    let charlie = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.charlie.app_state.clone()),
        &network::V0,
    );
    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_111_222), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    let _alice_node_id = create_preflight_test_session(
        &alice,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;
    let charlie_node_id = create_preflight_test_session(
        &charlie,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;

    // Prime both sides' authenticated evidence binding before taking the state
    // snapshot. Public preflight must not populate or otherwise mutate DKG state.
    evidence_build_context(&alice, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");
    let charlie_refresh_context = evidence_build_context(&charlie, refresh_attempt)
        .await
        .expect("build accused evidence context")
        .expect("Refresh must have an evidence binding");

    let mut invalid_dealer = *DkgImpl::new(
        charlie_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        refresh_attempt.session_id(),
        DkgRole::Standard,
    )
    .expect("create invalid Refresh dealer");
    invalid_dealer
        .generate_polynomial(DkgMode::Fresh)
        .expect("generate non-identity commitment");
    let invalid_commitment =
        serialize_commitment_coefficients(&invalid_dealer.commitment().coefficients)
            .expect("serialize invalid Refresh commitment");
    let invalid_evidence = build_commitment_evidence_with_context(
        &charlie,
        &charlie_refresh_context,
        charlie_node_id,
        invalid_commitment.clone(),
    )
    .expect("sign invalid Refresh commitment evidence");

    let mut identity_dealer = *DkgImpl::new(
        charlie_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        refresh_attempt.session_id(),
        DkgRole::Standard,
    )
    .expect("create valid Refresh dealer");
    identity_dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate identity-term Refresh commitment");
    let identity_commitment =
        serialize_commitment_coefficients(&identity_dealer.commitment().coefficients)
            .expect("serialize valid Refresh commitment");
    let identity_evidence = build_commitment_evidence_with_context(
        &charlie,
        &charlie_refresh_context,
        charlie_node_id,
        identity_commitment.clone(),
    )
    .expect("sign valid Refresh commitment evidence");

    let state_before = alice
        .app_state
        .dkg_session_state
        .with_attempt_state(refresh_attempt, |state| {
            (
                state.phase,
                state.commitments_received,
                state.shares_received,
            )
        })
        .await
        .expect("read Refresh state before preflight");

    let malformed = prepare_commitment_message(
        &alice,
        refresh_attempt,
        charlie_node_id,
        &[0xff; 3],
        None,
        None,
    )
    .await
    .expect_err("malformed commitment must fail");
    assert!(matches!(
        malformed,
        DkgError::CommitmentVerificationFailed(_)
    ));

    let mut invalid_signature = invalid_evidence.clone();
    invalid_signature.signature[0] ^= 0x01;
    let bad_signature = prepare_commitment_message(
        &alice,
        refresh_attempt,
        charlie_node_id,
        &invalid_commitment,
        Some(&invalid_signature),
        None,
    )
    .await
    .expect_err("invalid evidence signature must fail");
    assert!(matches!(bad_signature, DkgError::Unauthorized(_)));

    let mut wrong_binding = invalid_evidence.clone();
    wrong_binding.statement.request_id = "wrong-session".to_string();
    let wrong_binding_error = prepare_commitment_message(
        &alice,
        refresh_attempt,
        charlie_node_id,
        &invalid_commitment,
        Some(&wrong_binding),
        None,
    )
    .await
    .expect_err("wrong evidence binding must fail");
    assert!(matches!(wrong_binding_error, DkgError::Unauthorized(_)));

    prepare_commitment_message(
        &alice,
        refresh_attempt,
        charlie_node_id,
        &identity_commitment,
        Some(&identity_evidence),
        None,
    )
    .await
    .expect("identity-term Refresh commitment must pass preflight");

    let fresh_attempt = AttemptKey::new(CeremonyId(777_000_111_223), AttemptId::random());
    create_preflight_test_session(&alice, fresh_attempt, &ring_id, &ring, SessionKind::Fresh).await;
    prepare_commitment_message(
        &alice,
        fresh_attempt,
        charlie_node_id,
        &invalid_commitment,
        None,
        None,
    )
    .await
    .expect("Fresh commitment must not be classified as invalid Refresh evidence");

    let reshare_attempt = AttemptKey::new(CeremonyId(777_000_111_224), AttemptId::random());
    let reshare_kind = SessionKind::Reshare {
        ring_pk_hex: ring.ring_pk.clone(),
        new_peer_node_keys: ring.peer_node_keys.clone(),
        new_threshold: ring.threshold,
        bulletin_post_id: ring_id.clone(),
    };
    create_preflight_test_session(
        &alice,
        reshare_attempt,
        &ring_id,
        &ring,
        reshare_kind.clone(),
    )
    .await;
    create_preflight_test_session(&charlie, reshare_attempt, &ring_id, &ring, reshare_kind).await;
    evidence_build_context(&alice, reshare_attempt)
        .await
        .expect("prime Reshare reporter evidence binding")
        .expect("Reshare must have an evidence binding");
    let charlie_reshare_context = evidence_build_context(&charlie, reshare_attempt)
        .await
        .expect("build Reshare accused evidence context")
        .expect("Reshare must have an evidence binding");
    let reshare_evidence = build_commitment_evidence_with_context(
        &charlie,
        &charlie_reshare_context,
        charlie_node_id,
        invalid_commitment.clone(),
    )
    .expect("sign Reshare commitment evidence");
    prepare_commitment_message(
        &alice,
        reshare_attempt,
        charlie_node_id,
        &invalid_commitment,
        Some(&reshare_evidence),
        None,
    )
    .await
    .expect("Reshare commitment must not be classified as invalid Refresh evidence");

    let rejection = prepare_commitment_message(
        &alice,
        refresh_attempt,
        charlie_node_id,
        &invalid_commitment,
        Some(&invalid_evidence),
        None,
    )
    .await
    .expect_err("non-identity Refresh commitment must be rejected");
    assert!(matches!(
        rejection,
        DkgError::CommitmentVerificationFailed(ref message)
            if message.contains("non-identity constant term")
    ));

    let state_after = alice
        .app_state
        .dkg_session_state
        .with_attempt_state(refresh_attempt, |state| {
            (
                state.phase,
                state.commitments_received,
                state.shares_received,
            )
        })
        .await
        .expect("read Refresh state after preflight");
    assert_eq!(state_after, state_before, "preflight mutated DKG state");

    alice.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1, "expected exactly one queued report");
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(
        submission.accused_node_key,
        network.charlie.app_state.node_key
    );
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized invalid-refresh payload")
    {
        InvalidCryptoResponse::DkgInvalidRefreshCommitment { statement, .. } => {
            assert_eq!(statement.origin_protocol, "pss_refresh");
            assert_eq!(statement.request_id, submission.session_id);
            assert_eq!(statement.responder_node_key, submission.accused_node_key);
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn undecodable_refresh_commitment_preflight_queues_report_before_rejection() {
    let db_name = "reporting_undecodable_refresh_commitment_preflight";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let alice = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &network::V0,
    );
    let charlie = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.charlie.app_state.clone()),
        &network::V0,
    );
    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_222_333), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    let _alice_node_id = create_preflight_test_session(
        &alice,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;
    let charlie_node_id = create_preflight_test_session(
        &charlie,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;

    // Prime both sides' authenticated evidence binding before taking the state
    // snapshot. Public preflight must not populate or otherwise mutate DKG state.
    evidence_build_context(&alice, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");
    let charlie_refresh_context = evidence_build_context(&charlie, refresh_attempt)
        .await
        .expect("build accused evidence context")
        .expect("Refresh must have an evidence binding");

    // A validly-shaped identity-term commitment (would otherwise pass
    // preflight) with its first coefficient's bytes replaced by an invalid
    // curve-point encoding. Same length and coefficient count as a real
    // commitment, isolating the deserialization branch from the
    // constant-term check exercised by the test above.
    let mut identity_dealer = *DkgImpl::new(
        charlie_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        refresh_attempt.session_id(),
        DkgRole::Standard,
    )
    .expect("create valid Refresh dealer");
    identity_dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate identity-term Refresh commitment");
    let mut undecodable_commitment =
        serialize_commitment_coefficients(&identity_dealer.commitment().coefficients)
            .expect("serialize valid Refresh commitment");
    undecodable_commitment[..crypto::GROUP_POINT_SIZE].fill(0xff);
    let undecodable_evidence = build_commitment_evidence_with_context(
        &charlie,
        &charlie_refresh_context,
        charlie_node_id,
        undecodable_commitment.clone(),
    )
    .expect("sign undecodable Refresh commitment evidence");

    let state_before = alice
        .app_state
        .dkg_session_state
        .with_attempt_state(refresh_attempt, |state| {
            (
                state.phase,
                state.commitments_received,
                state.shares_received,
            )
        })
        .await
        .expect("read Refresh state before preflight");

    let rejection = prepare_commitment_message(
        &alice,
        refresh_attempt,
        charlie_node_id,
        &undecodable_commitment,
        Some(&undecodable_evidence),
        None,
    )
    .await
    .expect_err("undecodable Refresh commitment must fail preflight");
    assert!(
        matches!(rejection, DkgError::Deserialization(_)),
        "expected a deserialization failure, got {rejection:?}"
    );

    let state_after = alice
        .app_state
        .dkg_session_state
        .with_attempt_state(refresh_attempt, |state| {
            (
                state.phase,
                state.commitments_received,
                state.shares_received,
            )
        })
        .await
        .expect("read Refresh state after preflight");
    assert_eq!(state_after, state_before, "preflight mutated DKG state");

    alice.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1, "expected exactly one queued report");
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(
        submission.accused_node_key,
        network.charlie.app_state.node_key
    );
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized invalid-refresh payload")
    {
        InvalidCryptoResponse::DkgInvalidRefreshCommitment { statement, .. } => {
            assert_eq!(statement.origin_protocol, "pss_refresh");
            assert_eq!(statement.request_id, submission.session_id);
            assert_eq!(statement.responder_node_key, submission.accused_node_key);
            assert_eq!(statement.commitment, undecodable_commitment);
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn public_origin_invalid_payload_queues_report_before_abort() {
    let db_name = "reporting_public_origin_invalid_payload";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let alice = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &network::V0,
    );
    let charlie = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.charlie.app_state.clone()),
        &network::V0,
    );
    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_111_224), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    create_preflight_test_session(
        &alice,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;
    let charlie_node_id =
        create_preflight_test_session(&charlie, refresh_attempt, &ring_id, &ring, refresh_kind)
            .await;

    let route_by_node_key = HashMap::from([
        (
            network.alice.app_state.node_key.clone(),
            network.alice.address.clone(),
        ),
        (
            network.bob.app_state.node_key.clone(),
            network.bob.address.clone(),
        ),
        (
            network.charlie.app_state.node_key.clone(),
            network.charlie.address.clone(),
        ),
    ]);
    let committee = CommitteeConfig {
        node_keys: ring.peer_node_keys.clone(),
        peer_routes: ring
            .peer_node_keys
            .iter()
            .map(|node_key| route_by_node_key[node_key].clone())
            .collect(),
        node_id_assignments: ring
            .peer_node_keys
            .iter()
            .map(|node_key| {
                (
                    node_key.clone(),
                    determine_session_node_id(node_key, &ring.peer_node_keys)
                        .expect("finalized member must have a canonical node ID"),
                )
            })
            .collect(),
        threshold: ring.threshold,
    };
    let committee_digest = configure_public_test_session(&alice, refresh_attempt, committee).await;
    evidence_build_context(&alice, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");

    let (signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        ParticipantRef::current(charlie_node_id),
        DkgPublicPayload::Commitment {
            commitment: Vec::new(),
            report_evidence: None,
        },
    )
    .await;
    let sender = network.charlie.app_state.network.local_peer_id().clone();
    let rejection = handle_control_for_test(
        alice.app_state.clone(),
        &network::V0,
        DkgControlMessage::PublicContribution(signed),
        &sender,
    )
    .await
    .expect_err("an endpoint-signed empty Refresh commitment must be rejected");
    assert!(matches!(
        rejection,
        DkgError::CommitmentVerificationFailed(_)
    ));
    assert_eq!(
        alice
            .app_state
            .dkg_session_state
            .transport_attempt(&refresh_attempt.session_id())
            .await,
        None,
        "the original public protocol path must abort the attempt"
    );

    alice.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1, "expected one public-origin report");
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(
        submission.accused_node_key,
        network.charlie.app_state.node_key
    );
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized public-origin payload")
    {
        InvalidCryptoResponse::DkgPublicOriginFault { statement } => {
            assert_eq!(
                statement.fault_kind,
                DkgPublicOriginFaultKind::InvalidPayload
            );
            assert_eq!(statement.origin_protocol, "pss_refresh");
            assert_eq!(statement.phase, "commitments");
            assert_eq!(statement.attempt_id, refresh_attempt.attempt_id.0);
            assert!(statement.contribution_b.is_none());
            assert_eq!(
                hex::encode(&statement.contribution_a.origin),
                extract_node_part(&submission.accused_peer_id)
            );
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn staged_refresh_result_invalid_payload_queues_report_before_abort() {
    let db_name = "reporting_staged_refresh_result_invalid_payload";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    // RefreshHealthCheckResult must come from canonical node 1; find which
    // test-harness member that is so it can act as leader/sender, and use a
    // different member as the validating receiver.
    let leader_app_state = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ]
    .into_iter()
    .find(|app_state| {
        determine_session_node_id(&app_state.node_key, &ring.peer_node_keys) == Some(1)
    })
    .expect("one test-harness member must be canonical node 1")
    .clone();
    let receiver_app_state = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ]
    .into_iter()
    .find(|app_state| app_state.node_key != leader_app_state.node_key)
    .expect("a non-leader test-harness member must exist")
    .clone();

    let receiver =
        DkgCoordinator::<DkgImpl>::with_routes(Arc::new(receiver_app_state), &network::V0);
    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_333_111), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    create_preflight_test_session(&receiver, refresh_attempt, &ring_id, &ring, refresh_kind).await;

    let route_by_node_key = HashMap::from([
        (
            network.alice.app_state.node_key.clone(),
            network.alice.address.clone(),
        ),
        (
            network.bob.app_state.node_key.clone(),
            network.bob.address.clone(),
        ),
        (
            network.charlie.app_state.node_key.clone(),
            network.charlie.address.clone(),
        ),
    ]);
    let committee = CommitteeConfig {
        node_keys: ring.peer_node_keys.clone(),
        peer_routes: ring
            .peer_node_keys
            .iter()
            .map(|node_key| route_by_node_key[node_key].clone())
            .collect(),
        node_id_assignments: ring
            .peer_node_keys
            .iter()
            .map(|node_key| {
                (
                    node_key.clone(),
                    determine_session_node_id(node_key, &ring.peer_node_keys)
                        .expect("finalized member must have a canonical node ID"),
                )
            })
            .collect(),
        threshold: ring.threshold,
    };
    let committee_digest =
        configure_public_test_session(&receiver, refresh_attempt, committee).await;
    // The session was configured with the receiver as its own leader;
    // override it to the real leader (canonical node 1) so its message
    // passes `validate_leader_sender`.
    let leader_route = route_by_node_key[&leader_app_state.node_key].clone();
    receiver
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(refresh_attempt, |state| {
            state.transport.leader_node_key = Some(leader_app_state.node_key.clone());
            state.transport.leader_peer_route = Some(leader_route);
        })
        .await
        .expect("override test session leader to canonical node 1");
    evidence_build_context(&receiver, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");

    // A RefreshHealthCheckResult with the wrong domain: correctly shaped,
    // but fails validate_result_scope's domain check — an attributable
    // preflight failure staged over the control-plane result barrier.
    let bad_statement = crate::sign::v0::messages::RefreshHealthCheckStatement {
        domain: "wrong-domain".to_string(),
        session_id: refresh_attempt.session_id(),
        ring_pk: ring.ring_pk.clone(),
        public_polynomial_sha256: "00".repeat(32),
        peer_node_keys_sha256: "00".repeat(32),
        threshold: ring.threshold,
        total_participants: ring.peer_node_keys.len() as u32,
    };
    let (signed, _) = sign_test_public_contribution(
        &leader_app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        ParticipantRef::current(1),
        DkgPublicPayload::RefreshHealthCheckResult {
            statement: bad_statement,
            signature: None,
        },
    )
    .await;
    let sender = leader_app_state.network.local_peer_id().clone();
    let rejection = handle_control_for_test(
        receiver.app_state.clone(),
        &network::V0,
        DkgControlMessage::StageRefreshResult(signed),
        &sender,
    )
    .await
    .expect_err("a wrong-domain staged refresh result must be rejected");
    assert!(matches!(rejection, DkgError::Unauthorized(_)));
    assert_eq!(
        receiver
            .app_state
            .dkg_session_state
            .transport_attempt(&refresh_attempt.session_id())
            .await,
        None,
        "the staged-result path must abort the attempt"
    );

    receiver.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1, "expected one public-origin report");
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(submission.accused_node_key, leader_app_state.node_key);
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized public-origin payload")
    {
        InvalidCryptoResponse::DkgPublicOriginFault { statement } => {
            assert_eq!(
                statement.fault_kind,
                DkgPublicOriginFaultKind::InvalidPayload
            );
            assert_eq!(statement.origin_protocol, "pss_refresh");
            assert_eq!(statement.phase, "refresh_health_check");
            assert_eq!(statement.attempt_id, refresh_attempt.attempt_id.0);
            assert!(statement.contribution_b.is_none());
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn public_origin_non_commitment_equivocation_queues_report_before_abort() {
    let db_name = "reporting_public_origin_non_commitment_equivocation";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let alice = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &network::V0,
    );
    let charlie = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.charlie.app_state.clone()),
        &network::V0,
    );
    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_111_226), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    create_preflight_test_session(
        &alice,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;
    let charlie_node_id =
        create_preflight_test_session(&charlie, refresh_attempt, &ring_id, &ring, refresh_kind)
            .await;
    let route_by_node_key = HashMap::from([
        (
            network.alice.app_state.node_key.clone(),
            network.alice.address.clone(),
        ),
        (
            network.bob.app_state.node_key.clone(),
            network.bob.address.clone(),
        ),
        (
            network.charlie.app_state.node_key.clone(),
            network.charlie.address.clone(),
        ),
    ]);
    let committee = CommitteeConfig {
        node_keys: ring.peer_node_keys.clone(),
        peer_routes: ring
            .peer_node_keys
            .iter()
            .map(|node_key| route_by_node_key[node_key].clone())
            .collect(),
        node_id_assignments: ring
            .peer_node_keys
            .iter()
            .map(|node_key| {
                (
                    node_key.clone(),
                    determine_session_node_id(node_key, &ring.peer_node_keys)
                        .expect("finalized member must have a canonical node ID"),
                )
            })
            .collect(),
        threshold: ring.threshold,
    };
    let committee_digest = configure_public_test_session(&alice, refresh_attempt, committee).await;
    evidence_build_context(&alice, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");
    let charlie_context = evidence_build_context(&charlie, refresh_attempt)
        .await
        .expect("build accused evidence context")
        .expect("Refresh must have an evidence binding");

    let mut dealer = *DkgImpl::new(
        charlie_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        refresh_attempt.session_id(),
        DkgRole::Standard,
    )
    .expect("create Refresh audit dealer");
    dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate Refresh audit commitment");
    let commitment = serialize_commitment_coefficients(&dealer.commitment().coefficients)
        .expect("serialize Refresh audit commitment");
    let audit_reveal = build_commitment_evidence_with_context(
        &charlie,
        &charlie_context,
        charlie_node_id,
        commitment,
    )
    .expect("sign Refresh audit evidence");

    let origin = ParticipantRef::current(charlie_node_id);
    let (first_signed, first) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::CommitmentAudit {
            revealed: Vec::new(),
        },
    )
    .await;
    let (second_signed, second) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::CommitmentAudit {
            revealed: vec![audit_reveal],
        },
    )
    .await;
    assert!(record_public_contribution_at_leader_for_test(
        &alice.app_state,
        &network::V0,
        first_signed.clone(),
        &first,
    )
    .await
    .expect("first contribution must be retained"));
    assert!(
        !record_public_contribution_at_leader_for_test(
            &alice.app_state,
            &network::V0,
            first_signed.clone(),
            &first,
        )
        .await
        .expect("an identical retransmission must remain a harmless duplicate"),
        "an identical endpoint envelope must not be recorded or reported twice"
    );
    let rejection = record_public_contribution_at_leader_for_test(
        &alice.app_state,
        &network::V0,
        second_signed.clone(),
        &second,
    )
    .await
    .expect_err("the conflicting contribution must abort the attempt");
    assert!(matches!(rejection, DkgError::ProtocolError(_)));
    assert_eq!(
        alice
            .app_state
            .dkg_session_state
            .transport_attempt(&refresh_attempt.session_id())
            .await,
        None,
        "the original public protocol path must abort the attempt"
    );

    alice.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1, "expected one public-origin report");
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(
        submission.accused_node_key,
        network.charlie.app_state.node_key
    );
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized public-origin payload")
    {
        InvalidCryptoResponse::DkgPublicOriginFault { statement } => {
            assert_eq!(
                statement.fault_kind,
                DkgPublicOriginFaultKind::OriginEquivocation
            );
            assert_eq!(statement.phase, "commitment_audit");
            assert_eq!(statement.attempt_id, refresh_attempt.attempt_id.0);
            assert_eq!(statement.signed_at, first.signed_at.max(second.signed_at));
            assert_eq!(statement.contribution_a.data, first_signed.data);
            assert_eq!(
                statement
                    .contribution_b
                    .expect("equivocation requires a second contribution")
                    .data,
                second_signed.data
            );
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn refresh_health_check_origin_equivocation_queues_report_before_abort() {
    let db_name = "reporting_refresh_health_check_origin_equivocation";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    // RefreshHealthCheckResult must come from canonical node 1; find which
    // test-harness member that is so it can act as the equivocating origin,
    // and use a different member as the recording leader.
    let origin_app_state = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ]
    .into_iter()
    .find(|app_state| {
        determine_session_node_id(&app_state.node_key, &ring.peer_node_keys) == Some(1)
    })
    .expect("one test-harness member must be canonical node 1")
    .clone();
    let recorder_app_state = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ]
    .into_iter()
    .find(|app_state| app_state.node_key != origin_app_state.node_key)
    .expect("a non-origin test-harness member must exist")
    .clone();
    let recorder =
        DkgCoordinator::<DkgImpl>::with_routes(Arc::new(recorder_app_state), &network::V0);

    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_444_222), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    create_preflight_test_session(&recorder, refresh_attempt, &ring_id, &ring, refresh_kind).await;

    let route_by_node_key = HashMap::from([
        (
            network.alice.app_state.node_key.clone(),
            network.alice.address.clone(),
        ),
        (
            network.bob.app_state.node_key.clone(),
            network.bob.address.clone(),
        ),
        (
            network.charlie.app_state.node_key.clone(),
            network.charlie.address.clone(),
        ),
    ]);
    let committee = CommitteeConfig {
        node_keys: ring.peer_node_keys.clone(),
        peer_routes: ring
            .peer_node_keys
            .iter()
            .map(|node_key| route_by_node_key[node_key].clone())
            .collect(),
        node_id_assignments: ring
            .peer_node_keys
            .iter()
            .map(|node_key| {
                (
                    node_key.clone(),
                    determine_session_node_id(node_key, &ring.peer_node_keys)
                        .expect("finalized member must have a canonical node ID"),
                )
            })
            .collect(),
        threshold: ring.threshold,
    };
    let committee_digest =
        configure_public_test_session(&recorder, refresh_attempt, committee).await;
    evidence_build_context(&recorder, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");

    let origin = ParticipantRef::current(1);
    let statement = crate::sign::v0::messages::RefreshHealthCheckStatement {
        domain: crate::sign::v0::messages::REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
        session_id: refresh_attempt.session_id(),
        ring_pk: ring.ring_pk.clone(),
        public_polynomial_sha256: "00".repeat(32),
        peer_node_keys_sha256: "00".repeat(32),
        threshold: ring.threshold,
        total_participants: ring.peer_node_keys.len() as u32,
    };
    let (first_signed, first) = sign_test_public_contribution(
        &origin_app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::RefreshHealthCheckResult {
            statement: statement.clone(),
            signature: None,
        },
    )
    .await;
    let mut conflicting_statement = statement;
    conflicting_statement.public_polynomial_sha256 = "22".repeat(32);
    let (second_signed, second) = sign_test_public_contribution(
        &origin_app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::RefreshHealthCheckResult {
            statement: conflicting_statement,
            signature: None,
        },
    )
    .await;

    assert!(record_public_contribution_at_leader_for_test(
        &recorder.app_state,
        &network::V0,
        first_signed.clone(),
        &first,
    )
    .await
    .expect("first result must be retained"));
    let rejection = record_public_contribution_at_leader_for_test(
        &recorder.app_state,
        &network::V0,
        second_signed.clone(),
        &second,
    )
    .await
    .expect_err("the conflicting result must abort the attempt");
    assert!(matches!(rejection, DkgError::ProtocolError(_)));
    assert_eq!(
        recorder
            .app_state
            .dkg_session_state
            .transport_attempt(&refresh_attempt.session_id())
            .await,
        None,
        "the original public protocol path must abort the attempt"
    );

    recorder.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1, "expected one public-origin report");
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(submission.accused_node_key, origin_app_state.node_key);
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized public-origin payload")
    {
        InvalidCryptoResponse::DkgPublicOriginFault { statement } => {
            assert_eq!(
                statement.fault_kind,
                DkgPublicOriginFaultKind::OriginEquivocation
            );
            assert_eq!(statement.phase, "refresh_health_check");
            assert_eq!(statement.attempt_id, refresh_attempt.attempt_id.0);
            assert_eq!(statement.signed_at, first.signed_at.max(second.signed_at));
            assert_eq!(statement.contribution_a.data, first_signed.data);
            assert_eq!(
                statement
                    .contribution_b
                    .expect("equivocation requires a second contribution")
                    .data,
                second_signed.data
            );
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn public_commitment_origin_equivocation_queues_report_before_abort() {
    let db_name = "reporting_public_commitment_origin_equivocation";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let alice = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &network::V0,
    );
    let charlie = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.charlie.app_state.clone()),
        &network::V0,
    );
    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_111_225), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    create_preflight_test_session(
        &alice,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;
    let charlie_node_id =
        create_preflight_test_session(&charlie, refresh_attempt, &ring_id, &ring, refresh_kind)
            .await;

    let route_by_node_key = HashMap::from([
        (
            network.alice.app_state.node_key.clone(),
            network.alice.address.clone(),
        ),
        (
            network.bob.app_state.node_key.clone(),
            network.bob.address.clone(),
        ),
        (
            network.charlie.app_state.node_key.clone(),
            network.charlie.address.clone(),
        ),
    ]);
    let node_id_assignments = ring
        .peer_node_keys
        .iter()
        .map(|node_key| {
            (
                node_key.clone(),
                determine_session_node_id(node_key, &ring.peer_node_keys)
                    .expect("finalized member must have a canonical node ID"),
            )
        })
        .collect();
    let committee = CommitteeConfig {
        node_keys: ring.peer_node_keys.clone(),
        peer_routes: ring
            .peer_node_keys
            .iter()
            .map(|node_key| {
                route_by_node_key
                    .get(node_key)
                    .cloned()
                    .expect("finalized member must have a test route")
            })
            .collect(),
        node_id_assignments,
        threshold: ring.threshold,
    };
    let committee_digest =
        configure_public_test_session(&alice, refresh_attempt, committee.clone()).await;
    evidence_build_context(&alice, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");
    let charlie_context = evidence_build_context(&charlie, refresh_attempt)
        .await
        .expect("build accused evidence context")
        .expect("Refresh must have an evidence binding");

    let mut first_dealer = *DkgImpl::new(
        charlie_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        refresh_attempt.session_id(),
        DkgRole::Standard,
    )
    .expect("create first Refresh dealer");
    first_dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate first Refresh commitment");
    let first_commitment =
        serialize_commitment_coefficients(&first_dealer.commitment().coefficients)
            .expect("serialize first Refresh commitment");
    let mut second_dealer = *DkgImpl::new(
        charlie_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        refresh_attempt.session_id(),
        DkgRole::Standard,
    )
    .expect("create second Refresh dealer");
    second_dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate second Refresh commitment");
    let second_commitment =
        serialize_commitment_coefficients(&second_dealer.commitment().coefficients)
            .expect("serialize second Refresh commitment");
    assert_ne!(
        first_commitment, second_commitment,
        "test must construct two different Refresh commitments"
    );

    let first_evidence = build_commitment_evidence_with_context(
        &charlie,
        &charlie_context,
        charlie_node_id,
        first_commitment.clone(),
    )
    .expect("sign first Refresh commitment evidence");
    let second_evidence = build_commitment_evidence_with_context(
        &charlie,
        &charlie_context,
        charlie_node_id,
        second_commitment.clone(),
    )
    .expect("sign second Refresh commitment evidence");
    assert_eq!(
        first_evidence.statement.session_nonce, second_evidence.statement.session_nonce,
        "both statements must belong to the same transport attempt"
    );
    let origin = ParticipantRef::current(charlie_node_id);
    let (first_signed, first_contribution) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: first_commitment.clone(),
            report_evidence: Some(Box::new(first_evidence.clone())),
        },
    )
    .await;
    let (second_signed, second_contribution) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(second_evidence.clone())),
        },
    )
    .await;

    let (missing_a, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: first_commitment.clone(),
            report_evidence: None,
        },
    )
    .await;
    let (missing_b, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: None,
        },
    )
    .await;
    assert!(!queue_public_commitment_equivocation_for_test(
        &alice.app_state,
        &network::V0,
        refresh_attempt,
        origin,
        missing_a,
        missing_b,
    )
    .await
    .expect("missing evidence is a non-reportable conflict"));

    let (wrong_ring_signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        "foreign-ring",
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(second_evidence.clone())),
        },
    )
    .await;
    assert!(
        queue_public_commitment_equivocation_for_test(
            &alice.app_state,
            &network::V0,
            refresh_attempt,
            origin,
            first_signed.clone(),
            wrong_ring_signed,
        )
        .await
        .is_err(),
        "a foreign outer ring binding must not queue a report"
    );

    let foreign_attempt = AttemptKey::new(
        refresh_attempt.ceremony_id,
        AttemptId([refresh_attempt.attempt_id.0[0].wrapping_add(1); 32]),
    );
    let (wrong_attempt_signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        foreign_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(second_evidence.clone())),
        },
    )
    .await;
    assert!(
        queue_public_commitment_equivocation_for_test(
            &alice.app_state,
            &network::V0,
            refresh_attempt,
            origin,
            first_signed.clone(),
            wrong_attempt_signed,
        )
        .await
        .is_err(),
        "a foreign outer attempt binding must not queue a report"
    );

    let alice_node_id =
        determine_session_node_id(&network.alice.app_state.node_key, &ring.peer_node_keys)
            .expect("reporter must have a canonical node ID");
    let (wrong_origin_signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        ParticipantRef::current(alice_node_id),
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(second_evidence.clone())),
        },
    )
    .await;
    assert!(
        queue_public_commitment_equivocation_for_test(
            &alice.app_state,
            &network::V0,
            refresh_attempt,
            origin,
            first_signed.clone(),
            wrong_origin_signed,
        )
        .await
        .is_err(),
        "an endpoint/origin mismatch must not queue a report"
    );

    let mut bad_signature_evidence = second_evidence.clone();
    bad_signature_evidence.signature[0] ^= 1;
    let (bad_signature_signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(bad_signature_evidence)),
        },
    )
    .await;
    assert!(
        queue_public_commitment_equivocation_for_test(
            &alice.app_state,
            &network::V0,
            refresh_attempt,
            origin,
            first_signed.clone(),
            bad_signature_signed,
        )
        .await
        .is_err(),
        "an invalid nested signature must not queue a report"
    );

    let signing_key = String::from_utf8(
        network
            .charlie
            .app_state
            .local_storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .expect("read accused signing key")
            .expect("accused signing key must exist")
            .to_vec(),
    )
    .expect("test signing key must be UTF-8");
    let mut wrong_binding_evidence = second_evidence.clone();
    wrong_binding_evidence.statement.request_id = "wrong-refresh-attempt".to_string();
    wrong_binding_evidence.signature = sign_node_message_with_hex_key(
        &signing_key,
        &wrong_binding_evidence.statement.canonical_bytes(),
    )
    .expect("re-sign wrong-binding evidence");
    let (wrong_binding_signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(wrong_binding_evidence)),
        },
    )
    .await;
    assert!(
        queue_public_commitment_equivocation_for_test(
            &alice.app_state,
            &network::V0,
            refresh_attempt,
            origin,
            first_signed.clone(),
            wrong_binding_signed,
        )
        .await
        .is_err(),
        "wrong session binding must not queue a report"
    );

    let mut different_nonce_evidence = second_evidence.clone();
    different_nonce_evidence.statement.session_nonce[0] ^= 1;
    different_nonce_evidence.signature = sign_node_message_with_hex_key(
        &signing_key,
        &different_nonce_evidence.statement.canonical_bytes(),
    )
    .expect("re-sign different-nonce evidence");
    let (different_nonce_signed, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        refresh_attempt,
        &ring_id,
        committee_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: Some(Box::new(different_nonce_evidence)),
        },
    )
    .await;
    assert!(!queue_public_commitment_equivocation_for_test(
        &alice.app_state,
        &network::V0,
        refresh_attempt,
        origin,
        first_signed.clone(),
        different_nonce_signed,
    )
    .await
    .expect("different nonces are a non-reportable transport conflict"));

    let fresh_attempt = AttemptKey::new(CeremonyId(777_000_111_226), AttemptId::random());
    create_preflight_test_session(&alice, fresh_attempt, &ring_id, &ring, SessionKind::Fresh).await;
    let fresh_digest = configure_public_test_session(&alice, fresh_attempt, committee).await;
    let (fresh_a, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        fresh_attempt,
        &ring_id,
        fresh_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: first_commitment.clone(),
            report_evidence: None,
        },
    )
    .await;
    let (fresh_b, _) = sign_test_public_contribution(
        &network.charlie.app_state,
        fresh_attempt,
        &ring_id,
        fresh_digest,
        origin,
        DkgPublicPayload::Commitment {
            commitment: second_commitment.clone(),
            report_evidence: None,
        },
    )
    .await;
    assert!(!queue_public_commitment_equivocation_for_test(
        &alice.app_state,
        &network::V0,
        fresh_attempt,
        origin,
        fresh_a,
        fresh_b,
    )
    .await
    .expect("Fresh commitment conflicts must remain unreported"));
    assert!(
        network
            .dummy_bulletin
            .as_ref()
            .expect("reporting test requires DummyBulletin")
            .take_submitted_reports()
            .is_empty(),
        "non-proofs must not submit reports"
    );

    assert!(record_public_contribution_at_leader_for_test(
        &alice.app_state,
        &network::V0,
        first_signed,
        &first_contribution,
    )
    .await
    .expect("first contribution must be retained"));
    let rejection = record_public_contribution_at_leader_for_test(
        &alice.app_state,
        &network::V0,
        second_signed,
        &second_contribution,
    )
    .await
    .expect_err("second signed commitment must be rejected as equivocation");
    assert!(matches!(
        rejection,
        DkgError::ProtocolError(ref message) if message.contains("equivocated")
    ));
    assert_eq!(
        alice
            .app_state
            .dkg_session_state
            .transport_attempt(&refresh_attempt.session_id())
            .await,
        None,
        "the original protocol path must still abort the attempt"
    );

    alice.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(
        submissions.len(),
        1,
        "expected exactly one equivocation report"
    );
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(
        submission.accused_node_key,
        network.charlie.app_state.node_key
    );
    assert_eq!(
        submission.session_id,
        refresh_attempt.session_id().to_string()
    );
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized equivocation payload")
    {
        InvalidCryptoResponse::DkgEquivocation {
            commitment_a,
            commitment_b,
        } => {
            assert_eq!(commitment_a.statement.origin_protocol, "pss_refresh");
            assert_eq!(commitment_a.statement.request_id, submission.session_id);
            assert_eq!(
                commitment_a.statement.responder_node_key,
                submission.accused_node_key
            );
            assert_eq!(
                commitment_a.statement.session_nonce,
                commitment_b.statement.session_nonce
            );
            assert_ne!(
                commitment_a.statement.commitment,
                commitment_b.statement.commitment
            );
            assert_eq!(commitment_a.statement.commitment, first_commitment);
            assert_eq!(commitment_b.statement.commitment, second_commitment);
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn threshold_signs_offline_report_without_accused_node() {
    let db_name = "reporting_offline_signature";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;
    if let Some(router) = network.charlie.router.take() {
        router.shutdown().await.unwrap();
    }

    let routes = resolve_node_routes(&network.alice.app_state.bulletin, &ring.peer_node_keys)
        .await
        .unwrap();
    let accused_node_key = network.charlie.app_state.node_key.clone();
    let accused_peer_id = routes
        .iter()
        .find(|route| route.node_key == accused_node_key)
        .unwrap()
        .peer_id
        .clone();
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let observation = OfflineObservation {
        ring_id,
        accused_node_key: accused_node_key.clone(),
        accused_peer_id,
        origin_protocol: "pre".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        observed_at,
        session_id: "reporting-test-session".to_string(),
    };

    let app_state = Arc::new(network.alice.app_state.clone());
    assert!(queue_report::<DkgImpl, SignImpl>(
        app_state.clone(),
        &network::V0,
        ReportObservation::NodeOffline(observation),
    )
    .await
    .unwrap());
    app_state.reporting_state.shutdown().await;

    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap();
    let submissions = dummy_bulletin.take_submitted_reports();
    assert_eq!(submissions.len(), 1);
    let submission = &submissions[0];
    assert_eq!(submission.accused_node_key, accused_node_key);

    let envelope = ReportEnvelope {
        domain: submission.domain.clone(),
        report_type: submission.report_type.clone(),
        chain_id: submission.chain_id.clone(),
        ring_id: submission.ring_id.clone(),
        ring_pk: submission.ring_pk.clone(),
        ring_state_sha256: submission.ring_state_sha256.clone(),
        reporter_node_key: submission.reporter_node_key.clone(),
        accused_node_key: submission.accused_node_key.clone(),
        accused_peer_id: submission.accused_peer_id.clone(),
        observed_at: submission.observed_at,
        expires_at: submission.expires_at,
        payload: submission.payload.clone(),
        session_id: submission.session_id.clone(),
    };
    let message = envelope.canonical_bytes();
    let ring_pk_bytes = hex::decode(&ring.ring_pk).unwrap();
    let aggregate_pk = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).unwrap();
    let signature =
        <SignImpl as ThresholdSigner>::Signature::from_bytes(&submission.signature).unwrap();
    SignImpl::new()
        .verify(&aggregate_pk, &message, &signature)
        .expect("offline report signature should verify under ring key");

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn threshold_signs_invalid_crypto_pre_report_without_accused_node() {
    let db_name = "reporting_invalid_crypto_pre_signature";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let ring_pk_bytes = hex::decode(&ring.ring_pk).unwrap();
    let aggregate_pk = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).unwrap();
    let (_, encrypted_secret, proof) =
        PreImpl::encrypt_secret(&aggregate_pk, b"reportable invalid PRE proof", None, None)
            .unwrap();
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();
    let document_payload = DocumentPayload {
        ring_id: ring_id.clone(),
        document: String::from_utf8(secret_bytes).unwrap(),
        proof: String::try_from(proof).unwrap(),
        policy_id: "test-policy".to_string(),
        resource: "test-resource".to_string(),
        permission: "test-permission".to_string(),
        tier: None,
        timestamp: None,
    };
    let object_id = network
        .dummy_bulletin
        .as_ref()
        .unwrap()
        .post(
            BulletinWriteKind::Document,
            document_payload.try_into().unwrap(),
        )
        .await
        .unwrap();

    let (_reader_sk, rdr_pk) = PreImpl::generate_keypair();
    let rdr_pk_bytes = CryptoSerialize::to_bytes(&rdr_pk).unwrap();
    let charlie_bundle =
        RingShareBundle::load(&network.charlie.app_state.local_storage, &aggregate_pk).unwrap();
    let charlie_share = PriShare::<ScalarField>::from_bytes(&charlie_bundle.share_bytes).unwrap();
    let reply = PreImpl::new()
        .reencrypt(
            &DistKeyShare {
                pri_share: charlie_share,
            },
            &encrypted_secret,
            &rdr_pk,
            None,
        )
        .unwrap();
    let share_bytes = CryptoSerialize::to_bytes(&reply.share.v).unwrap();
    let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).unwrap();
    let invalid_proof = reply.proof + ScalarField::from(1u64);
    let proof_bytes = CryptoSerialize::to_bytes(&invalid_proof).unwrap();

    let request_id = "pre-invalid-proof-reporting-test".to_string();
    let routes = resolve_node_routes(&network.alice.app_state.bulletin, &ring.peer_node_keys)
        .await
        .unwrap();
    let accused_node_key = network.charlie.app_state.node_key.clone();
    let accused_peer_id = routes
        .iter()
        .find(|route| route.node_key == accused_node_key)
        .unwrap()
        .peer_id
        .clone();
    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let statement = PreReencryptResponseStatement {
        domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: network.alice.app_state.bulletin.chain_id(),
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        protocol_version: network::V0.version,
        request_id: request_id.clone(),
        signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: "pre".to_string(),
        object_id,
        rdr_pk: rdr_pk_bytes,
        derivation: None,
        from_node_id: reply.share.i,
        share: share_bytes,
        challenge: challenge_bytes,
        proof: proof_bytes,
        crypto_backend: PreImpl::name(),
    };
    let signing_key = network
        .charlie
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .unwrap()
        .unwrap();
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).unwrap();
    let response_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes()).unwrap();
    // The envelope must be anchored to the evidence: observed_at == signed_at - grace.
    let observed_at = signed_at - CHAIN_BLOCK_GRACE_SECS;
    let observation = InvalidCryptoResponseObservation {
        ring_id: ring_id.clone(),
        accused_node_key: accused_node_key.clone(),
        accused_peer_id: accused_peer_id.clone(),
        observed_at,
        evidence: InvalidCryptoResponse::Pre {
            statement,
            response_signature,
        },
    };

    let app_state = Arc::new(network.alice.app_state.clone());
    assert!(queue_report::<DkgImpl, SignImpl>(
        app_state.clone(),
        &network::V0,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .unwrap());
    app_state.reporting_state.shutdown().await;

    let submissions = network
        .dummy_bulletin
        .as_ref()
        .unwrap()
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1);
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.accused_node_key, accused_node_key);
    assert_eq!(submission.accused_peer_id, accused_peer_id);
    assert_eq!(submission.session_id, request_id);

    let envelope = ReportEnvelope {
        domain: submission.domain.clone(),
        report_type: submission.report_type.clone(),
        chain_id: submission.chain_id.clone(),
        ring_id: submission.ring_id.clone(),
        ring_pk: submission.ring_pk.clone(),
        ring_state_sha256: submission.ring_state_sha256.clone(),
        reporter_node_key: submission.reporter_node_key.clone(),
        accused_node_key: submission.accused_node_key.clone(),
        accused_peer_id: submission.accused_peer_id.clone(),
        observed_at: submission.observed_at,
        expires_at: submission.expires_at,
        payload: submission.payload.clone(),
        session_id: submission.session_id.clone(),
    };
    let signature =
        <SignImpl as ThresholdSigner>::Signature::from_bytes(&submission.signature).unwrap();
    SignImpl::new()
        .verify(&aggregate_pk, &envelope.canonical_bytes(), &signature)
        .expect("PRE invalid-proof report signature should verify under ring key");

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

// BLS-only: the fixture crafts the sig share directly without a nonce round,
// which FROST does not support.
#[cfg(feature = "bls12-381")]
#[tokio::test]
#[serial_test::serial]
async fn threshold_signs_invalid_crypto_sign_report_without_accused_node() {
    let db_name = "reporting_invalid_crypto_sign_signature";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let ring_pk_bytes = hex::decode(&ring.ring_pk).unwrap();
    let aggregate_pk = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).unwrap();

    // A share produced with a corrupted secret stays well-formed and honestly
    // signed but fails verification against the ring polynomial — the same
    // misbehavior the docker test injects by corrupting the stored ring share.
    let message = b"reportable invalid sign share".to_vec();
    let charlie_bundle =
        RingShareBundle::load(&network.charlie.app_state.local_storage, &aggregate_pk).unwrap();
    let charlie_share = PriShare::<ScalarField>::from_bytes(&charlie_bundle.share_bytes).unwrap();
    let pub_poly_bytes = hex::decode(&charlie_bundle.public_polynomial).unwrap();
    let pub_poly = <DkgImpl as Dkg>::PubPoly::from_bytes(&pub_poly_bytes).unwrap();
    let invalid_sig_share = SignImpl::new()
        .sign(
            &DistKeyShare {
                pri_share: PriShare {
                    i: charlie_share.i,
                    v: charlie_share.v + ScalarField::from(1u64),
                },
            },
            &message,
            &pub_poly,
            None,
            &[],
            None,
            None,
        )
        .unwrap();
    let sig_share_bytes = CryptoSerialize::to_bytes(&invalid_sig_share.v).unwrap();

    let request_id = "sign-invalid-share-reporting-test".to_string();
    let routes = resolve_node_routes(&network.alice.app_state.bulletin, &ring.peer_node_keys)
        .await
        .unwrap();
    let accused_node_key = network.charlie.app_state.node_key.clone();
    let accused_peer_id = routes
        .iter()
        .find(|route| route.node_key == accused_node_key)
        .unwrap()
        .peer_id
        .clone();
    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let statement = SignResponseStatement {
        domain: SIGN_RESPONSE_DOMAIN.to_string(),
        chain_id: network.alice.app_state.bulletin.chain_id(),
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        protocol_version: network::V0.version,
        request_id: request_id.clone(),
        signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: "sign".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: charlie_share.i,
        message,
        signing_commitments: Vec::new(),
        derivation: None,
        metadata: None,
        sig_share: sig_share_bytes,
        crypto_backend: SignImpl::name(),
    };
    let signing_key = network
        .charlie
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .unwrap()
        .unwrap();
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).unwrap();
    let response_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes()).unwrap();
    // The envelope must be anchored to the evidence: observed_at == signed_at - grace.
    let observed_at = signed_at - CHAIN_BLOCK_GRACE_SECS;
    let observation = InvalidCryptoResponseObservation {
        ring_id: ring_id.clone(),
        accused_node_key: accused_node_key.clone(),
        accused_peer_id: accused_peer_id.clone(),
        observed_at,
        evidence: InvalidCryptoResponse::Sign {
            statement,
            response_signature,
        },
    };

    let app_state = Arc::new(network.alice.app_state.clone());
    assert!(queue_report::<DkgImpl, SignImpl>(
        app_state.clone(),
        &network::V0,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .unwrap());
    app_state.reporting_state.shutdown().await;

    let submissions = network
        .dummy_bulletin
        .as_ref()
        .unwrap()
        .take_submitted_reports();
    assert_eq!(submissions.len(), 1);
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.accused_node_key, accused_node_key);
    assert_eq!(submission.accused_peer_id, accused_peer_id);
    assert_eq!(submission.session_id, request_id);

    let envelope = ReportEnvelope {
        domain: submission.domain.clone(),
        report_type: submission.report_type.clone(),
        chain_id: submission.chain_id.clone(),
        ring_id: submission.ring_id.clone(),
        ring_pk: submission.ring_pk.clone(),
        ring_state_sha256: submission.ring_state_sha256.clone(),
        reporter_node_key: submission.reporter_node_key.clone(),
        accused_node_key: submission.accused_node_key.clone(),
        accused_peer_id: submission.accused_peer_id.clone(),
        observed_at: submission.observed_at,
        expires_at: submission.expires_at,
        payload: submission.payload.clone(),
        session_id: submission.session_id.clone(),
    };
    let signature =
        <SignImpl as ThresholdSigner>::Signature::from_bytes(&submission.signature).unwrap();
    SignImpl::new()
        .verify(&aggregate_pk, &envelope.canonical_bytes(), &signature)
        .expect("Sign invalid-response report signature should verify under ring key");

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

/// Anti-framing: when the reported sig share actually verifies against the ring
/// polynomial, every co-signer's re-verification succeeds and it refuses to sign,
/// so the report never reaches threshold and nothing is submitted.
// BLS-only: the fixture crafts the sig share directly without a nonce round,
// which FROST does not support.
#[cfg(feature = "bls12-381")]
#[tokio::test]
#[serial_test::serial]
async fn co_signers_refuse_invalid_crypto_sign_report_when_share_verifies() {
    let db_name = "reporting_invalid_crypto_sign_antiframing";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let ring_pk_bytes = hex::decode(&ring.ring_pk).unwrap();
    let aggregate_pk = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).unwrap();

    // Charlie's genuine share: the evidence is honestly signed but the sig
    // share verifies, so co-signing it would frame an honest node.
    let message = b"framable valid sign share".to_vec();
    let charlie_bundle =
        RingShareBundle::load(&network.charlie.app_state.local_storage, &aggregate_pk).unwrap();
    let charlie_share = PriShare::<ScalarField>::from_bytes(&charlie_bundle.share_bytes).unwrap();
    let pub_poly_bytes = hex::decode(&charlie_bundle.public_polynomial).unwrap();
    let pub_poly = <DkgImpl as Dkg>::PubPoly::from_bytes(&pub_poly_bytes).unwrap();
    let valid_sig_share = SignImpl::new()
        .sign(
            &DistKeyShare {
                pri_share: PriShare {
                    i: charlie_share.i,
                    v: charlie_share.v,
                },
            },
            &message,
            &pub_poly,
            None,
            &[],
            None,
            None,
        )
        .unwrap();
    let sig_share_bytes = CryptoSerialize::to_bytes(&valid_sig_share.v).unwrap();

    let routes = resolve_node_routes(&network.alice.app_state.bulletin, &ring.peer_node_keys)
        .await
        .unwrap();
    let accused_node_key = network.charlie.app_state.node_key.clone();
    let accused_peer_id = routes
        .iter()
        .find(|route| route.node_key == accused_node_key)
        .unwrap()
        .peer_id
        .clone();
    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let statement = SignResponseStatement {
        domain: SIGN_RESPONSE_DOMAIN.to_string(),
        chain_id: network.alice.app_state.bulletin.chain_id(),
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        protocol_version: network::V0.version,
        request_id: "sign-antiframing-reporting-test".to_string(),
        signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: "sign".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: charlie_share.i,
        message,
        signing_commitments: Vec::new(),
        derivation: None,
        metadata: None,
        sig_share: sig_share_bytes,
        crypto_backend: SignImpl::name(),
    };
    let signing_key = network
        .charlie
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .unwrap()
        .unwrap();
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).unwrap();
    let response_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes()).unwrap();
    let observation = InvalidCryptoResponseObservation {
        ring_id: ring_id.clone(),
        accused_node_key,
        accused_peer_id,
        observed_at: signed_at - CHAIN_BLOCK_GRACE_SECS,
        evidence: InvalidCryptoResponse::Sign {
            statement,
            response_signature,
        },
    };

    let app_state = Arc::new(network.alice.app_state.clone());
    assert!(
        queue_report::<DkgImpl, SignImpl>(
            app_state.clone(),
            &network::V0,
            ReportObservation::InvalidCryptoResponse(Box::new(observation)),
        )
        .await
        .unwrap(),
        "report should be queued (not a duplicate)"
    );
    app_state.reporting_state.shutdown().await;

    let submissions = network
        .dummy_bulletin
        .as_ref()
        .unwrap()
        .take_submitted_reports();
    assert_eq!(
        submissions.len(),
        0,
        "no report should be submitted: the reported share verifies, so co-signers refuse"
    );

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

/// When the accused node is still reachable, co-signers run the health probe, confirm
/// the node is online, and refuse to contribute their signing shares. The report
/// coordinator (alice) cannot reach signing threshold and the report is never submitted.
#[tokio::test]
#[serial_test::serial]
async fn health_probe_blocks_report_when_accused_node_is_online() {
    let db_name = "reporting_health_probe_blocks";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    // Charlie is still online — the report about charlie being offline should be blocked.
    let routes = resolve_node_routes(&network.alice.app_state.bulletin, &ring.peer_node_keys)
        .await
        .unwrap();
    let accused_node_key = network.charlie.app_state.node_key.clone();
    let accused_peer_id = routes
        .iter()
        .find(|route| route.node_key == accused_node_key)
        .unwrap()
        .peer_id
        .clone();
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let observation = OfflineObservation {
        ring_id,
        accused_node_key,
        accused_peer_id,
        origin_protocol: "pre".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        observed_at,
        session_id: "health-reject-session".to_string(),
    };

    let app_state = Arc::new(network.alice.app_state.clone());
    assert!(
        queue_report::<DkgImpl, SignImpl>(
            app_state.clone(),
            &network::V0,
            ReportObservation::NodeOffline(observation),
        )
        .await
        .unwrap(),
        "report should be queued (not a duplicate)"
    );
    // Wait for the report task to complete (health probe + failed signing attempt).
    app_state.reporting_state.shutdown().await;

    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap();
    let submissions = dummy_bulletin.take_submitted_reports();
    assert_eq!(
        submissions.len(),
        0,
        "no report should be submitted: bob's health probe finds charlie reachable and refuses to co-sign"
    );

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

/// Builds the `CommitteeConfig` for a finalized test ring: node keys in ring
/// order, routes resolved from the live three-node test network, and
/// canonical node-ID assignments.
fn finalized_ring_committee(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
    ring: &RingPayload,
) -> CommitteeConfig {
    let route_by_node_key = HashMap::from([
        (
            network.alice.app_state.node_key.clone(),
            network.alice.address.clone(),
        ),
        (
            network.bob.app_state.node_key.clone(),
            network.bob.address.clone(),
        ),
        (
            network.charlie.app_state.node_key.clone(),
            network.charlie.address.clone(),
        ),
    ]);
    CommitteeConfig {
        node_keys: ring.peer_node_keys.clone(),
        peer_routes: ring
            .peer_node_keys
            .iter()
            .map(|node_key| route_by_node_key[node_key].clone())
            .collect(),
        node_id_assignments: ring
            .peer_node_keys
            .iter()
            .map(|node_key| {
                (
                    node_key.clone(),
                    determine_session_node_id(node_key, &ring.peer_node_keys)
                        .expect("finalized member must have a canonical node ID"),
                )
            })
            .collect(),
        threshold: ring.threshold,
    }
}

/// Two differently-signed acks (`Activated`) from the same follower for the
/// identical (ceremony, attempt, message_kind) request must be reported as
/// `AckEquivocation`, proving the leader-side control-ack recorder actually
/// detects and queues the fault rather than just silently overwriting the
/// first receipt.
#[tokio::test]
#[serial_test::serial]
async fn control_ack_equivocation_queues_report() {
    let db_name = "reporting_control_ack_equivocation";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let recorder = DkgCoordinator::<DkgImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &network::V0,
    );
    let follower_app_state = network.bob.app_state.clone();

    let refresh_attempt = AttemptKey::new(CeremonyId(777_000_555_333), AttemptId::random());
    let refresh_kind = SessionKind::Refresh {
        ring_pk_hex: ring.ring_pk.clone(),
    };
    create_preflight_test_session(
        &recorder,
        refresh_attempt,
        &ring_id,
        &ring,
        refresh_kind.clone(),
    )
    .await;

    let committee = finalized_ring_committee(&network, &ring);
    configure_public_test_session(&recorder, refresh_attempt, committee.clone()).await;
    evidence_build_context(&recorder, refresh_attempt)
        .await
        .expect("prime reporter evidence binding")
        .expect("Refresh must have an evidence binding");

    let follower_route = committee
        .node_keys
        .iter()
        .position(|node_key| node_key == &follower_app_state.node_key)
        .and_then(|index| committee.peer_routes.get(index))
        .cloned()
        .expect("follower must have a committee route");

    let prepare = PrepareSession {
        ceremony_id: refresh_attempt.ceremony_id,
        attempt_id: refresh_attempt.attempt_id,
        config_digest: [0; 32],
        topic_id: [0; 32],
        leader_node_key: network.alice.app_state.node_key.clone(),
        committees: CeremonyConfig {
            current: committee,
            next: None,
        },
        token_string: String::new(),
        kind: refresh_kind,
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id.clone(),
        ring_id: ring_id.clone(),
        report_signature: None,
    };

    let first_digest = [0x11; 32];
    let second_digest = [0x22; 32];
    let first_signature = sign_control_message(
        &Arc::new(follower_app_state.clone()),
        refresh_attempt.ceremony_id,
        refresh_attempt.attempt_id,
        "activated",
        first_digest,
    )
    .expect("sign first activated ack");
    let second_signature = sign_control_message(
        &Arc::new(follower_app_state.clone()),
        refresh_attempt.ceremony_id,
        refresh_attempt.attempt_id,
        "activated",
        second_digest,
    )
    .expect("sign conflicting activated ack");

    record_control_ack_best_effort_for_test(
        &recorder.app_state,
        &network::V0,
        &prepare,
        refresh_attempt.ceremony_id,
        refresh_attempt.attempt_id,
        "activated",
        first_digest,
        &follower_route,
        Some(first_signature.clone()),
    )
    .await;
    record_control_ack_best_effort_for_test(
        &recorder.app_state,
        &network::V0,
        &prepare,
        refresh_attempt.ceremony_id,
        refresh_attempt.attempt_id,
        "activated",
        second_digest,
        &follower_route,
        Some(second_signature.clone()),
    )
    .await;

    recorder.app_state.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(
        submissions.len(),
        1,
        "expected one control-ack-equivocation report"
    );
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(submission.accused_node_key, follower_app_state.node_key);
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized control-message-fault payload")
    {
        InvalidCryptoResponse::DkgControlMessageFault { statement } => {
            assert_eq!(
                statement.fault_kind,
                DkgControlMessageFaultKind::AckEquivocation
            );
            assert_eq!(statement.message_kind, "activated");
            assert_eq!(statement.responder_node_key, follower_app_state.node_key);
            let artifact_b = statement
                .artifact_b
                .expect("equivocation requires two artifacts");
            let digests: std::collections::BTreeSet<_> =
                [statement.artifact_a.data.clone(), artifact_b.data.clone()]
                    .into_iter()
                    .collect();
            assert_eq!(
                digests,
                std::collections::BTreeSet::from([first_digest.to_vec(), second_digest.to_vec()])
            );
            // Anchored to the later of the two followers' own authenticated
            // signed_at values, not report-construction time.
            let signed_ats: std::collections::BTreeSet<_> =
                [statement.artifact_a.signed_at, artifact_b.signed_at]
                    .into_iter()
                    .collect();
            assert_eq!(
                signed_ats,
                std::collections::BTreeSet::from([
                    first_signature.signed_at,
                    second_signature.signed_at
                ])
            );
            assert_eq!(
                statement.signed_at,
                first_signature.signed_at.max(second_signature.signed_at)
            );
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

/// A `Prepare` signed by a noncanonical leader is independently provable
/// (self-consistent digest, but the leader isn't the deterministic
/// `canonical_leader` for the committee) and must be reported as
/// `LeaderPrepareFault` by any current-committee recipient, without needing
/// any live session state (the report fires before a session would even be
/// created for such a `Prepare`).
#[tokio::test]
#[serial_test::serial]
async fn leader_prepare_fault_queues_report_for_noncanonical_leader() {
    let db_name = "reporting_leader_prepare_fault";
    let db_paths = [
        test_db_path(&format!("{db_name}_1")),
        test_db_path(&format!("{db_name}_2")),
        test_db_path(&format!("{db_name}_3")),
    ];
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    sleep(Duration::from_millis(100)).await;

    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("Fresh DKG should start");
    let (ring, ring_id) = wait_for_finalized_ring(&network).await;
    wait_for_all_nodes_ring_state(&network, &ring.ring_pk).await;

    let canonical = canonical_leader(&ring.peer_node_keys)
        .expect("finalized ring must have a canonical leader")
        .to_string();
    let noncanonical_app_state = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ]
    .into_iter()
    .find(|app_state| app_state.node_key != canonical)
    .expect("a non-canonical-leader test-harness member must exist")
    .clone();
    let recorder_app_state = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ]
    .into_iter()
    .find(|app_state| app_state.node_key != noncanonical_app_state.node_key)
    .expect("a distinct recording test-harness member must exist")
    .clone();

    let committee = finalized_ring_committee(&network, &ring);
    let mut prepare = PrepareSession {
        ceremony_id: CeremonyId(777_000_666_444),
        attempt_id: AttemptId::random(),
        config_digest: [0; 32],
        topic_id: [0; 32],
        leader_node_key: noncanonical_app_state.node_key.clone(),
        committees: CeremonyConfig {
            current: committee,
            next: None,
        },
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring.ring_pk.clone(),
        },
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id.clone(),
        ring_id: ring_id.clone(),
        report_signature: None,
    };
    prepare.config_digest =
        crate::dkg::v0::transport::config_digest(&prepare).expect("compute config digest");
    assert_ne!(
        canonical_leader(&prepare.committees.current.node_keys),
        Some(prepare.leader_node_key.as_str()),
        "test must construct a genuinely noncanonical leader claim"
    );

    let prepare_signature = sign_control_message(
        &Arc::new(noncanonical_app_state.clone()),
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepare",
        prepare.config_digest,
    )
    .expect("sign noncanonical Prepare");
    prepare.report_signature = Some(prepare_signature.clone());

    let recorder = Arc::new(recorder_app_state.clone());
    report_leader_prepare_fault_best_effort(&recorder, &network::V0, &prepare).await;

    recorder.reporting_state.shutdown().await;
    let submissions = network
        .dummy_bulletin
        .as_ref()
        .expect("reporting test requires DummyBulletin")
        .take_submitted_reports();
    assert_eq!(
        submissions.len(),
        1,
        "expected one leader-prepare-fault report"
    );
    let submission = &submissions[0];
    assert_eq!(submission.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(submission.ring_id, ring_id);
    assert_eq!(submission.accused_node_key, noncanonical_app_state.node_key);
    match InvalidCryptoResponse::from_canonical_bytes(&submission.payload)
        .expect("decode sanitized control-message-fault payload")
    {
        InvalidCryptoResponse::DkgControlMessageFault { statement } => {
            assert_eq!(
                statement.fault_kind,
                DkgControlMessageFaultKind::LeaderPrepareFault
            );
            assert_eq!(statement.message_kind, "prepare");
            assert_eq!(
                statement.responder_node_key,
                noncanonical_app_state.node_key
            );
            assert!(statement.artifact_b.is_none());
            let decoded: PrepareSession = crate::dkg::v0::transport::decode(
                &statement.artifact_a.data,
                crate::dkg::v0::transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
            )
            .expect("decode retained Prepare artifact");
            assert_eq!(decoded.config_digest, prepare.config_digest);
            // Anchored to the leader's own authenticated signed_at, not
            // report-construction time.
            assert_eq!(statement.artifact_a.signed_at, prepare_signature.signed_at);
            assert_eq!(statement.signed_at, prepare_signature.signed_at);
        }
        other => panic!("unexpected invalid-response payload: {other:?}"),
    }

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
    }
}

/// Polls each node's local storage until all three have persisted their `RingShareBundle`
/// for `ring_pk`. This must be called after `wait_for_finalized_ring` because the bulletin
/// update (which unblocks that helper) races with the concurrent Phase 4 storage writes on
/// bob and charlie.
async fn wait_for_all_nodes_ring_state(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
    ring_pk: &str,
) {
    let start = Instant::now();
    loop {
        let all_ready = [
            &network.alice.app_state.local_storage,
            &network.bob.app_state.local_storage,
            &network.charlie.app_state.local_storage,
        ]
        .iter()
        .all(|storage| RingPolyState::load_from_ring_pk_hex(*storage, ring_pk).is_ok());
        if all_ready {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "nodes did not persist ring state in time"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_finalized_ring(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
) -> (RingPayload, String) {
    let bulletin = network.dummy_bulletin.as_ref().unwrap();
    let start = Instant::now();
    loop {
        let post = get_test_ring_post(bulletin);
        if let Ok(payload) = RingPayload::try_from(post.clone()) {
            if !payload.ring_pk.is_empty() {
                return (payload, post.id);
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "DKG did not finalize in time"
        );
        sleep(Duration::from_millis(250)).await;
    }
}

// Suppress unused-import warning on the Result alias imported for trait impls
// that no longer exist in this module.
#[allow(dead_code)]
fn _use_result(_: Result<()>) {}
