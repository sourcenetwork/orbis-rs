use super::error::Result;
use super::observation::{InvalidCryptoResponseObservation, OfflineObservation, ReportObservation};
use super::types::{
    ring_state_sha256, CommitteeScope, InvalidCryptoResponse, PreReencryptResponseStatement,
    RelayRequestStatement, ReportEnvelope, CHAIN_BLOCK_GRACE_SECS,
    INVALID_CRYPTO_RESPONSE_REPORT_TYPE, PRE_REENCRYPT_RESPONSE_DOMAIN, RELAY_REQUEST_DOMAIN,
};
#[cfg(feature = "bls12-381")]
use super::types::{SignResponseStatement, SIGN_RESPONSE_DOMAIN};
use super::{
    build_signed_relay_statement, queue_report, validate_relay_request_binding,
    RelayRequestBinding, RelayRequestTimestampBinding, RelayStatementInputs,
};
use crate::dkg::v0::coordinator::evidence::{
    build_commitment_evidence_with_context, evidence_build_context,
};
use crate::dkg::v0::coordinator::message_handlers::prepare_commitment_message;
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::serialize_commitment_coefficients;
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::service::DkgServiceImpl;
use crate::dkg::v0::transport::{AttemptId, AttemptKey, CeremonyId};
use crate::helpers::identity::determine_session_node_id;
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
