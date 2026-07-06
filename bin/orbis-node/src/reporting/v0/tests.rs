use super::error::Result;
use super::observation::{InvalidCryptoResponseObservation, OfflineObservation, ReportObservation};
use super::queue_report;
use super::types::{
    ring_state_sha256, CommitteeScope, InvalidCryptoResponse, PreReencryptResponseStatement,
    ReportEnvelope, CHAIN_BLOCK_GRACE_SECS, INVALID_CRYPTO_RESPONSE_REPORT_TYPE,
    PRE_REENCRYPT_RESPONSE_DOMAIN,
};
use crate::dkg::v0::service::DkgServiceImpl;
use crate::helpers::node_routes::resolve_node_routes;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, get_test_ring_post,
    setup_three_node_network_with_sign, test_db_path, TestKeyPair, TEST_FRESH_DKG_RING_ID,
};
use crate::ring_state::{RingPolyState, RingShareBundle};
use bulletin::r#trait::{Bulletin, BulletinWriteKind, DocumentPayload, RingPayload};
use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PriShare, ThresholdDealer,
    ThresholdSigner,
};
use crypto::{DkgImpl, PreImpl, ScalarField, SignImpl};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

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
    assert_eq!(
        submission.report_type,
        INVALID_CRYPTO_RESPONSE_REPORT_TYPE
    );
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
