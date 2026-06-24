use super::error::Result;
use super::observation::{OfflineObservation, ReportObservation};
use super::queue_report;
use super::sink::ReportSink;
use super::state::ReportingState;
use super::types::{CommitteeScope, SignedReport};
use crate::dkg::v0::service::DkgServiceImpl;
use crate::helpers::node_routes::resolve_node_routes;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, get_test_ring_post,
    setup_three_node_network_with_sign, test_db_path, TestKeyPair, TEST_FRESH_DKG_RING_ID,
};
use async_trait::async_trait;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoDeserialize, Dkg, ThresholdSigner};
use crypto::{DkgImpl, SignImpl};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[derive(Default)]
struct MemoryReportSink {
    reports: tokio::sync::Mutex<Vec<SignedReport>>,
}

#[async_trait]
impl ReportSink for MemoryReportSink {
    async fn submit(&self, report: SignedReport) -> Result<()> {
        self.reports.lock().await.push(report);
        Ok(())
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
    let sink = Arc::new(MemoryReportSink::default());
    network.alice.app_state.reporting_state = Arc::new(ReportingState::with_sink(sink.clone()));
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

    let reports = sink.reports.lock().await;
    assert_eq!(reports.len(), 1);
    let signed_report = &reports[0];
    assert_eq!(signed_report.report.accused_node_key, accused_node_key);
    let message = signed_report.report.canonical_bytes();
    let ring_pk_bytes = hex::decode(&ring.ring_pk).unwrap();
    let aggregate_pk = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).unwrap();
    let signature_bytes = hex::decode(&signed_report.signature).unwrap();
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes).unwrap();
    SignImpl::new()
        .verify(&aggregate_pk, &message, &signature)
        .expect("offline report signature should verify under ring key");
    drop(reports);

    network.shutdown_routers().await.unwrap();
    for path in db_paths {
        cleanup_db(&path);
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
