//! Docker integration test for stale pending-DKG cancellation.
//!
//! Run with:
//!   cargo test -p orbis-node --features integration-test \
//!     test_stale_pending_dkg_is_cancelled_on_sourcehub -- --nocapture

use crate::ring_state::RingIndexEntry;
use common::{blockchain::SourceHubClient, IntegrationTestNetwork};
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
};
use tokio::time::{sleep, Duration, Instant};

const RING_ID: &str = "integration-test-stale-pending-ring";
const PSS_INTERVAL_SECS: u64 = 30;

use super::constants::{reporting_genesis_json, NODE_KEY_1, NODE_KEY_2, NODE_KEY_3};

#[tokio::test]
#[serial_test::serial]
async fn test_stale_pending_dkg_is_cancelled_on_sourcehub() {
    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": PSS_INTERVAL_SECS,
                    "policy_id": "integration-test-policy",
                    "reporting": reporting_genesis_json(1, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    crate::helpers::test_helpers::wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1))
        .await;

    let indexed_at_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let ring_index = vec![RingIndexEntry {
        ring_pk_str: format!("pending:{RING_ID}"),
        bulletin_post_id: RING_ID.to_string(),
        indexed_at_secs,
    }];
    let ring_index_bytes = serde_json::to_vec(&ring_index).expect("serialize RingIndex");

    for (index, endpoint) in endpoints.iter().enumerate() {
        let mut unsafe_client = UnsafeTestingServiceClient::connect((*endpoint).to_string())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "connect to node {} unsafe testing service: {error}",
                    index + 1
                )
            });
        unsafe_client
            .set_local_storage(SetLocalStorageRequest {
                key: Some(ring_index_key()),
                access_mode: LocalStorageAccessMode::Plain as i32,
                value: ring_index_bytes.clone(),
            })
            .await
            .unwrap_or_else(|error| panic!("seed node {} RingIndex: {error}", index + 1));
        let stored = unsafe_client
            .get_local_storage(GetLocalStorageRequest {
                key: Some(ring_index_key()),
                access_mode: LocalStorageAccessMode::Plain as i32,
            })
            .await
            .unwrap_or_else(|error| panic!("read node {} RingIndex: {error}", index + 1))
            .into_inner();
        assert!(stored.found, "node {} RingIndex should exist", index + 1);
        assert_eq!(
            serde_json::from_slice::<Vec<RingIndexEntry>>(&stored.value)
                .expect("parse stored RingIndex")
                .len(),
            1,
            "node {} should store one pending RingIndex entry",
            index + 1
        );

        let info = cli_tool::query_node_info((*endpoint).to_string())
            .await
            .unwrap_or_else(|error| panic!("query node {} info: {error}", index + 1));
        assert_eq!(
            info.managed_ring_count,
            1,
            "node {} should start with the seeded pending ring index",
            index + 1
        );
    }

    let chain_client = SourceHubClient::new(chain_config)
        .await
        .expect("SourceHub client");
    let initial_ring = chain_client
        .orbis_read_ring(RING_ID)
        .await
        .expect("read pending ring")
        .expect("pending ring should exist before timeout");
    assert!(initial_ring.ring_pk.is_empty());

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if chain_client
            .orbis_read_ring(RING_ID)
            .await
            .expect("poll pending ring")
            .is_none()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "pending ring was not cancelled within 90 seconds"
        );
        sleep(Duration::from_secs(1)).await;
    }

    let cleanup_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut lengths = Vec::with_capacity(endpoints.len());
        for endpoint in &endpoints {
            let mut unsafe_client = UnsafeTestingServiceClient::connect((*endpoint).to_string())
                .await
                .expect("connect unsafe testing service after cancellation");
            let stored = unsafe_client
                .get_local_storage(GetLocalStorageRequest {
                    key: Some(ring_index_key()),
                    access_mode: LocalStorageAccessMode::Plain as i32,
                })
                .await
                .expect("read RingIndex after cancellation")
                .into_inner();
            lengths.push(if stored.found {
                serde_json::from_slice::<Vec<RingIndexEntry>>(&stored.value)
                    .expect("parse RingIndex after cancellation")
                    .len()
            } else {
                0
            });
        }
        if lengths.iter().all(|length| *length == 0) {
            break;
        }
        assert!(
            Instant::now() < cleanup_deadline,
            "nodes did not clean their pending ring indexes; lengths={lengths:?}"
        );
        sleep(Duration::from_secs(1)).await;
    }
}

fn ring_index_key() -> LocalStorageKey {
    LocalStorageKey {
        key_type: LocalStorageKeyType::RingIndex as i32,
        ring_key: String::new(),
    }
}
