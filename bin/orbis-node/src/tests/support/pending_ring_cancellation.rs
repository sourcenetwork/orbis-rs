//! Shared DKG-ring lifecycle test: a pending ring that never finalizes
//! should eventually be cleaned up without any actor action.
//!
//! Tendermint/Cosmos's chain enforces this with a real timeout — that's the
//! correct, authoritative behavior and what this test asserts. Commonware/
//! native has no such capability yet (abort-only design: only an explicit
//! operator-initiated `RingCommand::Cancel` exists) — ignored there for now
//! rather than weakening the assertion; see the `#[cfg_attr]` below.
//!
//! Run with:
//!   cargo test -p orbis-node --features integration-test \
//!     test_stale_pending_dkg_is_cancelled -- --nocapture

// `crate::` means two different things depending on which backend's entry
// point `#[path]`-included this file: Cosmos includes it from inside
// `orbis-node`'s own `#[cfg(test)]` tree (so `crate::` reaches it directly),
// native includes it from the separate `tests/native_startup.rs` binary
// (which only sees `orbis-node`'s public API, hence `ring_state` is `pub
// mod` in `lib.rs` and reached here via the crate's own external name).
#[cfg(feature = "integration-test-cosmos")]
use crate::ring_state::RingIndexEntry;
#[cfg(feature = "integration-test-native")]
use orbis_node::ring_state::RingIndexEntry;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole, RingFixture,
    ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Duration, Instant};

use super::TestEnvironmentImpl;

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "commonware/native has no automatic pending-ring timeout \
              (abort-only design — only explicit RingCommand::Cancel \
              exists); fix when native grows this capability"
)]
async fn test_stale_pending_dkg_is_cancelled() {
    // Minimal placeholder policy — unused by Cosmos (its ring materializer
    // always substitutes its own content-addressed governance policy
    // regardless, and this ring never finalizes DKG so nothing ever checks
    // document/key-derivation authorization), but native's ring creation
    // needs a real backing `PolicyFixture` to register as the ring's
    // `ring_policy` object either way.
    const PLACEHOLDER_POLICY_YAML: &str = r#"
name: pending ring cancellation placeholder policy
resources:
- name: document
  permissions:
  - name: read
    expr: reader
  relations:
  - name: reader
    types:
    - actor
"#;

    let policy = FixtureId::new("policy");
    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![test_support::fixture::PolicyFixture {
            id: policy.clone(),
            definition: PLACEHOLDER_POLICY_YAML.to_string(),
        }],
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(30),
            requires_pet: false,
            policy: policy.clone(),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let endpoints: Vec<String> = environment
        .nodes()
        .iter()
        .map(|node| node.grpc_endpoint.clone())
        .collect();

    let indexed_at_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let ring_index = vec![RingIndexEntry {
        ring_pk_str: format!("pending:{}", ring_id.0),
        bulletin_post_id: ring_id.0.clone(),
        indexed_at_secs,
    }];
    let ring_index_bytes = serde_json::to_vec(&ring_index).expect("serialize RingIndex");

    for (index, endpoint) in endpoints.iter().enumerate() {
        let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
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

        let info = cli_tool::query_node_info(endpoint.clone())
            .await
            .unwrap_or_else(|error| panic!("query node {} info: {error}", index + 1));
        assert_eq!(
            info.managed_ring_count,
            1,
            "node {} should start with the seeded pending ring index",
            index + 1
        );
    }

    let initial_ring = environment
        .read_ring(&ring_id)
        .await
        .expect("pending ring should exist before timeout");
    assert!(initial_ring.ring_pk.is_empty());

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if environment.read_ring(&ring_id).await.is_none() {
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
            let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
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
