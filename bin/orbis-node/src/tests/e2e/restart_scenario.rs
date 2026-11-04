//! A restarted committee member keeps the identity and ring polynomial it
//! had before the process stopped.
//!
//! The adapter owns how the process is stopped and started. This scenario
//! only talks to `NetworkTestDriver` and the node's info service. The node
//! id inside the advertised p2p address is part of that identity. A
//! discovered direct socket is not: the process may publish a new mapped
//! port the next time it starts.

use super::{pre_scenario, TestEnvironmentImpl};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoRequest, GetNodeInfoResponse,
    GetRingStateRequest, NodeStatus,
};
use std::time::Duration;
use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole, RingFixture, ScenarioFixture,
    TestEnvironment,
};
use tokio::time::{sleep, Duration as TokioDuration, Instant};

const RESTARTED_MEMBER: usize = 1;

#[tokio::test]
#[serial_test::serial]
async fn test_restarted_member_keeps_identity_and_polynomial() {
    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            // Long enough that a share refresh cannot rotate the polynomial
            // while the member is stopped. Native also refuses a shorter
            // live interval.
            pss_interval: Duration::from_secs(86_400),
            requires_pet: false,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let (keys, local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    let before = environment.nodes()[RESTARTED_MEMBER].clone();
    let polynomial = local_state[RESTARTED_MEMBER].clone();
    let before_info = ready_info(&before.grpc_endpoint).await;
    assert_eq!(before_info.node_key, before.node_key);
    assert_eq!(before_info.peer_id, before.peer_id);
    assert!(
        before_info.managed_ring_count >= 1,
        "the member must already be holding the finalized ring"
    );

    environment.stop_node(RESTARTED_MEMBER).await;
    let endpoint = environment.start_node(RESTARTED_MEMBER).await;
    let recovered = ready_info(&endpoint).await;

    assert_eq!(recovered.node_key, before.node_key);
    assert_eq!(recovered.peer_id, before.peer_id);
    assert_eq!(
        common::peer_id::node_part(&recovered.p2p_address),
        common::peer_id::node_part(&before.p2p_address),
        "restart must keep the node id advertised in the p2p address"
    );
    assert_eq!(recovered.public_address, before.public_address);
    assert_eq!(
        recovered.managed_ring_count, before_info.managed_ring_count,
        "restart must not drop a locally managed ring"
    );
    assert_eq!(
        ring_polynomial(&endpoint, &keys.main).await,
        polynomial,
        "restart must keep the member's polynomial"
    );
}

async fn ready_info(endpoint: &str) -> GetNodeInfoResponse {
    let deadline = Instant::now() + TokioDuration::from_secs(90);
    loop {
        if let Ok(mut client) = InfoServiceClient::connect(endpoint.to_string()).await {
            if let Ok(response) = client.get_node_info(GetNodeInfoRequest {}).await {
                let info = response.into_inner();
                if info.status() == NodeStatus::Ready {
                    return info;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "node at {endpoint} did not become ready"
        );
        sleep(TokioDuration::from_millis(200)).await;
    }
}

async fn ring_polynomial(endpoint: &str, ring_pk: &str) -> String {
    let deadline = Instant::now() + TokioDuration::from_secs(60);
    loop {
        if let Ok(mut client) = InfoServiceClient::connect(endpoint.to_string()).await {
            if let Ok(response) = client
                .get_ring_state(GetRingStateRequest {
                    ring_pk_hex: ring_pk.to_string(),
                })
                .await
            {
                let polynomial = response.into_inner().public_polynomial;
                if !polynomial.is_empty() {
                    return polynomial;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "restarted member did not reload its polynomial"
        );
        sleep(TokioDuration::from_millis(200)).await;
    }
}
