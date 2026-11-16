//! Cosmos fixtures must publish live transport routes before ring creation and after restart.

use common::blockchain::{TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY};
use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRole, ScenarioFixture, TestEnvironment,
};
use test_support::node_readiness::wait_for_nodes_ready;
use test_support::CosmosTestEnvironment;

#[tokio::test]
#[serial_test::serial]
async fn publishes_peer_routes_without_preseeded_rings() {
    // Live-created rings, including the Defra PRE scenario, start from this
    // shape. Updating routes only while provisioning fixture rings leaves
    // these nodes registered by bare peer identity and unable to dial directly.
    let environment = CosmosTestEnvironment::provision(ScenarioFixture {
        nodes: (0..3)
            .map(|index| NodeFixture {
                id: FixtureId::new(format!("node{index}")),
                role: NodeRole::Running,
            })
            .collect(),
        ..Default::default()
    })
    .await;
    assert!(environment.fixture().rings.is_empty());

    let client = VeraClient::with_signer(
        environment.chain_config(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, environment.chain_config())
            .expect("test controller signer"),
    )
    .await
    .expect("chain client for published peer routes");
    assert_live_routes(&environment, &client, &[0, 1, 2]).await;

    // Make the old route deterministically stale, even if the OS happens to
    // reuse the previous UDP port. Keep the peer identity valid so startup
    // succeeds and lifecycle route restoration is the behavior under test.
    stale_route(&environment, &client, 0).await;
    environment.stop_node(0).await;
    let endpoint = environment.start_node(0).await;
    wait_for_nodes_ready(&[endpoint]).await;
    assert_live_routes(&environment, &client, &[0]).await;

    for index in 0..environment.nodes().len() {
        stale_route(&environment, &client, index).await;
        environment.stop_node(index).await;
    }
    let endpoints = environment.restart_nodes().await;
    assert_eq!(endpoints.len(), environment.nodes().len());
    wait_for_nodes_ready(&endpoints).await;
    assert_live_routes(&environment, &client, &[0, 1, 2]).await;
}

async fn stale_route(environment: &CosmosTestEnvironment, client: &VeraClient, index: usize) {
    assert!(
        !environment.node_udp_listen_ports(index).contains(&1),
        "test requires UDP port 1 to be unused by the node"
    );
    // Restart route publication uses another signer for the same controller.
    client
        .resync_nonce()
        .await
        .expect("resync controller after restart");
    let node = &environment.nodes()[index];
    let update = client
        .orbis_update_node_peer_id(
            &node.node_key,
            &format!("{}@node{}:1", node.peer_id, index + 1),
        )
        .await
        .expect("set a stale route before restart");
    assert_eq!(update.code, 0, "set stale route failed: {}", update.log);
}

async fn assert_live_routes(
    environment: &CosmosTestEnvironment,
    client: &VeraClient,
    indices: &[usize],
) {
    for &index in indices {
        let node = &environment.nodes()[index];
        let info = client
            .orbis_read_node_info(&node.node_key)
            .await
            .expect("read registered NodeInfo")
            .expect("ready node must be registered");
        let (peer, host_port) = info
            .peer_id
            .split_once('@')
            .expect("published route must include a socket address");
        assert_eq!(
            peer, node.peer_id,
            "restarting must retain the peer identity"
        );
        let (host, port) = host_port
            .rsplit_once(':')
            .expect("P2P address must include a port");
        assert_eq!(host, format!("node{}", index + 1));
        let port: u16 = port.parse().expect("P2P port must be numeric");
        let live_ports = environment.node_udp_listen_ports(index);
        assert!(
            live_ports.contains(&port),
            "node {index} has stale published route {}: live UDP ports are {live_ports:?}",
            info.peer_id
        );
        assert_eq!(
            environment.reporting_peer_address(index),
            info.peer_id,
            "reports must target the current published route"
        );
    }
}
