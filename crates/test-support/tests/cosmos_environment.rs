//! Cosmos fixture provisioning must prepare transport routes before any ring exists.

use common::blockchain::VeraClient;
use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRole, ScenarioFixture, TestEnvironment,
};
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

    let client = VeraClient::new(environment.chain_config())
        .await
        .expect("chain client for published peer routes");
    for (index, node) in environment.nodes().iter().enumerate() {
        let info = client
            .orbis_read_node_info(&node.node_key)
            .await
            .expect("read registered NodeInfo")
            .expect("ready node must be registered");
        let (_, host_port) = node
            .p2p_address
            .split_once('@')
            .expect("ready node must expose a socket address");
        let port: u16 = host_port
            .rsplit_once(':')
            .expect("P2P address must include a port")
            .1
            .parse()
            .expect("P2P port must be numeric");
        assert_ne!(port, 0, "published route must use the bound UDP port");
        assert_eq!(
            info.peer_id,
            format!("{}@node{}:{port}", node.peer_id, index + 1),
            "every running node needs a container-reachable route before ring creation"
        );
    }
}
