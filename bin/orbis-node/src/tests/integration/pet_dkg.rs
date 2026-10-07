use super::{
    pet_dkg_contract, pre_scenario, reporting_genesis_json, sign_scenario,
    wait_for_node_info_on_chain, wait_for_ring_state_on_all_nodes, RingStateSnapshot, NODE_KEY_1,
    NODE_KEY_2, NODE_KEY_3,
};
use bulletin::r#trait::{BulletinKind, BulletinWriteKind};
use common::blockchain::{
    orbis::WhitelistTarget, ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY,
};
use std::time::Duration;
use test_support::IntegrationTestNetwork;

pub(super) struct Config {
    pub ring_id: &'static str,
    pub expected_policy_id: &'static str,
    pub mode: pet_dkg_contract::DkgMode,
}

/// Cosmos/SourceHub adapter for the shared paired-DKG scenario. It owns the
/// network so the returned fixture can continue into the longer PET/PRE test.
pub(super) struct Cosmos {
    pub network: IntegrationTestNetwork,
    pub chain_config: ChainConfig,
    pub controller_client: VeraClient,
    pub endpoint: String,
    pub node_keys: [String; 3],
    pub threshold: u32,
    pub ring_id: String,
    mode: pet_dkg_contract::DkgMode,
    node_endpoints: [String; 3],
    store_signer_address: String,
}

impl pet_dkg_contract::ScenarioBackend for Cosmos {
    type Config = Config;

    async fn provision(config: Self::Config) -> Self {
        // Cosmos can bypass its production pss_interval minimum only by
        // seeding this test ring in genesis. Native provisions its equivalent
        // through its protocol in its own adapter.
        let network = IntegrationTestNetwork::builder()
            .with_module_genesis(
                "orbis",
                serde_json::json!({
                    "rings": [{
                        "id": config.ring_id,
                        "ring_pk": "",
                        "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                        "threshold": 2,
                        "pss_interval": 5,
                        "policy_id": config.expected_policy_id,
                        "reporting": reporting_genesis_json(1, &[], 3),
                        "requires_pet": config.mode.requires_pet()
                    }]
                }),
            )
            .build();
        let chain_config = network.chain_config();
        let endpoints = network.all_endpoints();

        crate::helpers::test_helpers::wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1))
            .await;

        let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
            .await
            .expect("Failed to query node1 info");
        let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
            .await
            .expect("Failed to query node2 info");
        let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
            .await
            .expect("Failed to query node3 info");

        let peer_addresses = [
            IntegrationTestNetwork::transform_p2p_address(
                &node1_info.p2p_address,
                IntegrationTestNetwork::NODE1_SERVICE,
            ),
            IntegrationTestNetwork::transform_p2p_address(
                &node2_info.p2p_address,
                IntegrationTestNetwork::NODE2_SERVICE,
            ),
            IntegrationTestNetwork::transform_p2p_address(
                &node3_info.p2p_address,
                IntegrationTestNetwork::NODE3_SERVICE,
            ),
        ];
        let node_endpoints = [
            endpoints[0].to_string(),
            endpoints[1].to_string(),
            endpoints[2].to_string(),
        ];
        let node_keys = [
            node1_info.node_key.clone(),
            node2_info.node_key.clone(),
            node3_info.node_key.clone(),
        ];
        assert_eq!(
            node_keys,
            [
                NODE_KEY_1.to_string(),
                NODE_KEY_2.to_string(),
                NODE_KEY_3.to_string(),
            ],
            "node keys must match the deterministic Compose signing keys"
        );

        let controller_client = VeraClient::with_signer(
            chain_config.clone(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
                .expect("test account signer"),
        )
        .await
        .expect("controller chain client");

        let governance_policy_id = crate::helpers::test_helpers::create_ring_governance_with_ring(
            &controller_client,
            config.ring_id,
            &[NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
        )
        .await;
        assert_eq!(
            governance_policy_id, config.expected_policy_id,
            "ACP policy ID changed; update the policy ID used by the genesis fixture"
        );

        for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
            wait_for_node_info_on_chain(
                &controller_client,
                node_key,
                Duration::from_secs(60),
                Duration::from_millis(500),
            )
            .await;
            let peer_update = controller_client
                .orbis_update_node_peer_id(node_key, peer_address)
                .await
                .expect("update NodeInfo peer ID");
            assert_eq!(
                peer_update.code, 0,
                "update NodeInfo peer ID tx failed: {}",
                peer_update.log
            );
            let whitelist_update = controller_client
                .orbis_add_node_to_whitelist(
                    node_key,
                    WhitelistTarget::RingId(config.ring_id.to_string()),
                )
                .await
                .expect("add ring to NodeInfo whitelist");
            assert_eq!(
                whitelist_update.code, 0,
                "add ring to NodeInfo whitelist tx failed: {}",
                whitelist_update.log
            );
        }

        Self {
            network,
            chain_config,
            controller_client,
            endpoint: node_endpoints[0].clone(),
            node_keys,
            threshold: 2,
            ring_id: config.ring_id.to_string(),
            mode: config.mode,
            node_endpoints,
            store_signer_address: node1_info.public_address,
        }
    }

    async fn start_dkg(&self) -> String {
        println!("Starting DKG for ring {}...", self.ring_id);
        cli_tool::do_dkg(self.endpoint.clone(), self.ring_id.clone())
            .await
            .expect("DKG should succeed")
            .session_id
    }
}

impl pet_dkg_contract::Backend for Cosmos {
    type LocalState = Vec<RingStateSnapshot>;

    fn mode(&self) -> pet_dkg_contract::DkgMode {
        self.mode
    }

    async fn finalized_ring(&self) -> pet_dkg_contract::FinalizedRing {
        let expected = crate::helpers::test_helpers::wait_for_ring_finalized(
            &self.chain_config,
            &self.ring_id,
            Duration::from_secs(240),
        )
        .await;
        let ring = self
            .controller_client
            .orbis_read_ring(&self.ring_id)
            .await
            .expect("read finalized ring")
            .expect("finalized ring should exist");
        assert_eq!(
            ring.ring_pk, expected,
            "finalized main key must match read-back"
        );
        pet_dkg_contract::FinalizedRing {
            requires_pet: ring.requires_pet,
            confirmations: ring.confirmations.len(),
            public_key: ring.ring_pk,
            pet_public_key: ring.pet_pk,
        }
    }

    async fn local_state(&self, keys: &pet_dkg_contract::Keys) -> Self::LocalState {
        let states = wait_for_ring_state_on_all_nodes(
            &self.node_endpoints,
            &keys.main,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        for state in &states {
            pet_dkg_contract::assert_polynomial(&state.public_polynomial, &keys.main);
        }
        states
    }
}

impl pre_scenario::Backend for Cosmos {
    fn node_endpoint(&self) -> String {
        self.endpoint.clone()
    }

    fn ring_id(&self) -> &str {
        &self.ring_id
    }

    fn authorization_chain_id(&self) -> String {
        self.chain_config.chain_id.clone()
    }

    async fn document_policy_id(&self) -> String {
        cli_tool::add_policy_to_chain_with_config(self.chain_config.clone())
            .await
            .expect("create shared PRE document policy")
    }

    async fn authorize_object(
        &self,
        policy_id: &str,
        object_id: &str,
        resource: &str,
        relation: &str,
        actor_did: &str,
    ) {
        cli_tool::register_object_to_chain_with_config(
            policy_id.to_string(),
            object_id.to_string(),
            resource.to_string(),
            self.chain_config.clone(),
        )
        .await
        .expect("register shared PRE document");
        cli_tool::set_relationship_on_chain(
            policy_id.to_string(),
            object_id.to_string(),
            resource.to_string(),
            relation.to_string(),
            actor_did.to_string(),
            self.chain_config.clone(),
            TEST_ACCOUNT_HEX_KEY,
        )
        .await
        .expect("grant shared scenario actor");
    }

    async fn read_document(&self, object_id: &str) -> Vec<u8> {
        cli_tool::read_bulletin_post_with_config(
            object_id.to_string(),
            BulletinKind::Document,
            self.chain_config.clone(),
        )
        .await
        .expect("read shared scenario document")
    }

    async fn store_write_marker(&self) -> pre_scenario::Capability<u64> {
        pre_scenario::Capability::Supported(
            cli_tool::get_account_sequence_with_config(
                &self.store_signer_address,
                self.chain_config.clone(),
            )
            .await
            .expect("read StoreSecret submitting account sequence"),
        )
    }

    async fn post_document_direct(&self, payload: Vec<u8>) -> pre_scenario::Capability<String> {
        pre_scenario::Capability::Supported(
            cli_tool::create_bulletin_post_with_config(
                BulletinWriteKind::Document,
                payload,
                self.chain_config.clone(),
            )
            .await
            .expect("post shared scenario document directly"),
        )
    }
}

impl sign_scenario::Backend for Cosmos {
    async fn post_key_derivation(
        &self,
        policy_id: &str,
        derivation: &str,
        resource: &str,
        permission: &str,
        _ring_pk: &str,
    ) -> (String, String) {
        cli_tool::post_key_derivation_with_config(
            self.ring_id.clone(),
            derivation.to_string(),
            policy_id.to_string(),
            resource.to_string(),
            permission.to_string(),
            self.chain_config.clone(),
        )
        .await
        .expect("post shared Sign key derivation")
    }
}

pub(super) async fn run(
    ring_id: &'static str,
    expected_policy_id: &'static str,
) -> (Cosmos, pet_dkg_contract::Keys, Vec<RingStateSnapshot>) {
    pet_dkg_contract::run::<Cosmos>(Config {
        ring_id,
        expected_policy_id,
        mode: pet_dkg_contract::DkgMode::Pet,
    })
    .await
}
