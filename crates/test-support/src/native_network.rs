//! Native genesis fixtures launched through the shared Compose lifecycle.

use crate::{ContainerNode, NativeImage};
use commonware_codec::Encode;
use std::{fs, net::TcpListener, path::Path, time::Duration};
use vera_client::VeraClient;
use vera_harness::cluster::{
    ConsensusPreset, GenesisBuilder, KeySet, NodeConfigBuilder, ValidatorConfig,
};

pub struct NativeTestNode {
    rpc_url: String,
    _container: ContainerNode,
}
impl NativeTestNode {
    pub fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }
}

pub struct NativeTestNetwork {
    nodes: Vec<NativeTestNode>,
    _root: tempfile::TempDir,
}
impl NativeTestNetwork {
    pub async fn start(deployment: u64) -> Self {
        Self::start_with_genesis(deployment, GenesisBuilder::devnet()).await
    }

    /// Customize only fresh fixture genesis; deployment, validators and normal timers stay shared.
    pub async fn start_with_genesis(deployment: u64, genesis: GenesisBuilder) -> Self {
        let mut directory = tempfile::Builder::new();
        directory.prefix("orbis-native-vera-");
        let mut root = if let Some(parent) = std::env::var_os("VERA_E2E_DIR") {
            fs::create_dir_all(&parent).unwrap();
            directory.tempdir_in(parent).unwrap()
        } else {
            directory.tempdir().unwrap()
        };
        if std::env::var("VERA_E2E_KEEP").is_ok_and(|value| value == "1") {
            root.disable_cleanup(true);
        }
        let root_path = root.path().canonicalize().unwrap();
        let keys = KeySet::builder().nodes(4).seed(deployment).build().unwrap();
        let listeners: Vec<_> = (0..8)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect();
        let dirs: Vec<_> = (0..4)
            .map(|i| root_path.join(format!("vera-{i}")))
            .collect();
        keys.write_to(&dirs).unwrap();
        keys.write_peers(&root_path.join("peers.json"), &ports[..4])
            .unwrap();
        let validators = keys
            .participants()
            .iter()
            .enumerate()
            .map(|(i, key)| ValidatorConfig {
                evm_address: format!("{:?}", vera_node::validator_address(key)),
                consensus_pubkey: hex::encode(key.encode()),
                p2p_address: format!("127.0.0.1:{}", ports[i]),
            })
            .collect();
        let genesis = genesis
            .chain_id(deployment)
            .blocks_per_epoch(192)
            .simplex(Default::default())
            .validators(validators)
            .epoch_info(keys.epoch_info_hex())
            .build();
        let config = NodeConfigBuilder::new()
            .chain_id(deployment)
            .preset(ConsensusPreset::Normal);
        for (i, dir) in dirs.iter().enumerate() {
            fs::write(
                dir.join("genesis.json"),
                serde_json::to_vec(&genesis).unwrap(),
            )
            .unwrap();
            fs::write(
                dir.join("config.toml"),
                config.build_config_toml(dir, ports[i], ports[4 + i]),
            )
            .unwrap();
        }
        let consensus = config.consensus();
        // Containers share the host loopback network, matching the existing fixture.
        drop(listeners);
        let mut nodes = Vec::new();
        for (i, dir) in dirs.iter().enumerate() {
            let args = vec![
                "--config".into(),
                path(dir, "config.toml"),
                "--data-dir".into(),
                dir.display().to_string(),
                "--chain-id".into(),
                deployment.to_string(),
                "validator".into(),
                "--peers".into(),
                path(&root_path, "peers.json"),
                "--rpc-port".into(),
                ports[4 + i].to_string(),
                "--leader-timeout-ms".into(),
                consensus.leader_timeout.as_millis().to_string(),
                "--notarization-timeout-ms".into(),
                consensus.notarization_timeout.as_millis().to_string(),
                "--nullify-retry-ms".into(),
                consensus.nullify_retry.as_millis().to_string(),
            ];
            let container = ContainerNode::start(
                NativeImage::Vera,
                &root_path,
                dir,
                &args,
                &[("RUST_LOG", "info"), ("NO_COLOR", "1")],
                &dir.join("node.log"),
            )
            .unwrap();
            nodes.push(NativeTestNode {
                rpc_url: format!("http://127.0.0.1:{}", ports[4 + i]),
                _container: container,
            });
        }
        let cluster = Self { nodes, _root: root };
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut ready = true;
                for node in &cluster.nodes {
                    assert!(
                        node._container.try_wait_async().await.unwrap().is_none(),
                        "native validator exited"
                    );
                    ready &= VeraClient::new(node.rpc_url())
                        .chain_id()
                        .await
                        .is_ok_and(|id| id == deployment);
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("native validators become RPC-ready");
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut ready = true;
                for node in &cluster.nodes {
                    assert!(
                        node._container.try_wait_async().await.unwrap().is_none(),
                        "native validator exited"
                    );
                    ready &= VeraClient::new(node.rpc_url())
                        .block_number()
                        .await
                        .is_ok_and(|height| height >= 3);
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("native validators reach height 3");
        cluster
    }
    pub fn node(&self, index: usize) -> &NativeTestNode {
        &self.nodes[index]
    }
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
fn path(directory: &Path, file: &str) -> String {
    directory.join(file).display().to_string()
}
