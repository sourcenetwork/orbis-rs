#[path = "defra_peer_forgery.rs"]
mod forgery;

use defra_core::signing::{self, SigningConfig, SigningKeyType};
use defra_node::{EmbeddedNode, P2PConfig};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub struct Peers {
    source: EmbeddedNode,
    target: EmbeddedNode,
    signer_did: String,
    path: PathBuf,
}

fn config(path: &Path) -> P2PConfig {
    P2PConfig {
        port: 0,
        bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        relay_mode: defra_p2p::iroh::IrohRelayModeConfig::Disabled,
        discovery: defra_p2p::iroh::IrohDiscoveryConfig::Disabled,
        max_concurrent_multipath_paths: None,
        secret_key_path: Some(path.join("p2p.key")),
        load_persisted_collections: true,
        max_concurrent_dag_fetches: defra_p2p::sync::DEFAULT_MAX_CONCURRENT_DAG_FETCHES,
        max_concurrent_push_tasks: defra_p2p::sync::DEFAULT_MAX_CONCURRENT_PUSH_TASKS,
        max_doc_sync_request_doc_ids: defra_p2p::sync::DEFAULT_MAX_DOC_SYNC_REQUEST_DOC_IDS,
        rate_limit_burst: defra_p2p::sync::DEFAULT_RATE_LIMIT_BURST,
        rate_limit_rate: defra_p2p::sync::DEFAULT_RATE_LIMIT_RATE,
        max_pending_dags: defra_p2p::sync::DEFAULT_MAX_PENDING_DAGS,
        rebroadcast_on_merge: false,
    }
}

async fn address(node: &EmbeddedNode) -> String {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(address) = node
                .p2p()
                .unwrap()
                .listen_addresses()
                .await
                .unwrap()
                .first()
            {
                return address.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Defra listen address")
}

impl Peers {
    pub async fn new(path: &Path, signer: Arc<defra_orbis::OrbisClient>) -> Self {
        let signer_did = signer.signer_did().to_owned();
        signing::store_identity(
            &signer_did,
            SigningConfig {
                key_type: SigningKeyType::Bls,
                private_key_bytes: Vec::new(),
                public_key_bytes: signer.public_key_bytes().to_vec(),
                public_key_hex: signer.public_key_hex().to_owned(),
                remote_signer: Some(signer),
                signing_authorization: None,
            },
        );
        let source = EmbeddedNode::builder()
            .data_path(path.join("source"))
            .with_node_identity_did(&signer_did)
            .with_p2p(config(&path.join("source")))
            .build()
            .await
            .unwrap();
        let target = EmbeddedNode::builder()
            .data_path(path.join("target"))
            .with_p2p(config(&path.join("target")))
            .build()
            .await
            .unwrap();
        for node in [&source, &target] {
            node.add_schema("type NetworkSigned { name: String }")
                .await
                .unwrap();
        }
        let source_peer = source.p2p().unwrap();
        let target_peer = target.p2p().unwrap();
        let source_addr = address(&source).await;
        let target_addr = address(&target).await;
        source_peer.connect_peer(&target_addr).await.unwrap();
        for peer in [source_peer, target_peer] {
            tokio::time::timeout(Duration::from_secs(10), async {
                while peer.connected_peers().await.unwrap().is_empty() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("Defra peer connection");
            peer.add_collections(vec!["NetworkSigned".into()])
                .await
                .unwrap();
        }
        target_peer
            .add_replicator(
                vec!["NetworkSigned".into()],
                Some(&source_addr),
                Default::default(),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        source_peer
            .add_replicator(
                vec!["NetworkSigned".into()],
                Some(&target_addr),
                Default::default(),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        Self {
            source,
            target,
            signer_did,
            path: path.to_owned(),
        }
    }

    async fn create(&self, name: &str) -> defra_query::QueryResponse {
        let allowed = defra_core::block::go_verifiable_policy::non_go_verifiable_signing_allowed();
        defra_core::block::go_verifiable_policy::allow_non_go_verifiable_signing(true);
        let response = self
            .source
            .execute(&format!(
                "mutation {{ add_NetworkSigned(input: {{name: {}}}) {{ _docID name }} }}",
                serde_json::to_string(name).unwrap(),
            ))
            .await;
        defra_core::block::go_verifiable_policy::allow_non_go_verifiable_signing(allowed);
        response
    }

    pub async fn verify_replication(&self) {
        self.verify_document("over QUIC", 1).await;
        self.verify_forgery().await;
    }

    pub async fn verify_restart(self) -> Self {
        let Self {
            source,
            target,
            signer_did,
            path,
        } = self;
        target.shutdown().await;
        drop(target);
        let target = EmbeddedNode::builder()
            .data_path(path.join("target"))
            .with_p2p(config(&path.join("target")))
            .build()
            .await
            .unwrap();
        let restored = target.execute("query { NetworkSigned { name } }").await;
        assert!(restored.errors.is_empty(), "{:?}", restored.errors);
        assert_eq!(
            restored.data.unwrap()["NetworkSigned"],
            serde_json::json!([{ "name": "over QUIC" }])
        );
        source
            .p2p()
            .unwrap()
            .connect_peer(&address(&target).await)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while target
                .p2p()
                .unwrap()
                .connected_peers()
                .await
                .unwrap()
                .is_empty()
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("reconnected Defra receiver");
        let peers = Self {
            source,
            target,
            signer_did,
            path,
        };
        peers.verify_document("after restart", 2).await;
        peers
    }

    async fn verify_document(&self, name: &str, count: usize) {
        let created = self.create(name).await;
        assert!(created.errors.is_empty(), "{:?}", created.errors);
        let data = created.data.unwrap();
        let id = data["add_NetworkSigned"][0]["_docID"].as_str().unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let response = self
                    .target
                    .execute("query { NetworkSigned { _docID name } }")
                    .await;
                assert!(response.errors.is_empty(), "{:?}", response.errors);
                let data = response.data.unwrap();
                let docs = data["NetworkSigned"].as_array().unwrap();
                if let Some(doc) = docs.iter().find(|doc| doc["_docID"] == id) {
                    assert_eq!(docs.len(), count);
                    assert_eq!(doc["name"], name);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("signed document replication");
        let history = self
            .target
            .execute(&format!("query {{ _commits(docID: \"{id}\") {{ cid }} }}"))
            .await;
        assert!(history.errors.is_empty(), "{:?}", history.errors);
        let data = history.data.unwrap();
        let commits = data["_commits"].as_array().unwrap();
        assert!(!commits.is_empty());
        for commit in commits {
            assert_eq!(
                self.target
                    .verified_block_signer_did(commit["cid"].as_str().unwrap())
                    .await
                    .unwrap(),
                self.signer_did
            );
        }
    }

    pub async fn verify_revocation(&self) {
        assert!(!self.create("revoked").await.errors.is_empty());
        for node in [&self.source, &self.target] {
            let response = node.execute("query { NetworkSigned { name } }").await;
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            let data = response.data.unwrap();
            let mut names: Vec<_> = data["NetworkSigned"]
                .as_array()
                .unwrap()
                .iter()
                .map(|doc| doc["name"].as_str().unwrap())
                .collect();
            names.sort_unstable();
            assert_eq!(names, ["after restart", "over QUIC"]);
        }
    }

    pub async fn shutdown(&self) {
        self.source.shutdown().await;
        self.target.shutdown().await;
        signing::clear_identity_store();
    }
}
