use super::*;
use defra_core::block::{Block, CrdtDelta};
use defra_p2p::{
    iroh::{IrohEndpointConfig, IrohTransport, parse_public_peer_addr, spawn_endpoint},
    message::PushLogRequest,
    transport::P2PTransport,
};

impl Peers {
    pub(super) async fn verify_forgery(&self) {
        let docs = self
            .source
            .execute("query { NetworkSigned { _docID } }")
            .await;
        assert!(docs.errors.is_empty());
        let data = docs.data.unwrap();
        let id = data["NetworkSigned"][0]["_docID"].as_str().unwrap();
        let history = self
            .source
            .execute(&format!("query {{ _commits(docID: \"{id}\") {{ cid }} }}"))
            .await;
        assert!(history.errors.is_empty());
        let mut forged = None;
        for commit in history.data.unwrap()["_commits"].as_array().unwrap() {
            let (bytes, _) = self
                .source
                .authorized_signed_block_bytes(commit["cid"].as_str().unwrap(), None)
                .await
                .unwrap();
            let mut block = Block::from_dag_cbor(&bytes).unwrap();
            if let CrdtDelta::Composite(delta) = &mut block.delta {
                delta.status = 2;
                forged = Some(block);
                break;
            }
        }
        let forged = forged.expect("signed composite commit");
        let cid = forged.generate_cid().unwrap();
        let doc_id = defra_document::DocID::new_v0(cid).to_string();
        let collection_id = self
            .source
            .get_collection("NetworkSigned")
            .unwrap()
            .unwrap()
            .collection_id;
        let config = IrohEndpointConfig {
            relay_mode: defra_p2p::iroh::IrohRelayModeConfig::Disabled,
            discovery: defra_p2p::iroh::IrohDiscoveryConfig::Disabled,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..Default::default()
        };
        let key = config.secret_key.clone();
        let (commands, _events, _replicators, task) = spawn_endpoint(config).await.unwrap();
        let attacker = IrohTransport::new(commands, key);
        let (peer, addresses) = parse_public_peer_addr(&address(&self.target).await).unwrap();
        attacker.dial(&peer, addresses).await.unwrap();
        attacker
            .poll_until_connected(&peer, Duration::from_secs(10))
            .await
            .unwrap();
        let attacker_addr = defra_p2p::iroh::best_shareable_public_addr(
            attacker.local_peer_id(),
            &attacker.listen_addresses().await.unwrap(),
        )
        .unwrap();
        self.target
            .p2p()
            .unwrap()
            .add_replicator(
                vec!["NetworkSigned".into()],
                Some(&attacker_addr),
                Default::default(),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        let before = self.target.p2p().unwrap().sync_status().await.unwrap();
        let quarantined = before["pending_dag_terminal_quarantined"].as_u64().unwrap();
        let request = PushLogRequest::new(
            doc_id.clone(),
            cid.to_bytes().into(),
            collection_id,
            self.signer_did.clone(),
            forged.to_dag_cbor().unwrap().into(),
        );
        let reply = tokio::time::timeout(
            Duration::from_secs(10),
            attacker.send_two_stream_request(&peer, request),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(reply.err_message.is_none(), "{:?}", reply.err_message);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = self.target.p2p().unwrap().sync_status().await.unwrap();
                if status["pending_dag_terminal_quarantined"].as_u64().unwrap() > quarantined {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("forged root rejected after network ingestion");
        let error = self
            .target
            .verified_block_signer_did(&cid.to_string())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("signature verification"),
            "{error}"
        );
        let response = self
            .target
            .execute("query { NetworkSigned { _docID name } }")
            .await;
        assert!(response.errors.is_empty());
        let data = response.data.unwrap();
        assert_eq!(data["NetworkSigned"].as_array().unwrap().len(), 1);
        assert_eq!(data["NetworkSigned"][0]["_docID"], id);
        assert_eq!(data["NetworkSigned"][0]["name"], "over QUIC");
        attacker.shutdown().await.unwrap();
        task.await.unwrap();
    }
}
