use super::{
    add_orbis_node4, endpoint, read_ring, stored_bundle as store, submit, unix_now,
    wait_polynomials, Delivery, Document, Node, Polynomials, PreChecks, Reader,
};
use crypto::r#trait::CryptoDeserialize;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoRequest, GetNodeInfoResponse,
    GetPetRingStateRequest, GetRingStateRequest,
};
use std::{path::Path, time::Duration};
use test_support::NativeTestNetwork as TestCluster;
use vera_client::{
    create_scoped_bearer_token,
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
    rings::{encode_ring_command, RingCommand, RingPublicKeys, RingRecord, RingState, RingUpdate},
    threshold_objects::ObjectKind,
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;

pub(super) struct MemberReplacement<'a> {
    pub cluster: &'a TestCluster,
    pub client: &'a VeraClient,
    pub trusted: &'a ConsensusPublicKey,
    pub deployment: u64,
    pub deployment_root: &'a [u8; 32],
    pub controller: &'a k256::ecdsa::SigningKey,
    pub worker: &'a BlsSigner,
    pub policy: &'a str,
    pub ring_id: &'a str,
    pub keys: &'a RingPublicKeys,
    pub base: &'a Path,
    pub addresses: &'a [String],
    pub infos: &'a [GetNodeInfoResponse],
}

impl MemberReplacement<'_> {
    pub async fn run(
        &self,
        nodes: &mut Vec<Node>,
        reader: &Reader,
        audit: &str,
        documents: [(&Document, Delivery); 2],
        baseline: &[Polynomials],
    ) {
        assert_eq!(nodes.len(), 3);
        let (incoming, address, info) = self.incoming().await;
        assert!(self.infos.iter().all(|old| old.node_key != info.node_key));
        let mut addresses = self.addresses.to_vec();
        addresses.push(address);
        let mut infos = self.infos.to_vec();
        infos.push(info);
        nodes.push(incoming);
        let mut target: Vec<_> = infos[1..]
            .iter()
            .map(|info| info.node_key.clone())
            .collect();
        target.sort();
        assert_eq!(target.len(), 3);
        assert!(!target.contains(&infos[0].node_key));
        let finalized = self.reshare(target.clone()).await;
        let previous = vec![baseline[0].clone(); 3];
        let reshared =
            wait_polynomials(&addresses[1..], self.ring_id, self.keys, Some(&previous)).await;

        // Keep the departed process alive until its normal scheduler removes both bundles.
        // Public PRE/sign RPCs allow external coordinators, so blanket RPC rejection would
        // not establish exclusion from the current share committee.
        self.wait_departed_cleanup(&addresses[0]).await;
        nodes[0].stop().await;
        self.assert_departed_store();
        nodes[1].stop().await;
        assert!(nodes[0].0.try_wait().unwrap().is_some());
        assert!(nodes[1].0.try_wait().unwrap().is_some());
        // Only old member 2 and fresh member 3 remain: threshold 2 requires the new share.
        let checks = PreChecks::new(endpoint(&addresses[3]), reader, Some(audit));
        for (document, delivery) in documents {
            checks.decrypt(document, delivery).await;
        }
        for node in &mut nodes[2..] {
            assert!(node.0.try_wait().unwrap().is_none());
            node.0.kill().unwrap();
            assert!(!node.0.wait().unwrap().success());
        }
        // Spawn both threshold participants before waiting on readiness.
        for (index, node) in nodes.iter_mut().enumerate().take(4).skip(2) {
            let log = self
                .base
                .join(format!("node-{index}/pet-replacement-restart.log"));
            *node = Node::restart(self.cluster.project_name(), index, &log);
        }
        for index in 2..4 {
            let log = self
                .base
                .join(format!("node-{index}/pet-replacement-restart.log"));
            let recovered = nodes[index].ready(&addresses[index], &log).await;
            assert_eq!(recovered.node_key, infos[index].node_key);
            assert_eq!(recovered.p2p_address, infos[index].p2p_address);
            assert_eq!(recovered.managed_ring_count, 1);
        }
        assert_eq!(
            wait_polynomials(&addresses[2..], self.ring_id, self.keys, None).await,
            reshared[1..],
        );
        self.assert_certified_state(&finalized, documents).await;
        for (document, delivery) in documents {
            checks.decrypt(document, delivery).await;
        }
        for node in &mut nodes[2..] {
            node.stop().await;
        }
        // Check canonical persisted shares, including their new sorted committee indices.
        // The helper keeps secret bytes in zeroizing buffers and never prints them.
        let main_key = self.main_storage_key();
        for index in 1..4 {
            let storage = store::open(&self.base.join(format!("node-{index}")));
            let member = target
                .iter()
                .position(|key| key == &infos[index].node_key)
                .unwrap() as u32
                + 1;
            let main = store::Bundle::load(
                &storage,
                LocalStorageKeys::RingKey(main_key.clone()),
                &self.keys.public_key,
                member,
            );
            let pet = store::Bundle::load(
                &storage,
                LocalStorageKeys::PetRingKey(self.ring_id.into()),
                self.keys.pet_public_key.as_ref().unwrap(),
                member,
            );
            assert_eq!(main.polynomial, reshared[index - 1].main);
            assert_eq!(pet.polynomial, reshared[index - 1].pet);
        }
        self.assert_departed_store();
        eprintln!("native PET phase=member-replacement-restart incoming-required=true paired-keys-stable=true departed-secrets-absent=true");
    }

    async fn incoming(&self) -> (Node, String, GetNodeInfoResponse) {
        let (mut incoming, address) = add_orbis_node4(self.cluster, self.base);
        let log = self.base.join("node-3/node.log");
        let info = incoming.ready(&address, &log).await;
        assert_eq!(info.managed_ring_count, 0);
        for command in [
            NodeCommand::SetPeer(info.p2p_address.clone()),
            NodeCommand::Allow(NodeTarget::Policy(self.policy.into())),
        ] {
            let current = self
                .client
                .read_threshold_node(&info.node_key, 1, self.trusted)
                .await
                .unwrap()
                .record
                .unwrap();
            let signed = sign_node_request(
                NodeRequest {
                    deployment_root: *self.deployment_root,
                    deployment_id: self.deployment,
                    node_key: info.node_key.clone(),
                    sequence: current.sequence,
                    expires_at: unix_now() + 300,
                    command,
                },
                self.controller,
            )
            .unwrap();
            submit(
                self.client,
                self.worker,
                self.trusted,
                encode_node_request(&signed).unwrap(),
                "authorize incoming PET member",
                self.cluster,
            )
            .await;
        }
        (incoming, address, info)
    }

    async fn reshare(&self, target: Vec<String>) -> RingRecord {
        let previous = self
            .client
            .read_threshold_ring(self.ring_id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(previous.current_settings().threshold, 2);
        assert!(previous.current_settings().pending_reshare.is_none());
        let now = unix_now();
        let token = create_scoped_bearer_token(
            self.controller,
            self.worker.did(),
            self.deployment,
            now,
            now + 300,
            DelegationScope::ManageRings,
        )
        .unwrap();
        submit(
            self.client,
            self.worker,
            self.trusted,
            encode_ring_command(
                &RingCommand::Update {
                    ring_id: self.ring_id.into(),
                    expected_sequence: previous.sequence,
                    update: RingUpdate::StartReshare {
                        peer_node_keys: Some(target.clone()),
                        threshold: Some(2),
                    },
                },
                &token,
            )
            .unwrap(),
            "replace PET member",
            self.cluster,
        )
        .await;
        tokio::time::timeout(Duration::from_secs(75), async {
            loop {
                if let Some(current) = read_ring(self.client, self.trusted, self.ring_id).await {
                    assert!(current.config.requires_pet);
                    assert_eq!(
                        current.state,
                        RingState::Active {
                            keys: self.keys.clone()
                        }
                    );
                    let settings = current.current_settings();
                    if settings.peer_node_keys == target && settings.pending_reshare.is_none() {
                        assert_eq!(settings.threshold, 2);
                        assert_eq!(current.sequence, previous.sequence + 2);
                        return current;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("native PET member replacement must finalize")
    }

    async fn wait_departed_cleanup(&self, address: &str) {
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut client = InfoServiceClient::connect(endpoint(address)).await.unwrap();
            loop {
                let info = client
                    .get_node_info(GetNodeInfoRequest {})
                    .await
                    .unwrap()
                    .into_inner();
                let main = client
                    .get_ring_state(GetRingStateRequest {
                        ring_pk_hex: self.keys.public_key.clone(),
                    })
                    .await;
                let pet = client
                    .get_pet_ring_state(GetPetRingStateRequest {
                        ring_id: self.ring_id.into(),
                    })
                    .await;
                let missing = |result: Result<(), tonic::Status>| match result {
                    Ok(()) => false,
                    Err(status) => {
                        assert_eq!(status.code(), tonic::Code::NotFound);
                        true
                    }
                };
                let main_absent = missing(main.map(|_| ()));
                let pet_absent = missing(pet.map(|_| ()));
                if info.managed_ring_count == 0 && main_absent && pet_absent {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("departed native scheduler must clean paired material and index");
    }

    fn main_storage_key(&self) -> String {
        crypto::GroupAffine::from_bytes(&hex::decode(&self.keys.public_key).unwrap())
            .unwrap()
            .to_string()
    }

    fn assert_departed_store(&self) {
        let storage = store::open(&self.base.join("node-0"));
        let main_key = self.main_storage_key();
        for key in [
            LocalStorageKeys::RingKey(main_key.clone()),
            LocalStorageKeys::PetRingKey(self.ring_id.into()),
            LocalStorageKeys::PendingReshareBundle(main_key),
            LocalStorageKeys::PendingResharePetBundle(self.ring_id.into()),
        ] {
            assert!(
                !storage.contains(key).unwrap(),
                "departed secret or pending record remains"
            );
        }
        if let Some(bytes) = storage.get(LocalStorageKeys::RingIndex).unwrap() {
            assert!(bytes.len() <= 65_536, "fixture ring index exceeds bound");
            let entries: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
            assert!(entries.is_empty(), "departed ring index remains");
        }
    }

    async fn assert_certified_state(
        &self,
        finalized: &RingRecord,
        documents: [(&Document, Delivery); 2],
    ) {
        let current = self
            .client
            .read_threshold_ring(self.ring_id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(&current, finalized, "restart changed certified paired ring");
        let stored = self
            .client
            .read_threshold_object(ObjectKind::Document, &documents[0].0.id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(stored.object, documents[0].0.object);
        assert!(self
            .client
            .read_threshold_object(ObjectKind::Document, &documents[1].0.id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .is_none());
    }
}
