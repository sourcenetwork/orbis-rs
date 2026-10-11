use super::{
    endpoint, member_replacement::MemberReplacement, stored_bundle as store, wait_polynomials,
    Delivery, Document, Node, Permissions, Polynomials, PreChecks, Reader,
};
use local_storage::r#trait::LocalStorageKeys;
use proto::info_service::GetNodeInfoResponse;

pub(super) struct Committee {
    pub infos: Vec<GetNodeInfoResponse>,
    pub polynomials: Vec<Polynomials>,
}

impl MemberReplacement<'_> {
    pub(super) async fn run_churn(
        &self,
        nodes: &mut Vec<Node>,
        reader: &Reader,
        audit: &str,
        documents: [(&Document, Delivery); 2],
        baseline: &[Polynomials],
    ) {
        let Committee {
            infos,
            mut polynomials,
        } = self.run(nodes, reader, audit, documents, baseline).await;
        assert_eq!(nodes.len(), 4);
        assert_eq!(infos.len(), 4);
        std::fs::write(
            self.base.join("diagnostic-peer-routes.json"),
            serde_json::to_vec(&infos.iter().map(|info| &info.peer_id).collect::<Vec<_>>())
                .unwrap(),
        )
        .unwrap();
        let mut addresses = vec![String::new(); 4];
        let mut changes = 1;
        let mut crash_restarts = 2;
        for round in 1..=4 {
            eprintln!("native PET phase=churn-round-start round={round}");
            let departed = round % 4;
            let incoming = (round - 1) % 4;
            self.assert_departed_store(incoming);
            let all = [0, 1, 2, 3];
            self.restart_churn_nodes(nodes, &mut addresses, &infos, &all, round)
                .await;
            self.wait_departed_cleanup(&addresses[incoming]).await;
            let members: Vec<_> = all.into_iter().filter(|index| *index != departed).collect();
            let mut target: Vec<_> = members
                .iter()
                .map(|index| infos[*index].node_key.clone())
                .collect();
            target.sort();
            assert!(target.contains(&infos[incoming].node_key));
            assert!(!target.contains(&infos[departed].node_key));
            let finalized = self.reshare(target.clone()).await;
            eprintln!("native PET phase=churn-finalized round={round}");
            let next_addresses: Vec<_> = members
                .iter()
                .map(|index| addresses[*index].clone())
                .collect();
            let previous = vec![polynomials[0].clone(); 3];
            let next =
                wait_polynomials(&next_addresses, self.ring_id, self.keys, Some(&previous)).await;
            self.wait_departed_cleanup(&addresses[departed]).await;
            nodes[departed].stop().await;
            self.assert_departed_store(departed);

            // Exactly two current members remain, so the rejoining member's share is required.
            let idle = *members.iter().find(|index| **index != incoming).unwrap();
            nodes[idle].stop().await;
            let participants: Vec<_> = members
                .iter()
                .copied()
                .filter(|index| *index != idle)
                .collect();
            assert_eq!(participants.len(), 2);
            assert!(participants.contains(&incoming));
            for index in &all {
                assert_eq!(
                    nodes[*index].0.try_wait().unwrap().is_none(),
                    participants.contains(index)
                );
            }
            self.check_churn_access(
                &addresses,
                &participants,
                reader,
                audit,
                documents,
                round as u64 * 100,
            )
            .await;
            for index in &participants {
                nodes[*index].0.kill().unwrap();
                assert!(!nodes[*index].0.wait().unwrap().success());
            }
            self.restart_churn_nodes(nodes, &mut addresses, &infos, &participants, round)
                .await;
            crash_restarts += participants.len();
            let restored_addresses: Vec<_> = participants
                .iter()
                .map(|index| addresses[*index].clone())
                .collect();
            let restored =
                wait_polynomials(&restored_addresses, self.ring_id, self.keys, None).await;
            for (index, material) in participants.iter().zip(&restored) {
                let position = members.iter().position(|member| member == index).unwrap();
                assert_eq!(material, &next[position]);
            }
            self.assert_certified_state(&finalized, documents).await;
            self.check_churn_access(
                &addresses,
                &participants,
                reader,
                audit,
                documents,
                round as u64 * 100 + 10,
            )
            .await;
            let permission = Permissions {
                client: self.client,
                worker: self.worker,
                trusted: self.trusted,
                policy: self.policy_bytes,
                reader: &reader.signer.did_uri,
            };
            permission.set(&self.signing.id, false).await;
            for index in &participants {
                self.signing
                    .denied(&addresses[*index], reader, round as u64 * 100 + 20)
                    .await;
            }
            permission.set(&self.signing.id, true).await;
            for index in &participants {
                self.signing
                    .verify(&addresses[*index], reader, round as u64 * 100 + 30)
                    .await;
                nodes[*index].stop().await;
            }
            for (position, index) in members.iter().enumerate() {
                let storage = store::open(&self.base.join(format!("node-{index}")));
                let member = target
                    .iter()
                    .position(|key| key == &infos[*index].node_key)
                    .unwrap() as u32
                    + 1;
                let main = store::Bundle::load(
                    &storage,
                    LocalStorageKeys::RingKey(self.main_storage_key()),
                    &self.keys.public_key,
                    member,
                );
                let pet = store::Bundle::load(
                    &storage,
                    LocalStorageKeys::PetRingKey(self.ring_id.into()),
                    self.keys.pet_public_key.as_ref().unwrap(),
                    member,
                );
                assert_eq!(main.polynomial, next[position].main);
                assert_eq!(pet.polynomial, next[position].pet);
            }
            self.assert_departed_store(departed);
            polynomials = next;
            changes += 1;
            eprintln!("native PET phase=member-churn round={round} incoming-required=true departed-secrets-absent=true");
        }
        assert_eq!(changes, 5);
        assert_eq!(crash_restarts, 10);
        eprintln!(
            "native_threshold_churn={}",
            serde_json::json!({
                "changes": changes, "reentries": changes - 1, "crash_restarts": crash_restarts,
            })
        );
    }

    async fn restart_churn_nodes(
        &self,
        nodes: &mut [Node],
        addresses: &mut [String],
        infos: &[GetNodeInfoResponse],
        selected: &[usize],
        round: usize,
    ) {
        for index in selected {
            let log = self.base.join(format!("node-{index}/churn-{round}.log"));
            nodes[*index] = Node::restart(self.cluster.project_name(), *index, &log);
            addresses[*index] = nodes[*index].endpoint();
        }
        for index in selected {
            let log = self.base.join(format!("node-{index}/churn-{round}.log"));
            let recovered = nodes[*index].ready(&addresses[*index], &log).await;
            let expected = &infos[*index];
            assert_eq!(recovered.node_key, expected.node_key);
            assert_eq!(recovered.peer_id, expected.peer_id);
            assert_eq!(recovered.p2p_address, expected.p2p_address);
            assert_eq!(recovered.public_address, expected.public_address);
        }
    }

    async fn check_churn_access(
        &self,
        addresses: &[String],
        participants: &[usize],
        reader: &Reader,
        audit: &str,
        documents: [(&Document, Delivery); 2],
        message: u64,
    ) {
        // A new recipient key prevents an earlier committee's PRE result satisfying this phase.
        let recipient = Reader::new(vera_client::rings::ring_deployment_label(
            *self.deployment_root,
            self.deployment,
        ));
        assert_eq!(recipient.signer.did_uri, reader.signer.did_uri);
        for index in participants {
            let checks = PreChecks::new(endpoint(&addresses[*index]), &recipient, Some(audit));
            for (document, delivery) in documents {
                checks.decrypt(document, delivery).await;
            }
            eprintln!("native_churn_sign member={index} cycle={message}");
            self.signing
                .verify(&addresses[*index], reader, message)
                .await;
        }
    }
}
