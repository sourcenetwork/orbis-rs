use super::{endpoint, unix_now, Delivery, Document, Node, PreChecks};
use crypto::r#trait::CryptoDeserialize;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoResponse, GetPetRingStateRequest,
};
use std::{path::Path, time::Duration};
use vera_client::{
    rings::{RingPublicKeys, RingState},
    threshold_objects::ObjectKind,
    VeraClient,
};
use vera_domain::ConsensusPublicKey;

use super::stored_bundle as store;

pub(super) struct ScheduledRefresh<'a> {
    pub client: &'a VeraClient,
    pub trusted: &'a ConsensusPublicKey,
    pub ring_id: &'a str,
    pub keys: &'a RingPublicKeys,
    pub base: &'a Path,
    pub addresses: &'a [String],
    pub infos: &'a [GetNodeInfoResponse],
    pub controller: &'a str,
}

impl ScheduledRefresh<'_> {
    pub async fn run(
        &self,
        nodes: &mut [Node],
        checks: &PreChecks<'_>,
        documents: [(&Document, Delivery); 2],
    ) {
        assert_eq!(nodes.len(), 3);
        assert_eq!(self.addresses.len(), 3);
        assert_eq!(self.infos.len(), 3);
        let initial = self
            .client
            .read_threshold_ring(self.ring_id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(initial.config.pss_interval, 86_400);
        assert_eq!(initial.current_settings().threshold, 2);
        assert!(initial.current_settings().pending_reshare.is_none());
        assert_eq!(
            initial.state,
            RingState::Active {
                keys: self.keys.clone()
            }
        );
        for node in nodes.iter_mut() {
            node.stop().await;
        }
        let main_key =
            crypto::GroupAffine::from_bytes(&hex::decode(&self.keys.public_key).unwrap())
                .unwrap()
                .to_string();
        let pet_key = self.keys.pet_public_key.as_ref().unwrap();
        let members = &initial.current_settings().peer_node_keys;
        assert_eq!(members.len(), 3);
        let mut before = Vec::new();
        for (index, info) in self.infos.iter().enumerate() {
            let directory = self.base.join(format!("node-{index}"));
            let storage = store::open(&directory);
            let member = members
                .iter()
                .position(|key| key == &info.node_key)
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
                pet_key,
                member,
            );
            assert!(main.last_pss > 0 && main.last_pss <= unix_now());
            assert!(
                unix_now().saturating_sub(main.last_pss) + 10 < 86_400,
                "main refresh must not be due"
            );
            assert!(pet.last_pss > 0 && pet.last_pss <= unix_now());
            let index_bytes = storage.get(LocalStorageKeys::RingIndex).unwrap().unwrap();
            pet.make_due(&storage, self.ring_id);
            assert!(
                storage
                    .get_encrypted(LocalStorageKeys::RingKey(main_key.clone()))
                    .unwrap()
                    .unwrap()
                    == main.bytes,
                "backdating changed main bundle"
            );
            assert!(
                storage.get(LocalStorageKeys::RingIndex).unwrap().unwrap() == index_bytes,
                "backdating changed ring index"
            );
            before.push((main, pet, index_bytes, member));
        }
        // All store handles have closed before any native process restarts.
        let restarted_at = unix_now();
        for (index, node) in nodes.iter_mut().enumerate() {
            let directory = self.base.join(format!("node-{index}"));
            let log = directory.join("scheduled-pet-refresh.log");
            let bind = self.infos[index].p2p_address.split_once('@').unwrap().1;
            *node = Node::start_bound(
                &directory,
                &self.addresses[index],
                self.controller,
                &log,
                bind,
            );
        }
        for (index, node) in nodes.iter_mut().enumerate() {
            let log = self
                .base
                .join(format!("node-{index}/scheduled-pet-refresh.log"));
            let recovered = node.ready(&self.addresses[index], &log).await;
            assert_eq!(recovered.node_key, self.infos[index].node_key);
            assert_eq!(recovered.p2p_address, self.infos[index].p2p_address);
            assert_eq!(recovered.managed_ring_count, 1);
        }
        let observed = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let mut states = Vec::new();
                for address in self.addresses {
                    let response = InfoServiceClient::connect(endpoint(address))
                        .await
                        .unwrap()
                        .get_pet_ring_state(GetPetRingStateRequest {
                            ring_id: self.ring_id.into(),
                        })
                        .await
                        .unwrap()
                        .into_inner();
                    states.push(response);
                }
                if states.iter().zip(&before).all(|(state, (_, old, _, _))| {
                    state.last_pss >= restarted_at && state.public_polynomial != old.polynomial
                }) && states
                    .iter()
                    .all(|state| state.public_polynomial == states[0].public_polynomial)
                {
                    break states;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("restarted native schedulers must independently refresh PET within 60 seconds");
        let current = self
            .client
            .read_threshold_ring(self.ring_id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(
            current, initial,
            "PET refresh changed certified ring configuration or keys"
        );
        for (document, delivery) in documents {
            checks.decrypt(document, delivery).await;
        }
        let (stored, _) = documents[0];
        let found = self
            .client
            .read_threshold_object(ObjectKind::Document, &stored.id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(
            found.object, stored.object,
            "PET refresh changed stored document or tag"
        );
        assert!(self
            .client
            .read_threshold_object(ObjectKind::Document, &documents[1].0.id, 1, self.trusted)
            .await
            .unwrap()
            .record
            .is_none());
        for node in nodes.iter_mut() {
            node.stop().await;
        }
        for (index, (old_main, old_pet, index_bytes, member)) in before.iter().enumerate() {
            let storage = store::open(&self.base.join(format!("node-{index}")));
            let main = store::Bundle::load(
                &storage,
                LocalStorageKeys::RingKey(main_key.clone()),
                &self.keys.public_key,
                *member,
            );
            let pet = store::Bundle::load(
                &storage,
                LocalStorageKeys::PetRingKey(self.ring_id.into()),
                pet_key,
                *member,
            );
            assert!(
                main.bytes == old_main.bytes,
                "scheduled PET refresh changed main bundle"
            );
            assert!(
                storage.get(LocalStorageKeys::RingIndex).unwrap().unwrap() == *index_bytes,
                "scheduled PET refresh changed ring index"
            );
            assert!(
                pet.share() != old_pet.share(),
                "scheduled refresh retained old PET share"
            );
            assert_eq!(pet.polynomial, observed[index].public_polynomial);
            assert_eq!(pet.last_pss, observed[index].last_pss);
            assert!(pet.last_pss >= restarted_at && pet.last_pss <= unix_now());
        }
        eprintln!("native PET phase=scheduled-refresh-after-restart members=3 ring_interval_secs=86400 fixture_poll_secs=1 pet_rotated=true main_unchanged=true");
    }
}
