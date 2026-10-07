use super::{
    endpoint, pet_dkg_contract, pre_scenario, read_ring, sign_scenario, wait_polynomials,
    Polynomials,
};
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, ThresholdSigner};
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use std::time::Duration;
use vera_client::{
    create_scoped_bearer_token,
    rings::{RingPublicKeys, RingState},
    threshold_objects::{encode_threshold_object, KeyDerivation, ObjectKind, ThresholdObject},
    DelegationScope,
};

struct Native {
    workflow: super::super::native_workflow::NativeWorkflow,
    mode: pet_dkg_contract::DkgMode,
}

impl pet_dkg_contract::Backend for Native {
    type LocalState = Vec<Polynomials>;

    fn mode(&self) -> pet_dkg_contract::DkgMode {
        self.mode
    }

    async fn finalized_ring(&self) -> pet_dkg_contract::FinalizedRing {
        let record = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let Some(record) = read_ring(
                    &self.workflow.client,
                    &self.workflow.trusted,
                    &self.workflow.ring_id,
                )
                .await
                else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                match record.state {
                    RingState::Active { .. } => break record,
                    RingState::Pending { .. } => (),
                    state => panic!("paired DKG terminated: {state:?}"),
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("paired DKG must finalize within the native deadline");
        let RingState::Active { keys } = record.state else {
            unreachable!()
        };
        pet_dkg_contract::FinalizedRing {
            requires_pet: record.config.requires_pet,
            // Active stores the certified pair; confirmations exist only in Pending.
            confirmations: 0,
            public_key: keys.public_key,
            pet_public_key: keys.pet_public_key,
        }
    }

    async fn local_state(&self, keys: &pet_dkg_contract::Keys) -> Self::LocalState {
        let states = if keys.pet.is_some() {
            wait_polynomials(
                &self.workflow.addresses,
                &self.workflow.ring_id,
                &RingPublicKeys {
                    public_key: keys.main.clone(),
                    pet_public_key: keys.pet.clone(),
                },
                None,
            )
            .await
        } else {
            wait_main_polynomials(&self.workflow.addresses, &keys.main).await
        };
        for state in &states {
            pet_dkg_contract::assert_polynomial(&state.main, &keys.main);
            if let Some(pet) = &keys.pet {
                pet_dkg_contract::assert_polynomial(&state.pet, pet);
            }
        }
        states
    }
}

impl pet_dkg_contract::ScenarioBackend for Native {
    type Config = (u64, bool, pet_dkg_contract::DkgMode);

    async fn provision((deployment, report_fault, mode): Self::Config) -> Self {
        Self {
            workflow: super::super::native_workflow::NativeWorkflow::start(
                deployment,
                mode.requires_pet(),
                report_fault,
            )
            .await,
            mode,
        }
    }

    async fn start_dkg(&self) -> String {
        DkgServiceClient::connect(endpoint(&self.workflow.addresses[0]))
            .await
            .unwrap()
            .start_dkg(StartDkgRequest {
                ring_id: self.workflow.ring_id.clone(),
            })
            .await
            .unwrap()
            .into_inner()
            .session_id
    }
}

impl pre_scenario::Backend for Native {
    fn node_endpoint(&self) -> String {
        format!("http://{}", self.workflow.addresses[0])
    }

    fn ring_id(&self) -> &str {
        &self.workflow.ring_id
    }

    fn authorization_chain_id(&self) -> String {
        vera_client::rings::ring_deployment_label(self.workflow.root.0, self.workflow.deployment)
    }

    async fn document_policy_id(&self) -> String {
        self.workflow.policy.clone()
    }

    async fn authorize_object(
        &self,
        policy_id: &str,
        object_id: &str,
        resource: &str,
        relation: &str,
        actor_did: &str,
    ) {
        assert_eq!(
            policy_id, self.workflow.policy,
            "shared scenario must use the workflow's policy"
        );
        let registered = self
            .workflow
            .client
            .native_register_object(
                &self.workflow.worker,
                self.workflow.policy_bytes,
                object_id,
                resource,
            )
            .await
            .expect("register shared scenario object");
        super::super::confirmed(
            &self.workflow.client,
            registered.transaction_hash,
            &self.workflow.trusted,
        )
        .await;
        let granted = self
            .workflow
            .client
            .native_set_relationship(
                &self.workflow.worker,
                self.workflow.policy_bytes,
                resource,
                object_id,
                relation,
                actor_did,
            )
            .await
            .expect("grant shared scenario actor");
        super::super::confirmed(
            &self.workflow.client,
            granted.transaction_hash,
            &self.workflow.trusted,
        )
        .await;
    }

    async fn read_document(&self, object_id: &str) -> Vec<u8> {
        let record = self
            .workflow
            .client
            .read_threshold_object(ObjectKind::Document, object_id, 1, &self.workflow.trusted)
            .await
            .expect("read shared scenario native document")
            .record
            .expect("shared scenario native document must exist");
        let ThresholdObject::Document(document) = record.object else {
            panic!("document lookup returned a key derivation")
        };
        serde_json::to_vec(&document).expect("serialize authoritative native document")
    }
}

impl sign_scenario::Backend for Native {
    async fn post_key_derivation(
        &self,
        policy_id: &str,
        derivation: &str,
        resource: &str,
        permission: &str,
        ring_pk: &str,
    ) -> (String, String) {
        assert_eq!(
            policy_id, self.workflow.policy,
            "shared Sign must use the workflow's policy"
        );
        let derivation = KeyDerivation {
            ring_id: self.workflow.ring_id.clone(),
            derivation: derivation.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        };
        let object = ThresholdObject::KeyDerivation(derivation.clone());
        let derivation_id = object.id().expect("derive native key-derivation id");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let token = create_scoped_bearer_token(
            &self.workflow.controller,
            self.workflow.worker.did(),
            self.workflow.deployment,
            now,
            now + 300,
            DelegationScope::StoreThresholdObject,
        )
        .expect("create native key-derivation delegation");
        super::super::submit(
            &self.workflow.client,
            &self.workflow.worker,
            &self.workflow.trusted,
            encode_threshold_object(&object, &token).expect("encode native key derivation"),
            "store shared Sign key derivation",
            &self.workflow.cluster,
        )
        .await;

        let ring_pk =
            crypto::GroupAffine::from_bytes(&hex::decode(ring_pk).expect("ring public key is hex"))
                .expect("ring public key must decode");
        let metadata = crypto::SignImpl::encode_metadata(policy_id, resource, permission);
        let derived_pk = crypto::SignImpl::derive_public_key(
            &ring_pk,
            derivation.derivation.as_bytes(),
            Some(&metadata),
        )
        .expect("derive shared Sign public key");
        (
            derivation_id,
            hex::encode(derived_pk.to_bytes().expect("serialize derived public key")),
        )
    }
}

pub(super) async fn run(
    deployment: u64,
    report_fault: bool,
) -> (
    super::super::native_workflow::NativeWorkflow,
    RingPublicKeys,
    Vec<Polynomials>,
) {
    let (native, keys, baseline) =
        pet_dkg_contract::run::<Native>((deployment, report_fault, pet_dkg_contract::DkgMode::Pet))
            .await;
    (
        native.workflow,
        RingPublicKeys {
            public_key: keys.main,
            pet_public_key: keys.pet,
        },
        baseline,
    )
}

pub(super) async fn run_pre(deployment: u64) -> (String, String) {
    let (native, keys, _local_state, outcome) =
        pre_scenario::run::<Native>((deployment, false, pet_dkg_contract::DkgMode::Standard)).await;
    assert!(
        keys.pet.is_none(),
        "standard DKG must not produce a PET key"
    );
    let sign = sign_scenario::run(&native, &keys, &outcome.policy_id).await;
    (outcome.object_id, sign.derivation_id)
}

async fn wait_main_polynomials(addresses: &[String], ring_pk: &str) -> Vec<Polynomials> {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let mut states = Vec::new();
            for address in addresses {
                let mut client = InfoServiceClient::connect(endpoint(address)).await.unwrap();
                match client
                    .get_ring_state(GetRingStateRequest {
                        ring_pk_hex: ring_pk.to_string(),
                    })
                    .await
                {
                    Ok(state) => states.push(Polynomials {
                        main: state.into_inner().public_polynomial,
                        pet: String::new(),
                    }),
                    Err(_) => break,
                }
            }
            if states.len() == addresses.len()
                && !states[0].main.is_empty()
                && states.iter().all(|state| state.main == states[0].main)
            {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("all members must hold the same main polynomial generation")
}
