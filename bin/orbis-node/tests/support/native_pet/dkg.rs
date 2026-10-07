use super::{endpoint, pet_dkg_contract, pre_scenario, read_ring, wait_polynomials, Polynomials};
use alloy_primitives::B256;
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use std::time::Duration;
use vera_client::rings::{RingPublicKeys, RingState};

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

    async fn authorize_reader(&self, policy_id: &str, object_id: &str, reader_did: &str) {
        assert_eq!(
            policy_id, self.workflow.policy,
            "shared PRE must use the workflow's policy"
        );
        let policy =
            B256::from_slice(&hex::decode(policy_id).expect("native policy id must be hex"));
        let registered = self
            .workflow
            .client
            .native_register_object(&self.workflow.worker, policy, object_id, "document")
            .await
            .expect("register shared PRE document");
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
                policy,
                "document",
                object_id,
                "reader",
                reader_did,
            )
            .await
            .expect("grant shared PRE reader");
        super::super::confirmed(
            &self.workflow.client,
            granted.transaction_hash,
            &self.workflow.trusted,
        )
        .await;
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

pub(super) async fn run_pre(deployment: u64) -> String {
    let (_native, keys, _local_state, outcome) =
        pre_scenario::run::<Native>((deployment, false, pet_dkg_contract::DkgMode::Standard)).await;
    assert!(
        keys.pet.is_none(),
        "standard DKG must not produce a PET key"
    );
    outcome.object_id
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
