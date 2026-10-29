use super::{endpoint, pet_dkg_contract, read_ring, wait_polynomials, Polynomials};
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
            wait_main_polynomials(&self.workflow.addresses, &keys.main, None).await
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
        // The shared standard-ring scenario uses the diagnostic local-storage
        // API to make an otherwise 24-hour native refresh due without
        // restarting nodes or changing production ring validation.
        let enable_unsafe_testing = report_fault || mode == pet_dkg_contract::DkgMode::Standard;
        Self {
            workflow: super::super::native_workflow::NativeWorkflow::start(
                deployment,
                mode.requires_pet(),
                enable_unsafe_testing,
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

async fn wait_main_polynomials(
    addresses: &[String],
    ring_pk: &str,
    previous: Option<&[Polynomials]>,
) -> Vec<Polynomials> {
    if let Some(previous) = previous {
        assert_eq!(previous.len(), addresses.len());
    }
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
                && previous.is_none_or(|old| {
                    states
                        .iter()
                        .zip(old)
                        .all(|(now, old)| now.main != old.main)
                })
            {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("all members must hold the same main polynomial generation")
}
