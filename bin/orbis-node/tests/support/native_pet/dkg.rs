use super::{pet_dkg_contract, read_ring, wait_polynomials, Polynomials};
use std::time::Duration;
use vera_client::{
    rings::{RingPublicKeys, RingState},
    VeraClient,
};
use vera_domain::ConsensusPublicKey;

struct Native<'a> {
    client: &'a VeraClient,
    trusted: &'a ConsensusPublicKey,
    ring_id: &'a str,
    addresses: &'a [String],
}

impl pet_dkg_contract::Backend for Native<'_> {
    type LocalState = Vec<Polynomials>;

    async fn finalized_ring(&self) -> pet_dkg_contract::FinalizedRing {
        let record = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let Some(record) = read_ring(self.client, self.trusted, self.ring_id).await else {
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
        let states = wait_polynomials(
            self.addresses,
            self.ring_id,
            &RingPublicKeys {
                public_key: keys.main.clone(),
                pet_public_key: Some(keys.pet.clone()),
            },
            None,
        )
        .await;
        for state in &states {
            pet_dkg_contract::assert_polynomial(&state.main, &keys.main);
            pet_dkg_contract::assert_polynomial(&state.pet, &keys.pet);
        }
        states
    }
}

pub(super) async fn verify(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    ring_id: &str,
    addresses: &[String],
) -> (RingPublicKeys, Vec<Polynomials>) {
    let (keys, baseline) = pet_dkg_contract::verify(&Native {
        client,
        trusted,
        ring_id,
        addresses,
    })
    .await;
    (
        RingPublicKeys {
            public_key: keys.main,
            pet_public_key: Some(keys.pet),
        },
        baseline,
    )
}
