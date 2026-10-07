use super::{pet_dkg_contract, wait_for_ring_state_on_all_nodes, RingStateSnapshot};
use common::blockchain::{ChainConfig, VeraClient};
use std::time::Duration;

struct Cosmos<'a> {
    config: &'a ChainConfig,
    client: &'a VeraClient,
    ring_id: &'a str,
    endpoints: &'a [String],
}

impl pet_dkg_contract::Backend for Cosmos<'_> {
    type LocalState = Vec<RingStateSnapshot>;

    async fn finalized_ring(&self) -> pet_dkg_contract::FinalizedRing {
        let expected = crate::helpers::test_helpers::wait_for_ring_finalized(
            self.config,
            self.ring_id,
            Duration::from_secs(240),
        )
        .await;
        let ring = self
            .client
            .orbis_read_ring(self.ring_id)
            .await
            .expect("read finalized ring")
            .expect("finalized ring should exist");
        assert_eq!(
            ring.ring_pk, expected,
            "finalized main key must match read-back"
        );
        pet_dkg_contract::FinalizedRing {
            requires_pet: ring.requires_pet,
            confirmations: ring.confirmations.len(),
            public_key: ring.ring_pk,
            pet_public_key: ring.pet_pk,
        }
    }

    async fn local_state(&self, keys: &pet_dkg_contract::Keys) -> Self::LocalState {
        let states = wait_for_ring_state_on_all_nodes(
            self.endpoints,
            &keys.main,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        for state in &states {
            pet_dkg_contract::assert_polynomial(&state.public_polynomial, &keys.main);
        }
        states
    }
}

pub(super) async fn verify(
    config: &ChainConfig,
    client: &VeraClient,
    ring_id: &str,
    endpoints: &[String],
) -> pet_dkg_contract::Keys {
    pet_dkg_contract::verify(&Cosmos {
        config,
        client,
        ring_id,
        endpoints,
    })
    .await
    .0
}
