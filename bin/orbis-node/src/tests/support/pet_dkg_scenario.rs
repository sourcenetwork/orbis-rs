//! Shared PET (checking-key) paired-DKG trigger/finalize/verify scenario.
//!
//! Cosmos's half of the bare paired-DKG slice (`cosmos_dkg`) and the
//! foundation `test_cli_calls_dkg_for_pet_ring`/
//! `test_pet_ring_refresh_and_reshare` build on top of. Native's equivalent
//! (`native_dkg`, plus `native_pet`'s `Scenario` family via
//! `native_pet::dkg::run`) is a separate, non-generic implementation —
//! `pet_dkg_contract.rs`, the generic trait family both backends used to
//! share, is gone now that neither side needs it. Deliberately
//! self-contained (no `use super::pre_scenario`) rather than reusing
//! `pre_scenario::assert_polynomial`: on native, `pre_scenario` is gated
//! behind `unsafe-testing`, but `native_dkg` (this file's native consumer)
//! isn't and shouldn't become so.

use super::TestEnvironmentImpl;
use crypto::r#trait::{CryptoDeserialize, Dkg, PubPoly};
use crypto::{DkgImpl, GroupAffine};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetPetRingStateRequest, GetRingStateRequest,
};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use test_support::admin::RingId;
use test_support::fixture::{BulletinTestDriver, NetworkTestDriver};
use tokio::time::Duration;

pub(super) struct Keys {
    pub main: String,
    pub pet: String,
}

/// Trigger paired DKG on `ring`, wait for both the main and PET keys to
/// finalize together, and return them plus every running node's local
/// `(main, pet)` polynomial commitment pair.
pub(super) async fn run_dkg(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
) -> (Keys, Vec<(String, String)>) {
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let session_id = DkgServiceClient::connect(endpoint)
        .await
        .expect("connect to node for PET DKG trigger")
        .start_dkg(StartDkgRequest {
            ring_id: ring.0.clone(),
        })
        .await
        .expect("paired DKG should succeed")
        .into_inner()
        .session_id;
    assert!(
        !session_id.is_empty(),
        "paired DKG must return a session id"
    );

    let view = environment
        .wait_for_finalized(ring, Duration::from_secs(240))
        .await;
    assert_eq!(
        view.confirmations, 0,
        "finalized confirmations must be cleared"
    );
    assert!(
        view.requires_pet,
        "the shared PET DKG scenario uses a requires_pet ring"
    );
    let main = view.ring_pk;
    let pet = view.pet_pk.expect("paired DKG must finalize the PET key");
    assert!(!main.is_empty(), "paired DKG must finalize the main key");
    assert!(!pet.is_empty(), "paired DKG must finalize the PET key");
    assert_ne!(main, pet, "PET and main keys must be independent");
    for key in [&main, &pet] {
        let bytes = hex::decode(key).expect("finalized key must be hex");
        let point =
            GroupAffine::from_bytes(&bytes).expect("finalized key must be a valid curve point");
        assert_ne!(
            point,
            GroupAffine::default(),
            "finalized key must not be identity"
        );
    }

    let local_state = wait_for_pet_polynomials(
        environment.nodes(),
        &main,
        &ring.0,
        None,
        Duration::from_secs(60),
    )
    .await;
    for (main_state, pet_state) in &local_state {
        assert_polynomial(main_state, &main);
        assert_polynomial(pet_state, &pet);
    }
    (Keys { main, pet }, local_state)
}

/// Poll every node in `nodes`'s `InfoService.GetRingState` (main) and
/// `GetPetRingState` (PET) until all of them agree on the same, non-empty
/// pair of polynomial commitments — and, when `previous` is given, until
/// *both* have changed from it. Same `InfoService` contract on both
/// backends. A deliberate strengthening versus the pre-migration adapters:
/// Cosmos's old `Cosmos::local_state` checked only the main polynomial;
/// native's `Native::local_state` already checked both — this raises
/// Cosmos to native's existing, stronger bar.
pub(super) async fn wait_for_pet_polynomials(
    nodes: &[test_support::NodeInfo],
    ring_pk: &str,
    ring_id: &str,
    previous: Option<&[(String, String)]>,
    timeout: Duration,
) -> Vec<(String, String)> {
    if let Some(previous) = previous {
        assert_eq!(previous.len(), nodes.len());
    }
    tokio::time::timeout(timeout, async {
        loop {
            let mut states = Vec::with_capacity(nodes.len());
            for node in nodes {
                let Ok(mut client) = InfoServiceClient::connect(node.grpc_endpoint.clone()).await
                else {
                    break;
                };
                let main = match client
                    .get_ring_state(GetRingStateRequest {
                        ring_pk_hex: ring_pk.to_string(),
                    })
                    .await
                {
                    Ok(state) => state.into_inner().public_polynomial,
                    Err(_) => break,
                };
                let pet = match client
                    .get_pet_ring_state(GetPetRingStateRequest {
                        ring_id: ring_id.to_string(),
                    })
                    .await
                {
                    Ok(state) => state.into_inner().public_polynomial,
                    Err(_) => break,
                };
                states.push((main, pet));
            }
            if states.len() == nodes.len()
                && !states[0].0.is_empty()
                && !states[0].1.is_empty()
                && states.iter().all(|state| state == &states[0])
                && previous.is_none_or(|old| {
                    states
                        .iter()
                        .zip(old)
                        .all(|(now, old)| now.0 != old.0 && now.1 != old.1)
                })
            {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("all members must hold the same main and PET polynomial generation")
}

fn assert_polynomial(encoded: &str, key: &str) {
    let bytes = hex::decode(encoded).expect("local polynomial must be hex");
    let polynomial = <DkgImpl as Dkg>::PubPoly::from_bytes(&bytes)
        .expect("local polynomial must decode on the selected curve");
    let key = GroupAffine::from_bytes(&hex::decode(key).expect("finalized key must be hex"))
        .expect("finalized key must decode on the selected curve");
    assert_eq!(
        polynomial.eval(0),
        key,
        "local polynomial must commit to the finalized key"
    );
}
