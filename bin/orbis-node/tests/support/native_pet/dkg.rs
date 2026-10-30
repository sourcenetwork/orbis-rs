//! Native's paired-DKG trigger/finalize/verify step for the `native_pet`
//! scenario family — provisions a `NativeWorkflow` (always with
//! `requires_pet: true`; no scenario here ever requests a standard ring),
//! triggers DKG, and waits for both the main and PET polynomials to settle
//! on every node. Parallel to, but independent of, Cosmos's
//! `pet_dkg_scenario.rs` — downstream `Scenario` variants in `native_pet.rs`
//! consume the returned `NativeWorkflow` directly, not a `test-support`
//! fixture, so there's no shared code to reuse across backends here.

use super::{endpoint, read_ring, wait_polynomials, Polynomials};
use crypto::r#trait::{Dkg, PubPoly};
use crypto::{CryptoDeserialize, DkgImpl, GroupAffine};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use std::time::Duration;
use vera_client::rings::{RingPublicKeys, RingState};

pub(super) async fn run(
    deployment: u64,
    report_fault: bool,
) -> (
    super::super::native_workflow::NativeWorkflow,
    RingPublicKeys,
    Vec<Polynomials>,
) {
    let workflow =
        super::super::native_workflow::NativeWorkflow::start(deployment, true, report_fault).await;

    let session_id = DkgServiceClient::connect(endpoint(&workflow.addresses[0]))
        .await
        .unwrap()
        .start_dkg(StartDkgRequest {
            ring_id: workflow.ring_id.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .session_id;
    assert!(!session_id.is_empty(), "DKG must return a session id");

    let record = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let Some(record) =
                read_ring(&workflow.client, &workflow.trusted, &workflow.ring_id).await
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
    assert!(
        record.config.requires_pet,
        "finalized ring must retain its configured DKG mode"
    );
    let RingState::Active { keys } = record.state else {
        unreachable!()
    };
    assert!(
        !keys.public_key.is_empty(),
        "DKG must finalize the main key"
    );
    let pet_key = keys
        .pet_public_key
        .clone()
        .expect("paired DKG must finalize the PET key");
    assert!(!pet_key.is_empty(), "paired DKG must finalize the PET key");
    assert_ne!(
        keys.public_key, pet_key,
        "PET and main keys must be independent"
    );
    for key in [&keys.public_key, &pet_key] {
        let bytes = hex::decode(key).expect("finalized key must be hex");
        let point =
            GroupAffine::from_bytes(&bytes).expect("finalized key must be a valid curve point");
        assert_ne!(
            point,
            GroupAffine::default(),
            "finalized key must not be identity"
        );
    }

    let baseline = wait_polynomials(&workflow.addresses, &workflow.ring_id, &keys, None).await;
    for state in &baseline {
        assert_polynomial(&state.main, &keys.public_key);
        assert_polynomial(&state.pet, &pet_key);
    }

    (workflow, keys, baseline)
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
