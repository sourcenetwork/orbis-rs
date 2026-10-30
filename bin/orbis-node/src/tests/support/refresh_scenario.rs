//! Shared PSS-refresh continuation contract.
//!
//! Each backend differs only in *how* it makes a refresh become due during a
//! test (`TestEnvironment::force_refresh_due`); the externally-visible
//! promise checked here is common: the certified ring record doesn't
//! change, every running node's local polynomial commitment rotates away
//! from its pre-refresh baseline, and objects/derivations created before
//! refresh keep working afterward.

use super::{pre_scenario, sign_scenario, TestEnvironmentImpl};
use test_support::admin::{RingId, RingView};
use test_support::fixture::{BulletinTestDriver, NetworkTestDriver};
use tokio::time::Duration;

pub(super) async fn run(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    keys: &pre_scenario::Keys,
    baseline: &[String],
    pre: &pre_scenario::Outcome,
    sign: &sign_scenario::Outcome,
) {
    let certified_before = environment
        .read_ring(ring)
        .await
        .expect("ring must exist before shared refresh");

    environment
        .force_refresh_due(ring, &keys.main, &certified_before.peer_node_keys)
        .await;

    let refreshed = pre_scenario::wait_for_polynomials(
        environment.nodes(),
        &keys.main,
        Some(baseline),
        Duration::from_secs(300),
    )
    .await;
    for state in &refreshed {
        pre_scenario::assert_polynomial(state, &keys.main);
    }

    let certified_after = environment
        .read_ring(ring)
        .await
        .expect("ring must remain present after shared refresh");
    assert_unchanged(&certified_before, &certified_after, "PSS refresh");

    pre_scenario::verify_existing(environment, keys, pre).await;
    sign_scenario::verify_existing(environment, keys, sign).await;
}

fn assert_unchanged(before: &RingView, after: &RingView, context: &str) {
    assert_eq!(
        before.ring_pk, after.ring_pk,
        "{context} must not change the ring public key"
    );
    let mut before_members = before.peer_node_keys.clone();
    before_members.sort();
    let mut after_members = after.peer_node_keys.clone();
    after_members.sort();
    assert_eq!(
        before_members, after_members,
        "{context} must not change ring membership"
    );
    assert_eq!(
        before.threshold, after.threshold,
        "{context} must not change the ring threshold"
    );
    assert_eq!(
        before.requires_pet, after.requires_pet,
        "{context} must not change requires_pet"
    );
    assert_eq!(
        before.pet_pk, after.pet_pk,
        "{context} must not change the PET key"
    );
}
