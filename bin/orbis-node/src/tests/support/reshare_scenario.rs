//! Shared committee-reshare continuation contract.

use super::{pre_scenario, sign_scenario, TestEnvironmentImpl};
use test_support::admin::RingId;
use test_support::fixture::{BulletinTestDriver, NetworkTestDriver};
use tokio::time::{sleep, Duration, Instant};

const RESHARE_THRESHOLD: u32 = 2;

pub(super) async fn run(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    keys: &pre_scenario::Keys,
    pre: &pre_scenario::Outcome,
    sign: &sign_scenario::Outcome,
) {
    let certified_before = environment
        .read_ring(ring)
        .await
        .expect("ring must exist before shared reshare");
    assert!(
        !certified_before.pending_reshare,
        "shared reshare must start from a settled ring"
    );

    let remaining = &environment.nodes()[..2];
    let mut target: Vec<String> = remaining.iter().map(|node| node.node_key.clone()).collect();
    target.sort();

    let baselines =
        pre_scenario::wait_for_polynomials(remaining, &keys.main, None, Duration::from_secs(60))
            .await;

    environment
        .update_membership(ring, target.clone(), RESHARE_THRESHOLD)
        .await;

    let certified_after =
        wait_for_reshare_completion(environment, ring, &target, RESHARE_THRESHOLD).await;
    assert_eq!(
        certified_after.ring_pk, certified_before.ring_pk,
        "reshare must not change the ring public key"
    );
    assert_eq!(
        certified_after.requires_pet, certified_before.requires_pet,
        "reshare must not change requires_pet"
    );
    assert_eq!(
        certified_after.pet_pk, certified_before.pet_pk,
        "reshare must not change the PET key"
    );
    let mut certified_target = certified_after.peer_node_keys.clone();
    certified_target.sort();
    assert_eq!(
        certified_target, target,
        "reshare must settle on the announced committee"
    );
    assert_eq!(certified_after.threshold, RESHARE_THRESHOLD);

    let reshared = pre_scenario::wait_for_polynomials(
        remaining,
        &keys.main,
        Some(&baselines),
        Duration::from_secs(120),
    )
    .await;
    for state in &reshared {
        pre_scenario::assert_polynomial(state, &keys.main);
    }

    pre_scenario::verify_existing(environment, keys, pre).await;
    sign_scenario::verify_existing(environment, keys, sign).await;
}

async fn wait_for_reshare_completion(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    target: &[String],
    threshold: u32,
) -> test_support::admin::RingView {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(view) = environment.read_ring(ring).await {
            let mut members = view.peer_node_keys.clone();
            members.sort();
            if !view.pending_reshare && members == target && view.threshold == threshold {
                return view;
            }
        }
        assert!(
            Instant::now() < deadline,
            "reshare did not complete before the shared scenario deadline"
        );
        sleep(Duration::from_millis(200)).await;
    }
}
