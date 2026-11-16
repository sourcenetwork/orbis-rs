//! A share refresh that is already due still completes after every member
//! restarts.
//!
//! The fixture interval is short enough that a backend which honors it finds
//! the refresh due on the scheduler's next tick. `arm_refresh_for_next_start`
//! covers a backend that cannot persist an interval that short: it records
//! the due state while the members are stopped, and the restarted processes
//! perform the refresh. The certified ring stays the same, and PRE and
//! signing still succeed on the new shares.

use super::{pre_scenario, refresh_scenario, sign_scenario, standard_dkg_pre, TestEnvironmentImpl};
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep_until, timeout_at, Instant};

#[tokio::test]
#[serial_test::serial]
async fn test_due_refresh_completes_after_restart() {
    let ring = FixtureId::new("ring");
    let ring_policy = FixtureId::new("ring-policy");
    let document_policy = FixtureId::new("document-policy");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![
            PolicyFixture {
                id: document_policy.clone(),
                definition: standard_dkg_pre::POLICY_YAML.to_string(),
            },
            PolicyFixture {
                id: ring_policy.clone(),
                definition: standard_dkg_pre::POLICY_YAML.to_string(),
            },
        ],
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            // Short enough to be due immediately on a backend that stores
            // this value. The arming step below handles a backend that
            // raises it to the production minimum.
            pss_interval: Duration::from_secs(5),
            requires_pet: false,
            policy: ring_policy,
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let policy_id = environment.fixture().policies[&document_policy].id.clone();
    let (keys, baselines, pre) = pre_scenario::run(&environment, &ring_id, &policy_id).await;
    let sign = sign_scenario::run(&environment, &ring_id, &keys, &policy_id).await;
    let before = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must exist before the scheduled refresh");
    assert_eq!(baselines.len(), environment.nodes().len());

    for index in 0..environment.nodes().len() {
        environment.stop_node(index).await;
    }
    environment
        .arm_refresh_for_next_start(&ring_id, &keys.main, &before.peer_node_keys)
        .await;
    let restarted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let endpoints = environment.restart_nodes().await;
    assert_eq!(endpoints.len(), baselines.len());

    let refreshed =
        wait_for_refresh_after_restart(&endpoints, &keys.main, &baselines, restarted_at).await;
    for state in &refreshed {
        pre_scenario::assert_polynomial(state, &keys.main);
    }

    let after = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must remain present after the scheduled refresh");
    refresh_scenario::assert_unchanged(&before, &after, "scheduled refresh after restart");

    pre_scenario::verify_existing_at(&environment, &endpoints[0], &keys, &pre).await;
    sign_scenario::verify_existing_at(&environment, &endpoints[0], &keys, &sign).await;
}

async fn wait_for_refresh_after_restart(
    endpoints: &[String],
    ring_pk: &str,
    baselines: &[String],
    restarted_at: u64,
) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(500);
    let mut observations: Vec<RefreshObservation> = endpoints
        .iter()
        .map(|_| RefreshObservation::default())
        .collect();
    loop {
        let mut states = Vec::with_capacity(endpoints.len());
        let mut ready = true;
        for (endpoint, observation) in endpoints.iter().zip(&mut observations) {
            match ring_state(endpoint, ring_pk, deadline).await {
                Ok(state) => {
                    observation.last_state = Some(state.clone());
                    observation.last_error = None;
                    if state.0.is_empty() {
                        ready = false;
                    } else {
                        states.push(state);
                    }
                }
                Err(error) => {
                    observation.last_error = Some(error);
                    observation.rpc_failures += 1;
                    ready = false;
                }
            }
        }
        if ready
            && states.len() == baselines.len()
            && states.iter().all(|state| state.0 == states[0].0)
            && states
                .iter()
                .zip(baselines)
                .all(|(state, baseline)| state.0 != *baseline && state.1 >= restarted_at)
        {
            return states
                .into_iter()
                .map(|(polynomial, _)| polynomial)
                .collect();
        }
        assert!(
            Instant::now() < deadline,
            "scheduled refresh did not complete on the restarted members; restarted_at={restarted_at}\n{}",
            refresh_diagnostics(endpoints, &observations, baselines, restarted_at)
        );
        sleep_until(deadline.min(Instant::now() + Duration::from_millis(200))).await;
    }
}

#[derive(Default)]
struct RefreshObservation {
    last_state: Option<(String, u64)>,
    last_error: Option<String>,
    rpc_failures: usize,
}

fn refresh_diagnostics(
    endpoints: &[String],
    observations: &[RefreshObservation],
    baselines: &[String],
    restarted_at: u64,
) -> String {
    let first_polynomial = observations
        .first()
        .and_then(|observation| observation.last_state.as_ref())
        .map(|state| &state.0);
    endpoints
        .iter()
        .zip(observations)
        .zip(baselines)
        .enumerate()
        .map(|(index, ((endpoint, observation), baseline))| {
            let state = match &observation.last_state {
                Some((polynomial, last_pss)) => format!(
                    "last_pss={last_pss} after_restart={} changed_from_baseline={} polynomial_sha256={} baseline_sha256={} agrees_with_node_1={:?}",
                    *last_pss >= restarted_at,
                    polynomial != baseline,
                    hex::encode(Sha256::digest(polynomial.as_bytes())),
                    hex::encode(Sha256::digest(baseline.as_bytes())),
                    first_polynomial.map(|first| first == polynomial),
                ),
                None => "no successful GetRingState response".to_string(),
            };
            format!(
                "node={} endpoint={endpoint} last_observed_state=[{state}] rpc_failures={} latest_poll_error={:?}",
                index + 1,
                observation.rpc_failures,
                observation.last_error,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn ring_state(
    endpoint: &str,
    ring_pk: &str,
    deadline: Instant,
) -> Result<(String, u64), String> {
    // Bound connection and RPC together, including when the overall poll budget expires.
    let request_deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    timeout_at(request_deadline, async {
        let mut client = InfoServiceClient::connect(endpoint.to_string())
            .await
            .map_err(|error| format!("connect: {error}"))?;
        let state = client
            .get_ring_state(GetRingStateRequest {
                ring_pk_hex: ring_pk.to_string(),
            })
            .await
            .map_err(|error| format!("GetRingState: {error}"))?
            .into_inner();
        Ok((state.public_polynomial, state.last_pss))
    })
    .await
    .map_err(|_| "connect/GetRingState exceeded its 5s or remaining test budget".to_string())?
}
