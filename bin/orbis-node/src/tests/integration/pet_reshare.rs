use super::{sorted_peer_ids, RingStateSnapshot};
use bulletin::r#trait::{BulletinKind, RingPayload};
use common::blockchain::ChainConfig;
use sha2::{Digest, Sha256};
use tokio::time::{sleep_until, timeout_at, Duration, Instant};

// Info snapshots expose polynomials, not ceremony IDs. A timestamp can advance
// on an independent refresh while other members still hold different shares.
#[allow(clippy::too_many_arguments)]
pub(super) async fn wait_for_pet_reshare(
    chain_config: &ChainConfig,
    endpoints: &[String],
    ring_id: &str,
    expected: &RingPayload,
    main_baselines: &[RingStateSnapshot],
    pet_baselines: &[RingStateSnapshot],
    timeout: Duration,
    poll_interval: Duration,
) -> Vec<RingStateSnapshot> {
    assert!(!endpoints.is_empty(), "reshare requires surviving members");
    assert_eq!(endpoints.len(), expected.peer_node_keys.len());
    assert_eq!(endpoints.len(), main_baselines.len());
    assert_eq!(endpoints.len(), pet_baselines.len());
    assert!(expected.requires_pet && expected.pet_pk.is_some());
    assert!(expected.new_peer_node_keys.is_none() && expected.new_threshold.is_none());

    let deadline = Instant::now() + timeout;
    let mut next_status_log = Instant::now() + Duration::from_secs(15);
    let mut last_status = "no observation completed".to_string();
    loop {
        let observation = async {
            let payload = cli_tool::read_bulletin_post_with_config(
                ring_id.to_string(),
                BulletinKind::Ring,
                chain_config.clone(),
            )
            .await
            .map_err(|error| format!("bulletin read: {error}"))?;
            let payload: RingPayload = serde_json::from_slice(&payload)
                .map_err(|error| format!("bulletin decode: {error}"))?;
            let committee_matches = same_finalized_committee(&payload, expected);
            let mut states = Vec::with_capacity(endpoints.len());
            let mut status = format!(
                "committee_matches={committee_matches} members={} threshold={} pending={}",
                payload.peer_node_keys.len(),
                payload.threshold,
                payload.new_peer_node_keys.is_some() || payload.new_threshold.is_some(),
            );
            for (index, endpoint) in endpoints.iter().enumerate() {
                let (main, pet) = tokio::try_join!(
                    cli_tool::query_ring_state(endpoint.clone(), expected.ring_pk.clone()),
                    cli_tool::query_pet_ring_state(endpoint.clone(), ring_id.to_string()),
                )
                .map_err(|error| format!("node{} state: {error}", index + 1))?;
                status.push_str(&format!(
                    "; node{} main={}@{} pet={}@{}",
                    index + 1,
                    fingerprint(&main.0),
                    main.1,
                    fingerprint(&pet.0),
                    pet.1,
                ));
                states.push((
                    RingStateSnapshot {
                        public_polynomial: main.0,
                        last_pss: main.1,
                    },
                    RingStateSnapshot {
                        public_polynomial: pet.0,
                        last_pss: pet.1,
                    },
                ));
            }
            Ok::<_, String>((committee_matches, states, status))
        };
        match timeout_at(deadline, observation).await {
            Ok(Ok((committee_matches, states, status))) => {
                last_status = status;
                if committee_matches
                    && polynomials_converged(&states, main_baselines, pet_baselines)
                {
                    println!("PET reshare state converged: {last_status}");
                    return states.into_iter().map(|(_, pet)| pet).collect();
                }
            }
            Ok(Err(error)) => last_status = error.chars().take(240).collect(),
            Err(_) => panic!(
                "PET reshare state did not converge within {}s; last observation: {}",
                timeout.as_secs(),
                last_status,
            ),
        }
        let now = Instant::now();
        assert!(
            now < deadline,
            "PET reshare state did not converge within {}s; last observation: {}",
            timeout.as_secs(),
            last_status,
        );
        if now >= next_status_log {
            println!("Still waiting for PET reshare state: {last_status}");
            next_status_log = now + Duration::from_secs(15);
        }
        sleep_until((now + poll_interval).min(deadline)).await;
    }
}

fn same_finalized_committee(current: &RingPayload, expected: &RingPayload) -> bool {
    current.ring_pk == expected.ring_pk
        && current.pet_pk == expected.pet_pk
        && current.requires_pet
        && current.threshold == expected.threshold
        && sorted_peer_ids(&current.peer_node_keys) == sorted_peer_ids(&expected.peer_node_keys)
        && current.new_peer_node_keys.is_none()
        && current.new_threshold.is_none()
}

fn polynomials_converged(
    states: &[(RingStateSnapshot, RingStateSnapshot)],
    main_baselines: &[RingStateSnapshot],
    pet_baselines: &[RingStateSnapshot],
) -> bool {
    let Some((main, pet)) = states.first() else {
        return false;
    };
    states.len() == main_baselines.len()
        && states.len() == pet_baselines.len()
        && !main.public_polynomial.is_empty()
        && !pet.public_polynomial.is_empty()
        && states
            .iter()
            .enumerate()
            .all(|(index, (current_main, current_pet))| {
                current_main.public_polynomial == main.public_polynomial
                    && current_pet.public_polynomial == pet.public_polynomial
                    && current_main.public_polynomial != main_baselines[index].public_polynomial
                    && current_pet.public_polynomial != pet_baselines[index].public_polynomial
            })
}

fn fingerprint(polynomial: &str) -> String {
    hex::encode(&Sha256::digest(polynomial.as_bytes())[..8])
}

#[test]
fn convergence_rejects_timestamp_only_and_mixed_generations() {
    let state = |poly: &str, time| RingStateSnapshot {
        public_polynomial: poly.to_string(),
        last_pss: time,
    };
    let main = [state("main-old", 10), state("main-old", 10)];
    let pet = [state("pet-old", 10), state("pet-old", 10)];
    let mut current = vec![
        (state("main-old", 30), state("pet-old", 30)),
        (state("main-old", 31), state("pet-old", 31)),
    ];
    assert!(!polynomials_converged(&current, &main, &pet));
    current[0] = (state("main-new", 30), state("pet-new", 30));
    current[1] = (state("main-new", 31), state("pet-other", 31));
    assert!(!polynomials_converged(&current, &main, &pet));
    current[1].1 = state("pet-new", 31);
    assert!(polynomials_converged(&current, &main, &pet));
    current[1].0 = state("main-other", 31);
    assert!(!polynomials_converged(&current, &main, &pet));
    assert!(!polynomials_converged(&current[..1], &main, &pet));
    current[0].0.public_polynomial.clear();
    current[1].0.public_polynomial.clear();
    assert!(!polynomials_converged(&current, &main, &pet));
}

#[test]
fn convergence_requires_the_exact_finalized_committee() {
    let expected = RingPayload {
        ring_pk: "main-key".into(),
        pet_pk: Some("pet-key".into()),
        requires_pet: true,
        peer_node_keys: vec!["node1".into(), "node2".into()],
        threshold: 2,
        ..RingPayload::default()
    };
    let mut current = expected.clone();
    current.peer_node_keys.reverse();
    assert!(same_finalized_committee(&current, &expected));
    current.peer_node_keys[0] = "node3".into();
    assert!(!same_finalized_committee(&current, &expected));
    current = expected.clone();
    current.new_threshold = Some(2);
    assert!(!same_finalized_committee(&current, &expected));
    current = expected.clone();
    current.threshold = 1;
    assert!(!same_finalized_committee(&current, &expected));
}
