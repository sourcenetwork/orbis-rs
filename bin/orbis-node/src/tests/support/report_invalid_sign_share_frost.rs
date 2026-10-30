//! Shared integration test: FROST-only variant of the Sign invalid-crypto
//! test (`report_invalid_crypto_response.rs`'s non-interactive-BLS sibling,
//! `#[cfg(not(feature = "jubjub"))]`-gated there). Under jubjub the signing
//! set is exactly threshold-sized and chosen from whichever nonces arrive
//! first, so a corrupted node is only exercised when the nonce race selects
//! it — and when it IS selected, FROST cannot recover the signature (shares
//! are bound to the commitment set), so the sign fails outright instead of
//! succeeding around the bad node like BLS does.
//!
//! The test embraces both properties: it corrupts node2 (the favourite of
//! the sorted, self-preferring selection), fires single store-with-proof
//! attempts until one fails — the failure itself is the signal that node2
//! was selected and its bad share observed — then asserts the invalid-crypto
//! report landed on chain with exactly one demerit. A 3-of-3 ring would make
//! selection deterministic but could never report: the ring must be able to
//! threshold-sign the report envelope without the accused (the chain
//! enforces threshold <= peers - 1 when the accused sits in the signing
//! committee).
//!
//! Corruption/report-detection is the same backend-neutral production code
//! `report_invalid_crypto_response.rs` already proved dual-backend, so this
//! is gated only on the crypto feature (`jubjub`), not on backend.

use super::report_scenario::{
    store_secret_with_retry, wait_for_demerits, STANDARD_RING_POLICY_YAML,
};
use super::{pre_scenario, TestEnvironmentImpl};
use crypto::r#trait::{CryptoDeserialize, Dkg, PriShare};
use crypto::CryptoSerialize;
use crypto::{DkgImpl, ScalarField};
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
};
use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture,
    ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Duration};
use zeroize::Zeroizing;

#[cfg(feature = "integration-test-cosmos")]
use crate::ring_state::RingShareBundle;
#[cfg(feature = "integration-test-native")]
use orbis_node::ring_state::RingShareBundle;

#[tokio::test]
#[serial_test::serial]
async fn test_frost_invalid_sign_share_triggers_on_chain_report() {
    println!("Starting FROST invalid sign-share reporting integration test...");

    let ring = FixtureId::new("ring");
    let policy = FixtureId::new("policy");
    let ring_policy = FixtureId::new("ring-policy");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![
            PolicyFixture {
                id: policy.clone(),
                definition: STANDARD_RING_POLICY_YAML.to_string(),
            },
            PolicyFixture {
                id: ring_policy.clone(),
                definition: STANDARD_RING_POLICY_YAML.to_string(),
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
            pss_interval: Duration::from_secs(86_400),
            requires_pet: false,
            policy: ring_policy.clone(),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let members = environment.fixture().rings[&ring].members.clone();
    let node2_key = members[1].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let node2_endpoint = environment.nodes()[1].grpc_endpoint.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    let resource = "document";
    let permission = "read";
    let did_pk_string = "frost-invalid-sign-report-test-did".to_string();

    let prepared = cli_tool::prepare_secret(
        b"frost-invalid-sign-report-test-secret",
        &keys.main,
        None,
        policy_id.0.clone(),
        resource.to_string(),
        permission.to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    // Baseline: store-with-proof must succeed while all shares are honest.
    // This both proves 3-node FROST signing works and warms every connection
    // so a later single-shot failure can only mean the corrupted share.
    println!("Baseline store-with-proof (all nodes honest)...");
    store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        ring_id.0.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    println!("Baseline store succeeded.");

    // Corrupt node2's stored ring share: bump the secret scalar by one. Node2,
    // not node3: the FROST selection prefers self plus the lowest node IDs, so
    // node2 is the likeliest network pick.
    let ring_pk_bytes = hex::decode(&keys.main).expect("decode ring pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("parse ring pk");
    let storage_key = LocalStorageKey {
        key_type: LocalStorageKeyType::RingKey as i32,
        ring_key: aggregate_pk.to_string(),
    };
    let mut unsafe_client = UnsafeTestingServiceClient::connect(node2_endpoint)
        .await
        .expect("connect unsafe-testing client to node2");
    let stored = unsafe_client
        .get_local_storage(GetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        })
        .await
        .expect("read node2 ring share bundle")
        .into_inner();
    assert!(stored.found, "node2 ring share bundle should exist");
    let bundle = RingShareBundle::from_bytes(&stored.value).expect("parse ring share bundle");
    let pri_share = bundle.pri_share().expect("deserialize node2 share");
    let corrupted_share = PriShare {
        i: pri_share.i,
        v: pri_share.v + ScalarField::from(1u64),
    };
    let corrupted_bundle = RingShareBundle {
        share_bytes: Zeroizing::new(
            CryptoSerialize::to_bytes(&corrupted_share).expect("serialize corrupted share"),
        ),
        public_polynomial: bundle.public_polynomial.clone(),
        last_pss: bundle.last_pss,
    };
    unsafe_client
        .set_local_storage(SetLocalStorageRequest {
            key: Some(storage_key),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
            value: corrupted_bundle.to_bytes().to_vec(),
        })
        .await
        .expect("store corrupted ring share bundle");
    println!("node2 ring share corrupted.");

    // Fire single-shot store attempts. Each attempt runs a fresh FROST round:
    // if the nonce race selects node3, the sign succeeds and nothing is
    // reported; once it selects node2, its bad share is observed (queued for
    // reporting) and the sign fails with InsufficientShares. Break on the
    // first failure so exactly one report is minted (demerits stay at 1).
    let mut sign_failed = false;
    for attempt in 1..=10usize {
        match cli_tool::store_prepared_secret(
            endpoint.clone(),
            &prepared,
            ring_id.0.clone(),
            Some(did_pk_string.clone()),
            true,
            None,
        )
        .await
        {
            Ok(_) => {
                println!(
                    "attempt {attempt}: FROST set skipped corrupted node2 (sign succeeded); retrying..."
                );
                sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                println!("attempt {attempt}: sign failed with corrupted node2 selected: {e}");
                sign_failed = true;
                break;
            }
        }
    }
    assert!(
        sign_failed,
        "corrupted node2 was never selected into the FROST signing set in 10 attempts"
    );

    println!("Waiting for node2's demerits to reflect the invalid-crypto report...");
    let demerits = wait_for_demerits(
        &environment,
        &ring_id,
        &node2_key,
        1,
        Duration::from_secs(120),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "node2 should have exactly 1 demerit: attempts stop at the first failed sign, got {demerits}"
    );
    println!("node2 demerit points: {demerits}");
}
