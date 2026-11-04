//! Shared integration test: FROST-only variant of the Sign invalid-crypto
//! test (`report_invalid_crypto_response.rs`'s non-interactive-BLS sibling,
//! `#[cfg(not(feature = "jubjub"))]`-gated there). Under jubjub the signing
//! set is exactly threshold-sized: the coordinator keeps itself, then fills
//! from the lowest canonical ids among the nonces in hand. When the
//! corrupted partner is in that set, FROST cannot recover the signature
//! (shares are bound to the commitment set), so the sign fails outright
//! instead of succeeding around the bad node like BLS does.
//!
//! The partner is the other member with the smaller key. Canonical id is
//! that key's rank, not the fixture index, so on native it is not always
//! node 1. The test corrupts that share, then fires single
//! store-with-proof attempts until one fails — the failure itself is the
//! signal that the partner was selected and its bad share observed — then
//! asserts the invalid-crypto report landed on chain with exactly one
//! demerit. A retry covers a nonce that has not arrived yet; once every
//! nonce is in hand the choice does not change between attempts. A 3-of-3
//! ring would make selection include every member but could never report:
//! the ring must be able to threshold-sign the report envelope without the
//! accused (the chain enforces threshold <= peers - 1 when the accused sits
//! in the signing committee).
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

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use crate::ring_state::RingShareBundle;
#[cfg(all(feature = "integration-test", feature = "native"))]
use crate::ring_state::RingShareBundle;

#[tokio::test]
#[serial_test::serial]
async fn test_frost_invalid_sign_share_triggers_on_chain_report() {
    println!("Starting FROST invalid sign-share reporting integration test...");

    let ring = FixtureId::new("ring");
    let policy = FixtureId::new("policy");
    let ring_policy = FixtureId::new("ring-policy");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
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
    // StoreSecret is sent to nodes[0], and that node keeps itself in the
    // FROST set. The other seat goes to the lowest canonical id among the
    // rest. Fixture index 1 is that seat only when its key sorts first.
    let partner = frost_partner_index(&members, 0);
    let partner_key = members[partner].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let partner_endpoint = environment.nodes()[partner].grpc_endpoint.clone();
    println!(
        "FROST partner is fixture node {partner} ({})",
        &partner_key[..partner_key.len().min(16)]
    );
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

    // Corrupt the partner's stored ring share: bump the secret scalar by one.
    // Selection will not substitute another member once the set is chosen, so
    // the bad share fails the sign instead of being skipped.
    let ring_pk_bytes = hex::decode(&keys.main).expect("decode ring pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("parse ring pk");
    let storage_key = LocalStorageKey {
        key_type: LocalStorageKeyType::RingKey as i32,
        ring_key: aggregate_pk.to_string(),
    };
    let mut unsafe_client = UnsafeTestingServiceClient::connect(partner_endpoint)
        .await
        .expect("connect unsafe-testing client to the FROST partner");
    let stored = unsafe_client
        .get_local_storage(GetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        })
        .await
        .expect("read partner ring share bundle")
        .into_inner();
    assert!(stored.found, "partner ring share bundle should exist");
    let bundle = RingShareBundle::from_bytes(&stored.value).expect("parse ring share bundle");
    let pri_share = bundle.pri_share().expect("deserialize partner share");
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
    println!("partner ring share corrupted.");

    // Fire single-shot store attempts. A round whose nonce set does not yet
    // include the partner signs with the other member and reports nothing.
    // Once the partner's nonce is in hand, selection keeps that share, the
    // bad share is observed, and the sign fails. Break on the first failure
    // so exactly one report is minted (demerits stay at 1).
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
                    "attempt {attempt}: FROST set skipped corrupted partner (sign succeeded); retrying..."
                );
                sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                println!("attempt {attempt}: sign failed with corrupted partner selected: {e}");
                sign_failed = true;
                break;
            }
        }
    }
    assert!(
        sign_failed,
        "corrupted partner was never selected into the FROST signing set in 10 attempts"
    );

    println!("Waiting for the partner's demerits to reflect the invalid-crypto report...");
    let demerits = wait_for_demerits(
        &environment,
        &ring_id,
        &partner_key,
        1,
        Duration::from_secs(120),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "partner should have exactly 1 demerit: attempts stop at the first failed sign, got {demerits}"
    );
    println!("partner demerit points: {demerits}");
}

/// Index of the non-coordinator signer `select_signing_commitments` keeps.
///
/// The coordinator is preferred, then seats fill from the lowest canonical
/// ids. Canonical id is the key's rank in sorted order, so the partner is
/// the other member with the smaller key.
fn frost_partner_index(member_keys: &[String], coordinator: usize) -> usize {
    member_keys
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != coordinator)
        .min_by(|(_, left), (_, right)| left.cmp(right))
        .map(|(index, _)| index)
        .expect("threshold signing needs a second member")
}

#[test]
fn frost_partner_follows_canonical_id_not_fixture_index() {
    // Native CI: nodes[0] coordinated, nodes[1] had the highest key, and the
    // signer that was actually kept was nodes[2].
    let native = vec![
        "026dc4dfbc01eb0fefff7f421a765e3963b05a0fe7a6c2f681961451c1692cd485".to_string(),
        "036f83170854da2d4db05b52ee5d3caf5d905de5e7587d193e31e057440365487e".to_string(),
        "021bc3470b838c29c62c825d458dfad39cdff19301e4f90aa84126acb1a78b8622".to_string(),
    ];
    assert_eq!(frost_partner_index(&native, 0), 2);

    // Cosmos keys are fixed and already sorted, so fixture index 1 is the partner.
    let cosmos = vec![
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".to_string(),
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
    ];
    assert_eq!(frost_partner_index(&cosmos, 0), 1);
}
