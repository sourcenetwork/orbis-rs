//! Shared integration test: a node signing cryptographically-invalid
//! responses (its own stored share is corrupted) fires on-chain
//! `invalid_crypto_response` reports for both PRE and Sign.
//!
//! Report detection/submission is backend-neutral production code (same
//! reasoning as `report_offline_pre_sign.rs`), so this is written as one
//! real test on both backends, verified via `report_scenario::
//! wait_for_demerits`/`try_wait_for_demerits` instead of Cosmos's
//! `ReportEventSubscription`.

use super::report_scenario::{
    pre_with_retry, store_secret_with_retry, try_wait_for_demerits, wait_for_demerits,
    STANDARD_RING_POLICY_YAML,
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
    AuthorizationTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;
use zeroize::Zeroizing;

#[cfg(feature = "integration-test-cosmos")]
use crate::ring_state::RingShareBundle;
#[cfg(feature = "integration-test-native")]
use orbis_node::ring_state::RingShareBundle;

#[tokio::test]
#[serial_test::serial]
async fn test_invalid_crypto_response_triggers_on_chain_report() {
    println!("Starting invalid-crypto reporting integration test...");

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
    let node3_key = members[2].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let node3_endpoint = environment.nodes()[2].grpc_endpoint.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // Set up ACP and a secret so PRE has something to decrypt.
    let resource = "document";
    let permission = "read";
    let did_pk_string = "invalid-proof-report-test-did".to_string();
    let reader_did = cli_tool::reader_did_from_seed(&did_pk_string);

    let prepared = cli_tool::prepare_secret(
        b"invalid-proof-report-test-secret",
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

    let store_result = store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        ring_id.0.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    let object_id = store_result.object_id.clone();

    environment
        .register_object(&policy_id, resource, &object_id)
        .await;
    environment
        .grant(&policy_id, resource, &object_id, "reader", &reader_did)
        .await;

    // Corrupt node3's stored ring share: bump the secret scalar by one. Its
    // reencryptions and signature shares stay well-formed and honestly
    // signed, but neither verifies against the ring polynomial — exactly
    // the misbehavior the invalid_crypto_response report type accuses.
    let ring_pk_bytes = hex::decode(&keys.main).expect("decode ring pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("parse ring pk");
    let storage_key = LocalStorageKey {
        key_type: LocalStorageKeyType::RingKey as i32,
        ring_key: aggregate_pk.to_string(),
    };
    let mut unsafe_client = UnsafeTestingServiceClient::connect(node3_endpoint)
        .await
        .expect("connect unsafe-testing client to node3");
    let stored = unsafe_client
        .get_local_storage(GetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        })
        .await
        .expect("read node3 ring share bundle")
        .into_inner();
    assert!(stored.found, "node3 ring share bundle should exist");
    let bundle = RingShareBundle::from_bytes(&stored.value).expect("parse ring share bundle");
    let pri_share = bundle.pri_share().expect("deserialize node3 share");
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
    println!("node3 ring share corrupted.");

    // PRE still succeeds (node1 self-share + node2), while node3's signed
    // response carries a proof that fails verification and gets reported —
    // inline if it races ahead of threshold, otherwise via the
    // post-threshold response drain. A single node3 response can
    // occasionally miss the drain window under CI load, so retry the whole
    // PRE (each attempt is a fresh reportable response) if the demerit
    // doesn't land within one attempt's window.
    println!(
        "Triggering PRE until node3's invalid proof is reported (PRE succeeds each attempt)..."
    );
    let mut demerits_after_pre = None;
    for attempt in 1..=2 {
        let _plaintext = pre_with_retry(
            endpoint.clone(),
            environment.chain_id(),
            keys.main.clone(),
            object_id.clone(),
            did_pk_string.clone(),
        )
        .await;
        println!(
            "PRE attempt {attempt} succeeded; waiting for node3's invalid-proof demerit (up to 150s)..."
        );
        if let Some(demerits) = try_wait_for_demerits(
            &environment,
            &ring_id,
            &node3_key,
            1,
            Duration::from_secs(150),
        )
        .await
        {
            demerits_after_pre = Some(demerits);
            break;
        }
        println!("Invalid-proof demerit not seen on attempt {attempt}/2, retrying PRE...");
    }
    let demerits_after_pre = demerits_after_pre.expect(
        "node3 should accumulate a demerit from an invalid-proof report within 2 PRE attempts",
    );
    assert_eq!(
        demerits_after_pre, 1,
        "node3 should have exactly 1 demerit after the invalid-proof report"
    );
    println!("node3 demerit points after invalid-proof report: {demerits_after_pre}");

    // ── Sign: the corrupted share also breaks node3's signature shares ──────
    // Storing a second secret with proof triggers a ring threshold
    // signature over the bulletin document (SignContext::Bulletin) — the
    // CLI-reachable sign path that produces invalid-crypto evidence
    // (policy/JWT signing is deliberately unreportable). The sign still
    // succeeds with node1 + node2, while node3's signed response carries a
    // sig share that fails verification and gets reported. Note: this
    // relies on the default non-interactive BLS backend, where every ring
    // peer receives a sign request; FROST's threshold-sized signing set
    // would deterministically exclude node3 — hence `#[cfg(not(feature =
    // "jubjub"))]` on the whole test, same as the raw version.
    let sign_prepared = cli_tool::prepare_secret(
        b"invalid-crypto-sign-report-test-secret",
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
    .expect("prepare_secret for sign");

    println!("Triggering Sign via store-with-proof (expects success with node3 submitting an invalid share)...");
    let _sign_store = store_secret_with_retry(
        endpoint.clone(),
        &sign_prepared,
        ring_id.0.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    println!("Store with proof succeeded (node3's invalid sig share ignored).");

    println!("Waiting for node3's demerits to reflect the Sign invalid-crypto report...");
    let demerits = wait_for_demerits(
        &environment,
        &ring_id,
        &node3_key,
        2,
        Duration::from_secs(120),
    )
    .await;
    assert_eq!(
        demerits, 2,
        "node3 should have exactly 2 demerits after the PRE and Sign invalid-crypto reports"
    );
    println!("node3 demerit points after Sign invalid-crypto report: {demerits}");
}
