//! Shared integration test: a dealer's refresh commitment with a non-
//! identity constant term (i.e. not actually a refresh — the constant term
//! must stay fixed across a refresh) is forged and injected directly via
//! `UnsafeTestingService::submit_dkg_invalid_refresh_commitment_evidence`,
//! bypassing a live DKG session entirely (the report is built from the ring
//! and the signed statement alone, so injecting with a fixed request_id and
//! no live session avoids racing a healthy same-committee refresh).
//!
//! Fully backend-neutral — no `#[cfg]` split in this file. Same reasoning
//! as `report_reshare_bad_dkg_share_relay.rs`/`report_reshare_dkg_equivocation.rs`:
//! `NODE3_SIGNING_KEY_HEX` is node3's real signing key on both backends now,
//! and the ring's current `RingPayload` comes from
//! `BulletinTestDriver::read_ring_state_facts` rather than a Cosmos-only
//! raw cli-tool bulletin read.

use super::pre_scenario;
use super::TestEnvironmentImpl;
use crate::dkg::v0::helpers::serialize_commitment_coefficients;
use crate::dkg::v0::messages::SignedDkgCommitment;
use crate::reporting::v0::types::{CommitteeScope, DkgCommitmentStatement, DKG_COMMITMENT_DOMAIN};
use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{Dkg, DkgMode, DkgRole, PolynomialCommitment as _};
use crypto::DkgImpl;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient,
    SubmitDkgInvalidRefreshCommitmentEvidenceRequest,
};
use test_support::admin::RingStateFacts;
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole, RingFixture,
    ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

const NODE3_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";

fn canonical_node_id(node_key: &str, node_keys: &[String]) -> u32 {
    let mut sorted = node_keys.to_vec();
    sorted.sort();
    sorted
        .iter()
        .position(|candidate| candidate == node_key)
        .map(|index| index as u32 + 1)
        .expect("node key should be in committee")
}

fn signed_bad_refresh_commitment(
    chain_id: String,
    ring_id: String,
    facts: &RingStateFacts,
    session_id: u128,
    accused_node_key: &str,
    accused_signing_key_hex: &str,
) -> SignedDkgCommitment {
    let from_node_id = canonical_node_id(accused_node_key, &facts.peer_node_keys);

    let mut dealer = DkgImpl::new(
        from_node_id,
        facts.threshold as usize,
        facts.peer_node_keys.len(),
        session_id,
        DkgRole::Standard,
    )
    .expect("create refresh dealer");
    dealer
        .generate_polynomial(DkgMode::Fresh)
        .expect("generate non-refresh polynomial");
    assert!(
        !dealer.commitment().constant_term_is_identity(),
        "test evidence must use a non-identity constant term"
    );

    let commitment =
        serialize_commitment_coefficients(&dealer.commitment().coefficients).expect("commitment");
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    let statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id,
        ring_id,
        ring_pk: facts.ring_pk.clone(),
        ring_state_sha256: facts.state_sha256.clone(),
        protocol_version: network::V0.version,
        request_id: session_id.to_string(),
        signed_at,
        responder_node_key: accused_node_key.to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        commitment,
        session_nonce: [9u8; 16],
        attempt_id: [9; 32],
        crypto_backend: DkgImpl::name(),
    };
    let signature =
        sign_node_message_with_hex_key(accused_signing_key_hex, &statement.canonical_bytes())
            .expect("sign invalid refresh commitment evidence");

    SignedDkgCommitment {
        statement,
        signature,
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_invalid_commitment_triggers_on_chain_report() {
    println!("Starting PSS refresh invalid-commitment reporting integration test...");

    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
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
            policy: FixtureId::new("ring-policy"),
            // kick_threshold=10: a single accepted report must not trigger
            // auto-kick.
            reporting: test_support::fixture::ReportingFixture {
                kick_threshold: 10,
                ..Default::default()
            },
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let members = environment.fixture().rings[&ring].members.clone();
    let node3_key = members[2].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let chain_id = environment.chain_id();

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    let facts = environment.read_ring_state_facts(&ring_id).await;
    assert_eq!(
        facts.ring_pk, keys.main,
        "ring payload should contain finalized ring_pk"
    );

    let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
        .await
        .expect("connect unsafe-testing client to node1");

    // The report is built from the ring + the signed statement, not
    // from a live DKG session, so inject once with a fixed request_id
    // (it only serves as the on-chain session dedupe key).
    let request_id: u128 = 777_000_111_222_u128;
    let evidence = signed_bad_refresh_commitment(
        chain_id,
        ring_id.0.clone(),
        &facts,
        request_id,
        &node3_key,
        NODE3_SIGNING_KEY_HEX,
    );
    unsafe_client
        .submit_dkg_invalid_refresh_commitment_evidence(
            SubmitDkgInvalidRefreshCommitmentEvidenceRequest {
                session_id: request_id.to_string(),
                signed_commitment_json: serde_json::to_vec(&evidence)
                    .expect("serialize signed refresh commitment evidence"),
            },
        )
        .await
        .expect("submit invalid refresh commitment evidence");
    println!("Submitted invalid refresh commitment evidence (request_id {request_id})");

    println!("Waiting for node3's demerits to reflect the invalid refresh commitment report...");
    let demerits = super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node3_key,
        1,
        Duration::from_secs(120),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the invalid refresh commitment report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}
