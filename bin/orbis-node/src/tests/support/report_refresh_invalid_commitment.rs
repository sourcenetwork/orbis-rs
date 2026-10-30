//! Shared integration test: a dealer's refresh commitment with a non-
//! identity constant term (i.e. not actually a refresh — the constant term
//! must stay fixed across a refresh) is forged and injected directly via
//! `UnsafeTestingService::submit_dkg_invalid_refresh_commitment_evidence`,
//! bypassing a live DKG session entirely (the report is built from the ring
//! and the signed statement alone, so injecting with a fixed request_id and
//! no live session avoids racing a healthy same-committee refresh).
//!
//! Forging the evidence requires signing *as* node3 using Cosmos's
//! deterministic per-node secp256k1 identity key (`NODE3_SIGNING_KEY_HEX`,
//! matching docker-compose's `ORBIS_SIGNING_KEY`) — same technique, same
//! native-unverified caveat, as `report_reshare_bad_dkg_share_relay.rs`/
//! `report_reshare_dkg_equivocation.rs`. Not yet ported for native.

#[cfg(feature = "integration-test-cosmos")]
use super::pre_scenario;
use super::TestEnvironmentImpl;
#[cfg(feature = "integration-test-native")]
use test_support::fixture::TestEnvironment;
use test_support::fixture::{
    FixtureId, NodeFixture, NodeRef, NodeRole, RingFixture, ScenarioFixture,
};
use tokio::time::Duration;

#[cfg(feature = "integration-test-cosmos")]
const NODE3_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "the Cosmos-deterministic-signing-key evidence forgery this \
              test depends on hasn't been verified against native's own \
              node-identity scheme; fix when this is re-verified"
)]
async fn test_refresh_invalid_commitment_triggers_on_chain_report() {
    println!("Starting PSS refresh invalid-commitment reporting integration test...");

    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
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

    #[cfg(feature = "integration-test-native")]
    {
        let _environment = TestEnvironmentImpl::provision(fixture).await;
        unimplemented!("native: Cosmos-signing-key refresh commitment forgery not ported");
    }

    #[cfg(feature = "integration-test-cosmos")]
    cosmos::run(fixture).await;
}

#[cfg(feature = "integration-test-cosmos")]
mod cosmos {
    use super::{pre_scenario, TestEnvironmentImpl, NODE3_SIGNING_KEY_HEX};
    use crate::dkg::v0::helpers::serialize_commitment_coefficients;
    use crate::dkg::v0::messages::SignedDkgCommitment;
    use crate::reporting::v0::types::{
        ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DKG_COMMITMENT_DOMAIN,
    };
    use bulletin::r#trait::{BulletinKind, RingPayload};
    use common::blockchain::sign_node_message_with_hex_key;
    use crypto::r#trait::{Dkg, DkgMode, DkgRole, PolynomialCommitment as _};
    use crypto::DkgImpl;
    use proto::unsafe_testing::{
        unsafe_testing_service_client::UnsafeTestingServiceClient,
        SubmitDkgInvalidRefreshCommitmentEvidenceRequest,
    };
    use test_support::fixture::{NetworkTestDriver, ScenarioFixture, TestEnvironment};
    use tokio::time::Duration;

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
        ring: &RingPayload,
        session_id: u128,
        accused_node_key: &str,
        accused_signing_key_hex: &str,
    ) -> SignedDkgCommitment {
        let from_node_id = canonical_node_id(accused_node_key, &ring.peer_node_keys);

        let mut dealer = DkgImpl::new(
            from_node_id,
            ring.threshold as usize,
            ring.peer_node_keys.len(),
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

        let commitment = serialize_commitment_coefficients(&dealer.commitment().coefficients)
            .expect("commitment");
        let signed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();
        let statement = DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id,
            ring_id,
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
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

    pub(super) async fn run(fixture: ScenarioFixture) {
        let ring = fixture.rings[0].id.clone();
        let environment = TestEnvironmentImpl::provision(fixture).await;
        let ring_id = environment.fixture().rings[&ring].id.clone();
        let members = environment.fixture().rings[&ring].members.clone();
        let node3_key = members[2].clone();
        let endpoint = environment.nodes()[0].grpc_endpoint.clone();
        let chain_config = environment.chain_config();

        println!("Starting DKG for ring {}...", ring_id.0);
        let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
        println!(
            "DKG finalized. Ring PK: {}...",
            &keys.main[..40.min(keys.main.len())]
        );

        let payload_bytes = cli_tool::read_bulletin_post_with_config(
            ring_id.0.clone(),
            BulletinKind::Ring,
            chain_config.clone(),
        )
        .await
        .expect("read finalized ring payload");
        let ring_payload: RingPayload =
            serde_json::from_slice(&payload_bytes).expect("parse finalized RingPayload");
        assert_eq!(
            ring_payload.ring_pk, keys.main,
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
            chain_config.chain_id.clone(),
            ring_id.0.clone(),
            &ring_payload,
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

        println!(
            "Waiting for node3's demerits to reflect the invalid refresh commitment report..."
        );
        let demerits = super::super::report_scenario::wait_for_demerits(
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
}
