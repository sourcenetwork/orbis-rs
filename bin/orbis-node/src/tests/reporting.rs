//! Docker-based integration tests for report submission on-chain.
//!
//! Offline reporting and invalid-crypto reporting are kept in separate tests so
//! each fault path has its own isolated setup and assertions.
//!
//! Run with:
//!   cargo test -p orbis-node --features integration-test test_pre_and_sign_offline_triggers_on_chain_report -- --nocapture
//!   cargo test -p orbis-node --features integration-test test_invalid_crypto_response_triggers_on_chain_report -- --nocapture
//!
//! FROST variant (builds the node containers with decaf377 automatically):
//!   cargo test -p orbis-node --no-default-features --features "redb,integration-test,decaf377" test_frost_invalid_sign_share_triggers_on_chain_report -- --nocapture

use crate::constants::DKG_FINALIZE_WAIT_TIMEOUT;
use crate::dkg::v0::helpers::serialize_commitment_coefficients;
use crate::dkg::v0::messages::{SignedDkgCommitment, SignedDkgShare};
use crate::helpers::test_helpers::{
    create_ring_governance_with_ring, wait_for_nodes_ready, wait_for_ring_finalized,
};
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
    RelayRequestStatement, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN, RELAY_REQUEST_DOMAIN,
    UNAUTHORIZED_REQUEST_REPORT_TYPE,
};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use authn::JwtSigner;
use bulletin::r#trait::{BulletinKind, RingPayload};
use common::{
    blockchain::{
        acp::Object,
        events::{ReportAcceptedEvent, ReportEventSubscription},
        orbis::WhitelistTarget,
        sign_node_message_with_hex_key, ChainConfig, SourceHubClient, TxSigner,
        TEST_ACCOUNT_HEX_KEY, TEST_ACCOUNT_PUBKEY_HEX,
    },
    IntegrationTestNetwork,
};
use crypto::helpers::generate_keypair;
use crypto::r#trait::{
    CryptoDeserialize, Dkg, DkgMode, DkgRole, PolynomialCommitment as _, PriShare,
};
use crypto::CryptoSerialize;
use crypto::{DkgImpl, GroupAffine, ScalarField};
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetActivePssSessionRequest,
    GetLocalStorageRequest, LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType,
    SetLocalStorageRequest, SubmitDkgEquivocationEvidenceRequest,
    SubmitDkgInvalidRefreshCommitmentEvidenceRequest, SubmitDkgInvalidShareEvidenceRequest,
    SubmitOrganicConflictingCommitmentRequest, SubmitOrganicConflictingManifestRequest,
    SubmitOrganicInvalidRefreshResultRequest, SubmitOrganicNoncanonicalPrepareRequest,
    SubmitPssStallOfflineReportRequest, SubmitUnauthorizedRelayEvidenceRequest,
};
use tokio::time::{sleep, Duration, Instant};
use zeroize::Zeroizing;

const RING_ID: &str = "reporting-test-ring";
const NODE1_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const NODE2_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";
const NODE3_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
const UNAUTHORIZED_RELAY_TEST_POLICY_YAML: &str = r#"
name: unauthorized-relay-test-policy
resources:
  - name: document
    relations:
      - name: creator
        types:
          - actor
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: reader
      - name: write
        expr: creator
"#;

use super::constants::{
    reporting_genesis_json, NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4, NODE_KEY_OFFLINE,
    OFFLINE_NODE_PEER_ID, RING_GOVERNANCE_POLICY_ID,
};

fn canonical_node_id(node_key: &str, node_keys: &[String]) -> u32 {
    let mut sorted = node_keys.to_vec();
    sorted.sort();
    sorted
        .iter()
        .position(|candidate| candidate == node_key)
        .map(|index| index as u32 + 1)
        .expect("node key should be in committee")
}

fn sorted_node_keys(node_keys: &[String]) -> Vec<String> {
    let mut sorted = node_keys.to_vec();
    sorted.sort();
    sorted
}

fn ring_key_from_ring_pk_hex(ring_pk_hex: &str) -> String {
    let bytes = hex::decode(ring_pk_hex).expect("decode ring_pk hex");
    GroupAffine::from_bytes(&bytes)
        .expect("deserialize ring_pk")
        .to_string()
}

async fn wait_for_active_pss_session(endpoint: &str, ring_pk: &str, timeout: Duration) -> String {
    let mut client = UnsafeTestingServiceClient::connect(endpoint.to_string())
        .await
        .expect("connect unsafe-testing client for active PSS lookup");
    let deadline = Instant::now() + timeout;
    loop {
        let response = client
            .get_active_pss_session(GetActivePssSessionRequest {
                ring_pk: ring_pk.to_string(),
            })
            .await
            .expect("query active PSS session")
            .into_inner();
        if response.found {
            return response.session_id;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for active PSS session for ring_pk {ring_pk}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn ensure_ring_index_on_nodes(endpoints: &[String], ring_pk_hex: &str, ring_id: &str) {
    let ring_key = ring_key_from_ring_pk_hex(ring_pk_hex);
    let indexed_at_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();

    for (index, endpoint) in endpoints.iter().enumerate() {
        let mut client = UnsafeTestingServiceClient::connect(endpoint.clone())
            .await
            .expect("connect unsafe-testing client for RingIndex");
        let key = LocalStorageKey {
            key_type: LocalStorageKeyType::RingIndex as i32,
            ring_key: String::new(),
        };
        let stored = client
            .get_local_storage(GetLocalStorageRequest {
                key: Some(key.clone()),
                access_mode: LocalStorageAccessMode::Plain as i32,
            })
            .await
            .expect("read RingIndex")
            .into_inner();
        let mut ring_index: Vec<RingIndexEntry> = if stored.found {
            serde_json::from_slice(&stored.value).expect("parse RingIndex")
        } else {
            Vec::new()
        };

        if let Some(entry) = ring_index
            .iter_mut()
            .find(|entry| entry.ring_pk_str == ring_key)
        {
            entry.bulletin_post_id = ring_id.to_string();
        } else {
            ring_index.push(RingIndexEntry {
                ring_pk_str: ring_key.clone(),
                bulletin_post_id: ring_id.to_string(),
                indexed_at_secs,
            });
        }

        client
            .set_local_storage(SetLocalStorageRequest {
                key: Some(key),
                access_mode: LocalStorageAccessMode::Plain as i32,
                value: serde_json::to_vec(&ring_index).expect("serialize RingIndex"),
            })
            .await
            .expect("write RingIndex");
        println!(
            "Ensured RingIndex entry on node{} for local ring key {}...",
            index + 1,
            &ring_key[..40.min(ring_key.len())]
        );
    }
}

async fn wait_for_ring_state_on_nodes(endpoints: &[String], ring_pk_hex: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut statuses = Vec::with_capacity(endpoints.len());
        let mut ready = true;
        for (index, endpoint) in endpoints.iter().enumerate() {
            match cli_tool::query_ring_state(endpoint.clone(), ring_pk_hex.to_string()).await {
                Ok((_, last_pss)) => {
                    statuses.push(format!("node{}: last_pss={last_pss}", index + 1));
                }
                Err(error) => {
                    statuses.push(format!("node{}: {error}", index + 1));
                    ready = false;
                    break;
                }
            }
        }
        if ready {
            println!(
                "All selected nodes have local DKG ring state: {}",
                statuses.join("; ")
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for local DKG ring state: {}",
            statuses.join("; ")
        );
        sleep(Duration::from_millis(250)).await;
    }
}

fn signed_bad_reshare_dkg_share(
    chain_id: String,
    ring_id: String,
    ring: &RingPayload,
    session_id: u128,
    accused_node_key: &str,
    accused_signing_key_hex: &str,
    receiver_node_key: &str,
) -> SignedDkgShare {
    let from_node_id = canonical_node_id(accused_node_key, &ring.peer_node_keys);
    let receiver_node_keys = ring
        .new_peer_node_keys
        .clone()
        .expect("reshare announcement should include new_peer_node_keys");
    let to_node_id = canonical_node_id(receiver_node_key, &receiver_node_keys);

    let mut dealer = DkgImpl::new(
        from_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        session_id,
        DkgRole::Dealer,
    )
    .expect("create reshare dealer");
    dealer
        .generate_polynomial(DkgMode::Reshare {
            old_share: ScalarField::from(42_u64),
            participating_ids: (1..=ring.peer_node_keys.len() as u32).collect(),
            new_threshold: ring
                .new_threshold
                .unwrap_or(ring.threshold)
                .try_into()
                .expect("new threshold fits usize"),
            new_total_nodes: receiver_node_keys.len(),
            new_node_id: None,
        })
        .expect("generate reshare polynomial");

    let commitment =
        serialize_commitment_coefficients(&dealer.commitment().coefficients).expect("commitment");
    let share = dealer
        .generate_shares()
        .expect("generate reshare shares")
        .into_iter()
        .find(|share| share.to_id == to_node_id)
        .expect("share for receiver");
    let share_value = <ScalarField as CryptoSerialize>::to_bytes(&share.value).expect("share");
    let mut bad_share_value = ScalarField::from_bytes(&share_value).expect("deserialize share");
    bad_share_value += ScalarField::from(1_u64);
    let bad_share_value =
        <ScalarField as CryptoSerialize>::to_bytes(&bad_share_value).expect("bad share");
    assert_ne!(share_value, bad_share_value);

    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    let commitment_statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: chain_id.clone(),
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id: session_id.to_string(),
        signed_at: signed_at - 1,
        responder_node_key: accused_node_key.to_string(),
        origin_protocol: "pss_reshare".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        commitment,
        session_nonce: [0u8; 16],
        attempt_id: [9; 32],
        crypto_backend: DkgImpl::name(),
    };
    let commitment_signature = sign_node_message_with_hex_key(
        accused_signing_key_hex,
        &commitment_statement.canonical_bytes(),
    )
    .expect("sign DKG commitment evidence");
    let statement = DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id,
        ring_id,
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id: session_id.to_string(),
        signed_at,
        responder_node_key: accused_node_key.to_string(),
        receiver_node_key: receiver_node_key.to_string(),
        origin_protocol: "pss_reshare".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        to_node_id,
        commitment_statement,
        commitment_signature,
        share_value: bad_share_value,
        nonce: share.nonce,
        crypto_backend: DkgImpl::name(),
    };
    let signature =
        sign_node_message_with_hex_key(accused_signing_key_hex, &statement.canonical_bytes())
            .expect("sign DKG share evidence");

    SignedDkgShare {
        statement,
        signature,
    }
}

fn signed_equivocation_commitments(
    chain_id: String,
    ring_id: String,
    ring: &RingPayload,
    session_id: u128,
    accused_node_key: &str,
    accused_signing_key_hex: &str,
) -> (SignedDkgCommitment, SignedDkgCommitment) {
    let from_node_id = canonical_node_id(accused_node_key, &ring.peer_node_keys);
    let receiver_node_keys = ring
        .new_peer_node_keys
        .clone()
        .expect("reshare announcement should include new_peer_node_keys");
    let participating_ids: Vec<u32> = (1..=ring.peer_node_keys.len() as u32).collect();
    let new_threshold = ring
        .new_threshold
        .unwrap_or(ring.threshold)
        .try_into()
        .expect("new threshold fits usize");
    let new_total_nodes = receiver_node_keys.len();

    let make_commitment = || {
        let mut dealer = DkgImpl::new(
            from_node_id,
            ring.threshold as usize,
            ring.peer_node_keys.len(),
            session_id,
            DkgRole::Dealer,
        )
        .expect("create reshare dealer");
        dealer
            .generate_polynomial(DkgMode::Reshare {
                old_share: ScalarField::from(42_u64),
                participating_ids: participating_ids.clone(),
                new_threshold,
                new_total_nodes,
                new_node_id: None,
            })
            .expect("generate reshare polynomial");
        serialize_commitment_coefficients(&dealer.commitment().coefficients).expect("commitment")
    };

    let commitment_a = make_commitment();
    let commitment_b = make_commitment();
    assert_ne!(
        commitment_a, commitment_b,
        "equivocation evidence must contain two different commitments"
    );

    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    let session_nonce = [7u8; 16];
    let sign_commitment = |commitment: Vec<u8>| {
        let statement = DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: chain_id.clone(),
            ring_id: ring_id.clone(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version: network::V0.version,
            request_id: session_id.to_string(),
            signed_at,
            responder_node_key: accused_node_key.to_string(),
            origin_protocol: "pss_reshare".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id,
            commitment,
            session_nonce,
            attempt_id: [9; 32],
            crypto_backend: DkgImpl::name(),
        };
        let signature =
            sign_node_message_with_hex_key(accused_signing_key_hex, &statement.canonical_bytes())
                .expect("sign DKG equivocation commitment");
        SignedDkgCommitment {
            statement,
            signature,
        }
    };

    (sign_commitment(commitment_a), sign_commitment(commitment_b))
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

#[tokio::test]
#[serial_test::serial]
async fn test_pre_and_sign_offline_triggers_on_chain_report() {
    println!("Starting reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    // kick_threshold=10: this test accumulates two accepted offline
                    // reports against node3 and must not trigger the auto-kick reshare.
                    "reporting": reporting_genesis_json(1, &[], 10)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Set up ACP policy and a secret so PRE has something to decrypt.
    let resource = "document".to_string();
    let permission = "read".to_string();
    let did_pk_string = "report-test-did".to_string();
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("add policy");

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));

    let prepared = cli_tool::prepare_secret(
        b"report-test-secret",
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    let store_result = store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        RING_ID.to_string(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    let object_id = store_result.object_id.clone();

    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await
    .expect("register object");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did_pk_string.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set relationship");

    // Subscribe before stopping node3 to avoid missing the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 to trigger an offline observation during PRE.
    println!("Stopping node3 to simulate offline node...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    // PRE succeeds with 2/3 shares (threshold=2) and fires an offline report for node3.
    println!("Triggering PRE (expects success with node3 offline)...");
    let _plaintext = pre_with_retry(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        reader_sk_hex.clone(),
        object_id.clone(),
        did_pk_string.clone(),
    )
    .await;
    println!("PRE succeeded (2/3 shares collected).");

    // The offline report is threshold-signed and submitted to the chain.
    println!("Waiting for EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("EventReportAccepted should be emitted");

    println!(
        "Report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    // ── Sign: node3 is still offline ────────────────────────────────────────
    println!("Setting up Sign key derivation (node3 still offline)...");
    let sign_derivation = "sign-report-derivation".to_string();
    let sign_did_pk = "sign-report-test-did".to_string();

    let (derivation_id, _) = cli_tool::post_key_derivation_with_config(
        RING_ID.to_string(),
        sign_derivation,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        chain_config.clone(),
    )
    .await
    .expect("post_key_derivation");

    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await
    .expect("register derivation_id");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(sign_did_pk.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set relationship for sign");

    // Fresh subscription — the previous one was consumed by wait_for_report_accepted.
    println!("Subscribing to report events for Sign...");
    let sign_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect sign report event subscription");

    // Sign succeeds with 2/3 shares (node3 still offline) and fires an offline report.
    println!("Triggering Sign (expects success with node3 still offline)...");
    let sign_result = sign_with_retry(
        endpoint.clone(),
        b"sign-offline-report-test-message".to_vec(),
        derivation_id.clone(),
        sign_did_pk.clone(),
    )
    .await;
    println!("Sign succeeded: status={}", sign_result.status);

    println!("Waiting for Sign EventReportAccepted on chain (up to 120s)...");
    let sign_event = sign_sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("Sign EventReportAccepted should be emitted");

    println!(
        "Sign report accepted: report_id={} accused={}",
        sign_event.report_id, sign_event.accused_node_key
    );

    assert_eq!(
        sign_event.report_type, "node_offline",
        "unexpected sign report_type"
    );
    assert_eq!(
        sign_event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(sign_event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        !sign_event.report_id.is_empty(),
        "sign report_id should be set"
    );
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&sign_event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        sign_event.reporter_node_key
    );

    // Both the PRE and Sign reports were accepted: node3 should have demerits.
    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 2,
        "node3 should have exactly 2 demerits after 2 accepted offline reports"
    );
    println!("node3 demerit points: {demerits}");
}

#[tokio::test]
#[serial_test::serial]
async fn test_unauthorized_relay_pre_and_sign_triggers_on_chain_report() {
    println!("Starting unauthorized relay reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    // kick_threshold=10: retries can produce more than one accepted
                    // unauthorized_request report, but must not trigger auto-kick.
                    "reporting": reporting_genesis_json(1, &[], 10)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let node1_endpoint = endpoints[0].to_string();
    let node2_endpoint = endpoints[1].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(node1_endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let ring = read_ring_payload(&chain_config, RING_ID).await;
    assert_eq!(ring.ring_pk, ring_pk_hex, "finalized ring_pk mismatch");

    let resource = "document".to_string();
    let permission = "read".to_string();
    let policy_id = create_policy_with_client(&controller_client).await;

    // PRE: node1 produced a relayer-signed statement for an actor with no ACP relationship.
    println!("Setting up PRE unauthorized relay fixture...");
    let (_, pre_object_id) = controller_client
        .orbis_store_document_get_id(
            RING_ID,
            "{}",
            "{}",
            &policy_id,
            &resource,
            &permission,
            None,
            None,
        )
        .await
        .expect("store PRE document");

    register_object_with_client(&controller_client, &policy_id, &pre_object_id, &resource).await;

    let (_, pre_reader_pk) = generate_keypair().expect("generate PRE reader keypair");
    let pre_reader_pk_bytes =
        CryptoSerialize::to_bytes(&pre_reader_pk).expect("serialize PRE reader public key");
    let pre_jwt_signer = JwtSigner::new();
    let pre_token = pre_jwt_signer
        .create_pre_jwt(pre_reader_pk_bytes.clone(), &pre_object_id, None, None)
        .expect("create PRE JWT");
    let pre_actor_is_reader = controller_client
        .acp_has_relationship(
            &policy_id,
            &pre_jwt_signer.did_uri,
            &resource,
            &pre_object_id,
            "reader",
        )
        .await
        .expect("check PRE reader relationship absence");
    assert!(
        !pre_actor_is_reader,
        "PRE actor must not have a reader relationship"
    );

    let (pre_statement, pre_signature) = signed_unauthorized_relay_statement(
        &chain_config,
        &ring,
        "pre",
        NODE_KEY_1,
        NODE1_SIGNING_KEY_HEX,
        &pre_object_id,
        &pre_jwt_signer.did_uri,
    );

    println!("Submitting PRE unauthorized relay evidence against node1 through node3...");
    let pre_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect PRE unauthorized report event subscription");
    submit_unauthorized_relay_evidence(
        node1_endpoint.clone(),
        peer_addresses[2].clone(),
        pre_statement,
        pre_signature,
        pre_token,
        pre_reader_pk_bytes,
    )
    .await;
    println!("PRE unauthorized relay evidence forwarded.");
    let pre_event = pre_sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(180), |event| {
            event.report_type == UNAUTHORIZED_REQUEST_REPORT_TYPE
                && event.accused_node_key == NODE_KEY_1
                && event.reporter_node_key == NODE_KEY_3
        })
        .await
        .expect("PRE unauthorized_request EventReportAccepted should be emitted");
    println!(
        "PRE unauthorized relay report accepted: report_id={} accused={} reporter={}",
        pre_event.report_id, pre_event.accused_node_key, pre_event.reporter_node_key
    );
    assert_unauthorized_relay_event(&pre_event, NODE_KEY_1, NODE_KEY_3);

    // Sign: node2 produced a relayer-signed statement for another unauthorized actor.
    println!("Setting up Sign unauthorized relay fixture...");
    let sign_derivation = "unauthorized-relay-sign-derivation".to_string();
    let (_, derivation_id) = controller_client
        .orbis_store_key_derivation_get_id(
            RING_ID,
            &sign_derivation,
            &policy_id,
            &resource,
            &permission,
        )
        .await
        .expect("store Sign key derivation");

    register_object_with_client(&controller_client, &policy_id, &derivation_id, &resource).await;

    let sign_message = b"unauthorized relay sign report test message";
    let sign_jwt_signer = JwtSigner::new();
    let sign_token = sign_jwt_signer
        .create_sign_jwt(&derivation_id, sign_message)
        .expect("create Sign JWT");
    let sign_actor_is_reader = controller_client
        .acp_has_relationship(
            &policy_id,
            &sign_jwt_signer.did_uri,
            &resource,
            &derivation_id,
            "reader",
        )
        .await
        .expect("check Sign reader relationship absence");
    assert!(
        !sign_actor_is_reader,
        "Sign actor must not have a reader relationship"
    );

    let (sign_statement, sign_signature) = signed_unauthorized_relay_statement(
        &chain_config,
        &ring,
        "sign",
        NODE_KEY_2,
        NODE2_SIGNING_KEY_HEX,
        &derivation_id,
        &sign_jwt_signer.did_uri,
    );

    println!("Submitting Sign unauthorized relay evidence against node2 through node1...");
    let sign_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect Sign unauthorized report event subscription");
    submit_unauthorized_relay_evidence(
        node2_endpoint,
        peer_addresses[0].clone(),
        sign_statement,
        sign_signature,
        sign_token,
        Vec::new(),
    )
    .await;
    println!("Sign unauthorized relay evidence forwarded.");
    let sign_event = sign_sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(180), |event| {
            event.report_type == UNAUTHORIZED_REQUEST_REPORT_TYPE
                && event.accused_node_key == NODE_KEY_2
                && event.reporter_node_key == NODE_KEY_1
        })
        .await
        .expect("Sign unauthorized_request EventReportAccepted should be emitted");
    println!(
        "Sign unauthorized relay report accepted: report_id={} accused={} reporter={}",
        sign_event.report_id, sign_event.accused_node_key, sign_event.reporter_node_key
    );
    assert_unauthorized_relay_event(&sign_event, NODE_KEY_2, NODE_KEY_1);

    println!("Checking relayer demerit points...");
    let node1_demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_1)
        .await
        .expect("query node1 demerits");
    let node2_demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_2)
        .await
        .expect("query node2 demerits");
    assert!(
        node1_demerits >= 1,
        "node1 should have at least 1 demerit after the PRE unauthorized relay report"
    );
    assert!(
        node2_demerits >= 1,
        "node2 should have at least 1 demerit after the Sign unauthorized relay report"
    );
    println!("relayer demerits: node1={node1_demerits}, node2={node2_demerits}");
}

#[tokio::test]
#[serial_test::serial]
#[cfg(not(feature = "decaf377"))]
async fn test_invalid_crypto_response_triggers_on_chain_report() {
    println!("Starting invalid-crypto reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node3_endpoint = endpoints[2].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Set up ACP policy and a secret so PRE has something to decrypt.
    let resource = "document".to_string();
    let permission = "read".to_string();
    let did_pk_string = "invalid-proof-report-test-did".to_string();
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("add policy");

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));

    let prepared = cli_tool::prepare_secret(
        b"invalid-proof-report-test-secret",
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    let store_result = store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        RING_ID.to_string(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    let object_id = store_result.object_id.clone();

    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await
    .expect("register object");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did_pk_string.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set relationship");

    // Corrupt node3's stored ring share: bump the secret scalar by one. Its
    // reencryptions and signature shares stay well-formed and honestly signed,
    // but neither verifies against the ring polynomial — exactly the
    // misbehavior the invalid_crypto_response report type accuses.
    let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring pk hex");
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

    // PRE still succeeds (node1 self-share + node2), while node3's signed response carries a proof
    // that fails verification and gets reported — inline if it races ahead of threshold, otherwise
    // via the post-threshold response drain. A single node3 response can occasionally miss the drain
    // window under CI load, so retry the whole PRE (each attempt is a fresh reportable response) if
    // the report doesn't land. The per-attempt wait (150s) far exceeds the report pipeline's maximum
    // latency (drain ≤30s + threshold-sign + submit + block inclusion ≈ tens of seconds), so a
    // timeout means that attempt produced no report at all — which makes the retry safe: exactly one
    // report lands, preserving the exact demerit count below. Each PRE uses a fresh request_id, so
    // multiple accepted reports would NOT dedupe on-chain — the "timeout ⇒ nothing generated"
    // property is what keeps this to a single report.
    println!(
        "Triggering PRE until node3's invalid proof is reported (PRE succeeds each attempt)..."
    );
    let mut invalid_proof_event = None;
    for attempt in 1..=2 {
        let invalid_proof_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
            .await
            .expect("connect invalid-proof report event subscription");
        let _plaintext = pre_with_retry(
            endpoint.clone(),
            ring_pk_hex.clone(),
            reader_pk_hex.clone(),
            reader_sk_hex.clone(),
            object_id.clone(),
            did_pk_string.clone(),
        )
        .await;
        println!(
            "PRE attempt {attempt} succeeded; waiting for invalid-proof EventReportAccepted (up to 150s)..."
        );
        match invalid_proof_sub
            .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(150), |event| {
                event.accused_node_key.as_str() == NODE_KEY_3
            })
            .await
        {
            Ok(event) => {
                invalid_proof_event = Some(event);
                break;
            }
            Err(error) => {
                println!("Invalid-proof report not seen on attempt {attempt}/2: {error}");
            }
        }
    }
    let invalid_proof_event = invalid_proof_event
        .expect("invalid-proof EventReportAccepted should be emitted within 2 attempts");

    println!(
        "Invalid-proof report accepted: report_id={} accused={}",
        invalid_proof_event.report_id, invalid_proof_event.accused_node_key
    );

    assert_eq!(
        invalid_proof_event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        invalid_proof_event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(invalid_proof_event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        !invalid_proof_event.report_id.is_empty(),
        "invalid-proof report_id should be set"
    );
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&invalid_proof_event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        invalid_proof_event.reporter_node_key
    );

    println!("Checking node3 demerit points after invalid-proof report...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly 1 demerit after the invalid-proof report"
    );
    println!("node3 demerit points after invalid-proof report: {demerits}");

    // ── Sign: the corrupted share also breaks node3's signature shares ──────
    // Storing a second secret with proof triggers a ring threshold signature
    // over the bulletin document (SignContext::Bulletin) — the CLI-reachable
    // sign path that produces invalid-crypto evidence (policy/JWT signing is
    // deliberately unreportable). The sign still succeeds with node1 + node2,
    // while node3's signed response carries a sig share that fails
    // verification and gets reported — inline if it races ahead of threshold,
    // otherwise via the sign response drain. Note: this section relies on the
    // default non-interactive BLS backend, where every ring peer receives a
    // sign request; FROST's threshold-sized signing set would deterministically
    // exclude node3.
    println!("Subscribing to report events for Sign...");
    let sign_report_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect sign invalid-crypto report event subscription");

    let sign_prepared = cli_tool::prepare_secret(
        b"invalid-crypto-sign-report-test-secret",
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret for sign");

    println!("Triggering Sign via store-with-proof (expects success with node3 submitting an invalid share)...");
    let _sign_store = store_secret_with_retry(
        endpoint.clone(),
        &sign_prepared,
        RING_ID.to_string(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    println!("Store with proof succeeded (node3's invalid sig share ignored).");

    println!("Waiting for Sign invalid-crypto EventReportAccepted on chain (up to 120s)...");
    let sign_event = sign_report_sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("Sign invalid-crypto EventReportAccepted should be emitted");

    println!(
        "Sign invalid-crypto report accepted: report_id={} accused={}",
        sign_event.report_id, sign_event.accused_node_key
    );

    assert_eq!(
        sign_event.report_type, "invalid_crypto_response",
        "unexpected sign report_type"
    );
    assert_eq!(
        sign_event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(sign_event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        !sign_event.report_id.is_empty(),
        "sign report_id should be set"
    );
    assert_ne!(
        sign_event.report_id, invalid_proof_event.report_id,
        "sign report must be distinct from the PRE report"
    );
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&sign_event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        sign_event.reporter_node_key
    );

    println!("Checking node3 demerit points after Sign invalid-crypto report...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 2,
        "node3 should have exactly 2 demerits after the PRE and Sign invalid-crypto reports"
    );
    println!("node3 demerit points after Sign invalid-crypto report: {demerits}");
}

/// FROST-only variant of the Sign invalid-crypto test. Under decaf377 the
/// signing set is exactly threshold-sized and chosen from whichever nonces
/// arrive first, so a corrupted node is only exercised when the nonce race
/// selects it — and when it IS selected, FROST cannot recover the signature
/// (shares are bound to the commitment set), so the sign fails outright
/// instead of succeeding around the bad node like BLS does.
///
/// The test embraces both properties: it corrupts node2 (the favourite of the
/// sorted, self-preferring selection), fires single store-with-proof attempts
/// until one fails — the failure itself is the signal that node2 was selected
/// and its bad share observed — then asserts the invalid-crypto report landed
/// on chain with exactly one demerit. A 3-of-3 ring would make selection
/// deterministic but could never report: the ring must be able to
/// threshold-sign the report envelope without the accused (the chain enforces
/// threshold <= peers - 1 when the accused sits in the signing committee).
#[cfg(feature = "decaf377")]
#[tokio::test]
#[serial_test::serial]
async fn test_frost_invalid_sign_share_triggers_on_chain_report() {
    println!("Starting FROST invalid sign-share reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node2_endpoint = endpoints[1].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    let resource = "document".to_string();
    let permission = "read".to_string();
    let did_pk_string = "frost-invalid-sign-report-test-did".to_string();
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("add policy");

    let prepared = cli_tool::prepare_secret(
        b"frost-invalid-sign-report-test-secret",
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
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
        RING_ID.to_string(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    println!("Baseline store succeeded.");

    // Corrupt node2's stored ring share (see the invalid-crypto test above for
    // the mechanics). Node2, not node3: the FROST selection prefers self plus
    // the lowest node IDs, so node2 is the likeliest network pick.
    let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring pk hex");
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

    let report_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

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
            RING_ID.to_string(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            Some(did_pk_string.clone()),
            true,
            None,
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

    println!("Waiting for invalid-crypto EventReportAccepted on chain (up to 120s)...");
    let event = report_sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("invalid-crypto EventReportAccepted should be emitted");

    println!(
        "Invalid-crypto report accepted: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_2,
        "node2 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_3].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    println!("Checking node2 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_2)
        .await
        .expect("query node2 demerits");
    assert_eq!(
        demerits, 1,
        "node2 should have exactly 1 demerit: attempts stop at the first failed sign"
    );
    println!("node2 demerit points: {demerits}");
}

async fn wait_for_node_info_on_chain(
    client: &SourceHubClient,
    node_key: &str,
    timeout: Duration,
    poll_interval: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(_)) = client.orbis_read_node_info(node_key).await {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "NodeInfo for {node_key} not found on chain within {timeout:?}"
        );
        sleep(poll_interval).await;
    }
}

async fn create_policy_with_client(client: &SourceHubClient) -> String {
    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids before unauthorized relay test policy")
        .ids
        .into_iter()
        .collect();

    let result = client
        .acp_create_policy(UNAUTHORIZED_RELAY_TEST_POLICY_YAML, 1)
        .await
        .expect("create unauthorized relay test policy");
    assert_eq!(
        result.code, 0,
        "create unauthorized relay test policy failed: {}",
        result.log
    );

    client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids after unauthorized relay test policy")
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .expect("new unauthorized relay test policy ID not found")
}

async fn register_object_with_client(
    client: &SourceHubClient,
    policy_id: &str,
    object_id: &str,
    resource: &str,
) {
    let result = client
        .acp_register_object(
            policy_id,
            Object {
                resource: resource.to_string(),
                id: object_id.to_string(),
            },
        )
        .await
        .expect("register unauthorized relay test object");
    assert_eq!(
        result.code, 0,
        "register unauthorized relay test object failed: {}",
        result.log
    );
}

async fn read_ring_payload(chain_config: &ChainConfig, ring_id: &str) -> RingPayload {
    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        ring_id.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring bulletin post");
    serde_json::from_slice(&payload_bytes).expect("parse RingPayload")
}

fn current_unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

fn signed_unauthorized_relay_statement(
    chain_config: &ChainConfig,
    ring: &RingPayload,
    origin_protocol: &str,
    accused_node_key: &str,
    accused_signing_key_hex: &str,
    object_id: &str,
    actor_id: &str,
) -> (RelayRequestStatement, Vec<u8>) {
    let signed_at = current_unix_time_secs();
    let statement = RelayRequestStatement {
        domain: RELAY_REQUEST_DOMAIN.to_string(),
        chain_id: chain_config.chain_id.clone(),
        ring_id: RING_ID.to_string(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id: format!("unauthorized-relay-{origin_protocol}-{object_id}"),
        signed_at,
        user_signed_at: signed_at,
        relayer_node_key: accused_node_key.to_string(),
        origin_protocol: origin_protocol.to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: canonical_node_id(accused_node_key, &ring.peer_node_keys),
        actor_id: actor_id.to_string(),
        object_id: object_id.to_string(),
        valid_window_start: None,
        valid_window_end: None,
        timestamp: None,
    };
    let signature =
        sign_node_message_with_hex_key(accused_signing_key_hex, &statement.canonical_bytes())
            .expect("sign unauthorized relay statement");
    (statement, signature)
}

async fn submit_unauthorized_relay_evidence(
    endpoint: String,
    target_peer_id: String,
    statement: RelayRequestStatement,
    relay_signature: Vec<u8>,
    token_string: String,
    pre_reader_pk: Vec<u8>,
) {
    let mut client = UnsafeTestingServiceClient::connect(endpoint)
        .await
        .expect("connect unsafe-testing client for unauthorized relay evidence");
    client
        .submit_unauthorized_relay_evidence(SubmitUnauthorizedRelayEvidenceRequest {
            relay_statement_canonical_bytes: statement.canonical_bytes(),
            relay_signature,
            target_peer_id,
            token_string,
            pre_reader_pk,
        })
        .await
        .expect("submit unauthorized relay evidence");
}

fn assert_unauthorized_relay_event(
    event: &ReportAcceptedEvent,
    expected_accused_node_key: &str,
    expected_reporter_node_key: &str,
) {
    assert_eq!(
        event.report_type, UNAUTHORIZED_REQUEST_REPORT_TYPE,
        "unexpected report_type"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        !event.report_id.is_empty(),
        "unauthorized_request report_id should be set"
    );
    assert_eq!(
        event.accused_node_key, expected_accused_node_key,
        "relayer should be the accused node"
    );
    assert_ne!(
        event.reporter_node_key, event.accused_node_key,
        "reporter must not be the accused relayer"
    );
    assert_eq!(
        event.reporter_node_key, expected_reporter_node_key,
        "reporter should be the node that submitted the evidence"
    );
}

async fn store_secret_with_retry(
    endpoint: String,
    prepared: &cli_tool::PreparedSecret,
    ring_id: String,
    policy_id: String,
    resource: String,
    permission: String,
    reader_did_pk: Option<String>,
) -> cli_tool::StoreSecretResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::store_prepared_secret(
            endpoint.clone(),
            prepared,
            ring_id.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            reader_did_pk.clone(),
            true,
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "StoreSecret failed after {attempt} attempts: {e}"
                );
                println!("StoreSecret attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn pre_with_retry(
    endpoint: String,
    ring_pk: String,
    reader_pk: String,
    reader_sk: String,
    object_id: String,
    reader_did_pk: String,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::do_pre(
            endpoint.clone(),
            ring_pk.clone(),
            reader_pk.clone(),
            Some(reader_sk.clone()),
            object_id.clone(),
            Some(reader_did_pk.clone()),
            None,
            None,
            None,
            None,
            false,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "PRE failed after {attempt} attempts: {e}"
                );
                println!("PRE attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn sign_with_retry(
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    did_pk: String,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::do_sign(
            endpoint.clone(),
            message.clone(),
            derivation_id.clone(),
            Some(did_pk.clone()),
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "Sign failed after {attempt} attempts: {e}"
                );
                println!("Sign attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

/// Exercises organic Refresh transport reporting: node3 goes offline after the
/// initial DKG, the scheduled refresh exhausts its peer-specific preparation
/// budget, and the terminal observation traverses the full report pipeline.
#[tokio::test]
#[serial_test::serial]
async fn test_refresh_offline_triggers_on_chain_report() {
    println!("Starting PSS refresh offline reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 5,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(3, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Subscribe before stopping node3 so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 so it is unreachable at co-signer reachability-probe time.
    println!("Stopping node3 to simulate offline node during PSS refresh...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    println!("Waiting for organic PSS refresh EventReportAccepted on chain...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(180), |event| {
            event.report_type == "node_offline" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("Refresh transport should organically report unreachable node3");

    println!(
        "Refresh report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 3,
        "node3 should have exactly one report's worth of demerits (configured increment 3)"
    );
    println!("node3 demerit points: {demerits}");
}

/// Exercises the refresh **leader** being offline before any Prepare exists,
/// distinct from `test_refresh_offline_triggers_on_chain_report` above (which
/// stops the non-leader node3 mid-Prepare-fanout). Node1 is the canonical
/// refresh leader (lexicographically smallest node key). With node1 stopped
/// before `pss_interval` elapses, a non-leader's periodic health check forwards
/// `StartRefresh` to the dead leader and hits `PssOfflineStage::StartForward`
/// (`network.rs`) — a report path that fires before a Prepare is ever sent.
#[tokio::test]
#[serial_test::serial]
async fn test_refresh_leader_offline_before_preparation_triggers_on_chain_report() {
    println!(
        "Starting PSS refresh leader-offline-before-preparation reporting integration test..."
    );

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 5,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(3, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Subscribe before stopping node1 so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node1 — the canonical refresh leader — before any refresh attempt
    // begins, so the very first forwarded StartRefresh from node2/node3 finds
    // it unreachable and reports it via PssOfflineStage::StartForward.
    println!("Stopping node1 (refresh leader) before preparation begins...");
    network.stop_service(IntegrationTestNetwork::NODE1_SERVICE);

    println!("Waiting for organic PSS refresh EventReportAccepted on chain...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(180), |event| {
            event.report_type == "node_offline" && event.accused_node_key == NODE_KEY_1
        })
        .await
        .expect("Refresh transport should organically report unreachable leader node1");

    println!(
        "Refresh report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_1,
        "node1 (leader) should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_2, NODE_KEY_3].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    println!("Checking node1 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_1)
        .await
        .expect("query node1 demerits");
    assert_eq!(
        demerits, 3,
        "node1 should have exactly one report's worth of demerits (configured increment 3)"
    );
    println!("node1 demerit points: {demerits}");
}

/// Exercises the G1 stall→offline **report** path deterministically: a real `AbandonedPssSession`
/// is injected through the drain worker's own logic (`report_abandoned_pss_session`) naming node3
/// as the silent refresh dealer, with node3 stopped so the co-signer reachability probe passes and
/// the report is accepted. A real mid-ceremony crash can't be used because G1 and the send-failure
/// path emit byte-identical `node_offline` reports (same session_id) that dedupe against each other.
/// `pss_interval: 86400` means no background refresh runs, so the injected report is the only one —
/// making the demerit count deterministic.
#[tokio::test]
#[serial_test::serial]
async fn test_refresh_stall_offline_triggers_on_chain_report() {
    println!("Starting PSS refresh stall→offline reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Subscribe before stopping node3 so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 so the co-signer reachability probe finds it unreachable and accepts the report.
    // node3's on-chain NodeInfo (peer id) persists, so the report path still resolves it.
    println!("Stopping node3 so it is unreachable at co-signer probe time...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    // Inject a real AbandonedPssSession through the drain-worker path on node1, naming node3 as the
    // silent refresh dealer. This is the exact per-event logic the expiration sweep would drive.
    let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
        .await
        .expect("connect unsafe-testing client to node1");
    let session_id: u128 = 909_111_222_333_u128;
    unsafe_client
        .submit_pss_stall_offline_report(SubmitPssStallOfflineReportRequest {
            ring_id: RING_ID.to_string(),
            session_id: session_id.to_string(),
            peer_id: peer_addresses[2].clone(),
            ring_pk_hex: ring_pk_hex.clone(),
            new_peer_node_keys: Vec::new(),
            new_threshold: 0,
            bulletin_post_id: String::new(),
        })
        .await
        .expect("submit PSS stall offline report");
    println!("Injected abandoned-PSS-session offline attribution for node3.");

    println!("Waiting for stall→offline EventReportAccepted on chain (up to 180s)...");
    let event = sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(180))
        .await
        .expect("EventReportAccepted should be emitted after the PSS stall offline attribution");

    println!(
        "Stall→offline report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after a single stall offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_invalid_commitment_triggers_on_chain_report() {
    println!("Starting PSS refresh invalid-commitment reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 5,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch - update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    let dkg_node_endpoints: Vec<String> = endpoints[..3]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect();
    wait_for_ring_state_on_nodes(&dkg_node_endpoints, &ring_pk_hex, Duration::from_secs(60)).await;
    ensure_ring_index_on_nodes(&dkg_node_endpoints, &ring_pk_hex, RING_ID).await;

    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        RING_ID.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read finalized ring payload");
    let ring_payload: RingPayload =
        serde_json::from_slice(&payload_bytes).expect("parse finalized RingPayload");
    assert_eq!(
        ring_payload.ring_pk, ring_pk_hex,
        "ring payload should contain finalized ring_pk"
    );

    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
        .await
        .expect("connect unsafe-testing client to node1");

    // The report is built from the ring + the signed statement, not from a live DKG session, so we
    // inject once with a fixed request_id (it only serves as the on-chain session dedupe key). This
    // avoids racing a healthy same-committee refresh, which completes before an injection targeting
    // its live session could land.
    let request_id: u128 = 777_000_111_222_u128;
    let evidence = signed_bad_refresh_commitment(
        chain_config.chain_id.clone(),
        RING_ID.to_string(),
        &ring_payload,
        request_id,
        NODE_KEY_3,
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

    println!("Waiting for invalid-refresh-commitment EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("invalid-refresh-commitment EventReportAccepted should be emitted");

    println!(
        "Invalid-refresh-commitment report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused invalid refresh dealer"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the invalid refresh commitment report"
    );
}

/// Exercises organic Reshare transport reporting through a pure-new leader.
/// Node4 leads a pending committee containing one unreachable member, relays
/// the terminal preparation candidate to a current signer, and the resulting
/// `node_offline` report lands on chain.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_offline_triggers_on_chain_report() {
    println!("Starting PSS reshare offline reporting integration test...");

    // pss_interval=86400 prevents any PSS refresh from firing during the test window.
    // After DKG, Phase 4 writes last_pss=now_secs, so elapsed≈0 which is far below
    // 86400 — the scheduler always skips refresh and never acquires the PSS claim.
    // Reshare bypasses the pss_interval check entirely, so it still fires immediately
    // once new_peer_node_keys is announced on-chain.
    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 3)
                }],
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );
    let peer4_addr = IntegrationTestNetwork::transform_p2p_address(
        &node4_info.p2p_address,
        IntegrationTestNetwork::NODE4_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr, peer4_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Subscribe before announcing the pending committee so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // node4 sorts before the synthetic offline key and is not in the current
    // committee, making it the pure-new canonical Reshare leader.
    println!("Triggering ring reshare to [node4, offline] threshold=1...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        vec![NODE_KEY_4.to_string(), NODE_KEY_OFFLINE.to_string()],
        Some(1u32),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    // Verify MsgStartRingReshareByAcp actually updated the ring state on-chain.
    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        RING_ID.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring payload after reshare announcement");
    let ring_payload: RingPayload =
        serde_json::from_slice(&payload_bytes).expect("parse RingPayload");
    assert!(
        ring_payload.new_peer_node_keys.is_some(),
        "MsgStartRingReshareByAcp returned success but ring's new_peer_node_keys is still None \
         — the reshare was not announced on-chain"
    );
    assert_eq!(
        ring_payload
            .new_peer_node_keys
            .as_ref()
            .map(|keys| sorted_node_keys(keys)),
        Some(sorted_node_keys(&[
            NODE_KEY_4.to_string(),
            NODE_KEY_OFFLINE.to_string(),
        ])),
        "reshare should target the pure-new leader and offline member"
    );
    println!("Reshare announced on-chain.");

    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(180), |event| {
            event.report_type == "node_offline" && event.accused_node_key == NODE_KEY_OFFLINE
        })
        .await
        .expect("pure-new Reshare leader should relay the organic offline observation");

    println!(
        "Reshare report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_OFFLINE,
        "the unreachable pending member should be accused"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3].contains(&event.reporter_node_key.as_str()),
        "a current signer should submit the relayed report"
    );

    println!("Checking offline pending-member demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_OFFLINE)
        .await
        .expect("query offline-node demerits");
    assert_eq!(
        demerits, 1,
        "the offline pending member should receive exactly one report's worth of demerits"
    );
    println!("offline pending-member demerit points: {demerits}");
}

/// Exercises a pure-new reshare receiver (node4) stalling on a silent **old**
/// dealer (node3), distinct from `test_reshare_offline_triggers_on_chain_report`
/// above (which accuses a pending-new member that never comes up at all). Old
/// committee [1,2,3] threshold=2 so the surviving [1,2] can still co-sign a
/// report accusing node3 (chain requires current signing threshold >= 2 and
/// reachable while excluding the accused). New committee [2,4]: node2 is a
/// DealerReceiver (in both committees) and node4 is a pure Receiver — both
/// independently stall waiting on node3's share once it goes silent, so either
/// may win the report race; this asserts the organic end-to-end outcome rather
/// than pinning which node's stall-detection fired first.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_pure_new_receiver_stalled_on_old_dealer_triggers_on_chain_report() {
    println!("Starting PSS reshare pure-new-receiver-stalled-on-old-dealer reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(3, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );
    let peer4_addr = IntegrationTestNetwork::transform_p2p_address(
        &node4_info.p2p_address,
        IntegrationTestNetwork::NODE4_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr, peer4_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Subscribe before announcing the reshare so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    println!("Triggering ring reshare to [node2, node4] threshold=1...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        vec![NODE_KEY_2.to_string(), NODE_KEY_4.to_string()],
        Some(1u32),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    // Wait for node4 (the pure-new receiver) to have claimed an active PSS
    // session for this ring — proof it has processed the leader's Prepare —
    // then give the topology-probe/activation barrier a little more time to
    // clear on its own. Session-claim happens at Prepare-receipt, which is
    // earlier than topology-probe completion; stopping node3 before topology
    // acks land would abort the whole ceremony at the topology barrier
    // instead of exercising the share-stall path this test targets.
    println!("Waiting for node4 to join the reshare ceremony...");
    wait_for_active_pss_session(endpoints[3], &ring_pk_hex, Duration::from_secs(60)).await;
    sleep(Duration::from_secs(5)).await;

    // Stop node3 — an old-only dealer, not part of the new committee — so
    // node2 (DealerReceiver) and node4 (pure Receiver) both stall waiting on
    // its share.
    println!("Stopping node3 (old dealer) after the reshare ceremony has started...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    println!("Waiting for organic PSS reshare EventReportAccepted on chain (up to 300s)...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(300), |event| {
            event.report_type == "node_offline" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("stalled reshare should organically report the silent old dealer");

    println!(
        "Reshare report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 (silent old dealer) should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be a surviving current-committee co-signer, got {}",
        event.reporter_node_key
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 3,
        "node3 should have exactly one report's worth of demerits (configured increment 3)"
    );
    println!("node3 demerit points: {demerits}");
}

/// Verifies the reshare bad-DKG-share relay path: a pure-new receiver (node4) that
/// gets provably-bad reshare evidence relays it to the current committee, which
/// re-verifies, threshold-signs an `invalid_crypto_response` report, and lands it
/// on chain while the reshare is still pending.
///
/// Reshare bad-share reports are only valid while the ring is in the
/// pending-reshare state (PendingNew scope resolution node-side and the ring-state
/// digest check chain-side), and a reshare among healthy nodes completes within
/// seconds — closing that window before the relay/co-sign/tx pipeline can finish.
/// To hold the window open deterministically, the new committee includes
/// NODE_KEY_OFFLINE, which has genesis-seeded NodeInfo but no running node: a
/// dealer only completes once *every* new member acks its share, so the
/// participant set never freezes and the ring stays pending for the whole test.
/// This mirrors a real production state — a reshare stalled on an offline new
/// member — during which misbehaving dealers must still be reportable. (A bad
/// dealer in a reshare that *does* complete is intentionally unreportable: it is
/// being rotated out anyway.)
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_bad_dkg_share_relay_triggers_on_chain_report() {
    println!("Starting PSS reshare bad DKG-share relay reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }],
                // The offline member has no container; seed its NodeInfo so the
                // chain accepts it as a reshare target and nodes can resolve a
                // (syntactically valid, unreachable) route for it.
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node4_endpoint = endpoints[3].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer_addresses = [
        IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node4_info.p2p_address,
            IntegrationTestNetwork::NODE4_SERVICE,
        ),
    ];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let initial_node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &initial_node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let dkg_node_endpoints: Vec<String> = endpoints[..3]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect();
    wait_for_ring_state_on_nodes(&dkg_node_endpoints, &ring_pk_hex, Duration::from_secs(60)).await;
    ensure_ring_index_on_nodes(&dkg_node_endpoints, &ring_pk_hex, RING_ID).await;

    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // NODE_KEY_OFFLINE never acks its shares, so no dealer ever completes and the
    // ring stays in the pending-reshare state (see the test doc comment).
    let reshare_node_keys = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
        NODE_KEY_OFFLINE.to_string(),
    ];
    let reshare_threshold = 2u32;

    println!("Triggering ring reshare to node1/node2/node4/offline, threshold=2...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        reshare_node_keys.clone(),
        Some(reshare_threshold),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        RING_ID.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring payload after reshare announcement");
    let ring_payload: RingPayload =
        serde_json::from_slice(&payload_bytes).expect("parse RingPayload");
    assert_eq!(
        ring_payload
            .new_peer_node_keys
            .as_ref()
            .map(|node_keys| sorted_node_keys(node_keys)),
        Some(sorted_node_keys(&reshare_node_keys)),
        "reshare should target node1/node2/node4"
    );
    assert_eq!(
        ring_payload.new_threshold,
        Some(reshare_threshold),
        "reshare should target threshold 2"
    );

    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);
    let (node1_session_id, node2_session_id, node4_session_id) = tokio::join!(
        wait_for_active_pss_session(endpoints[0], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[1], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(&node4_endpoint, &local_ring_key, Duration::from_secs(180)),
    );
    assert_eq!(
        node2_session_id, node1_session_id,
        "node2 should join the same active reshare session as node1"
    );
    assert_eq!(
        node4_session_id, node1_session_id,
        "node4 should join the same active reshare session as current signers"
    );
    let session_id = node4_session_id
        .parse::<u128>()
        .expect("active PSS session id should parse");
    println!("node4 active reshare session: {session_id}");

    let evidence = signed_bad_reshare_dkg_share(
        chain_config.chain_id.clone(),
        RING_ID.to_string(),
        &ring_payload,
        session_id,
        NODE_KEY_3,
        NODE3_SIGNING_KEY_HEX,
        NODE_KEY_4,
    );

    let mut unsafe_client = UnsafeTestingServiceClient::connect(node4_endpoint)
        .await
        .expect("connect unsafe-testing client to node4");
    unsafe_client
        .submit_dkg_invalid_share_evidence(SubmitDkgInvalidShareEvidenceRequest {
            session_id: session_id.to_string(),
            signed_share_json: serde_json::to_vec(&evidence).expect("serialize signed evidence"),
        })
        .await
        .expect("submit bad DKG-share evidence through pure-new receiver");

    println!("Waiting for DKG bad-share EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("DKG bad-share EventReportAccepted should be emitted");

    println!(
        "DKG bad-share report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused bad-share dealer"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the DKG bad-share report"
    );
}

/// Verifies the reshare DKG-commitment equivocation relay path: a pure-new
/// receiver (node4) receives two conflicting, signed commitments from an
/// old-committee dealer (node3) and relays them to the current committee, which
/// re-verifies, threshold-signs an `invalid_crypto_response` report, and submits
/// it while the reshare is still pending.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_dkg_equivocation_triggers_on_chain_report() {
    println!("Starting PSS reshare DKG equivocation reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }],
                // The offline member has no container; seed its NodeInfo so the
                // chain accepts it as a reshare target and nodes can resolve a
                // syntactically valid, unreachable route for it.
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node4_endpoint = endpoints[3].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer_addresses = [
        IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node4_info.p2p_address,
            IntegrationTestNetwork::NODE4_SERVICE,
        ),
    ];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let initial_node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &initial_node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch - update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let dkg_node_endpoints: Vec<String> = endpoints[..3]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect();
    wait_for_ring_state_on_nodes(&dkg_node_endpoints, &ring_pk_hex, Duration::from_secs(60)).await;
    ensure_ring_index_on_nodes(&dkg_node_endpoints, &ring_pk_hex, RING_ID).await;

    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // NODE_KEY_OFFLINE never acks its shares, so no dealer ever completes and the
    // ring stays in the pending-reshare state.
    let reshare_node_keys = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
        NODE_KEY_OFFLINE.to_string(),
    ];
    let reshare_threshold = 2u32;

    println!("Triggering ring reshare to node1/node2/node4/offline, threshold=2...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        reshare_node_keys.clone(),
        Some(reshare_threshold),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        RING_ID.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring payload after reshare announcement");
    let ring_payload: RingPayload =
        serde_json::from_slice(&payload_bytes).expect("parse RingPayload");
    assert_eq!(
        ring_payload
            .new_peer_node_keys
            .as_ref()
            .map(|node_keys| sorted_node_keys(node_keys)),
        Some(sorted_node_keys(&reshare_node_keys)),
        "reshare should target node1/node2/node4/offline"
    );
    assert_eq!(
        ring_payload.new_threshold,
        Some(reshare_threshold),
        "reshare should target threshold 2"
    );

    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);
    let (node1_session_id, node2_session_id, node4_session_id) = tokio::join!(
        wait_for_active_pss_session(endpoints[0], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[1], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(&node4_endpoint, &local_ring_key, Duration::from_secs(180)),
    );
    assert_eq!(
        node2_session_id, node1_session_id,
        "node2 should join the same active reshare session as node1"
    );
    assert_eq!(
        node4_session_id, node1_session_id,
        "node4 should join the same active reshare session as current signers"
    );
    let session_id = node4_session_id
        .parse::<u128>()
        .expect("active PSS session id should parse");
    println!("node4 active reshare session: {session_id}");

    let (commitment_a, commitment_b) = signed_equivocation_commitments(
        chain_config.chain_id.clone(),
        RING_ID.to_string(),
        &ring_payload,
        session_id,
        NODE_KEY_3,
        NODE3_SIGNING_KEY_HEX,
    );

    let mut unsafe_client = UnsafeTestingServiceClient::connect(node4_endpoint)
        .await
        .expect("connect unsafe-testing client to node4");
    unsafe_client
        .submit_dkg_equivocation_evidence(SubmitDkgEquivocationEvidenceRequest {
            session_id: session_id.to_string(),
            commitment_a_json: serde_json::to_vec(&commitment_a)
                .expect("serialize commitment_a evidence"),
            commitment_b_json: serde_json::to_vec(&commitment_b)
                .expect("serialize commitment_b evidence"),
        })
        .await
        .expect("submit DKG equivocation evidence through pure-new receiver");

    println!("Waiting for DKG equivocation EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("DKG equivocation EventReportAccepted should be emitted");

    println!(
        "DKG equivocation report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused equivocation dealer"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the DKG equivocation report"
    );
}

/// Organic counterpart to `test_reshare_dkg_equivocation_triggers_on_chain_report`
/// above: instead of injecting a pre-signed conflicting-commitment pair directly
/// into node4's report pipeline, this makes node3 itself broadcast a second, real
/// Phase1 commitment through `SubmitOrganicConflictingCommitment` — the same
/// `build_and_store_commitment_evidence` + `submit_public_contribution` functions
/// the honest Phase1 flow uses, just with substituted bytes — so node4's (and any
/// other current signer's) *unmodified* production `record_public_batch`
/// conflict-detection path is what actually catches it. Ordering relative to
/// node3's own real automatic Phase1 commitment doesn't matter: the two are
/// independent broadcasts (this RPC never touches node3's own polynomial-generation
/// state), so whichever arrives first, the second is a genuine conflict either way.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_organic_dkg_equivocation_triggers_on_chain_report() {
    println!("Starting PSS reshare organic DKG equivocation reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }],
                // The offline member has no container; seed its NodeInfo so the
                // chain accepts it as a reshare target and nodes can resolve a
                // syntactically valid, unreachable route for it.
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node3_endpoint = endpoints[2].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer_addresses = [
        IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node4_info.p2p_address,
            IntegrationTestNetwork::NODE4_SERVICE,
        ),
    ];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let initial_node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &initial_node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let dkg_node_endpoints: Vec<String> = endpoints[..3]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect();
    wait_for_ring_state_on_nodes(&dkg_node_endpoints, &ring_pk_hex, Duration::from_secs(60)).await;
    ensure_ring_index_on_nodes(&dkg_node_endpoints, &ring_pk_hex, RING_ID).await;

    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // NODE_KEY_OFFLINE never acks its shares, so no dealer ever completes and the
    // ring stays in the pending-reshare state for the whole test.
    let reshare_node_keys = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
        NODE_KEY_OFFLINE.to_string(),
    ];
    let reshare_threshold = 2u32;

    println!("Triggering ring reshare to node1/node2/node4/offline, threshold=2...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        reshare_node_keys.clone(),
        Some(reshare_threshold),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);
    let (node1_session_id, node2_session_id, node3_session_id, node4_session_id) = tokio::join!(
        wait_for_active_pss_session(endpoints[0], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[1], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(&node3_endpoint, &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[3], &local_ring_key, Duration::from_secs(180)),
    );
    assert_eq!(
        node2_session_id, node1_session_id,
        "node2 should join the same active reshare session as node1"
    );
    assert_eq!(
        node3_session_id, node1_session_id,
        "node3 should join the same active reshare session as node1"
    );
    assert_eq!(
        node4_session_id, node1_session_id,
        "node4 should join the same active reshare session as current signers"
    );
    let session_id = node3_session_id
        .parse::<u128>()
        .expect("active PSS session id should parse");
    println!("node3 active reshare session: {session_id}");

    // A little headroom for node3's own real Phase1 commitment to also be in
    // flight — not required for correctness (see doc comment above), just
    // keeps this test's timeline closer to a real conflicting-broadcast window.
    sleep(Duration::from_secs(5)).await;

    println!("Making node3 organically broadcast a second, conflicting Phase1 commitment...");
    let mut node3_unsafe_client = UnsafeTestingServiceClient::connect(node3_endpoint)
        .await
        .expect("connect unsafe-testing client to node3");
    node3_unsafe_client
        .submit_organic_conflicting_commitment(SubmitOrganicConflictingCommitmentRequest {
            session_id: session_id.to_string(),
            commitment_bytes: vec![0x42; 32],
        })
        .await
        .expect("node3 should organically broadcast a conflicting commitment");

    println!("Waiting for organic DKG equivocation EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("organic DKG equivocation EventReportAccepted should be emitted");

    println!(
        "Organic DKG equivocation report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused equivocation dealer"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the organic DKG equivocation report"
    );
}

/// Exercises `dkg_public_origin_fault` (`InvalidPayload`) detection: node3
/// broadcasts a single, structurally-malformed Phase1 commitment (wrong byte
/// length) through the same `SubmitOrganicConflictingCommitment` RPC used by
/// the equivocation test above — but here the payload never needs to conflict
/// with a second commitment, because a length-invalid commitment fails
/// `prepare_commitment_message`'s preflight (`commitment.rs:72-78`) and is
/// rejected/reported before it is ever retained. That also means node3's own
/// real automatic Phase1 broadcast (whenever it happens to fire) can't turn
/// this into equivocation: nothing was ever recorded for it to conflict with.
/// Node4's (and any other current signer's) unmodified preflight-validation
/// path is what actually catches this, not evidence injected directly.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_organic_invalid_commitment_triggers_on_chain_report() {
    println!("Starting PSS reshare organic invalid-commitment reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }],
                // The offline member has no container; seed its NodeInfo so the
                // chain accepts it as a reshare target and nodes can resolve a
                // syntactically valid, unreachable route for it.
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node3_endpoint = endpoints[2].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer_addresses = [
        IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node4_info.p2p_address,
            IntegrationTestNetwork::NODE4_SERVICE,
        ),
    ];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let initial_node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &initial_node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let dkg_node_endpoints: Vec<String> = endpoints[..3]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect();
    wait_for_ring_state_on_nodes(&dkg_node_endpoints, &ring_pk_hex, Duration::from_secs(60)).await;
    ensure_ring_index_on_nodes(&dkg_node_endpoints, &ring_pk_hex, RING_ID).await;

    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // NODE_KEY_OFFLINE never acks its shares, so no dealer ever completes and the
    // ring stays in the pending-reshare state for the whole test.
    let reshare_node_keys = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
        NODE_KEY_OFFLINE.to_string(),
    ];
    let reshare_threshold = 2u32;

    println!("Triggering ring reshare to node1/node2/node4/offline, threshold=2...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        reshare_node_keys.clone(),
        Some(reshare_threshold),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);
    let (node1_session_id, node2_session_id, node3_session_id, node4_session_id) = tokio::join!(
        wait_for_active_pss_session(endpoints[0], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[1], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(&node3_endpoint, &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[3], &local_ring_key, Duration::from_secs(180)),
    );
    assert_eq!(
        node2_session_id, node1_session_id,
        "node2 should join the same active reshare session as node1"
    );
    assert_eq!(
        node3_session_id, node1_session_id,
        "node3 should join the same active reshare session as node1"
    );
    assert_eq!(
        node4_session_id, node1_session_id,
        "node4 should join the same active reshare session as current signers"
    );
    let session_id = node3_session_id
        .parse::<u128>()
        .expect("active PSS session id should parse");
    println!("node3 active reshare session: {session_id}");

    println!("Making node3 organically broadcast a structurally invalid Phase1 commitment...");
    let mut node3_unsafe_client = UnsafeTestingServiceClient::connect(node3_endpoint)
        .await
        .expect("connect unsafe-testing client to node3");
    node3_unsafe_client
        .submit_organic_conflicting_commitment(SubmitOrganicConflictingCommitmentRequest {
            session_id: session_id.to_string(),
            // Not a multiple of G1_COMPRESSED_SIZE — fails `prepare_commitment_
            // message`'s length check before anything is ever retained.
            commitment_bytes: vec![0x42; 7],
        })
        .await
        .expect("node3 should organically broadcast an invalid commitment");

    println!("Waiting for organic invalid-commitment EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_3
        })
        .await
        .expect("organic invalid-commitment EventReportAccepted should be emitted");

    println!(
        "Organic invalid-commitment report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused invalid-commitment dealer"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the organic invalid-commitment report"
    );
}

/// Exercises `dkg_leader_equivocation` detection: node1 (the real canonical
/// leader for this reshare) uses `SubmitOrganicConflictingManifest` to
/// broadcast a second Phase1-Commitments manifest with the same phase_root and
/// contribution_ids as the one it already published for real (so it passes the
/// receiver's own self-consistency recheck) but a different chunk_count —
/// organically exercising node2/node4's *unmodified* `PublicBatchAssembler::
/// insert_manifest` conflict detection (`network.rs`) instead of injecting
/// evidence directly. The underlying signed contributions can't be forged
/// without their original signer's key, so chunk_count is the one field a
/// leader fully controls independent of them — matching what the RPC actually
/// exploits.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_organic_leader_manifest_equivocation_triggers_on_chain_report() {
    println!(
        "Starting PSS reshare organic leader-manifest-equivocation reporting integration test..."
    );

    let network = IntegrationTestNetwork::builder()
        .with_node_count(4)
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[], 10)
                }],
                // The offline member has no container; seed its NodeInfo so the
                // chain accepts it as a reshare target and nodes can resolve a
                // syntactically valid, unreachable route for it.
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node1_endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");
    let node4_info = cli_tool::query_node_info(endpoints[3].to_string())
        .await
        .expect("query node4 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");
    assert_eq!(node4_info.node_key, NODE_KEY_4, "node4 key mismatch");

    let peer_addresses = [
        IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node4_info.p2p_address,
            IntegrationTestNetwork::NODE4_SERVICE,
        ),
    ];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let initial_node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &initial_node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4]
        .iter()
        .zip(&peer_addresses)
    {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let dkg_node_endpoints: Vec<String> = endpoints[..3]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect();
    wait_for_ring_state_on_nodes(&dkg_node_endpoints, &ring_pk_hex, Duration::from_secs(60)).await;
    ensure_ring_index_on_nodes(&dkg_node_endpoints, &ring_pk_hex, RING_ID).await;

    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // NODE_KEY_OFFLINE never acks its shares, so no dealer ever completes and the
    // ring stays in the pending-reshare state for the whole test. Phase1
    // Commitments itself still completes normally (all 3 old dealers are real
    // and reachable), which is all this test needs.
    let reshare_node_keys = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
        NODE_KEY_OFFLINE.to_string(),
    ];
    let reshare_threshold = 2u32;

    // node1 sorts before node2/node4/offline, making it the canonical reshare
    // leader — the only node that legitimately publishes Phase1 manifests.
    println!("Triggering ring reshare to node1/node2/node4/offline, threshold=2...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        reshare_node_keys.clone(),
        Some(reshare_threshold),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);
    let (node1_session_id, node2_session_id, node3_session_id, node4_session_id) = tokio::join!(
        wait_for_active_pss_session(&node1_endpoint, &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[1], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[2], &local_ring_key, Duration::from_secs(180)),
        wait_for_active_pss_session(endpoints[3], &local_ring_key, Duration::from_secs(180)),
    );
    assert_eq!(
        node2_session_id, node1_session_id,
        "node2 should join the same active reshare session as node1"
    );
    assert_eq!(
        node3_session_id, node1_session_id,
        "node3 should join the same active reshare session as node1"
    );
    assert_eq!(
        node4_session_id, node1_session_id,
        "node4 should join the same active reshare session as node1"
    );
    let session_id = node1_session_id
        .parse::<u128>()
        .expect("active PSS session id should parse");
    println!("node1 active reshare session: {session_id}");

    // Give Phase1 Commitments time to actually complete and the real manifest
    // to be published — session-active only means Prepare has been processed,
    // not that all 3 dealers' commitments have landed and been assembled yet.
    sleep(Duration::from_secs(10)).await;

    println!("Making node1 (leader) organically broadcast a conflicting Phase1 manifest...");
    let mut node1_unsafe_client = UnsafeTestingServiceClient::connect(node1_endpoint)
        .await
        .expect("connect unsafe-testing client to node1");
    node1_unsafe_client
        .submit_organic_conflicting_manifest(SubmitOrganicConflictingManifestRequest {
            session_id: session_id.to_string(),
        })
        .await
        .expect("node1 should organically broadcast a conflicting manifest");

    println!(
        "Waiting for organic leader-manifest-equivocation EventReportAccepted on chain (up to 120s)..."
    );
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_1
        })
        .await
        .expect("organic leader-manifest-equivocation EventReportAccepted should be emitted");

    println!(
        "Organic leader-manifest-equivocation report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_1,
        "node1 (leader) should be the accused for equivocating on its own manifest"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        [NODE_KEY_2, NODE_KEY_3].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_1)
        .await
        .expect("query node1 demerits");
    assert_eq!(
        demerits, 1,
        "node1 should have exactly one demerit after the organic leader-manifest-equivocation report"
    );
}

/// Exercises `dkg_public_origin_fault` (`InvalidPayload`) detection on the
/// *last* public phase of a refresh: node1 (the real canonical leader), after
/// a healthy refresh completes normally, uses `SubmitOrganicInvalidRefreshResult`
/// to broadcast a second `RefreshHealthCheckResult` whose parameters match its
/// own real staged candidate but whose `public_polynomial_sha256` is wrong —
/// organically exercising node2/node3's *unmodified* `verify_result_signature`
/// (`refresh_health_check.rs`), which rejects on content mismatch against their
/// own independently-staged candidate before ever touching the (placeholder,
/// not real) signature bytes.
///
/// Unlike the reshare-based tests above, refresh has no "pending forever" knob
/// (no offline new-committee member to hold it open), so this lets a healthy
/// 3-node refresh complete fully and relies on `DKG_COMPLETED_SESSION_TTL`
/// (5 minutes) to keep the completed session's `transport_attempt` and staged
/// `refresh.candidate` resolvable long enough to fire the RPC afterward — no
/// production code path was found that clears the candidate on natural
/// completion, but this wasn't verified by actually running the ceremony.
#[tokio::test]
#[serial_test::serial]
async fn test_refresh_organic_invalid_result_triggers_on_chain_report() {
    println!("Starting PSS refresh organic invalid-result reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 5,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(3, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node1_endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);

    // Subscribe before the automatic refresh fires so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    println!("Waiting for the automatic PSS refresh to start (node1 is the canonical leader)...");
    let session_id =
        wait_for_active_pss_session(&node1_endpoint, &local_ring_key, Duration::from_secs(60))
            .await;

    // No offline member is available to hold refresh open (unlike the reshare
    // tests above), so let it complete fully and rely on DKG_COMPLETED_SESSION_
    // TTL (5 minutes) to keep node1's transport_attempt/candidate resolvable.
    // Captured session_id above before completion: once the ceremony
    // completes, `rings_pss` (what GetActivePssSession itself reads) is
    // expected to clear even though the underlying session state doesn't.
    println!("Letting the healthy 3-node refresh complete naturally...");
    sleep(Duration::from_secs(30)).await;

    println!("Making node1 (leader) organically broadcast an invalid refresh result...");
    let mut node1_unsafe_client = UnsafeTestingServiceClient::connect(node1_endpoint)
        .await
        .expect("connect unsafe-testing client to node1");
    node1_unsafe_client
        .submit_organic_invalid_refresh_result(SubmitOrganicInvalidRefreshResultRequest {
            session_id,
        })
        .await
        .expect("node1 should organically broadcast an invalid refresh result");

    println!(
        "Waiting for organic invalid-refresh-result EventReportAccepted on chain (up to 120s)..."
    );
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_1
        })
        .await
        .expect("organic invalid-refresh-result EventReportAccepted should be emitted");

    println!(
        "Organic invalid-refresh-result report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_1,
        "node1 (leader) should be the accused for broadcasting an invalid refresh result"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(
        [NODE_KEY_2, NODE_KEY_3].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_1)
        .await
        .expect("query node1 demerits");
    assert_eq!(
        demerits, 3,
        "node1 should have exactly one report's worth of demerits (configured increment 3)"
    );
    println!("node1 demerit points: {demerits}");
}

/// Exercises `leader_prepare_fault` detection: node2 (a real current-committee
/// member, not the canonical leader) uses `SubmitOrganicNoncanonicalPrepare` to
/// build, sign, and broadcast a real refresh Prepare claiming itself as leader.
/// Node1 and node3's *unmodified* `prepare_participant` (`network.rs`) rejects
/// it and reports node2, rather than evidence being injected directly.
///
/// `pss_interval: 0` makes refresh due immediately once DKG's Phase4 sets
/// `last_pss`, and the RPC fires as soon as `wait_for_ring_finalized` returns —
/// racing node1's own background scheduler (`--reshare-interval-secs 5` in the
/// Docker image), which only wakes up every 5s. This is a timing heuristic, not
/// a hard guarantee: if node1's scheduler wins, its own legitimate refresh
/// claims the deterministic session first and the RPC fails loudly
/// (`AlreadyActive`) instead of silently passing without exercising anything.
#[tokio::test]
#[serial_test::serial]
async fn test_refresh_noncanonical_prepare_triggers_on_chain_report() {
    println!("Starting PSS refresh noncanonical-Prepare reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 0,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(3, &[], 3)
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();
    let node2_endpoint = endpoints[1].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );
    let local_ring_key = ring_key_from_ring_pk_hex(&ring_pk_hex);

    // Subscribe before racing node1's scheduler so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    println!("Making node2 organically broadcast a noncanonical Prepare...");
    let mut node2_unsafe_client = UnsafeTestingServiceClient::connect(node2_endpoint)
        .await
        .expect("connect unsafe-testing client to node2");
    node2_unsafe_client
        .submit_organic_noncanonical_prepare(SubmitOrganicNoncanonicalPrepareRequest {
            ring_id: RING_ID.to_string(),
            ring_pk: local_ring_key,
        })
        .await
        .expect(
            "node2 should organically broadcast a noncanonical Prepare \
             (if this fails with AlreadyActive, node1's own scheduler won the race — rerun)",
        );

    println!(
        "Waiting for organic leader-Prepare-fault EventReportAccepted on chain (up to 120s)..."
    );
    let event = sub
        .wait_for_report_accepted_matching(RING_ID, Duration::from_secs(120), |event| {
            event.report_type == "invalid_crypto_response" && event.accused_node_key == NODE_KEY_2
        })
        .await
        .expect("noncanonical Prepare should organically report node2");

    println!(
        "Noncanonical-Prepare report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(
        event.report_type, "invalid_crypto_response",
        "unexpected report_type"
    );
    assert_eq!(
        event.accused_node_key, NODE_KEY_2,
        "node2 (noncanonical Prepare sender) should be accused"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_3].contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current signer, got {}",
        event.reporter_node_key
    );

    println!("Checking node2 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_2)
        .await
        .expect("query node2 demerits");
    assert_eq!(
        demerits, 3,
        "node2 should have exactly one report's worth of demerits (configured increment 3)"
    );
    println!("node2 demerit points: {demerits}");
}

/// Verifies the on-chain kick + backup-node promotion flow: node3 starts with
/// kick_threshold - 1 demerits seeded in genesis, a single accepted offline report
/// pushes it over the threshold, and the chain schedules an auto-reshare that swaps
/// node3 out for the backup node in the ring's `new_peer_node_keys`.
///
/// Reshare completion is out of scope: NODE_KEY_4 has no running node, so the test
/// asserts the announced pending committee, not the finalized one.
#[tokio::test]
#[serial_test::serial]
async fn test_report_kick_promotes_backup_node() {
    println!("Starting backup-node promotion integration test...");

    // Demerits reset once reset_interval_seconds elapse after window_started_at, so
    // anchor the seeded window at test start to keep the seed live for the whole run.
    let window_started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": reporting_genesis_json(1, &[NODE_KEY_4], 3)
                }],
                // The backup node has no running container; seed its NodeInfo so the
                // chain considers it eligible for promotion (registered + whitelisted).
                "node_infos": [{
                    "node_key": NODE_KEY_4,
                    "node_info": {
                        "peer_id": "backup-node-4-peer-id",
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }],
                // Seed node3 at kick_threshold - 1 so a single accepted report kicks it.
                "node_demerits": [{
                    "ring_id": RING_ID,
                    "node_key": NODE_KEY_3,
                    "points": 2,
                    "window_started_at": window_started_at
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1)).await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    // Sanity check: the genesis-seeded demerits for node3 are visible on-chain.
    let seeded_demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query seeded node3 demerits");
    assert_eq!(
        seeded_demerits, 2,
        "genesis should seed node3 with kick_threshold - 1 demerits"
    );

    let governance_policy_id =
        create_ring_governance_with_ring(&controller_client, RING_ID, &node_keys).await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, DKG_FINALIZE_WAIT_TIMEOUT).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Set up ACP policy and a secret so PRE has something to decrypt.
    let resource = "document".to_string();
    let permission = "read".to_string();
    let did_pk_string = "backup-kick-test-did".to_string();
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("add policy");

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));

    let prepared = cli_tool::prepare_secret(
        b"backup-kick-test-secret",
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    let store_result = store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        RING_ID.to_string(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    let object_id = store_result.object_id.clone();

    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await
    .expect("register object");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did_pk_string.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set relationship");

    // Subscribe before stopping node3 to avoid missing the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 to trigger an offline observation during PRE.
    println!("Stopping node3 to simulate offline node...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    // PRE succeeds with 2/3 shares (threshold=2) and fires an offline report for node3.
    println!("Triggering PRE (expects success with node3 offline)...");
    let _plaintext = pre_with_retry(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        reader_sk_hex.clone(),
        object_id.clone(),
        did_pk_string.clone(),
    )
    .await;
    println!("PRE succeeded (2/3 shares collected).");

    println!("Waiting for EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("EventReportAccepted should be emitted");

    println!(
        "Report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");

    // The kick happens in the same tx as the threshold-crossing report; poll briefly
    // for the auto-reshare announcement to land in queryable state.
    println!("Waiting for auto-reshare announcement on the ring...");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ring = loop {
        let ring = controller_client
            .orbis_read_ring(RING_ID)
            .await
            .expect("read ring")
            .expect("ring should exist");
        if !ring.new_peer_node_keys.is_empty() {
            break ring;
        }
        assert!(
            Instant::now() < deadline,
            "ring never announced new_peer_node_keys after the kick-threshold report"
        );
        sleep(Duration::from_secs(1)).await;
    };

    // The chain stores the pending committee in canonical (sorted) order.
    let mut expected_committee = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
    ];
    expected_committee.sort();
    assert_eq!(
        ring.new_peer_node_keys, expected_committee,
        "pending committee should swap node3 out for the backup node"
    );
    assert!(
        !ring.new_peer_node_keys.contains(&NODE_KEY_3.to_string()),
        "kicked node3 must not be in the pending committee"
    );
    assert!(
        ring.peer_node_keys.contains(&NODE_KEY_3.to_string()),
        "active committee is unchanged until the reshare finalizes"
    );
    assert!(
        ring.new_threshold.is_none(),
        "auto-reshare must not change the threshold"
    );
    let reporting = ring.reporting.expect("ring reporting config");
    assert!(
        !reporting.backup_node_keys.contains(&NODE_KEY_4.to_string()),
        "promoted backup key should be consumed from backup_node_keys"
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert!(
        demerits >= 3,
        "node3 demerits should be at least kick_threshold (3), got {demerits}"
    );
    println!("node3 demerit points: {demerits} — backup promotion verified.");
}
