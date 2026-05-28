//! Docker-based integration test: full DKG + PRE + SIGN flow.
//!
//! Spins up a full Docker Compose environment (SourceHub + 3 orbis-node containers)
//! and exercises the complete DKG → StoreSecret → PRE workflow via CLI commands.
//!
//! Run with:
//!   cargo test --features integration-test -- --nocapture

use crate::helpers::test_helpers::{BULLETIN_RING_NAMESPACE, TEST_FRESH_DKG_RING_ID};
use bulletin::r#trait::{
    BulletinKind, BulletinPost, BulletinWriteKind, DocumentPayload, RingPayload,
};
use common::IntegrationTestNetwork;
use common::SOURCEHUB_RPC_URL;
use crypto::helpers::generate_keypair;
use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, SignImpl};
use tokio::time::{sleep, Duration, Instant};

#[derive(Clone, Debug)]
struct RingStateSnapshot {
    public_polynomial: String,
    last_pss: u64,
}

/// Docker-based integration test: Run DKG and PRE using Docker Compose
///
/// This test spins up a full integration environment with:
/// - SourceHub chain
/// - 3 Orbis nodes
///
/// Then runs the full DKG -> PRE workflow via CLI commands.
#[tokio::test]
#[serial_test::serial]
async fn test_cli_calls_dkg_and_pre_endpoint() {
    // use tracing_subscriber;
    // // Initialize tracing for debugging
    // let _ = tracing_subscriber::fmt()
    //     .with_max_level(tracing::Level::DEBUG)
    //     .with_test_writer()
    //     .try_init();

    println!("Starting Docker-based integration test...");

    // Start the full integration network (sourcehub + 3 nodes)
    let _network = IntegrationTestNetwork::new();

    // Wait for all nodes to be ready by polling their gRPC endpoints
    crate::helpers::test_helpers::wait_for_nodes_ready(
        &[
            IntegrationTestNetwork::NODE1_GRPC,
            IntegrationTestNetwork::NODE2_GRPC,
            IntegrationTestNetwork::NODE3_GRPC,
        ],
        90,
        Duration::from_secs(1),
    )
    .await;

    // Query node info from all three nodes to get their peer IDs
    let node1_info = cli_tool::query_node_info(IntegrationTestNetwork::NODE1_GRPC.to_string())
        .await
        .expect("Failed to query node1 info");
    let node2_info = cli_tool::query_node_info(IntegrationTestNetwork::NODE2_GRPC.to_string())
        .await
        .expect("Failed to query node2 info");
    let node3_info = cli_tool::query_node_info(IntegrationTestNetwork::NODE3_GRPC.to_string())
        .await
        .expect("Failed to query node3 info");
    let node1_address = node1_info.public_address.clone();
    println!("Node 1 P2P address: {}", node1_info.p2p_address);
    println!("Node 2 P2P address: {}", node2_info.p2p_address);
    println!("Node 3 P2P address: {}", node3_info.p2p_address);

    // Transform P2P addresses for inter-container communication
    // The addresses from nodes will be like "peer_id@0.0.0.0:port"
    // We need to replace 0.0.0.0 with the container name for Docker networking
    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_CONTAINER,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_CONTAINER,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_CONTAINER,
    );

    println!("Transformed peer addresses for Docker networking:");
    println!("  Node 1: {}", peer1_addr);
    println!("  Node 2: {}", peer2_addr);
    println!("  Node 3: {}", peer3_addr);

    let peer_ids = vec![peer1_addr, peer2_addr, peer3_addr];
    let threshold = 2;
    let endpoint = IntegrationTestNetwork::NODE1_GRPC.to_string();
    let node_endpoints = [
        IntegrationTestNetwork::NODE1_GRPC.to_string(),
        IntegrationTestNetwork::NODE2_GRPC.to_string(),
        IntegrationTestNetwork::NODE3_GRPC.to_string(),
    ];

    // Step 1: Run DKG via CLI to get a ring public key
    //
    // Subscribe to chain events BEFORE starting DKG to avoid race conditions.
    // The DKG coordinator will post the ring payload to the bulletin with the
    // session_id as the artifact, emitting an EventPostCreated event.
    println!("Connecting to chain WebSocket for event subscription...");
    let event_subscription =
        common::blockchain::events::BulletinEventSubscription::connect(SOURCEHUB_RPC_URL)
            .await
            .expect("WebSocket event subscription");

    // Create the ring governance ACP policy before DKG so it can be embedded in the ring
    // payload. The Orbis keeper checks `update_ring` permission on this policy when
    // MsgUpdateRingByAcp is called. Registering the namespace object makes the signer the
    // `owner`, which grants `update_ring` via the policy's permission expression.
    let _ring_policy_id = cli_tool::add_ring_governance_policy(BULLETIN_RING_NAMESPACE)
        .await
        .expect("create ring governance policy");

    println!(
        "Starting DKG with threshold {} and {} peers...",
        threshold,
        peer_ids.len()
    );
    // pss_interval = 1s so the PSS scheduler (5s check interval in docker-compose) fires a
    // refresh shortly after DKG completes.
    let dkg_result = cli_tool::do_dkg(endpoint.clone(), TEST_FRESH_DKG_RING_ID.to_string()).await;
    assert!(
        dkg_result.is_ok(),
        "DKG should succeed: {:?}",
        dkg_result.err()
    );

    let dkg_result = dkg_result.unwrap();
    let session_id = dkg_result.session_id.clone();
    println!(
        "DKG initiated (session_id: {}), waiting for completion event...",
        session_id
    );

    // Wait for the event matching our session_id artifact
    let post_event = event_subscription
        .wait_for_artifact(&session_id, Duration::from_secs(60))
        .await
        .expect("DKG completion event");

    // Read the post payload using the post_id from the event
    let post_payload = cli_tool::read_bulletin_post(post_event.ring_id.clone(), BulletinKind::Ring)
        .await
        .expect("read ring post by event post_id");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk.clone();
    let ring_id = post_event.ring_id.clone();
    let dkg_ring_payload = ring_payload.clone();

    // The bulletin event proves the DKG was posted, but the other nodes may
    // still be finishing their local Phase 4 writes. Wait until every node can
    // serve the local ring state, then use each node's own state as the refresh
    // baseline.
    let initial_ring_states = wait_for_ring_state_on_all_nodes(
        &node_endpoints,
        &ring_pk_hex,
        Duration::from_secs(60),
        Duration::from_millis(500),
    )
    .await;

    println!(
        "DKG completed! Ring PK: {}..., Ring ID: {}",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    // Step 2: Generate reader keypair (uses selected curve impl from crypto crate)
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");

    let reader_sk_bytes = CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk");
    let reader_pk_bytes = CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk");
    let reader_sk_hex = hex::encode(&reader_sk_bytes);
    let reader_pk_hex = hex::encode(&reader_pk_bytes);

    let resource = "document".to_string();
    let relation = "reader".to_string();
    let permission = "read".to_string();
    let did_pk_string = "test_did_secret".to_string();
    let tier = Some("tier".to_string());
    let timestamp = Some(100u64);
    let valid_window_start = Some(50u64);
    let valid_window_end = Some(150u64);
    let salt = Some("salt".to_string());
    let policy_id = cli_tool::add_policy_to_chain().await.expect("policy_id");

    // ====================================================================
    // Create objects: MANUAL vs SERVICE
    // Both paths encrypt locally first, then post to bulletin
    // ====================================================================

    // Parse ring public key for encryption
    let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring_pk hex");
    let ring_pk_point = GroupAffine::from_bytes(&ring_pk_bytes).expect("deserialize ring_pk");

    // MANUAL PATH: Encrypt and post directly to bulletin
    let object_id_manual = {
        let metadata =
            PreImpl::encode_metadata(&policy_id, &resource, &permission, None, None, None);
        let (_enc_cmt, encrypted_secret, enc_proof) = PreImpl::encrypt_secret(
            &ring_pk_point,
            b"Hello from manual path!",
            None,
            Some(&metadata),
        )
        .expect("encrypt secret");
        let payload = DocumentPayload {
            ring_id: ring_id.clone(),
            document: serde_json::to_string(&encrypted_secret).expect("serialize"),
            proof: String::try_from(enc_proof).expect("serialize proof"),
            policy_id: policy_id.clone(),
            resource: resource.clone(),
            permission: permission.clone(),
            tier: tier.clone(),
            timestamp,
        };
        let serialized: Vec<u8> = payload.try_into().expect("serialize payload");
        cli_tool::create_bulletin_post(BulletinWriteKind::Document, serialized)
            .await
            .expect("create_bulletin_post")
    };
    let secret = b"Hello from StoreSecret!";

    // SERVICE PATH: Prepare secret once (encrypt locally), then store
    // This allows testing idempotency by reusing the same prepared data
    let prepared_secret = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret should succeed");
    let derivation = b"test_derivation".to_vec();
    let prepared_secret_derived = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        Some(derivation.clone()),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        tier.clone(),
        timestamp,
        salt.clone(),
    )
    .expect("prepare_secret should succeed");

    // Get sequence before first store to verify transaction is broadcast
    let sequence_before_first = cli_tool::get_account_sequence(&node1_address)
        .await
        .expect("get sequence before first store");
    println!(
        "Node1 sequence before first store: {}",
        sequence_before_first
    );

    let object_response = store_prepared_secret_expect_success(
        "initial StoreSecret",
        endpoint.clone(),
        &prepared_secret,
        ring_id.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        true,
        None,
        None,
    )
    .await;

    let object_id_service = object_response.object_id.clone();
    let signature_hex = object_response.signature.clone();

    let object_response_derived = store_prepared_secret_expect_success(
        "derived StoreSecret",
        endpoint.clone(),
        &prepared_secret_derived.clone(),
        ring_id.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        false,
        tier.clone(),
        timestamp,
    )
    .await;
    let object_id_derived = object_response_derived.object_id.clone();

    // Poll until sequence increments (confirms tx was broadcast and included in a block)
    let sequence_after_first = {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let seq = cli_tool::get_account_sequence(&node1_address)
                .await
                .expect("get sequence after first store");
            if seq > sequence_before_first {
                break seq;
            }
            if Instant::now() >= deadline {
                panic!("Timeout waiting for account sequence to increment after first store");
            }
            sleep(Duration::from_millis(200)).await;
        }
    };
    println!("Node1 sequence after first store: {}", sequence_after_first);
    assert!(
        sequence_after_first > sequence_before_first,
        "Sequence should increment after first store (tx was broadcast)"
    );

    // Read both from bulletin and compare metadata
    let manual_bytes =
        cli_tool::read_bulletin_post(object_id_manual.clone(), BulletinKind::Document)
            .await
            .expect("read manual post");
    let service_bytes =
        cli_tool::read_bulletin_post(object_id_service.clone(), BulletinKind::Document)
            .await
            .expect("read service post");

    let manual: DocumentPayload = serde_json::from_slice(&manual_bytes).expect("parse manual");
    let service: DocumentPayload = serde_json::from_slice(&service_bytes).expect("parse service");
    let bulletin_post = BulletinPost {
        id: object_id_service.clone(),
        payload: service_bytes.clone(),
    };

    // Serialize BulletinPost to bytes (this is what was signed)
    let message_bytes: Vec<u8> = bulletin_post
        .try_into()
        .expect("serialize BulletinPost to bytes");

    assert_eq!(manual.ring_id, service.ring_id, "ring_id mismatch");
    assert_eq!(manual.policy_id, service.policy_id, "policy_id mismatch");
    assert_eq!(manual.resource, service.resource, "resource mismatch");
    assert_eq!(manual.permission, service.permission, "permission mismatch");

    // Verify the threshold signature against the ring public key
    // The signature was created over the serialized BulletinPost
    let signature_bytes = hex::decode(&signature_hex).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("deserialize signature");

    let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring_pk hex");
    let ring_pk = GroupAffine::from_bytes(&ring_pk_bytes).expect("deserialize ring public key");

    let signer = SignImpl::new();
    signer
        .verify(&ring_pk, &message_bytes, &signature)
        .expect("BLS signature should verify against ring public key");

    // Run PRE to verify full flow works
    cli_tool::register_object_to_chain(
        policy_id.clone(),
        object_id_manual.clone(),
        resource.clone(),
    )
    .await
    .expect("register_object_to_chain");

    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        object_id_manual.clone(),
        resource.clone(),
        relation.clone(),
        Some(did_pk_string.clone()),
    )
    .await
    .expect("set_relationship_on_chain");

    // register service-stored encrypted object to chain
    cli_tool::register_object_to_chain(
        policy_id.clone(),
        object_id_service.clone(),
        resource.clone(),
    )
    .await
    .expect("register_object_to_chain");

    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        object_id_service.clone(),
        resource.clone(),
        relation.clone(),
        Some(did_pk_string.clone()),
    )
    .await
    .expect("set_relationship_on_chain");

    // register derived encrypted object to chain
    cli_tool::register_object_to_chain(
        policy_id.clone(),
        object_id_derived.clone(),
        resource.clone(),
    )
    .await
    .expect("register_object_to_chain");

    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        object_id_derived.clone(),
        resource.clone(),
        relation,
        Some(did_pk_string.clone()),
    )
    .await
    .expect("set_relationship_on_chain");

    // Step 3: Run PRE via CLI
    println!("Running PRE...");
    let decrypted = do_pre_expect_success(
        "initial PRE",
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_service.clone(),
        Some(did_pk_string.clone()),
        None,
        None,
        None,
        None,
        false,
    )
    .await;

    assert_eq!(
        decrypted, secret,
        "Decrypted secret should match original plaintext"
    );
    println!("PRE decryption verified: decrypted data matches original secret!");

    // testing derivition pre
    let decrypted_derived = do_pre_expect_success(
        "derived PRE",
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_derived.clone(),
        Some(did_pk_string.clone()),
        Some(derivation.clone()),
        salt.clone(),
        valid_window_start,
        valid_window_end,
        false,
    )
    .await;

    assert_eq!(
        decrypted_derived, secret,
        "Decrypted secret should match original plaintext"
    );

    // testing no permission
    let pre_result_no_permission = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_derived.clone(),
        Some("bad_key".to_string().clone()),
        Some(derivation.clone()),
        salt.clone(),
        valid_window_start,
        valid_window_end,
        false,
    )
    .await;

    let err = pre_result_no_permission.unwrap_err();
    assert!(
        err.to_string()
            .contains("Access denied: policy check failed"),
        "Expected policy check failure, got: {}",
        err
    );

    // testing timestamp out of bounds failure
    let pre_result_derived_failed_timestamp = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_derived.clone(),
        Some(did_pk_string.clone()),
        Some(derivation),
        salt.clone(),
        valid_window_start,
        valid_window_start,
        false,
    )
    .await;

    let err = pre_result_derived_failed_timestamp.unwrap_err();
    assert!(
        err.to_string()
            .contains("Access denied: policy check failed"),
        "Expected timestamp out-of-bounds failure, got: {}",
        err
    );

    // Test idempotency: store the same prepared secret again
    // This should succeed and return the same object_id (no duplicate post)
    println!("Testing idempotency: storing same secret again...");

    // Get sequence before second store
    let sequence_before_second = cli_tool::get_account_sequence(&node1_address)
        .await
        .expect("get sequence before second store");
    println!(
        "Node1 sequence before second store: {}",
        sequence_before_second
    );

    let object_response_2 = store_prepared_secret_expect_success(
        "idempotent StoreSecret",
        endpoint.clone(),
        &prepared_secret, // Same prepared data as first call
        ring_id.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        true,
        None,
        None,
    )
    .await;

    // Poll briefly; fail immediately if sequence changes (no tx should be broadcast for duplicate)
    let sequence_after_second = {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let seq = cli_tool::get_account_sequence(&node1_address)
                .await
                .expect("get sequence after second store");
            assert_eq!(
                seq, sequence_before_second,
                "Idempotency check: sequence changed unexpectedly (tx was broadcast for duplicate)"
            );
            if Instant::now() >= deadline {
                break seq;
            }
            sleep(Duration::from_millis(200)).await;
        }
    };
    println!(
        "Node1 sequence after second store: {}",
        sequence_after_second
    );

    // Verify idempotency: same object_id should be returned
    assert_eq!(
        object_id_service, object_response_2.object_id,
        "Idempotency check: second store should return same object_id"
    );

    // Verify no transaction was broadcast (sequence unchanged)
    assert_eq!(
        sequence_before_second, sequence_after_second,
        "Idempotency check: sequence should NOT change (no tx broadcast for duplicate)"
    );

    println!(
        "Idempotency verified: both calls returned object_id {}, sequence unchanged at {}",
        object_id_service, sequence_after_second
    );

    // Test sign
    println!("Testing Sign (Policy pathway)...");

    let sign_derivation = "sign-test-derivation-path".to_string();
    let sign_did_pk = "sign_test_did_secret".to_string();

    // Post a KeyDerivation to the bulletin (fetches ring PK automatically via ring_id)
    let (derivation_id, derived_pk_hex) = cli_tool::post_key_derivation(
        ring_id.clone(),
        sign_derivation.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
    )
    .await
    .expect("post_key_derivation");

    println!(
        "KeyDerivation posted: derivation_id={} derived_pk={}...",
        derivation_id,
        &derived_pk_hex[..40.min(derived_pk_hex.len())]
    );

    // Register derivation_id as an object on the policy and grant access to the DID
    cli_tool::register_object_to_chain(policy_id.clone(), derivation_id.clone(), resource.clone())
        .await
        .expect("register_object_to_chain for derivation_id");

    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(sign_did_pk.clone()),
    )
    .await
    .expect("set_relationship_on_chain for derivation_id");

    // Sign a test message
    let sign_message = b"hello from sign integration test";

    let sign_result = do_sign_expect_success(
        "initial policy Sign",
        endpoint.clone(),
        sign_message.to_vec(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
        None,
        None,
    )
    .await;

    println!("Sign completed: signature={}", sign_result.signature);

    // Verify the signature resolves against the derived public key (not the ring PK)
    let sig_bytes = hex::decode(&sign_result.signature).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&sig_bytes)
        .expect("deserialize signature");

    let derived_pk_bytes = hex::decode(&derived_pk_hex).expect("decode derived_pk hex");
    let derived_pk = GroupAffine::from_bytes(&derived_pk_bytes).expect("deserialize derived_pk");

    let signer = SignImpl::new();
    signer
        .verify(&derived_pk, sign_message, &signature)
        .expect("signature should verify against derived public key");

    println!("Signature verified against derived public key!");

    // Verify it does NOT verify against the bare ring public key
    let ring_pk_for_verify =
        GroupAffine::from_bytes(&hex::decode(&ring_pk_hex).expect("decode ring_pk hex"))
            .expect("deserialize ring_pk");
    assert!(
        signer
            .verify(&ring_pk_for_verify, sign_message, &signature)
            .is_err(),
        "signature should NOT verify against underivedring public key"
    );

    // Test failed policy access: a DID with no relationship should be denied
    let sign_no_access = cli_tool::do_sign(
        endpoint.clone(),
        sign_message.to_vec(),
        derivation_id.clone(),
        Some("unauthorized_did_key".to_string()),
        None,
        None,
    )
    .await;

    let err = sign_no_access.unwrap_err();
    assert!(
        err.to_string()
            .contains("Access denied: policy check failed"),
        "Expected policy check failure for unauthorized DID, got: {}",
        err
    );

    println!("Sign correctly rejected unauthorized DID!");

    // ====================================================================
    // Step 4: PSS Refresh — poll all nodes until their local polynomial has
    // changed from the per-node baseline captured after DKG.
    //
    // The DKG was started with pss_interval=1s. The nodes run with
    // --reshare-interval-secs=5 (docker-compose), so the first scheduler
    // tick fires within 5s of DKG completion. The public polynomial is
    // stored locally on each node (not on the bulletin), so the ring_id is
    // unchanged. We poll GetRingState on all three nodes to confirm the
    // refresh actually completed before testing Sign and PRE. The 300s
    // deadline covers a failed/early refresh attempt being cleaned up by the
    // phase timeout and retried by the next scheduler tick.
    // ====================================================================
    println!("Waiting for PSS refresh to complete (polling all 3 nodes)...");

    let refreshed_ring_states = wait_for_pss_refresh_on_all_nodes(
        &node_endpoints,
        &ring_pk_hex,
        &initial_ring_states,
        Duration::from_secs(300),
        Duration::from_secs(2),
    )
    .await;
    for (idx, (before, after)) in initial_ring_states
        .iter()
        .zip(refreshed_ring_states.iter())
        .enumerate()
    {
        println!(
            "  Node {} PSS last_pss: {} -> {}",
            idx + 1,
            before.last_pss,
            after.last_pss
        );
    }
    println!(
        "PSS refresh complete. ring_id={} is unchanged (polynomial is local-only).",
        &ring_id[..16.min(ring_id.len())]
    );

    // ====================================================================
    // Step 5: PSS Reshare — update the existing ring bulletin post with a
    // next committee.  SourceHub now supports in-place post updates, so the
    // ring_id stays stable while the payload first announces new_peer_node_keys
    // and then, after Phase 4, converges to peer_ids = new_peer_node_keys.
    // ====================================================================
    println!("Announcing PSS reshare via bulletin update...");

    let reshare_peer_ids = vec![peer_ids[0].clone(), peer_ids[1].clone()];
    let reshare_threshold = 2u32;
    assert_ne!(
        sorted_peer_ids(&dkg_ring_payload.peer_node_keys),
        sorted_peer_ids(&reshare_peer_ids),
        "Reshare test must change the committee"
    );

    let pre_reshare_ring_states = wait_for_ring_state_on_all_nodes(
        &node_endpoints[..2],
        &ring_pk_hex,
        Duration::from_secs(60),
        Duration::from_millis(500),
    )
    .await;

    cli_tool::update_ring_post_by_acp(
        ring_id.clone(),
        reshare_peer_ids.clone(),
        Some(reshare_threshold),
        dkg_ring_payload.pss_interval,
    )
    .await
    .expect("update ring bulletin post with reshare announcement");

    let announced_payload = read_ring_payload(&ring_id).await;
    let announced_new_peer_node_keys = announced_payload
        .new_peer_node_keys
        .as_ref()
        .map(|ids| sorted_peer_ids(ids))
        .expect("reshare announcement should set new_peer_node_keys");
    assert_eq!(
        announced_new_peer_node_keys,
        sorted_peer_ids(&reshare_peer_ids),
        "Reshare announcement should preserve the requested next committee"
    );
    assert_eq!(
        announced_payload.new_threshold,
        Some(reshare_threshold),
        "Reshare announcement should preserve the requested new threshold"
    );
    println!(
        "Reshare announced on stable ring_id={}; waiting for bulletin peer_ids to converge...",
        &ring_id[..16.min(ring_id.len())]
    );

    let reshared_payload = wait_for_reshare_bulletin_completion(
        &ring_id,
        &ring_pk_hex,
        &reshare_peer_ids,
        reshare_threshold,
        Duration::from_secs(300),
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(
        reshared_payload.ring_pk, ring_pk_hex,
        "Reshare should preserve the ring public key"
    );
    assert_eq!(
        sorted_peer_ids(&reshared_payload.peer_node_keys),
        sorted_peer_ids(&reshare_peer_ids),
        "Reshare should make peer_ids equal the requested next committee"
    );
    assert_eq!(
        reshared_payload.threshold, reshare_threshold,
        "Reshare should update the ring threshold"
    );
    assert!(
        reshared_payload.new_peer_node_keys.is_none() && reshared_payload.new_threshold.is_none(),
        "Completed reshare should clear the announcement fields"
    );

    let reshared_ring_states = wait_for_pss_refresh_on_all_nodes(
        &node_endpoints[..2],
        &ring_pk_hex,
        &pre_reshare_ring_states,
        Duration::from_secs(120),
        Duration::from_secs(2),
    )
    .await;
    for (idx, (before, after)) in pre_reshare_ring_states
        .iter()
        .zip(reshared_ring_states.iter())
        .enumerate()
    {
        println!(
            "  Reshare node {} PSS last_pss: {} -> {}",
            idx + 1,
            before.last_pss,
            after.last_pss
        );
    }
    println!(
        "PSS reshare complete. ring_id={} is unchanged; committee size is now {}.",
        &ring_id[..16.min(ring_id.len())],
        reshared_payload.peer_node_keys.len()
    );

    println!("Testing Sign after PSS reshare...");
    let sign_result_post_reshare = do_sign_expect_success(
        "post-reshare policy Sign",
        endpoint.clone(),
        sign_message.to_vec(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
        None,
        None,
    )
    .await;

    let sig_bytes_post_reshare =
        hex::decode(&sign_result_post_reshare.signature).expect("decode post-reshare sig hex");
    let signature_post_reshare =
        <SignImpl as ThresholdSigner>::Signature::from_bytes(&sig_bytes_post_reshare)
            .expect("deserialize post-reshare signature");
    signer
        .verify(&derived_pk, sign_message, &signature_post_reshare)
        .expect("post-reshare signature should verify against derived public key");

    println!("Post-reshare Sign verified against the unchanged derived public key!");

    // ====================================================================
    // Step 6: Post-refresh Sign — reuse existing derivation_id (ring_id
    // and derived PK are unchanged after PSS; the on-chain post already
    // exists and ACP relationships are already set).
    // ====================================================================
    println!("Testing Sign after PSS refresh...");

    let sign_result_post_refresh = do_sign_expect_success(
        "post-refresh policy Sign",
        endpoint.clone(),
        sign_message.to_vec(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
        None,
        None,
    )
    .await;

    let sig_bytes_pr = hex::decode(&sign_result_post_refresh.signature).expect("decode sig hex");
    let signature_pr = <SignImpl as ThresholdSigner>::Signature::from_bytes(&sig_bytes_pr)
        .expect("deserialize signature");
    let derived_pk_bytes_pr = hex::decode(&derived_pk_hex).expect("decode derived_pk hex");
    let derived_pk_pr =
        GroupAffine::from_bytes(&derived_pk_bytes_pr).expect("deserialize derived_pk");
    signer
        .verify(&derived_pk_pr, sign_message, &signature_pr)
        .expect("post-refresh signature should verify against derived public key");

    println!("Post-refresh Sign verified!");

    // ====================================================================
    // Step 6: Post-refresh PRE — encrypt a fresh secret using the original
    // ring_id (unchanged after PSS). Store it as a new object and run PRE
    // to verify decryption still works against the refreshed shares.
    // ====================================================================
    println!("Testing PRE after PSS refresh...");

    let post_refresh_secret = b"Hello after PSS refresh!";
    let prepared_post_refresh = cli_tool::prepare_secret(
        post_refresh_secret,
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret post-refresh");

    let object_response_post_refresh = store_prepared_secret_expect_success(
        "post-refresh StoreSecret",
        endpoint.clone(),
        &prepared_post_refresh,
        ring_id.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        true,
        None,
        None,
    )
    .await;

    let object_id_post_refresh = object_response_post_refresh.object_id.clone();

    cli_tool::register_object_to_chain(
        policy_id.clone(),
        object_id_post_refresh.clone(),
        resource.clone(),
    )
    .await
    .expect("register post-refresh object");

    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        object_id_post_refresh.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did_pk_string.clone()),
    )
    .await
    .expect("set_relationship for post-refresh object");

    let pre_result_post_refresh = do_pre_expect_success(
        "post-refresh PRE",
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_post_refresh.clone(),
        Some(did_pk_string.clone()),
        None,
        None,
        None,
        None,
        false,
    )
    .await;

    assert_eq!(
        pre_result_post_refresh, post_refresh_secret,
        "Post-refresh PRE should decrypt to original plaintext"
    );
    println!("Post-refresh PRE verified: decrypted data matches original secret!");

    // Cleanup happens automatically when _network is dropped
}

async fn wait_for_ring_state_on_all_nodes(
    endpoints: &[String],
    ring_pk_hex: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Vec<RingStateSnapshot> {
    let deadline = Instant::now() + timeout;

    loop {
        let mut snapshots = Vec::with_capacity(endpoints.len());
        let mut statuses = Vec::with_capacity(endpoints.len());

        for (idx, endpoint) in endpoints.iter().enumerate() {
            match cli_tool::query_ring_state(endpoint.clone(), ring_pk_hex.to_string()).await {
                Ok((public_polynomial, last_pss)) => {
                    statuses.push(format!("node{}: last_pss={}", idx + 1, last_pss));
                    snapshots.push(RingStateSnapshot {
                        public_polynomial,
                        last_pss,
                    });
                }
                Err(e) => {
                    statuses.push(format!("node{}: {}", idx + 1, e));
                    snapshots.clear();
                    break;
                }
            }
        }

        if snapshots.len() == endpoints.len() {
            println!(
                "All nodes have local DKG ring state: {}",
                statuses.join("; ")
            );
            return snapshots;
        }

        assert!(
            Instant::now() < deadline,
            "Timed out waiting for all nodes to expose DKG ring state. Last observed: {}",
            statuses.join("; ")
        );
        sleep(poll_interval).await;
    }
}

async fn read_ring_payload(ring_id: &str) -> RingPayload {
    let payload_bytes = cli_tool::read_bulletin_post(ring_id.to_string(), BulletinKind::Ring)
        .await
        .expect("read ring payload from bulletin");
    serde_json::from_slice(&payload_bytes).expect("parse RingPayload")
}

async fn wait_for_reshare_bulletin_completion(
    ring_id: &str,
    ring_pk_hex: &str,
    expected_peer_ids: &[String],
    expected_threshold: u32,
    timeout: Duration,
    poll_interval: Duration,
) -> RingPayload {
    let deadline = Instant::now() + timeout;
    let mut next_status_log = Instant::now() + Duration::from_secs(15);
    let expected_sorted = sorted_peer_ids(expected_peer_ids);

    loop {
        let last_status =
            match cli_tool::read_bulletin_post(ring_id.to_string(), BulletinKind::Ring).await {
                Ok(payload_bytes) => match serde_json::from_slice::<RingPayload>(&payload_bytes) {
                    Ok(payload) => {
                        let actual_sorted = sorted_peer_ids(&payload.peer_node_keys);
                        let complete = payload.ring_pk == ring_pk_hex
                            && actual_sorted == expected_sorted
                            && payload.threshold == expected_threshold
                            && payload.new_peer_node_keys.is_none()
                            && payload.new_threshold.is_none();
                        let status = format!(
                        "peer_count={} threshold={} new_peer_node_keys_set={} new_threshold={:?}",
                        payload.peer_node_keys.len(),
                        payload.threshold,
                        payload.new_peer_node_keys.is_some(),
                        payload.new_threshold
                    );
                        if complete {
                            return payload;
                        }
                        status
                    }
                    Err(e) => format!("parse error: {}", e),
                },
                Err(e) => e.to_string(),
            };

        let now = Instant::now();
        assert!(
            now < deadline,
            "PSS reshare did not update the bulletin within {}s. Last observed: {}",
            timeout.as_secs(),
            last_status
        );
        if now >= next_status_log {
            println!(
                "Still waiting for PSS reshare bulletin update: {}",
                last_status
            );
            next_status_log = now + Duration::from_secs(15);
        }
        sleep(poll_interval).await;
    }
}

fn sorted_peer_ids(peer_ids: &[String]) -> Vec<String> {
    let mut sorted = peer_ids.to_vec();
    sorted.sort();
    sorted
}

async fn do_sign_expect_success(
    context: &str,
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    reader_did_pk: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;

    loop {
        match cli_tool::do_sign(
            endpoint.clone(),
            message.clone(),
            derivation_id.clone(),
            reader_did_pk.clone(),
            valid_window_start,
            valid_window_end,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "{} failed after {} attempts: {}",
                    context,
                    attempt,
                    e
                );
                println!(
                    "{} attempt {} failed, retrying after transient signing race: {}",
                    context, attempt, e
                );
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn do_pre_expect_success(
    context: &str,
    endpoint: String,
    ring_pk: String,
    reader_pk: String,
    reader_sk: Option<String>,
    object_id: String,
    reader_did_pk: Option<String>,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
    xnc_only: bool,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;

    loop {
        match cli_tool::do_pre(
            endpoint.clone(),
            ring_pk.clone(),
            reader_pk.clone(),
            reader_sk.clone(),
            object_id.clone(),
            reader_did_pk.clone(),
            derivation.clone(),
            salt.clone(),
            valid_window_start,
            valid_window_end,
            xnc_only,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "{} failed after {} attempts: {}",
                    context,
                    attempt,
                    e
                );
                println!(
                    "{} attempt {} failed, retrying after transient PRE race: {}",
                    context, attempt, e
                );
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn store_prepared_secret_expect_success(
    context: &str,
    endpoint: String,
    prepared: &cli_tool::PreparedSecret,
    ring_id: String,
    policy_id: String,
    resource: String,
    permission: String,
    reader_did_pk: Option<String>,
    with_proof: bool,
    tier: Option<String>,
    timestamp: Option<u64>,
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
            with_proof,
            tier.clone(),
            timestamp,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "{} failed after {} attempts: {}",
                    context,
                    attempt,
                    e
                );
                println!(
                    "{} attempt {} failed, retrying with same prepared secret: {}",
                    context, attempt, e
                );
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn wait_for_pss_refresh_on_all_nodes(
    endpoints: &[String],
    ring_pk_hex: &str,
    baselines: &[RingStateSnapshot],
    timeout: Duration,
    poll_interval: Duration,
) -> Vec<RingStateSnapshot> {
    assert_eq!(
        endpoints.len(),
        baselines.len(),
        "ring-state baselines must match endpoint count"
    );

    let deadline = Instant::now() + timeout;
    let mut next_status_log = Instant::now() + Duration::from_secs(15);

    loop {
        let mut snapshots = Vec::with_capacity(endpoints.len());
        let mut statuses = Vec::with_capacity(endpoints.len());
        let mut all_refreshed = true;

        for (idx, endpoint) in endpoints.iter().enumerate() {
            match cli_tool::query_ring_state(endpoint.clone(), ring_pk_hex.to_string()).await {
                Ok((public_polynomial, last_pss)) => {
                    let baseline = &baselines[idx];
                    let polynomial_changed = public_polynomial != baseline.public_polynomial;
                    let timestamp_advanced = last_pss > baseline.last_pss;
                    if !polynomial_changed && !timestamp_advanced {
                        all_refreshed = false;
                    }
                    statuses.push(format!(
                        "node{}: poly_changed={} timestamp_advanced={} last_pss={} baseline={}",
                        idx + 1,
                        polynomial_changed,
                        timestamp_advanced,
                        last_pss,
                        baseline.last_pss,
                    ));
                    snapshots.push(RingStateSnapshot {
                        public_polynomial,
                        last_pss,
                    });
                }
                Err(e) => {
                    all_refreshed = false;
                    statuses.push(format!("node{}: {}", idx + 1, e));
                }
            }
        }

        if all_refreshed && snapshots.len() == endpoints.len() {
            return snapshots;
        }

        let now = Instant::now();
        assert!(
            now < deadline,
            "PSS refresh did not complete on all nodes within {}s. Last observed: {}",
            timeout.as_secs(),
            statuses.join("; ")
        );
        if now >= next_status_log {
            println!("Still waiting for PSS refresh: {}", statuses.join("; "));
            next_status_log = now + Duration::from_secs(15);
        }
        sleep(poll_interval).await;
    }
}
