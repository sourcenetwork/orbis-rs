//! Docker-based integration test: full DKG + PRE + SIGN flow.
//!
//! Spins up a full Docker Compose environment (SourceHub + 3 orbis-node containers)
//! and exercises the complete DKG → StoreSecret → PRE workflow via CLI commands.
//!
//! Run with:
//!   cargo test --features integration-test -- --nocapture

use crate::constants::{BULLETIN_PLACEHOLDER_PROOF, BULLETIN_RING_NAMESPACE};
use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
use common::IntegrationTestNetwork;
use common::SOURCEHUB_RPC_URL;
use crypto::helpers::generate_keypair;
use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, SignImpl};
use tokio::time::{sleep, Duration, Instant};

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

    // Register the namespace and add collaborators
    cli_tool::register_bulletin_namespace(BULLETIN_RING_NAMESPACE.to_string())
        .await
        .expect("Failed to register namespace");
    cli_tool::add_bulletin_collaborator(
        BULLETIN_RING_NAMESPACE.to_string(),
        node1_info.public_address.clone(),
    )
    .await
    .expect("add_bulletin_collaborator");
    cli_tool::add_bulletin_collaborator(
        BULLETIN_RING_NAMESPACE.to_string(),
        node2_info.public_address.clone(),
    )
    .await
    .expect("add_bulletin_collaborator");
    cli_tool::add_bulletin_collaborator(
        BULLETIN_RING_NAMESPACE.to_string(),
        node3_info.public_address.clone(),
    )
    .await
    .expect("add_bulletin_collaborator");
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

    let ring_namespace = BULLETIN_RING_NAMESPACE.to_string();

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

    println!(
        "Starting DKG with threshold {} and {} peers...",
        threshold,
        peer_ids.len()
    );
    // pss_interval = 1s so the PSS scheduler (5s check interval in docker-compose) fires a
    // refresh shortly after DKG completes.
    let dkg_result = cli_tool::do_dkg(endpoint.clone(), threshold, peer_ids.clone(), Some(1)).await;
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
    let post_payload =
        cli_tool::read_bulletin_post(ring_namespace.clone(), post_event.post_id.clone())
            .await
            .expect("read ring post by event post_id");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk.clone();
    let ring_id = post_event.post_id;
    let _dkg_ring_payload = ring_payload.clone();

    // Capture the initial polynomial from node 1 right after DKG so we can
    // confirm it changes after a refresh.
    let (initial_poly, _) = cli_tool::query_ring_state(endpoint.clone(), ring_pk_hex.clone())
        .await
        .expect("query_ring_state after DKG");

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
    let namespace = "docker_test_namespace".to_string();
    let full_namespace = format!("bulletin/{}", namespace);
    let tier = Some("tier".to_string());
    let timestamp = Some(100u64);
    let valid_window_start = Some(50u64);
    let valid_window_end = Some(150u64);
    let salt = Some("salt".to_string());
    let policy_id = cli_tool::add_policy_to_chain().await.expect("policy_id");
    let proof = vec![0x01];

    cli_tool::register_bulletin_namespace(namespace.clone())
        .await
        .expect("Failed to register namespace");

    // Add node1 as collaborator on the user namespace so it can post on user's behalf
    cli_tool::add_bulletin_collaborator(namespace.clone(), node1_info.public_address.clone())
        .await
        .expect("add node as collaborator on user namespace");

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
            timestamp: timestamp.clone(),
        };
        let serialized: Vec<u8> = payload.try_into().expect("serialize payload");
        cli_tool::create_bulletin_post(namespace.clone(), serialized, proof.clone())
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
        timestamp.clone(),
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

    let object_response = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared_secret,
        ring_id.clone(),
        namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        None,
        true,
        None,
        None,
        None,
    )
    .await
    .expect("store_prepared_secret");

    let object_id_service = object_response.object_id.clone();
    let signature_hex = object_response.signature.clone();

    let object_response_derived = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared_secret_derived.clone(),
        ring_id.clone(),
        namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        prepared_secret_derived.derived_pk,
        false,
        tier.clone(),
        timestamp.clone(),
        Some(prepared_secret_derived.metadata.clone()),
    )
    .await
    .expect("store_prepared_secret_derived");
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
        cli_tool::read_bulletin_post(full_namespace.clone(), object_id_manual.clone())
            .await
            .expect("read manual post");
    let service_bytes =
        cli_tool::read_bulletin_post(full_namespace.clone(), object_id_service.clone())
            .await
            .expect("read service post");

    let manual: DocumentPayload = serde_json::from_slice(&manual_bytes).expect("parse manual");
    let service: DocumentPayload = serde_json::from_slice(&service_bytes).expect("parse service");
    let bulletin_post = BulletinPost {
        id: object_id_service.clone(),
        namespace: namespace.clone(),
        payload: service_bytes.clone(),
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
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
    let pre_result = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_service.clone(),
        Some(did_pk_string.clone()),
        full_namespace.clone(),
        None,
        None,
        None,
        None,
        false,
    )
    .await;

    // The key test: CLI do_pre should succeed and return the original plaintext
    assert!(
        pre_result.is_ok(),
        "cli-tool do_pre should succeed against Docker orbis-nodes: {:?}",
        pre_result.err()
    );

    let decrypted = pre_result.unwrap();

    assert_eq!(
        decrypted, secret,
        "Decrypted secret should match original plaintext"
    );
    println!("PRE decryption verified: decrypted data matches original secret!");

    // testing derivition pre
    let pre_result_derived = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_derived.clone(),
        Some(did_pk_string.clone()),
        full_namespace.clone(),
        Some(derivation.clone()),
        salt.clone(),
        valid_window_start,
        valid_window_end,
        false,
    )
    .await;

    assert!(
        pre_result_derived.is_ok(),
        "derived PRE should succeed: {:?}",
        pre_result_derived.err()
    );
    let decrypted_derived = pre_result_derived.unwrap();

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
        full_namespace.clone(),
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
        full_namespace.clone(),
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

    let object_response_2 = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared_secret, // Same prepared data as first call
        ring_id.clone(),
        namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        None,
        true,
        None,
        None,
        None,
    )
    .await
    .expect("store_prepared_secret (idempotent call)");

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
        namespace.clone(),
        ring_id.clone(),
        sign_derivation.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        proof.clone(),
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

    let sign_result = cli_tool::do_sign(
        endpoint.clone(),
        sign_message.to_vec(),
        full_namespace.clone(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
        None,
        None,
    )
    .await
    .expect("do_sign should succeed");

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
        full_namespace.clone(),
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
    // Step 4: PSS Refresh — poll all nodes until refreshed_at > 0 and
    // polynomial has changed from the initial DKG value.
    //
    // The DKG was started with pss_interval=1s. The nodes run with
    // --reshare-interval-secs=5 (docker-compose), so the first scheduler
    // tick fires within 5s of DKG completion. The public polynomial is
    // stored locally on each node (not on the bulletin), so the ring_id is
    // unchanged. We poll GetRingState on all three nodes to confirm the
    // refresh actually completed before testing Sign and PRE.
    // ====================================================================
    println!("Waiting for PSS refresh to complete (polling all 3 nodes)...");

    let node_endpoints = [
        IntegrationTestNetwork::NODE1_GRPC.to_string(),
        IntegrationTestNetwork::NODE2_GRPC.to_string(),
        IntegrationTestNetwork::NODE3_GRPC.to_string(),
    ];
    let poll_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut all_refreshed = true;
        for ep in &node_endpoints {
            match cli_tool::query_ring_state(ep.clone(), ring_pk_hex.clone()).await {
                Ok((poly, refreshed_at)) if refreshed_at > 0 && poly != initial_poly => {}
                _ => {
                    all_refreshed = false;
                    break;
                }
            }
        }
        if all_refreshed {
            break;
        }
        assert!(
            Instant::now() < poll_deadline,
            "PSS refresh did not complete on all nodes within 60s"
        );
        sleep(Duration::from_secs(2)).await;
    }
    println!(
        "PSS refresh complete. ring_id={} is unchanged (polynomial is local-only).",
        &ring_id[..16.min(ring_id.len())]
    );

    // ====================================================================
    // Step 4a: Post-refresh Sign — reuse existing derivation_id (ring_id
    // and derived PK are unchanged after PSS; the on-chain post already
    // exists and ACP relationships are already set).
    // ====================================================================
    println!("Testing Sign after PSS refresh...");

    let sign_result_post_refresh = cli_tool::do_sign(
        endpoint.clone(),
        sign_message.to_vec(),
        full_namespace.clone(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
        None,
        None,
    )
    .await
    .expect("do_sign after PSS refresh");

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
    // Step 4b: Post-refresh PRE — encrypt a fresh secret using the original
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

    let object_response_post_refresh = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared_post_refresh,
        ring_id.clone(),
        namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
        None,
        true,
        None,
        None,
        None,
    )
    .await
    .expect("store_prepared_secret post-refresh");

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

    let pre_result_post_refresh = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id_post_refresh.clone(),
        Some(did_pk_string.clone()),
        full_namespace.clone(),
        None,
        None,
        None,
        None,
        false,
    )
    .await
    .expect("do_pre after PSS refresh");

    assert_eq!(
        pre_result_post_refresh, post_refresh_secret,
        "Post-refresh PRE should decrypt to original plaintext"
    );
    println!("Post-refresh PRE verified: decrypted data matches original secret!");

    // Cleanup happens automatically when _network is dropped
}
