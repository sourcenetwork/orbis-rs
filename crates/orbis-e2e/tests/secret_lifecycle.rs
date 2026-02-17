//! Secret lifecycle tests: DKG → StoreSecret → PRE → Decrypt.
//!
//! This is a port of `test_cli_calls_dkg_and_pre_endpoint` from the Docker-based
//! integration tests to the native e2e framework. It exercises the full Orbis
//! pipeline using cli-tool functions against real orbis-node processes backed
//! by a SourceHub devnet — no Docker required.

use std::time::Duration;

use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
use common::blockchain::events::BulletinEventSubscription;
use crypto::helpers::{generate_keypair, generate_policy_metadata};
use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, SignImpl};
use orbis_e2e::ring::OrbisRing;

/// The bulletin namespace used for ring payloads (must match orbis-node constant).
const BULLETIN_RING_NAMESPACE: &str = "orbis";

/// Placeholder proof (must match orbis-node constant).
const BULLETIN_PLACEHOLDER_PROOF: &[u8] = &[0x01];

/// Full DKG → StoreSecret → PRE → Decrypt pipeline.
///
/// Mirrors the Docker-based `test_cli_calls_dkg_and_pre_endpoint` but uses
/// the native e2e framework with dynamically allocated ports.
///
/// Steps:
/// 1. Start 3 orbis-node processes + SourceHub devnet
/// 2. Query node info for peer IDs and public addresses
/// 3. Register bulletin namespace + add node collaborators
/// 4. Run DKG via cli-tool, subscribe for completion event
/// 5. Store secret (both manual bulletin post and StoreSecret service)
/// 6. Verify BLS threshold signature
/// 7. Set up ACP (policy, register objects, set relationships)
/// 8. Run PRE + decrypt, verify plaintext matches
/// 9. Test derived-key PRE
/// 10. Test idempotent store
#[tokio::test]
async fn dkg_store_pre_decrypt_full_pipeline() {
    // Initialize tracing for test output
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    // ================================================================
    // Step 0: Start the ring with SourceHub
    // ================================================================
    println!("Starting 3-node ring with SourceHub devnet...");
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .with_sourcehub()
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("all nodes should be healthy");

    let chain_config = ring.chain_config();
    let endpoint = ring.node(0).grpc_addr();
    let sourcehub = ring.sourcehub().expect("sourcehub should be running");

    println!("Ring ready. Endpoint: {}", endpoint);
    println!("SourceHub: rpc={}, grpc={}", sourcehub.comet_rpc_url, sourcehub.grpc_url);

    // ================================================================
    // Step 1: Query node info for peer IDs and addresses
    // ================================================================
    let node1_info = cli_tool::query_node_info(ring.node(0).grpc_addr())
        .await
        .expect("query node0 info");
    let node2_info = cli_tool::query_node_info(ring.node(1).grpc_addr())
        .await
        .expect("query node1 info");
    let node3_info = cli_tool::query_node_info(ring.node(2).grpc_addr())
        .await
        .expect("query node2 info");

    let node1_address = node1_info.public_address.clone();
    println!("Node 0 peer: {}", node1_info.p2p_address);
    println!("Node 1 peer: {}", node2_info.p2p_address);
    println!("Node 2 peer: {}", node3_info.p2p_address);

    // ================================================================
    // Step 2: Register ring bulletin namespace + add collaborators
    // ================================================================
    cli_tool::register_bulletin_namespace(
        BULLETIN_RING_NAMESPACE.to_string(),
        chain_config.clone(),
    )
    .await
    .expect("register ring namespace");

    for info in [&node1_info, &node2_info, &node3_info] {
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            info.public_address.clone(),
            chain_config.clone(),
        )
        .await
        .expect("add collaborator");
    }

    // ================================================================
    // Step 3: Subscribe to chain events BEFORE starting DKG
    // ================================================================
    // No Docker address transform needed — all processes are on localhost
    let peer_ids = vec![
        node1_info.p2p_address.clone(),
        node2_info.p2p_address.clone(),
        node3_info.p2p_address.clone(),
    ];
    let threshold = ring.threshold();

    println!("Subscribing to chain events...");
    let event_subscription =
        BulletinEventSubscription::connect(&sourcehub.comet_rpc_url)
            .await
            .expect("WebSocket event subscription");

    // ================================================================
    // Step 4: Run DKG
    // ================================================================
    println!("Starting DKG with threshold {}/{}...", threshold, peer_ids.len());
    let dkg_result = cli_tool::do_dkg(endpoint.clone(), threshold, peer_ids)
        .await
        .expect("DKG should succeed");

    let session_id = dkg_result.session_id.clone();
    println!("DKG initiated (session_id: {}), waiting for completion event...", session_id);

    let post_event = event_subscription
        .wait_for_artifact(&session_id, Duration::from_secs(120))
        .await
        .expect("DKG completion event");

    // Read the ring payload from the bulletin
    let ring_namespace = BULLETIN_RING_NAMESPACE.to_string();
    let post_payload = cli_tool::read_bulletin_post(
        ring_namespace.clone(),
        post_event.post_id.clone(),
        chain_config.clone(),
    )
    .await
    .expect("read ring post");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk.clone();
    let ring_id = post_event.post_id;

    println!(
        "DKG completed! Ring PK: {}..., Ring ID: {}",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    // ================================================================
    // Step 5: Set up ACP + user namespace for secrets
    // ================================================================
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_bytes = CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk");
    let reader_pk_bytes = CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk");
    let reader_sk_hex = hex::encode(&reader_sk_bytes);
    let reader_pk_hex = hex::encode(&reader_pk_bytes);

    let resource = "document".to_string();
    let relation = "reader".to_string();
    let permission = "read".to_string();
    let did_pk_string = "test_did_secret".to_string();
    let namespace = "e2e_test_namespace".to_string();
    let full_namespace = format!("bulletin/{}", namespace);

    let policy_id = cli_tool::add_policy_to_chain(chain_config.clone())
        .await
        .expect("add policy");

    cli_tool::register_bulletin_namespace(namespace.clone(), chain_config.clone())
        .await
        .expect("register user namespace");

    // Add node0 as collaborator so it can post on user's behalf
    cli_tool::add_bulletin_collaborator(
        namespace.clone(),
        node1_info.public_address.clone(),
        chain_config.clone(),
    )
    .await
    .expect("add node as collaborator");

    // ================================================================
    // Step 6: Store secrets — both manual and service paths
    // ================================================================
    let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring_pk hex");
    let ring_pk_point = GroupAffine::from_bytes(&ring_pk_bytes).expect("deserialize ring_pk");
    let proof = vec![0x01];

    // MANUAL PATH: Encrypt and post directly to bulletin
    let object_id_manual = {
        let metadata = generate_policy_metadata(&policy_id, &resource, &permission);
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
        };
        let serialized: Vec<u8> = payload.try_into().expect("serialize payload");
        cli_tool::create_bulletin_post(
            namespace.clone(),
            serialized,
            proof,
            chain_config.clone(),
        )
        .await
        .expect("create_bulletin_post")
    };

    // SERVICE PATH: Prepare + store (tests idempotency too)
    let secret = b"Hello from StoreSecret!";
    let prepared_secret = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
    )
    .expect("prepare_secret");

    let derivation = b"test_derivation".to_vec();
    let prepared_secret_derived = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        Some(derivation.clone()),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
    )
    .expect("prepare_secret derived");

    // Get sequence before first store
    let sequence_before_first =
        cli_tool::get_account_sequence(&node1_address, chain_config.clone())
            .await
            .expect("get sequence before first store");

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
    )
    .await
    .expect("store_prepared_secret_derived");
    let object_id_derived = object_response_derived.object_id.clone();

    // Wait for block confirmation and check sequence incremented
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sequence_after_first =
        cli_tool::get_account_sequence(&node1_address, chain_config.clone())
            .await
            .expect("get sequence after first store");
    assert!(
        sequence_after_first > sequence_before_first,
        "Sequence should increment after first store (tx was broadcast)"
    );

    // ================================================================
    // Step 7: Verify bulletin posts and BLS signature
    // ================================================================
    let manual_bytes = cli_tool::read_bulletin_post(
        full_namespace.clone(),
        object_id_manual.clone(),
        chain_config.clone(),
    )
    .await
    .expect("read manual post");
    let service_bytes = cli_tool::read_bulletin_post(
        full_namespace.clone(),
        object_id_service.clone(),
        chain_config.clone(),
    )
    .await
    .expect("read service post");

    let manual: DocumentPayload = serde_json::from_slice(&manual_bytes).expect("parse manual");
    let service: DocumentPayload = serde_json::from_slice(&service_bytes).expect("parse service");

    assert_eq!(manual.ring_id, service.ring_id, "ring_id mismatch");
    assert_eq!(manual.policy_id, service.policy_id, "policy_id mismatch");
    assert_eq!(manual.resource, service.resource, "resource mismatch");
    assert_eq!(manual.permission, service.permission, "permission mismatch");

    // Verify threshold signature
    let bulletin_post = BulletinPost {
        id: object_id_service.clone(),
        namespace: namespace.clone(),
        payload: service_bytes.clone(),
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
    };
    let message_bytes: Vec<u8> = bulletin_post
        .try_into()
        .expect("serialize BulletinPost to bytes");

    let signature_bytes = hex::decode(&signature_hex).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("deserialize signature");
    let ring_pk = GroupAffine::from_bytes(
        &hex::decode(&ring_pk_hex).expect("decode ring_pk hex"),
    )
    .expect("deserialize ring public key");

    let signer = SignImpl::new();
    signer
        .verify(&ring_pk, &message_bytes, &signature)
        .expect("BLS signature should verify against ring public key");
    println!("BLS signature verified!");

    // ================================================================
    // Step 8: ACP setup — register objects and set relationships
    // ================================================================
    for obj_id in [&object_id_manual, &object_id_derived] {
        cli_tool::register_object_to_chain(
            policy_id.clone(),
            obj_id.clone(),
            resource.clone(),
            chain_config.clone(),
        )
        .await
        .expect("register_object_to_chain");

        cli_tool::set_relationship_on_chain(
            policy_id.clone(),
            obj_id.clone(),
            resource.clone(),
            relation.clone(),
            Some(did_pk_string.clone()),
            chain_config.clone(),
        )
        .await
        .expect("set_relationship_on_chain");
    }

    // ================================================================
    // Step 9: PRE + decrypt — verify full re-encryption flow
    // ================================================================
    println!("Running PRE...");
    let decrypted = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        reader_sk_hex.clone(),
        object_id_service.clone(),
        Some(did_pk_string.clone()),
        full_namespace.clone(),
        None,
    )
    .await
    .expect("PRE should succeed");

    assert_eq!(
        decrypted, secret,
        "Decrypted secret should match original plaintext"
    );
    println!("PRE decryption verified!");

    // ================================================================
    // Step 10: Derived-key PRE
    // ================================================================
    let decrypted_derived = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        reader_sk_hex.clone(),
        object_id_derived.clone(),
        Some(did_pk_string.clone()),
        full_namespace.clone(),
        Some(derivation),
    )
    .await
    .expect("derived PRE should succeed");

    assert_eq!(
        decrypted_derived, secret,
        "Derived-key decrypted secret should match original plaintext"
    );
    println!("Derived-key PRE verified!");

    // ================================================================
    // Step 11: Idempotency — storing same secret again
    // ================================================================
    let sequence_before_second =
        cli_tool::get_account_sequence(&node1_address, chain_config.clone())
            .await
            .expect("get sequence before second store");

    let object_response_2 = cli_tool::store_prepared_secret(
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
    )
    .await
    .expect("store_prepared_secret (idempotent)");

    tokio::time::sleep(Duration::from_secs(2)).await;
    let sequence_after_second =
        cli_tool::get_account_sequence(&node1_address, chain_config.clone())
            .await
            .expect("get sequence after second store");

    assert_eq!(
        object_id_service, object_response_2.object_id,
        "Idempotency: second store should return same object_id"
    );
    assert_eq!(
        sequence_before_second, sequence_after_second,
        "Idempotency: sequence should NOT change (no tx for duplicate)"
    );

    println!("Idempotency verified!");
    println!("=== Full pipeline test passed ===");
}
