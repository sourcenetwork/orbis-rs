//! Secret lifecycle test: DKG → StoreSecret → PRE → Decrypt.
//!
//! Native equivalent of the Docker-based `test_cli_calls_dkg_and_pre_endpoint`.
//! Starts a 3-node ring with SourceHub, runs the full pipeline, and verifies
//! encryption, signatures, re-encryption, and idempotency. All processes are
//! cleaned up on drop.

use std::time::Duration;

use bulletin::r#trait::{BulletinPost, DocumentPayload};
use crypto::helpers::{generate_keypair, generate_policy_metadata};
use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, SignImpl};
use orbis_e2e::fixture::setup_dkg;

/// Placeholder proof (must match orbis-node constant).
const BULLETIN_PLACEHOLDER_PROOF: &[u8] = &[0x01];

/// Full DKG → StoreSecret → PRE → Decrypt pipeline.
///
/// Mirrors the Docker-based test_cli_calls_dkg_and_pre_endpoint:
/// 1. Start 3 nodes + SourceHub, run DKG
/// 2. Store secrets (manual + service paths, with/without derivation)
/// 3. Verify BLS threshold signatures
/// 4. Register ACP objects + relationships
/// 5. PRE re-encryption + decrypt (normal + derived key)
/// 6. Idempotent store verification
#[tokio::test]
#[ignore = "requires sourcehubd on PATH and ~2 min runtime"]
async fn dkg_store_pre_decrypt_full_pipeline() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let fixture = setup_dkg().await;
    let chain_config = fixture.chain_config();
    let endpoint = fixture.endpoint();
    let ring_pk_hex = &fixture.ring_pk_hex;
    let ring_id = &fixture.ring_id;
    let node1_address = &fixture.node_infos[0].public_address;

    println!("Ring ready: pk={}...", &ring_pk_hex[..40]);

    // ================================================================
    // Setup: ACP policy + user namespace
    // ================================================================
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex = hex::encode(
        CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"),
    );
    let reader_pk_hex = hex::encode(
        CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"),
    );

    let resource = "document".to_string();
    let relation = "reader".to_string();
    let permission = "read".to_string();
    let did_pk_string = "test_did_secret".to_string();
    let namespace = "e2e_pipeline_ns".to_string();
    let full_namespace = format!("bulletin/{}", namespace);

    let policy_id = cli_tool::add_policy_to_chain(chain_config.clone())
        .await
        .expect("add policy");

    cli_tool::register_bulletin_namespace(namespace.clone(), chain_config.clone())
        .await
        .expect("register user namespace");

    cli_tool::add_bulletin_collaborator(
        namespace.clone(),
        fixture.node_infos[0].public_address.clone(),
        chain_config.clone(),
    )
    .await
    .expect("add node as collaborator");

    // ================================================================
    // Store secrets: manual + service paths
    // ================================================================
    let ring_pk_bytes = hex::decode(ring_pk_hex).expect("decode ring_pk hex");
    let ring_pk_point = GroupAffine::from_bytes(&ring_pk_bytes).expect("deserialize ring_pk");
    let proof = vec![0x01];

    // Manual path: encrypt + post directly to bulletin
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

    // Service path: prepare + store
    let secret = b"Hello from StoreSecret!";
    let prepared_secret = cli_tool::prepare_secret(
        secret,
        ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
    )
    .expect("prepare_secret");

    let derivation = b"test_derivation".to_vec();
    let prepared_secret_derived = cli_tool::prepare_secret(
        secret,
        ring_pk_hex,
        Some(derivation.clone()),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
    )
    .expect("prepare_secret derived");

    let sequence_before =
        cli_tool::get_account_sequence(node1_address, chain_config.clone())
            .await
            .expect("get sequence before store");

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

    // Verify tx was broadcast
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sequence_after =
        cli_tool::get_account_sequence(node1_address, chain_config.clone())
            .await
            .expect("get sequence after store");
    assert!(
        sequence_after > sequence_before,
        "Sequence should increment after store"
    );

    // ================================================================
    // Verify bulletin posts + BLS signature
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
    assert_eq!(manual.ring_id, service.ring_id);
    assert_eq!(manual.policy_id, service.policy_id);

    // Verify BLS threshold signature
    let bulletin_post = BulletinPost {
        id: object_id_service.clone(),
        namespace: namespace.clone(),
        payload: service_bytes.clone(),
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
    };
    let message_bytes: Vec<u8> = bulletin_post.try_into().expect("serialize BulletinPost");
    let signature_bytes = hex::decode(&signature_hex).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("deserialize signature");
    let ring_pk = GroupAffine::from_bytes(
        &hex::decode(ring_pk_hex).expect("decode ring_pk"),
    )
    .expect("deserialize ring pk");
    SignImpl::new()
        .verify(&ring_pk, &message_bytes, &signature)
        .expect("BLS signature should verify");
    println!("BLS signature verified!");

    // ================================================================
    // ACP: register objects + set relationships
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
    // PRE + decrypt
    // ================================================================
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
    assert_eq!(decrypted, secret, "Decrypted should match original");
    println!("PRE decryption verified!");

    // Derived-key PRE
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
    assert_eq!(decrypted_derived, secret, "Derived decrypted should match");
    println!("Derived-key PRE verified!");

    // ================================================================
    // Idempotent store
    // ================================================================
    let seq_before =
        cli_tool::get_account_sequence(node1_address, chain_config.clone())
            .await
            .expect("seq before idempotent store");

    let response_2 = cli_tool::store_prepared_secret(
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
    .expect("idempotent store");

    tokio::time::sleep(Duration::from_secs(2)).await;
    let seq_after =
        cli_tool::get_account_sequence(node1_address, chain_config.clone())
            .await
            .expect("seq after idempotent store");

    assert_eq!(object_id_service, response_2.object_id, "Same object_id");
    assert_eq!(seq_before, seq_after, "No tx for duplicate store");
    println!("Idempotency verified!");
    println!("=== Full pipeline test passed ===");
}
