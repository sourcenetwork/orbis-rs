use super::SourceHubAuth;
use common::blockchain::{
    acp::{Object, Actor, Relationship, Subject, SubjectKind}, ChainConfig, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
};
use crate::sourcehub::AccessCheckRequest;
use crate::r#trait::Authz;
use common::SourceHubTestContainer;
use did_key::{generate, Ed25519KeyPair, Fingerprint};

/// Test policy for ACP - simple document access control
const TEST_POLICY_YAML: &str = r#"
name: test-policy
resources:
  document:
    relations:
      owner:
        types:
          - actor
      reader:
        types:
          - actor
    permissions:
      read:
        expr: owner + reader
      write:
        expr: owner
actor:
  name: actor
"#;

/// Integration test that creates a policy and then queries it.
///
/// This test requires Docker to be running.
#[tokio::test]
#[serial_test::serial]
async fn test_create_and_query_policy() {
    // 1. Spin up SourceHub container
    let _container = SourceHubTestContainer::new();

    let config = ChainConfig::local();

    // 2. Use the known test account key (added to genesis in docker-compose)
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    println!("Test signer address: {}", signer.address());

    let client = SourceHubClient::with_signer(config.clone(), signer)
        .await
        .expect("Failed to create client with signer");

    // 3. Create a policy
    println!("Creating policy...");
    let result = client
        .acp_create_policy(TEST_POLICY_YAML, 1) // marshal_type 1 = YAML
        .await
        .expect("Failed to create policy");

    println!("Policy created! TX hash: {}", result.tx_hash);
    println!("TX code: {}", result.code);
    println!("TX log: {}", result.log);

    assert_eq!(result.code, 0, "Transaction should succeed");

    // 4. Query the policy using SourceHubAuth
    // Note: We need to extract the policy ID from the response
    // For now, we'll query all policies and find ours
    let policy_ids = client
        .acp_list_policy_ids()
        .await
        .expect("Failed to list policy IDs");

    println!("Policy IDs on chain: {:?}", policy_ids.ids);
    assert!(
        !policy_ids.ids.is_empty(),
        "Should have at least one policy"
    );

    // Get the first policy ID (our newly created one)
    let policy_id = &policy_ids.ids[0];

    // 5. Test SourceHubAuth.get_policy()
    let auth = SourceHubAuth::new().await;
    let policy = auth
        .get_policy(policy_id.clone())
        .await
        .expect("Failed to get policy");

    println!("Retrieved policy: {:?}", policy);
    assert_eq!(policy.name, "test-policy");
    // Create DID for reader user
    let key_pair = generate::<Ed25519KeyPair>(None);
    let reader_did = format!("did:key:{}", key_pair.fingerprint());

    // Register a document object (must match policy resource "document")
    // The signer automatically becomes the owner when registering
    let document = Object {
        resource: "document".to_string(),
        id: "doc-123".to_string(),
    };

    let access_request = AccessCheckRequest::new(
        policy_id.clone(),
        document.resource.clone(),
        document.id.clone(),
        "read".to_string(),
    );
    let is_authorized = auth
        .check(access_request.to_bytes().unwrap(), reader_did.clone())
        .await
        .unwrap();
    assert!(!is_authorized);

    let result = client
        .acp_register_object(policy_id, document.clone())
        .await
        .expect("Failed to register object");

    println!("Object registered! TX hash: {}", result.tx_hash);
    println!("Signer is now owner of document:doc-123");
    assert_eq!(result.code, 0, "Register object should succeed");

    // Set the reader actor - this grants read permission to another user
    let reader_relationship = Relationship {
        object: Some(document),
        relation: "reader".to_string(),
        subject: Some(Subject {
            kind: Some(SubjectKind::Actor(Actor {
                id: reader_did.clone(),
            })),
        }),
    };

    let result = client
        .acp_set_relationship(policy_id, reader_relationship)
        .await
        .expect("Failed to set reader relationship");

    println!("Reader relationship set! TX hash: {}", result.tx_hash);
    assert_eq!(result.code, 0, "Set reader relationship should succeed");

    // 6. Test that reader is now authorized via check()
    let access_request = AccessCheckRequest::new(
        policy_id.clone(),
        "document",
        "doc-123",
        "read",
    );

    let is_authorized = auth
        .check(access_request.to_bytes().unwrap(), reader_did.clone())
        .await
        .expect("Failed to check access");

    println!("Reader is authorized after setting relationship: {}", is_authorized);
    assert!(is_authorized, "Reader should be authorized to read after relationship is set");

    // 7. Test that the reader is NOT authorized to write (only owner can write)
    let write_request = AccessCheckRequest::new(
        policy_id.clone(),
        "document",
        "doc-123",
        "write",
    );

    let can_write = auth
        .check(write_request.to_bytes().unwrap(), reader_did.clone())
        .await
        .expect("Failed to check write access");

    println!("Reader can write: {}", can_write);
    assert!(!can_write, "Reader should NOT be authorized to write");
}
