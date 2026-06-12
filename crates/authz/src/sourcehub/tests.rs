use super::SourceHubAuth;
use crate::r#trait::Authz;
use crate::sourcehub::{AccessCheckRequest, ValidWindow};
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
};
use common::SourceHubTestContainer;
use did_key::{generate, Ed25519KeyPair, Fingerprint};

#[test]
fn test_name() {
    assert_eq!(SourceHubAuth::name(), "authz/sourcehub");
}

/// Test policy for ACP - simple document access control
const TEST_POLICY_YAML: &str = r#"
name: test-policy
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
        expr: creator + reader
      - name: write
        expr: creator
"#;

/// Integration test that creates a policy and then queries it.
///
/// This test requires Docker to be running.
#[tokio::test]
#[serial_test::serial]
async fn test_create_and_query_policy() {
    // 1. Spin up SourceHub container
    let container = SourceHubTestContainer::new();

    let config = container.chain_config();

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
    let auth = SourceHubAuth::new(container.chain_config_builder())
        .await
        .unwrap();
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
        None,
        None,
        None,
    );
    let is_authorized = auth
        .check(access_request.to_bytes().unwrap(), &reader_did.clone())
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
        "document".to_string(),
        "doc-123".to_string(),
        "read".to_string(),
        None,
        None,
        None,
    );

    let is_authorized = auth
        .check(access_request.to_bytes().unwrap(), &reader_did.clone())
        .await
        .expect("Failed to check access");

    println!(
        "Reader is authorized after setting relationship: {}",
        is_authorized
    );
    assert!(
        is_authorized,
        "Reader should be authorized to read after relationship is set"
    );
}

/// A more complex policy with multiple resources and permission expressions
/// to test the policy parser thoroughly.
const COMPLEX_POLICY_YAML: &str = r#"
name: project-policy
resources:
  - name: project
    relations:
      - name: admin
        types:
          - actor
      - name: editor
        types:
          - actor
      - name: viewer
        types:
          - actor
    permissions:
      - name: manage
        expr: admin
      - name: edit
        expr: admin + editor
      - name: view
        expr: admin + editor + viewer
      - name: delete
        expr: admin
  - name: file
    relations:
      - name: creator
        types:
          - actor
      - name: contributor
        types:
          - actor
    permissions:
      - name: read
        expr: creator + contributor
      - name: write
        expr: creator
"#;

/// Test the policy parser with a more complex policy containing
/// multiple resources and various permission expressions.
#[tokio::test]
#[serial_test::serial]
async fn test_complex_policy_permissions() {
    // 1. Spin up SourceHub container
    let container = SourceHubTestContainer::new();

    let config = container.chain_config();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    println!("Test signer address: {}", signer.address());

    let client = SourceHubClient::with_signer(config.clone(), signer)
        .await
        .expect("Failed to create client with signer");

    // 2. Create the complex policy
    println!("Creating complex policy...");
    let result = client
        .acp_create_policy(COMPLEX_POLICY_YAML, 1)
        .await
        .expect("Failed to create policy");

    println!("Policy created! TX hash: {}", result.tx_hash);
    assert_eq!(result.code, 0, "Transaction should succeed");

    // 3. Get the policy ID
    let policy_ids = client
        .acp_list_policy_ids()
        .await
        .expect("Failed to list policy IDs");

    let policy_id = &policy_ids.ids[0];
    println!("Policy ID: {}", policy_id);

    // 4. Create test users with different roles
    let admin_key = generate::<Ed25519KeyPair>(None);
    let admin_did = format!("did:key:{}", admin_key.fingerprint());

    let editor_key = generate::<Ed25519KeyPair>(None);
    let editor_did = format!("did:key:{}", editor_key.fingerprint());

    let viewer_key = generate::<Ed25519KeyPair>(None);
    let viewer_did = format!("did:key:{}", viewer_key.fingerprint());

    let outsider_key = generate::<Ed25519KeyPair>(None);
    let outsider_did = format!("did:key:{}", outsider_key.fingerprint());

    println!("Admin DID: {}", admin_did);
    println!("Editor DID: {}", editor_did);
    println!("Viewer DID: {}", viewer_did);
    println!("Outsider DID: {}", outsider_did);

    // 5. Register a project object
    let project = Object {
        resource: "project".to_string(),
        id: "proj-1".to_string(),
    };

    let result = client
        .acp_register_object(policy_id, project.clone())
        .await
        .expect("Failed to register project");
    println!("Project registered! TX hash: {}", result.tx_hash);
    assert_eq!(result.code, 0);

    // 6. Set up relationships: admin, editor, viewer
    // Admin relationship
    let result = client
        .acp_set_relationship(
            policy_id,
            Relationship {
                object: Some(project.clone()),
                relation: "admin".to_string(),
                subject: Some(Subject {
                    kind: Some(SubjectKind::Actor(Actor {
                        id: admin_did.clone(),
                    })),
                }),
            },
        )
        .await
        .expect("Failed to set admin");
    println!("Admin relationship set! TX hash: {}", result.tx_hash);
    assert_eq!(result.code, 0);

    // Editor relationship
    let result = client
        .acp_set_relationship(
            policy_id,
            Relationship {
                object: Some(project.clone()),
                relation: "editor".to_string(),
                subject: Some(Subject {
                    kind: Some(SubjectKind::Actor(Actor {
                        id: editor_did.clone(),
                    })),
                }),
            },
        )
        .await
        .expect("Failed to set editor");
    println!("Editor relationship set! TX hash: {}", result.tx_hash);
    assert_eq!(result.code, 0);

    // Viewer relationship
    let result = client
        .acp_set_relationship(
            policy_id,
            Relationship {
                object: Some(project.clone()),
                relation: "viewer".to_string(),
                subject: Some(Subject {
                    kind: Some(SubjectKind::Actor(Actor {
                        id: viewer_did.clone(),
                    })),
                }),
            },
        )
        .await
        .expect("Failed to set viewer");
    println!("Viewer relationship set! TX hash: {}", result.tx_hash);
    assert_eq!(result.code, 0);

    // 7. Test permissions using SourceHubAuth
    let auth = SourceHubAuth::new(container.chain_config_builder())
        .await
        .unwrap();

    // Verify the policy was parsed correctly
    let policy = auth
        .get_policy(policy_id.clone())
        .await
        .expect("Failed to get policy");
    println!("Retrieved policy: {:?}", policy);
    assert_eq!(policy.name, "project-policy");

    // Find the project resource and verify permissions exist
    let project_resource = policy
        .resources
        .iter()
        .find(|r| r.name == "project")
        .unwrap();
    println!(
        "Project permissions: {:?}",
        project_resource
            .permissions
            .iter()
            .map(|p| &p.name)
            .collect::<Vec<_>>()
    );

    // 7. Test authorization via permission evaluation (policy expr: manage=admin, edit=admin+editor, view=admin+editor+viewer)
    // check() uses acp_verify_access which evaluates the policy permission expression.

    // --- Test MANAGE permission (only admin) ---
    println!("\n--- Testing MANAGE permission ---");

    let check = |perm: &str| {
        AccessCheckRequest::new(
            policy_id.to_string(),
            "project".to_string(),
            "proj-1".to_string(),
            perm.to_string(),
            None,
            None,
            None,
        )
    };

    let can = |req: AccessCheckRequest, did: String| {
        let auth = &auth;
        async move { auth.check(req.to_bytes().unwrap(), &did).await.unwrap() }
    };

    assert!(
        can(check("manage"), admin_did.clone()).await,
        "Admin can manage"
    );
    assert!(
        !can(check("manage"), editor_did.clone()).await,
        "Editor cannot manage"
    );
    assert!(
        !can(check("manage"), viewer_did.clone()).await,
        "Viewer cannot manage"
    );
    assert!(
        !can(check("manage"), outsider_did.clone()).await,
        "Outsider cannot manage"
    );

    // --- Test EDIT permission (admin + editor) ---
    println!("\n--- Testing EDIT permission ---");

    assert!(
        can(check("edit"), admin_did.clone()).await,
        "Admin can edit"
    );
    assert!(
        can(check("edit"), editor_did.clone()).await,
        "Editor can edit"
    );
    assert!(
        !can(check("edit"), viewer_did.clone()).await,
        "Viewer cannot edit"
    );
    assert!(
        !can(check("edit"), outsider_did.clone()).await,
        "Outsider cannot edit"
    );

    // --- Test VIEW permission (admin + editor + viewer) ---
    println!("\n--- Testing VIEW permission ---");

    assert!(
        can(check("view"), admin_did.clone()).await,
        "Admin can view"
    );
    assert!(
        can(check("view"), editor_did.clone()).await,
        "Editor can view"
    );
    assert!(
        can(check("view"), viewer_did.clone()).await,
        "Viewer can view"
    );
    assert!(
        !can(check("view"), outsider_did.clone()).await,
        "Outsider cannot view"
    );

    println!("\n✓ All complex policy permission tests passed!");
}

/// Tests that a request with a valid_window entirely in the past returns false
/// without reaching the chain.
#[tokio::test]
#[serial_test::serial]
async fn test_valid_window_out_of_range() {
    let container = SourceHubTestContainer::new();

    let auth = SourceHubAuth::new(container.chain_config_builder())
        .await
        .unwrap();

    // timestamp "2" is after end "1", so it falls outside the window
    let request = AccessCheckRequest::new(
        "any-policy".to_string(),
        "document".to_string(),
        "doc-1".to_string(),
        "read".to_string(),
        None,
        Some(2u64),
        Some(ValidWindow { start: 0, end: 1 }),
    );

    let result = auth
        .check(request.to_bytes().unwrap(), "did:key:any")
        .await
        .expect("check should not error");

    assert!(!result, "Out-of-range window should deny access");
}

/// Tests that a request with a valid_window covering the current time passes
/// through to the chain and returns the chain's authorization result.
#[tokio::test]
#[serial_test::serial]
async fn test_valid_window_in_range() {
    let container = SourceHubTestContainer::new();

    let config = container.chain_config();
    let signer = common::blockchain::TxSigner::from_hex_key(
        common::blockchain::TEST_ACCOUNT_HEX_KEY,
        config.clone(),
    )
    .expect("Failed to create signer");
    let client = common::blockchain::SourceHubClient::with_signer(config.clone(), signer)
        .await
        .expect("Failed to create client");

    // Create a policy and register an object with a reader relationship
    let result = client
        .acp_create_policy(TEST_POLICY_YAML, 1)
        .await
        .expect("Failed to create policy");
    assert_eq!(result.code, 0);

    let policy_ids = client
        .acp_list_policy_ids()
        .await
        .expect("Failed to list policy IDs");
    let policy_id = &policy_ids.ids[0];

    let key_pair = did_key::generate::<did_key::Ed25519KeyPair>(None);
    let reader_did = format!("did:key:{}", did_key::Fingerprint::fingerprint(&key_pair));

    let document = common::blockchain::acp::Object {
        resource: "document".to_string(),
        id: "doc-window-test".to_string(),
    };

    client
        .acp_register_object(policy_id, document.clone())
        .await
        .expect("Failed to register object");

    client
        .acp_set_relationship(
            policy_id,
            common::blockchain::acp::Relationship {
                object: Some(document),
                relation: "reader".to_string(),
                subject: Some(common::blockchain::acp::Subject {
                    kind: Some(common::blockchain::acp::SubjectKind::Actor(
                        common::blockchain::acp::Actor {
                            id: reader_did.clone(),
                        },
                    )),
                }),
            },
        )
        .await
        .expect("Failed to set relationship");

    let auth = SourceHubAuth::new(container.chain_config_builder())
        .await
        .unwrap();

    // Use the current Unix timestamp; window 0..u64::MAX always contains it
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System clock error")
        .as_secs();

    let request = AccessCheckRequest::new(
        policy_id.clone(),
        "document".to_string(),
        "doc-window-test".to_string(),
        "read".to_string(),
        None,
        Some(now),
        Some(ValidWindow {
            start: 0,
            end: u64::MAX,
        }),
    );

    let result = auth
        .check(request.to_bytes().unwrap(), &reader_did)
        .await
        .expect("check should not error");

    assert!(
        result,
        "In-range window with valid relationship should grant access"
    );
}
