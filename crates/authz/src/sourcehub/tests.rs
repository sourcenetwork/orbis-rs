use super::SourceHubAuth;
use crate::r#trait::Authz;
use crate::sourcehub::AccessCheckRequest;
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    ChainConfig, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
};
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
    let access_request = AccessCheckRequest::new(policy_id.clone(), "document", "doc-123", "read");

    let is_authorized = auth
        .check(access_request.to_bytes().unwrap(), reader_did.clone())
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

    // 7. Test that the reader is NOT authorized to write (only owner can write)
    let write_request = AccessCheckRequest::new(policy_id.clone(), "document", "doc-123", "write");

    let can_write = auth
        .check(write_request.to_bytes().unwrap(), reader_did.clone())
        .await
        .expect("Failed to check write access");

    println!("Reader can write: {}", can_write);
    assert!(!can_write, "Reader should NOT be authorized to write");
}

/// A more complex policy with multiple resources and permission expressions
/// to test the policy parser thoroughly.
const COMPLEX_POLICY_YAML: &str = r#"
name: project-policy
resources:
  project:
    relations:
      admin:
        types:
          - actor
      editor:
        types:
          - actor
      viewer:
        types:
          - actor
    permissions:
      manage:
        expr: admin
      edit:
        expr: admin + editor
      view:
        expr: admin + editor + viewer
      delete:
        expr: admin
  file:
    relations:
      owner:
        types:
          - actor
      contributor:
        types:
          - actor
    permissions:
      read:
        expr: owner + contributor
      write:
        expr: owner
actor:
  name: actor
"#;

/// Test the policy parser with a more complex policy containing
/// multiple resources and various permission expressions.
#[tokio::test]
#[serial_test::serial]
async fn test_complex_policy_permissions() {
    // 1. Spin up SourceHub container
    let _container = SourceHubTestContainer::new();

    let config = ChainConfig::local();

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
    let auth = SourceHubAuth::new().await;

    // Verify the policy was parsed correctly
    let policy = auth
        .get_policy(policy_id.clone())
        .await
        .expect("Failed to get policy");
    println!("Policy name: {}", policy.name);
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

    // Test permission expressions were parsed correctly
    // Note: SourceHub may add "owner" to expressions since registering an object creates ownership
    let view_relations = policy
        .get_relations_for_permission("project", "view")
        .unwrap();
    println!("Relations for 'view' permission: {:?}", view_relations);
    assert!(
        view_relations.contains(&"admin".to_string()),
        "view should include admin"
    );
    assert!(
        view_relations.contains(&"editor".to_string()),
        "view should include editor"
    );
    assert!(
        view_relations.contains(&"viewer".to_string()),
        "view should include viewer"
    );

    let edit_relations = policy
        .get_relations_for_permission("project", "edit")
        .unwrap();
    println!("Relations for 'edit' permission: {:?}", edit_relations);
    assert!(
        edit_relations.contains(&"admin".to_string()),
        "edit should include admin"
    );
    assert!(
        edit_relations.contains(&"editor".to_string()),
        "edit should include editor"
    );
    assert!(
        !edit_relations.contains(&"viewer".to_string()),
        "edit should NOT include viewer"
    );

    let manage_relations = policy
        .get_relations_for_permission("project", "manage")
        .unwrap();
    println!("Relations for 'manage' permission: {:?}", manage_relations);
    assert!(
        manage_relations.contains(&"admin".to_string()),
        "manage should include admin"
    );
    assert!(
        !manage_relations.contains(&"editor".to_string()),
        "manage should NOT include editor"
    );
    assert!(
        !manage_relations.contains(&"viewer".to_string()),
        "manage should NOT include viewer"
    );

    // 8. Test actual authorization checks

    // --- VIEW permission (admin + editor + viewer) ---
    println!("\n--- Testing VIEW permission ---");

    // Admin can view
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "view");
    let can_view = auth
        .check(req.to_bytes().unwrap(), admin_did.clone())
        .await
        .unwrap();
    println!("Admin can view: {}", can_view);
    assert!(can_view, "Admin should be able to view");

    // Editor can view
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "view");
    let can_view = auth
        .check(req.to_bytes().unwrap(), editor_did.clone())
        .await
        .unwrap();
    println!("Editor can view: {}", can_view);
    assert!(can_view, "Editor should be able to view");

    // Viewer can view
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "view");
    let can_view = auth
        .check(req.to_bytes().unwrap(), viewer_did.clone())
        .await
        .unwrap();
    println!("Viewer can view: {}", can_view);
    assert!(can_view, "Viewer should be able to view");

    // Outsider cannot view
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "view");
    let can_view = auth
        .check(req.to_bytes().unwrap(), outsider_did.clone())
        .await
        .unwrap();
    println!("Outsider can view: {}", can_view);
    assert!(!can_view, "Outsider should NOT be able to view");

    // --- EDIT permission (admin + editor) ---
    println!("\n--- Testing EDIT permission ---");

    // Admin can edit
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "edit");
    let can_edit = auth
        .check(req.to_bytes().unwrap(), admin_did.clone())
        .await
        .unwrap();
    println!("Admin can edit: {}", can_edit);
    assert!(can_edit, "Admin should be able to edit");

    // Editor can edit
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "edit");
    let can_edit = auth
        .check(req.to_bytes().unwrap(), editor_did.clone())
        .await
        .unwrap();
    println!("Editor can edit: {}", can_edit);
    assert!(can_edit, "Editor should be able to edit");

    // Viewer CANNOT edit
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "edit");
    let can_edit = auth
        .check(req.to_bytes().unwrap(), viewer_did.clone())
        .await
        .unwrap();
    println!("Viewer can edit: {}", can_edit);
    assert!(!can_edit, "Viewer should NOT be able to edit");

    // --- MANAGE permission (admin only) ---
    println!("\n--- Testing MANAGE permission ---");

    // Admin can manage
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "manage");
    let can_manage = auth
        .check(req.to_bytes().unwrap(), admin_did.clone())
        .await
        .unwrap();
    println!("Admin can manage: {}", can_manage);
    assert!(can_manage, "Admin should be able to manage");

    // Editor CANNOT manage
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "manage");
    let can_manage = auth
        .check(req.to_bytes().unwrap(), editor_did.clone())
        .await
        .unwrap();
    println!("Editor can manage: {}", can_manage);
    assert!(!can_manage, "Editor should NOT be able to manage");

    // Viewer CANNOT manage
    let req = AccessCheckRequest::new(policy_id, "project", "proj-1", "manage");
    let can_manage = auth
        .check(req.to_bytes().unwrap(), viewer_did.clone())
        .await
        .unwrap();
    println!("Viewer can manage: {}", can_manage);
    assert!(!can_manage, "Viewer should NOT be able to manage");

    println!("\n✓ All complex policy permission tests passed!");
}
