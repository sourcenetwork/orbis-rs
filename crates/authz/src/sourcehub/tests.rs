use super::SourceHubAuth;
use common::blockchain::{ChainConfig, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY};
use common::SourceHubTestContainer;

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
}
