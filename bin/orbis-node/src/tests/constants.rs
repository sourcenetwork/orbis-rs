/// Deterministic secp256k1 signing keys injected via ORBIS_SIGNING_KEY in docker-compose.
/// Private keys 1, 2, 3 → standard G, 2G, 3G compressed public keys.
pub const NODE_KEY_1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
pub const NODE_KEY_2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
pub const NODE_KEY_3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

/// Private key 4 → 4G compressed public key. No running node uses this key; it serves
/// as a backup node key for the report-kick promotion test.
#[cfg(feature = "integration-test")]
pub const NODE_KEY_4: &str = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

/// Private key 6 → 6G compressed public key. Never has a running node: reshare tests
/// include it in the new committee so the reshare stalls (dealers only complete once
/// every new member acks, so an offline member keeps the ring pending indefinitely).
/// Private key 5 is skipped on purpose: 5G is 022f8bde... which sorts below NODE_KEY_1
/// and would make the offline node the reshare selector (new-committee node id 1);
/// 6G's 03 prefix sorts after every running node's key.
#[cfg(feature = "integration-test")]
pub const NODE_KEY_OFFLINE: &str =
    "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";

/// P2P address seeded into NODE_KEY_OFFLINE's genesis NodeInfo. It must pass
/// `validate_peer_id` (64-hex node part + host:port) so reshare route building
/// succeeds, but the host does not exist in the compose network, so every send
/// to it fails and the node never participates.
#[cfg(feature = "integration-test")]
pub const OFFLINE_NODE_PEER_ID: &str =
    "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f@node-offline:4242";

/// Deterministic ACP policy ID for ORBIS_RING_POLICY_YAML created as the first policy
/// (counter=0) on a fresh Vera chain. Computed via acp_core@v0.8.1 id_transformer.go.
pub const RING_GOVERNANCE_POLICY_ID: &str =
    "3199b84b4a6862c40fe2623879dfc36df281a2262898da36f7de65c376a93e05";

/// Genesis `reporting` blob for ring seeding; only `node_offline_demerits`,
/// `backup_node_keys`, and `kick_threshold` vary across tests.
pub fn reporting_genesis_json(
    node_offline_demerits: u64,
    backup_node_keys: &[&str],
    kick_threshold: u64,
) -> serde_json::Value {
    serde_json::json!({
        "demerit_config": {
            "node_offline_demerits": node_offline_demerits,
            // Same weight as node_offline; tests that need a different
            // invalid-proof weight can grow a dedicated parameter.
            "invalid_crypto_response_demerits": node_offline_demerits,
            // Required (>= 1) by the chain's ring validation; same weight as node_offline.
            "unauthorized_request_demerits": node_offline_demerits,
            "reset_interval_seconds": 86400
        },
        "backup_node_keys": backup_node_keys,
        "kick_threshold": kick_threshold
    })
}
