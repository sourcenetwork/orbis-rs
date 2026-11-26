use super::*;

fn test_network_args() -> NetworkArgs {
    NetworkArgs {
        endpoint: "http://localhost:50051".to_string(),
        chain_id: "test-chain".to_string(),
        rpc_url: "http://rpc.example".to_string(),
        rest_url: "http://rest.example".to_string(),
        chain_grpc_url: "http://grpc.example".to_string(),
        account_prefix: "prefix".to_string(),
        signing_key: None,
        allow_insecure_rpc: false,
    }
}

#[test]
fn chain_config_maps_each_field_to_the_matching_chain_config_field() {
    let config = test_network_args().chain_config();
    assert_eq!(config.chain_id, "test-chain");
    assert_eq!(config.rpc_url, "http://rpc.example");
    assert_eq!(config.rest_url, "http://rest.example");
    assert_eq!(config.grpc_url, "http://grpc.example");
    assert_eq!(config.account_prefix, "prefix");
    assert!(!config.allow_insecure_rpc);

    // The override threads through in both directions.
    let mut args = test_network_args();
    args.allow_insecure_rpc = true;
    assert!(args.chain_config().allow_insecure_rpc);
}

#[test]
fn require_signing_key_errors_when_absent() {
    let err = test_network_args().require_signing_key().unwrap_err();
    assert!(err.to_string().contains("No signing key configured"));
}

#[test]
fn require_signing_key_returns_value_when_present() {
    let mut network = test_network_args();
    network.signing_key = Some("deadbeef".to_string());
    assert_eq!(network.require_signing_key().unwrap(), "deadbeef");
}

#[test]
fn require_reader_did_pk_errors_when_absent() {
    let err = require_reader_did_pk(None).unwrap_err();
    assert!(err
        .to_string()
        .contains("No reader DID identity configured"));
}

#[test]
fn require_reader_did_pk_returns_value_when_present() {
    assert_eq!(
        require_reader_did_pk(Some("alice".to_string())).unwrap(),
        "alice"
    );
}

#[test]
fn resolve_secret_returns_the_given_value_without_prompting() {
    assert_eq!(
        resolve_secret(Some("shh".to_string()), "prompt: ").unwrap(),
        "shh"
    );
}

#[test]
fn require_valid_window_pair_accepts_both_absent_or_both_present() {
    assert!(require_valid_window_pair(None, None).is_ok());
    assert!(require_valid_window_pair(Some(1), Some(2)).is_ok());
}

#[test]
fn require_valid_window_pair_rejects_only_one_side() {
    let err = require_valid_window_pair(Some(1), None).unwrap_err();
    assert!(err.to_string().contains("must both be provided"));

    let err = require_valid_window_pair(None, Some(2)).unwrap_err();
    assert!(err.to_string().contains("must both be provided"));
}

#[test]
fn resolve_whitelist_target_prefers_policy_id_when_both_could_apply() {
    let target = resolve_whitelist_target(Some("p1".to_string()), None).unwrap();
    match target {
        WhitelistTarget::PolicyId(id) => assert_eq!(id, "p1"),
        WhitelistTarget::RingId(_) => panic!("expected PolicyId"),
    }
}

#[test]
fn resolve_whitelist_target_uses_ring_id_when_policy_absent() {
    let target = resolve_whitelist_target(None, Some("r1".to_string())).unwrap();
    match target {
        WhitelistTarget::RingId(id) => assert_eq!(id, "r1"),
        WhitelistTarget::PolicyId(_) => panic!("expected RingId"),
    }
}

#[test]
fn resolve_whitelist_target_errors_when_neither_given() {
    // WhitelistTarget has no Debug impl, so unwrap_err() isn't available here.
    match resolve_whitelist_target(None, None) {
        Err(e) => assert!(e
            .to_string()
            .contains("Must provide --policy-id or --ring-id")),
        Ok(_) => panic!("expected an error when neither --policy-id nor --ring-id is given"),
    }
}

#[test]
fn cli_parses_encrypt_secret_without_secret_flag() {
    // --secret is optional now; omitting it must not be a clap-level parse error —
    // the interactive-prompt fallback only kicks in at runtime, in resolve_secret.
    let cli = Cli::try_parse_from([
        "cli-tool",
        "encrypt-secret",
        "--ring-pk",
        "aa",
        "--policy-id",
        "p",
        "--resource",
        "r",
        "--permission",
        "read",
    ]);
    assert!(cli.is_ok(), "{:?}", cli.err());
}

#[test]
fn cli_rejects_whitelist_command_with_both_policy_and_ring_id() {
    let cli = Cli::try_parse_from([
        "cli-tool",
        "add-node-to-whitelist",
        "--node-key",
        "n1",
        "--policy-id",
        "p1",
        "--ring-id",
        "r1",
    ]);
    assert!(cli.is_err());
}
