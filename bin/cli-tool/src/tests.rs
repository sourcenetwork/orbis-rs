use super::*;
use crate::commands::{did_seed, is_retryable_dkg_start_error};
use crypto::CryptoSerialize;
use tonic::{Code, Status};

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

fn test_ring_pk_hex() -> String {
    let (_, pk) = crypto::helpers::generate_keypair().expect("keypair generation");
    hex::encode(CryptoSerialize::to_bytes(&pk).expect("serialize pk"))
}

#[test]
fn did_seed_is_always_32_bytes() {
    assert_eq!(did_seed("").len(), 32);
    assert_eq!(did_seed("a").len(), 32);
    assert_eq!(
        did_seed("a reader identity string much longer than 32 bytes on its own").len(),
        32
    );
}

#[test]
fn did_seed_is_deterministic_and_input_sensitive() {
    assert_eq!(did_seed("alice"), did_seed("alice"));
    assert_ne!(did_seed("alice"), did_seed("bob"));
}

#[test]
fn is_retryable_dkg_start_error_only_matches_unavailable_timeout() {
    assert!(is_retryable_dkg_start_error(&Status::new(
        Code::Unavailable,
        "request timed out waiting for peer"
    )));
    assert!(!is_retryable_dkg_start_error(&Status::new(
        Code::Unavailable,
        "connection refused"
    )));
    assert!(!is_retryable_dkg_start_error(&Status::new(
        Code::Internal,
        "timed out"
    )));
}

#[test]
fn prepare_secret_roundtrips_through_json() {
    let ring_pk_hex = test_ring_pk_hex();
    let prepared = prepare_secret(
        b"hello world",
        &ring_pk_hex,
        None,
        "policy".to_string(),
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
    )
    .expect("prepare_secret should succeed with a valid ring pk");

    assert!(!prepared.encrypted_document.is_empty());
    assert!(!prepared.enc_cmt.is_empty());

    let json = serde_json::to_string(&prepared).expect("serialize");
    let round_tripped: PreparedSecret = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        prepared.encrypted_document,
        round_tripped.encrypted_document
    );
    assert_eq!(prepared.enc_cmt, round_tripped.enc_cmt);
    assert_eq!(prepared.metadata, round_tripped.metadata);
}

#[test]
fn prepare_secret_rejects_invalid_hex_ring_pk() {
    let err = prepare_secret(
        b"secret",
        "not-valid-hex!!",
        None,
        "policy".to_string(),
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Invalid ring_pk hex"));
}

#[test]
fn prepare_secret_rejects_hex_that_is_not_a_valid_curve_point() {
    // Valid hex, but far too short to be a real compressed curve point.
    let err = prepare_secret(
        b"secret",
        "deadbeef",
        None,
        "policy".to_string(),
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Invalid ring_pk"));
}
