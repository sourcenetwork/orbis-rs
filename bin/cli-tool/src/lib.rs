//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    add_bulletin_collaborator, add_policy_to_chain, create_bulletin_post, derive_public_key,
    do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, do_sign, do_store_secret,
    do_utility_sign, fund, get_account_sequence, get_latest_ring, list_bulletin_posts,
    post_key_derivation, prepare_secret, query_node_info, read_bulletin_post,
    register_bulletin_namespace, register_object_to_chain, set_relationship_on_chain,
    signer_did_for_pk, store_prepared_secret, DerivePublicKeyResult, DkgResult, NodeInfoResult,
    PreparedSecret, SignAcpFields, SignResult, StoreSecretResult, UtilitySignResult,
};
