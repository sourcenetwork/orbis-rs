//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    add_bulletin_collaborator, add_policy_to_chain, create_bulletin_post, create_policy_on_chain,
    delete_relationship_on_chain, derive_public_key, do_dkg, do_encrypt_secret,
    do_generate_reader_key, do_pre, do_sign, do_store_secret, fund, get_account_sequence,
    list_bulletin_posts, prepare_secret, query_node_info, read_bulletin_post,
    register_bulletin_namespace, register_object_to_chain, set_relationship_direct,
    set_relationship_on_chain, signer_did_for_pk, store_prepared_secret, DerivePublicKeyResult,
    DkgResult, NodeInfoResult, PreparedSecret, SignAcpFields, SignResult, StoreSecretResult,
};
