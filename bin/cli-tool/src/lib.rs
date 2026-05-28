//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    add_bulletin_collaborator, add_policy_to_chain,
    create_bulletin_post, do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, do_sign,
    do_store_secret, fund, get_account_sequence, get_latest_ring, list_bulletin_posts,
    post_key_derivation, prepare_secret, query_node_info, query_ring_state, read_bulletin_post,
    register_bulletin_namespace, register_object_to_chain, set_relationship_on_chain,
    store_prepared_secret, update_ring_post_by_acp, DkgResult, NodeInfoResult, PreparedSecret,
    SignResult, StoreSecretResult,
};
