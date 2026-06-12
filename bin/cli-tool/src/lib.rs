//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    add_bulletin_collaborator, add_policy_to_chain, add_policy_to_chain_with_config,
    create_bulletin_post, create_bulletin_post_with_config, do_dkg, do_encrypt_secret,
    do_generate_reader_key, do_pre, do_sign, do_store_secret, fund, get_account_sequence,
    get_account_sequence_with_config, get_latest_ring, list_bulletin_posts, post_key_derivation,
    post_key_derivation_with_config, prepare_secret, query_node_info, query_ring_state,
    read_bulletin_post, read_bulletin_post_with_config, register_bulletin_namespace,
    register_object_to_chain, register_object_to_chain_with_config, set_relationship_on_chain,
    set_relationship_on_chain_with_config, store_prepared_secret, update_ring_post_by_acp,
    update_ring_post_by_acp_with_config, DkgResult, NodeInfoResult, PreparedSecret, SignResult,
    StoreSecretResult,
};
