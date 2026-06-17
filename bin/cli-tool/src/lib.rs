//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    add_bulletin_collaborator, add_node_to_whitelist, add_node_to_whitelist_with_config,
    add_policy_to_chain, add_policy_to_chain_with_config, cancel_ring_upgrade_by_acp,
    cancel_ring_upgrade_by_acp_with_config, create_bulletin_post, create_bulletin_post_with_config,
    do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, do_sign, do_store_secret, fund,
    get_account_sequence, get_account_sequence_with_config, get_latest_ring, list_bulletin_posts,
    post_key_derivation, post_key_derivation_with_config, prepare_secret, query_node_info,
    query_ring_state, read_bulletin_post, read_bulletin_post_with_config,
    register_bulletin_namespace, register_object_to_chain, register_object_to_chain_with_config,
    remove_node_from_whitelist, remove_node_from_whitelist_with_config,
    schedule_ring_upgrade_by_acp, schedule_ring_upgrade_by_acp_with_config,
    set_relationship_on_chain, set_relationship_on_chain_with_config, set_ring_pss_interval_by_acp,
    set_ring_pss_interval_by_acp_with_config, start_ring_reshare_by_acp,
    start_ring_reshare_by_acp_with_config, store_prepared_secret, transfer_node_controller,
    transfer_node_controller_with_config, update_node_peer_id, update_node_peer_id_with_config,
    DkgResult, NodeInfoResult, PreparedSecret, SignResult, StoreSecretResult,
};
