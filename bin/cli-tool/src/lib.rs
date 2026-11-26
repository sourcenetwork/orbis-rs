//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    build_passkey_pre_challenge, derive_signer_did, do_dkg, do_encrypt_secret, do_pre,
    do_pre_and_save, do_pre_with_inline_document, do_pre_with_passkey, do_retrieve_pre, do_sign,
    do_sign_with_passkey, do_store_secret, finish_passkey_pre, generate_pet_tag, prepare_secret,
    prove_pet_tag_knowledge, query_node_info, query_pet_ring_state, query_ring_state,
    reader_did_from_seed, store_prepared_secret, DkgResult, NodeInfoResult, PendingPasskeyPre,
    PendingPreRetrieval, PreparedPetTag, PreparedSecret, SignResult, StoreSecretResult,
};
