//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{
    add_policy_to_chain, do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre,
    register_object_to_chain, set_relationship_on_chain, DkgResult,
};
