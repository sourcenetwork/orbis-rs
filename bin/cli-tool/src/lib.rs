//! CLI tool library exports
//!
//! This module re-exports public items for use in integration tests.

mod commands;

// Re-export the main CLI functions for integration testing
pub use commands::{do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, DkgResult};
