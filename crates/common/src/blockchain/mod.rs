//! Shared Orbis object IDs and node message signatures.
//!
//! The `vera` feature provides `VeraConfig` and deployment-trust bootstrap
//! for the Vera backend.

mod error;
mod node_signing;
pub mod orbis;
#[cfg(feature = "vera")]
pub mod vera;

pub use error::{BlockchainError, Result};
pub use node_signing::{node_public_key_hex, sign_node_message_with_hex_key, verify_node_message};
#[cfg(feature = "vera")]
pub use vera::*;
