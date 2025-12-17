//! Crypto abstraction layer for orbis
//!
//! This module defines the core cryptography abstractions that can be implemented
//! by various curves.
pub mod error;
pub mod r#trait;

pub mod bls12_381;

pub use r#trait::{CryptoDeserialize, CryptoSerialize};

#[cfg(test)]
pub mod test_helper;

#[cfg(test)]
mod dkg_tests;
