//! Iroh networking implementation
//!
//! This module provides iroh-based implementations of the network traits.

pub mod base;
pub mod router;

pub use base::IrohNetwork;
pub use router::Router;
