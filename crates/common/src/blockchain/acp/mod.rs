//! Access Control Policy (ACP) module types and operations.
//!
//! This module provides types and methods for interacting with Vera's ACP module,
//! which manages access control policies for applications.
//!
//! - [`types`] — message, query, and domain types.
//! - [`client`] — `VeraClient` extension methods (`acp_*`) that call the chain.

mod client;
mod types;

pub use types::*;
