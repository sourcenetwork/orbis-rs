//! Cosmos bank module types and operations.
//!
//! This module provides types for interacting with Cosmos SDK's bank module,
//! which handles token transfers.

use prost::Message;

// ============================================================================
// Message Types (for transactions)
// ============================================================================

/// Cosmos bank MsgSend message for transferring tokens.
/// Proto field numbers match cosmos.bank.v1beta1.MsgSend:
/// - 1: from_address (string)
/// - 2: to_address (string)
/// - 3: amount (repeated Coin)
#[derive(Clone, Message)]
pub struct MsgSend {
    /// Sender's bech32 address
    #[prost(string, tag = "1")]
    pub from_address: String,
    /// Recipient's bech32 address
    #[prost(string, tag = "2")]
    pub to_address: String,
    /// Amount to transfer
    #[prost(message, repeated, tag = "3")]
    pub amount: Vec<Coin>,
}

impl MsgSend {
    pub const TYPE_URL: &'static str = "/cosmos.bank.v1beta1.MsgSend";
}

/// Coin represents a token with a denomination and an amount.
/// Proto field numbers match cosmos.base.v1beta1.Coin:
/// - 1: denom (string)
/// - 2: amount (string)
#[derive(Clone, Message)]
pub struct Coin {
    /// Denomination (e.g., "uopen")
    #[prost(string, tag = "1")]
    pub denom: String,
    /// Amount as a string (e.g., "1000000")
    #[prost(string, tag = "2")]
    pub amount: String,
}
