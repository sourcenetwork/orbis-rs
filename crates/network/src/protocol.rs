//! Protocol identifiers for Orbis
//!
//! This module defines the protocol identifiers used for different Orbis protocols.
//! These are network-agnostic protocol names that can be used with any network
//! implementation (iroh, libp2p, etc.).

/// DKG protocol between ring nodes
///
/// Used for Distributed Key Generation protocol communication between nodes
/// participating in a DKG session.
pub const DKG: &[u8] = b"orbis/dkg/0";

/// Re-encryption protocol (Bob → Ring nodes)
///
/// Used for Proxy Re-Encryption requests where a reader (Bob) requests
/// re-encryption from ring nodes.
pub const REENCRYPT: &[u8] = b"orbis/reencrypt/0";
