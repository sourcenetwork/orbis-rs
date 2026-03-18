//! DKG Protocol Messages
//!
//! This module defines the message types used for DKG protocol communication
//! between nodes over the iroh network.

use serde::{Deserialize, Serialize};

/// DKG protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DkgMessage {
    /// Phase 1: Polynomial commitment broadcast
    Commitment {
        session_id: u64,
        from_node_id: u32,
        commitment: Vec<u8>, // Serialized PolynomialCommitment
    },
    /// Phase 2: Share distribution
    Share {
        session_id: u64,
        from_node_id: u32,
        to_node_id: u32,
        share_value: Vec<u8>, // Serialized share value
        nonce: [u8; 16],
    },
    /// Phase 3: Complaint about a malicious node
    Complaint {
        session_id: u64,
        from_node_id: u32,
        accused_node_id: u32,
        reason: String,
    },
    /// Phase 4: Session initialization/coordination
    SessionInit {
        session_id: u64,
        threshold: u32,
        total_participants: u32,
        peer_ids: Vec<String>, // Peer IDs for all participants (so non-initiators know who to send to)
        node_id_assignments: std::collections::HashMap<String, u32>, // peer_id -> node_id mapping assigned by initiator
        token_string: String, // JWT token for authentication - validated by receiving nodes
        /// True when this is a PSS refresh session rather than a fresh DKG
        #[serde(default)]
        is_refresh: bool,
        /// For refresh sessions: the local-storage key of the ring being refreshed
        /// (`aggregate_pk.to_string()`).  Recipients use this to load the old share
        /// and combine it with the refresh delta in Phase 4.
        #[serde(default)]
        refresh_ring_pk_hex: Option<String>,
        /// Seconds between automatic PSS refresh ceremonies for this ring.
        /// `None` means automatic refresh is disabled.
        #[serde(default)]
        pss_interval: Option<u64>,
    },
    /// Error message
    Error { session_id: u64, error: String },
}

impl DkgMessage {
    /// Get the session ID from any message
    pub fn session_id(&self) -> u64 {
        match self {
            DkgMessage::Commitment { session_id, .. } => *session_id,
            DkgMessage::Share { session_id, .. } => *session_id,
            DkgMessage::Complaint { session_id, .. } => *session_id,
            DkgMessage::SessionInit { session_id, .. } => *session_id,
            DkgMessage::Error { session_id, .. } => *session_id,
        }
    }
}
