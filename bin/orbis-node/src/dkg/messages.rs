//! DKG Protocol Messages
//!
//! This module defines the message types used for DKG protocol communication
//! between nodes over the iroh network.

use serde::{Deserialize, Serialize};

use crate::sign::messages::RefreshHealthCheckStatement;

/// Describes what kind of ceremony a DKG session is running.
///
/// Replaces the old `is_refresh: bool` / `refresh_ring_pk_hex: Option<String>` pair.
/// Used in both the wire protocol (`SessionInit`) and in-process session state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionKind {
    /// Standard fresh DKG — all nodes are symmetric, new random secret.
    Fresh,
    /// PSS refresh — same secret, new shares, same committee (zero constant term).
    Refresh {
        /// Local-storage key of the ring being refreshed (`aggregate_pk.to_string()`).
        ring_pk_hex: String,
    },
    /// Reshare — same secret, new shares, potentially different committee.
    ///
    /// Old committee members act as Dealers; new committee members act as Receivers.
    /// Nodes in both committees are DealerReceivers.
    Reshare {
        /// Local-storage key of the ring being reshared (`aggregate_pk.to_string()`).
        ring_pk_hex: String,
        /// Peer IDs of the new committee.
        new_peer_ids: Vec<String>,
        /// Threshold for the new committee.
        new_threshold: u32,
        /// Bulletin post ID of the current ring entry.  Sent by the Dealer (who has a
        /// local RingIndexEntry) so that pure Receiver nodes — which have never been in
        /// this ring — can look up and verify the bulletin payload without a local index.
        bulletin_post_id: String,
    },
}

impl SessionKind {
    /// Returns the ring's local-storage key if this session is a Refresh or Reshare,
    /// or `None` for a Fresh DKG.  Used by session cleanup to clear the in-progress flag.
    pub fn ring_key(&self) -> Option<&str> {
        match self {
            SessionKind::Fresh => None,
            SessionKind::Refresh { ring_pk_hex } => Some(ring_pk_hex.as_str()),
            SessionKind::Reshare { ring_pk_hex, .. } => Some(ring_pk_hex.as_str()),
        }
    }
}

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
    /// Reshare-only: a new-committee receiver confirms it has verified one
    /// valid share from an old-committee dealer.
    ReshareShareAck {
        session_id: u64,
        receiver_node_id: u32,
        dealer_id: u32,
    },
    /// Reshare-only: new-committee node 1 freezes the old-dealer subset that
    /// every receiver must use for weighted Phase 4 aggregation.
    ReshareParticipantSet {
        session_id: u64,
        from_node_id: u32,
        selected_dealer_ids: Vec<u32>,
    },
    /// Refresh-only: node 1 distributes the diagnostic threshold signature
    /// result. Receivers verify the signature against their staged refresh
    /// bundle before promoting; `None` means rollback.
    RefreshHealthCheckResult {
        session_id: u64,
        from_node_id: u32,
        statement: RefreshHealthCheckStatement,
        signature: Option<String>,
    },
    /// Phase 4: Session initialization/coordination
    SessionInit {
        session_id: u64,
        threshold: u32,
        total_participants: u32,
        /// Peer IDs of the old (or only) committee — used for sender validation
        /// and commitment/share tracking. For Reshare, new committee IDs are
        /// carried inside `kind`.
        peer_ids: Vec<String>,
        /// peer_id_key → node_id assignments made by the initiator (old committee).
        node_id_assignments: std::collections::HashMap<String, u32>,
        /// JWT token for authentication — empty for Refresh/Reshare sessions.
        token_string: String,
        /// Session kind: Fresh, Refresh, or Reshare.
        kind: SessionKind,
        /// Seconds between automatic PSS refresh ceremonies for this ring.
        /// `None` means automatic refresh is disabled; `Some(0)` is present and immediate.
        #[serde(skip_serializing_if = "Option::is_none")]
        pss_interval: Option<u64>,
        /// Optional policy that externally governs ring updates.
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_id: Option<String>,
        /// Bulletin namespace this ring's payload lives under.
        namespace: String,
        /// Pre-created blank ring entry targeted by this DKG.
        ring_id: String,
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
            DkgMessage::ReshareShareAck { session_id, .. } => *session_id,
            DkgMessage::ReshareParticipantSet { session_id, .. } => *session_id,
            DkgMessage::RefreshHealthCheckResult { session_id, .. } => *session_id,
            DkgMessage::SessionInit { session_id, .. } => *session_id,
            DkgMessage::Error { session_id, .. } => *session_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn session_init_omits_absent_optionals_and_requires_kind() {
        let message = DkgMessage::SessionInit {
            session_id: 1,
            threshold: 1,
            total_participants: 1,
            peer_ids: vec!["peer-a".to_string()],
            node_id_assignments: HashMap::new(),
            token_string: "token".to_string(),
            kind: SessionKind::Fresh,
            pss_interval: None,
            policy_id: None,
            namespace: "orbis".to_string(),
            ring_id: "ring-1".to_string(),
        };

        let value = serde_json::to_value(&message).expect("serialize SessionInit");
        let init = value
            .get("SessionInit")
            .and_then(|v| v.as_object())
            .expect("SessionInit variant payload");

        assert!(!init.contains_key("pss_interval"));
        assert!(!init.contains_key("policy_id"));
        assert_eq!(init.get("kind"), Some(&json!({ "type": "fresh" })));

        let mut missing_kind = init.clone();
        missing_kind.remove("kind");
        let result = serde_json::from_value::<DkgMessage>(json!({
            "SessionInit": missing_kind
        }));
        assert!(result.is_err());
    }
}
