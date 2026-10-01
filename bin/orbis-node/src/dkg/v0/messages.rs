//! DKG Protocol Messages
//!
//! This module defines the message types used for DKG protocol communication
//! between nodes over the iroh network.

use serde::{Deserialize, Serialize};

use crate::reporting::v0::types::{DkgCommitmentStatement, DkgShareStatement};

/// Describes what kind of ceremony a DKG session is running.
///
/// Replaces the old `is_refresh: bool` / `refresh_ring_pk_hex: Option<String>` pair.
/// Used in both the wire protocol (`SessionInit`) and in-process session state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionKind {
    /// Standard fresh DKG — all nodes are symmetric, new random secret.
    Fresh,
    /// Fresh DKG for a ring's independent PET checking key, run sequentially
    /// after the ring's main-key `Fresh` ceremony finalizes (never in
    /// parallel with it). Same peer set/threshold as the main ceremony;
    /// unlike `Fresh`, this carries a storage-key override because `ring_id`
    /// is known before the ceremony starts while the resulting `pet_pk` is
    /// not. This key is never used for signing, including health checks.
    FreshPet {
        /// Local-storage key for the resulting PET `RingShareBundle`.
        /// `ring_id`, not a public key: the PET checking key doesn't exist
        /// yet when the ceremony starts, so there's nothing else to key on.
        ring_id: String,
    },
    /// PSS refresh — same secret, new shares, same committee (zero constant term).
    Refresh {
        /// Local-storage key of the ring being refreshed (`aggregate_pk.to_string()`).
        ring_pk_hex: String,
    },
    /// PSS refresh for a ring's independent PET checking key. Scheduled and
    /// triggered entirely independently of the main key's `Refresh` — its own
    /// `RingShareBundle.last_pss`, its own interval check, no chaining either
    /// direction. Same committee as the main ring; storage-key override for
    /// the same reason `FreshPet` has one (`ring_id`, not the PET public
    /// key). Never health-checked (this key is never used for signing).
    RefreshPet {
        /// Local-storage key for the PET `RingShareBundle` being refreshed
        /// (`ring_id` — see `FreshPet`'s doc comment).
        ring_id: String,
    },
    /// Reshare — same secret, new shares, potentially different committee.
    ///
    /// Old committee members act as Dealers; new committee members act as Receivers.
    /// Nodes in both committees are DealerReceivers.
    Reshare {
        /// Local-storage key of the ring being reshared (`aggregate_pk.to_string()`).
        ring_pk_hex: String,
        /// Chain node keys of the new committee.
        new_peer_node_keys: Vec<String>,
        /// Threshold for the new committee.
        new_threshold: u32,
        /// Bulletin post ID of the current ring entry.  Sent by the Dealer (who has a
        /// local RingIndexEntry) so that pure Receiver nodes — which have never been in
        /// this ring — can look up and verify the bulletin payload without a local index.
        bulletin_post_id: String,
    },
    /// Reshare for a ring's independent PET checking key — same old/new
    /// committees and threshold as the main ring's own `Reshare` (there is
    /// no separate PET-committee concept), redistributing the PET share
    /// instead of the main share. No separate `bulletin_post_id` field:
    /// unlike `Reshare`, `ring_id` alone resolves the ring directly (matching
    /// `FreshPet`/`RefreshPet`'s own resolution shape), so it already serves
    /// that purpose. Triggered directly by the new-committee leader as an
    /// atomicity gate before it signs and posts the main `Reshare`'s
    /// bulletin update (see `bulletin_update.rs`) — the PET key must reshare
    /// together with the main key, or not at all, since skipping it would
    /// leave the ring's PET check broken for both old and new committees.
    ResharePet {
        /// Local-storage key for the PET `RingShareBundle` being reshared
        /// (`ring_id` — see `FreshPet`'s doc comment).
        ring_id: String,
        /// Chain node keys of the new committee (same as the main ring's own
        /// reshare target — PET has no separate committee).
        new_peer_node_keys: Vec<String>,
        /// Threshold for the new committee.
        new_threshold: u32,
    },
}

impl SessionKind {
    /// Returns the ring's local-storage key if this session is a Refresh or Reshare,
    /// or `None` for a Fresh DKG.  Used by session cleanup to clear the in-progress flag.
    pub fn ring_key(&self) -> Option<&str> {
        match self {
            SessionKind::Fresh => None,
            SessionKind::FreshPet { ring_id } => Some(ring_id.as_str()),
            SessionKind::Refresh { ring_pk_hex } => Some(ring_pk_hex.as_str()),
            SessionKind::RefreshPet { ring_id } => Some(ring_id.as_str()),
            SessionKind::Reshare { ring_pk_hex, .. } => Some(ring_pk_hex.as_str()),
            SessionKind::ResharePet { ring_id, .. } => Some(ring_id.as_str()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDkgCommitment {
    pub statement: DkgCommitmentStatement,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDkgShare {
    pub statement: DkgShareStatement,
    pub signature: Vec<u8>,
}

/// A node-key signature over one control-plane handshake message
/// (`Prepare`/`Prepared`/`Activate`/`Activated`/`Begin`/`Begun`,
/// `PublicPhaseResponse`). Direct QUIC authentication proves the message to
/// the two endpoints on that connection but produces no portable artifact —
/// unlike Gossip, which signs each frame at the transport layer, control
/// messages carry no such signature to reclaim. This is deliberately a thin,
/// generic wrapper: what exactly was signed (the message's own existing
/// digest field) is reconstructed by the caller from data it already has,
/// not duplicated here. Purely an accountability layer, not a protocol
/// requirement — a message with an absent/invalid signature is still
/// accepted and processed normally, it's just unattributable if it turns
/// out to be faulty; see `reporting/README.md` for why this is a deliberate,
/// accepted tradeoff rather than a gap to close.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlSignature {
    pub signer_node_key: String,
    pub signed_at: u64,
    pub signature: Vec<u8>,
}
