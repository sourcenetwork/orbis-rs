//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, peer information, and the cryptographic DKG node state.
//!
//! `DkgSessionState` combines both the protocol state (phase tracking, connections,
//! message deduplication) and the cryptographic state (the DKG node itself) into
//! a single unified structure.

use crate::app_state::DkgOfflineRelayReceipt;
use crate::constants::{
    DKG_ATTEMPT_TIMEOUT, DKG_COMPLETED_SESSION_TTL, DKG_FAILED_SESSION_RECORD_TTL,
    DKG_PRIVATE_EXCHANGE_CONCURRENCY, DKG_SOFT_STALL_CHECK_INTERVAL,
    DKG_SOFT_STALL_MIN_REPAIR_ATTEMPTS, DKG_SOFT_STALL_NO_PROGRESS_THRESHOLD, MAX_DKG_SESSIONS,
    SESSION_EXPIRATION_CHECK_INTERVAL,
};
use crate::dkg::v0::coordinator::evidence::commitments_prove_equivocation;
use crate::dkg::v0::error::DkgError;
#[cfg(test)]
use crate::dkg::v0::helpers::bidirectional_node_peer_maps;
use crate::dkg::v0::messages::{
    ControlSignature, SessionKind, SignedDkgCommitment, SignedDkgShare,
};
use crate::dkg::v0::transport::{
    decode, AttemptId, AttemptKey, CeremonyConfig, CeremonyId, CommitteeScope, DkgPrivateMessage,
    MessageId, ParticipantRef, PublicPhase,
};
use crate::helpers::node_routes::canonical_node_id_assignments_from_node_keys;
use crate::metrics;
use crate::ring_state::RingShareBundle;
use crate::sign::v0::messages::RefreshHealthCheckStatement;
use crypto::r#trait::{DistributedShare, Dkg, DkgMode, DkgRole};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

const MAX_PUBLIC_COMMIT_RECEIPTS: usize = 4096;
const MAX_OFFLINE_RELAY_RECEIPTS: usize = 4096;
const MAX_OFFLINE_CANDIDATE_CLAIMS: usize = 4096;
const MAX_OFFLINE_RELAY_RECEIPT_PROCESSED_KEYS: usize = 4096;

/// DKG Protocol Phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgPhase {
    /// Initialization - session created, waiting to start
    Initializing,
    /// Fresh DKG pre-round - broadcasting commitment hashes before revealing commitments
    Phase0CommitmentHashes,
    /// Phase 1 - Generating polynomial and broadcasting commitments
    Phase1Commitments,
    /// Phase 2 - Generating and sending shares; share verification happens
    /// inline as each share is received (no separate phase state needed).
    Phase2Shares,
    /// Phase 4 has been claimed and durable completion side effects are running.
    Phase4Completing,
    /// Phase 4 - Computing final shares
    Phase4Complete,
}

impl DkgPhase {
    fn as_metric_label(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Phase0CommitmentHashes => "phase0_commitment_hashes",
            Self::Phase1Commitments => "phase1_commitments",
            Self::Phase2Shares => "phase2_shares",
            Self::Phase4Completing => "phase4_completing",
            Self::Phase4Complete => "phase4_complete",
        }
    }
}

/// Outcome of a `SessionStateManager::create_session` call.
///
/// Callers that claimed a ring/session pair for PSS before calling
/// `create_session` MUST clear that claim when they receive `LimitReached`.
/// `AlreadyExists` is safe to ignore because a concurrent handler already owns
/// the session and will clean up the PSS claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSessionOutcome {
    /// Session was created successfully.
    Created,
    /// A concurrent handler already created this session — treat as success.
    AlreadyExists,
    /// Participant count was zero, so no session was created.
    InvalidParticipantCount,
    /// `MAX_DKG_SESSIONS` is at capacity; session was NOT created.
    LimitReached,
}

/// Outcome of claiming the active PSS session for a ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingPssClaimOutcome {
    /// The ring had no active PSS ceremony and is now claimed by this session.
    Claimed,
    /// The ring is already claimed by this exact session. Safe to treat as idempotent.
    AlreadyClaimedBySameSession,
    /// The ring is currently claimed by a different session.
    Conflict { active_session_id: u128 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageProcessingClaim {
    Claimed,
    AlreadyProcessed,
    AlreadyProcessing,
    MissingSession,
    StaleAttempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptStateError {
    MissingSession,
    StaleAttempt,
}

/// RAII guard for a `MessageProcessingClaim::Claimed` claim. Construct it
/// immediately after a successful claim and call `finish` on the normal
/// completion path. If the future driving processing is instead dropped
/// before `finish` runs (e.g. by an outer `tokio::time::timeout` that fires
/// mid-flight), `Drop` releases the claim as failed so a retried delivery of
/// the same message can be processed again instead of spinning in
/// `AlreadyProcessing` forever.
pub(crate) struct TransportMessageClaimGuard<D: Dkg + 'static> {
    session_state: Option<Arc<SessionStateManager<D>>>,
    attempt: AttemptKey,
    message_id: MessageId,
}

impl<D: Dkg + 'static> TransportMessageClaimGuard<D> {
    pub(crate) fn new(
        session_state: Arc<SessionStateManager<D>>,
        attempt: AttemptKey,
        message_id: MessageId,
    ) -> Self {
        Self {
            session_state: Some(session_state),
            attempt,
            message_id,
        }
    }

    /// Release the claim on the normal-completion path and disarm the
    /// cancellation fallback in `Drop`.
    pub(crate) async fn finish(mut self, success: bool) {
        if let Some(session_state) = self.session_state.take() {
            session_state
                .finish_transport_message(self.attempt, self.message_id, success)
                .await;
        }
    }
}

impl<D: Dkg + 'static> Drop for TransportMessageClaimGuard<D> {
    fn drop(&mut self) {
        // Only reached if `finish` was never called, i.e. this guard's task
        // was cancelled between claiming the message and completing it.
        if let Some(session_state) = self.session_state.take() {
            let attempt = self.attempt;
            let message_id = self.message_id;
            tokio::spawn(async move {
                session_state
                    .finish_transport_message(attempt, message_id, false)
                    .await;
            });
        }
    }
}

/// Exact reshare bulletin update that this node is ready to sign.
///
/// A node records this once it has locally computed the new reshare share — not
/// necessarily written it to disk yet, see [`ReshareSignatureReadyMaterial`]. The
/// hashes bind readiness to one bulletin pre-state and one final payload, so a
/// later or different update must earn its own readiness marker.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReshareSignatureReadyKey {
    pub ring_key: String,
    pub session_id: u128,
    pub attempt_id: AttemptId,
    pub ring_id: String,
    pub current_ring_sha256: String,
    pub finalized_ring_sha256: String,
}

/// Material backing a reshare readiness marker.
///
/// `Staged` holds the new-committee share this node computed locally but has not
/// yet confirmed on the bulletin — disk still holds the OLD share, so a co-signer
/// for the exact statement this key names must sign with `bundle`, not disk.
/// `Promoted` means the bundle has since been written to disk (or this marker was
/// created via the test-only [`SessionStateManager::mark_reshare_signature_ready`]
/// without a bundle) — a late/retried co-signer request can safely fall back to
/// disk. The map entry is never removed on promotion (only on ceremony teardown),
/// so a late/retried finalize-sign request continues to authorize correctly.
#[derive(Clone)]
pub(crate) enum ReshareSignatureReadyMaterial {
    Staged {
        bundle: RingShareBundle,
        marked_at: Instant,
    },
    Promoted {
        marked_at: Instant,
    },
}

// Manual impl (not derived): `Staged` carries a `RingShareBundle`, whose
// `share_bytes` is a private key share — deriving Debug would print it in
// plaintext (`Zeroizing` only wipes memory on drop, it doesn't redact Debug
// output). Show the variant and `marked_at` only.
impl std::fmt::Debug for ReshareSignatureReadyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Staged { marked_at, .. } => f
                .debug_struct("Staged")
                .field("marked_at", marked_at)
                .finish_non_exhaustive(),
            Self::Promoted { marked_at } => f
                .debug_struct("Promoted")
                .field("marked_at", marked_at)
                .finish(),
        }
    }
}

impl ReshareSignatureReadyMaterial {
    fn marked_at(&self) -> Instant {
        match self {
            Self::Staged { marked_at, .. } | Self::Promoted { marked_at } => *marked_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RingPssOwner {
    session_id: u128,
    attempt_id: Option<AttemptId>,
}

/// Locally staged refresh output awaiting the post-refresh health-check result.
///
/// The active `RingShareBundle` is not overwritten until a valid diagnostic
/// threshold signature is distributed by node 1 and verified locally.
#[derive(Clone, Debug)]
pub struct RefreshHealthCheckCandidate {
    pub ring_key: String,
    pub ring_pk_hex: String,
    pub bundle: RingShareBundle,
    pub peer_node_keys: Vec<String>,
    pub peer_ids: Vec<String>,
    pub threshold: usize,
}

/// Refresh health-check result that arrived before this node staged its candidate.
#[derive(Clone, Debug)]
pub struct PendingRefreshHealthCheckResult {
    pub from_node_id: u32,
    pub statement: RefreshHealthCheckStatement,
    pub signature: Option<String>,
}

/// Emitted when the expiration sweep abandons a refresh/reshare session that stalled while
/// collecting commitments or Phase 2 shares. Carries the dealers this node never heard from so
/// a downstream worker can attempt `node_offline` reports for them. The co-signer reachability
/// probe gates acceptance, so a merely-slow (reachable) dealer is auto-exonerated — only dealers
/// that are genuinely unreachable at probe time (crashed/partitioned mid-phase) get demerited.
#[derive(Clone, Debug)]
pub struct AbandonedPssSession {
    pub session_id: u128,
    pub kind: SessionKind,
    pub ring_id: String,
    pub protocol_version: u64,
    pub missing_peer_ids: Vec<String>,
}

/// One committee member a Fresh DKG attempt could not get a response or
/// contribution from. Identity is the chain signing key from
/// `RingPayload.peer_node_keys` — the only form the external caller (the one
/// who started the ceremony) already has and can act on to swap in a
/// different node, unlike an internal peer route/id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingDkgParticipant {
    pub node_id: u32,
    pub node_key: String,
}

/// Coarse, client-facing stage label for a failed Fresh DKG attempt.
///
/// Deliberately NOT a `DkgPhase` variant: `DkgPhase` feeds the pure state
/// machine (`coordinator::state_machine`), `SessionSnapshot`, and every phase
/// handler, so adding a `Failed` case there would ripple through all of it.
/// This is a small, separate label used only by `FailedDkgSessionRecord`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgFailureStage {
    /// Prepare/TopologyProbe/Activate/Begin barrier, before the crypto phases
    /// ever started.
    Preparing,
    /// Fresh Phase0 (commitment-hash pre-round).
    CommitmentHashes,
    /// Fresh Phase1 (commitment reveal).
    Commitments,
    /// Fresh Phase2 (share exchange).
    ShareExchange,
    /// Caught by the hard-deadline fallback in a state the other stages
    /// don't cover (e.g. still `Initializing` past `Begin`).
    Unknown,
}

impl DkgFailureStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::CommitmentHashes => "commitment_hashes",
            Self::Commitments => "commitments",
            Self::ShareExchange => "share_exchange",
            Self::Unknown => "unknown",
        }
    }
}

/// Short-lived, client-facing failure attribution for a Fresh DKG attempt.
///
/// Deliberately NOT the full `DkgSessionState<D>` — that struct holds live
/// crypto material (some zeroized on `Drop`) and connection state that
/// should not linger for a client-polling window. This is a handful of
/// scalar-ish fields, written at the exact points a Fresh session is torn
/// down for cause (barrier abort, soft-stall, hard-deadline) and read by
/// `GetDkgSessionStatus`. Purely a client-facing diagnostic — not wired into
/// the on-chain `node_offline`/reputation reporting pipeline.
#[derive(Clone, Debug)]
pub struct FailedDkgSessionRecord {
    pub session_id: u128,
    pub ring_id: String,
    pub attempt_id: Option<AttemptId>,
    pub stage: DkgFailureStage,
    pub missing: Vec<MissingDkgParticipant>,
    pub reason: String,
    pub failed_at: SystemTime,
}

/// Published by the soft-stall detector when the leader observes a Fresh DKG
/// crypto phase that has genuinely stopped making progress against a
/// specific peer (repair/private-exchange retries already failing, not just
/// ordinary Gossip jitter). Drained by `spawn_dkg_soft_stall_worker`, which
/// does the actual abort + record write with full `AppState` access — the
/// detection tick itself only has access to the session-state maps.
#[derive(Clone, Debug)]
pub struct SoftStalledDkgAttempt {
    pub session_id: u128,
    pub attempt_id: AttemptId,
    pub ring_id: String,
    pub protocol_version: u64,
    pub missing: Vec<MissingDkgParticipant>,
    pub stage: DkgFailureStage,
}

/// Per-peer no-progress tracking for the soft-stall detector.
///
/// Populated only when repair (public plane) or a private pair-exchange
/// retry (private plane) against that peer has already failed at least once
/// — never on the first miss — so this reflects "repair tried and still
/// failing," not ordinary Gossip jitter. Cleared the moment that peer's
/// contribution or share is recorded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerNoProgressInfo {
    pub first_failure_at: Instant,
    pub consecutive_failures: u32,
}

#[derive(Default)]
pub(crate) struct SessionRoutingState {
    pub node_id_to_peer_id: HashMap<u32, String>,
    pub peer_id_to_node_id: HashMap<String, u32>,
    pub reshare_new_node_id_to_peer_id: HashMap<u32, String>,
    pub reshare_new_peer_id_to_node_id: HashMap<String, u32>,
    pub peer_ids: Vec<String>,
    pub peer_node_keys: Vec<String>,
    pub ring_id: String,
}

pub(crate) struct PendingDeliveryState<ShareValue: Zeroize> {
    pub pending_shares_waiting_for_commitment: HashMap<u32, PendingDkgShare<ShareValue>>,
    pub pending_commitments_waiting_for_hash: HashMap<u32, PendingDkgCommitment>,
}

impl<ShareValue: Zeroize> Default for PendingDeliveryState<ShareValue> {
    fn default() -> Self {
        Self {
            pending_shares_waiting_for_commitment: HashMap::new(),
            pending_commitments_waiting_for_hash: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PendingDkgCommitment {
    pub commitment: Vec<u8>,
    pub report_evidence: Option<SignedDkgCommitment>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingDkgShare<ShareValue: Zeroize> {
    pub share: DistributedShare<ShareValue>,
    pub report_evidence: Option<SignedDkgShare>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitmentHashRecordOutcome {
    Recorded,
    DuplicateSame,
    Mismatch { existing: [u8; 32] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportConfigureOutcome {
    Configured,
    AlreadyConfigured,
    ConflictingAttempt,
    MissingSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportActivationOutcome {
    Activated,
    AlreadyActivated,
    StaleAttempt,
    MissingSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportBeginOutcome {
    Begun,
    AlreadyBegun,
    NotActivated,
    StaleAttempt,
    MissingSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopologyAckRecordOutcome {
    Recorded,
    Duplicate,
    StaleAttempt,
    WrongNonce,
    MissingSession,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PublicContributionRecordOutcome {
    Recorded,
    DuplicateSame,
    ConflictingDuplicate {
        retained: network::SignedPayload,
        conflicting: network::SignedPayload,
    },
    StaleAttempt,
    MissingSession,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PublicBatchRecordOutcome {
    Recorded,
    DuplicateSame,
    ConflictingDuplicate {
        origin: ParticipantRef,
        retained: network::SignedPayload,
        conflicting: network::SignedPayload,
    },
    StaleAttempt,
    MissingSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicRepairClaimOutcome {
    Claimed,
    InFlight,
    Backoff,
    StaleAttempt,
}

#[derive(Debug, Clone, Copy)]
struct PublicRepairState {
    in_flight: bool,
    next_allowed_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopicTaskDisposition {
    Abort,
    DetachCurrent,
}

#[derive(Default)]
pub(crate) struct CommitRevealState {
    pub received_hashes: HashMap<u32, [u8; 32]>,
    pub own_hash_broadcast_complete: bool,
}

/// Dealer messages this node has accepted.
///
/// Signed commitments are kept so that on an equivocation-consistent failure
/// (phase4 aggregate/staged-pk mismatch) they can be revealed to peers who compare
/// them against their own to name the equivocating dealer, and to build a
/// threshold-signed on-chain equivocation report (see `evidence::queue_or_relay_equivocation`).
///
/// Refresh/reshare reuse a deterministic session_id across retries; false attribution
/// from a replayed prior-attempt commitment is avoided via `session_nonce`, a fresh
/// per-attempt anchor each dealer signs into every commitment it broadcasts.
#[derive(Default)]
pub(crate) struct CommitmentAuditState {
    pub received_commitments: HashMap<u32, SignedDkgCommitment>,
    pub received_shares: HashSet<u32>,
}

pub(crate) struct ReshareSessionState<ShareValue: Zeroize> {
    pub params: Option<ReshareParams<ShareValue>>,
    pub valid_share_dealers: HashSet<u32>,
    pub share_acks: HashMap<u32, HashSet<u32>>,
    pub dealer_completion_order: Vec<u32>,
    pub selected_dealers: Option<Vec<u32>>,
}

impl<ShareValue: Zeroize> Default for ReshareSessionState<ShareValue> {
    fn default() -> Self {
        Self {
            params: None,
            valid_share_dealers: HashSet::new(),
            share_acks: HashMap::new(),
            dealer_completion_order: Vec::new(),
            selected_dealers: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct RefreshSessionState {
    pub candidate: Option<RefreshHealthCheckCandidate>,
    pub pending_result: Option<PendingRefreshHealthCheckResult>,
}

#[derive(Clone, Debug)]
pub(crate) struct DkgReportEvidenceBinding {
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub chain_id: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub origin_protocol: String,
    pub current_node_keys: Vec<String>,
    pub receiver_node_keys: Vec<String>,
}

pub(crate) struct DkgSessionTransportState {
    pub ceremony_id: Option<CeremonyId>,
    pub attempt_id: Option<AttemptId>,
    pub committee_digest: Option<[u8; 32]>,
    pub config_digest: Option<[u8; 32]>,
    pub topic_id: Option<network::TopicId>,
    pub leader_node_key: Option<String>,
    pub leader_peer_route: Option<String>,
    pub participant_routes: Vec<String>,
    pub committees: Option<CeremonyConfig>,
    pub topic: Option<Arc<dyn network::Topic>>,
    pub topology_probe_nonce: Option<[u8; 32]>,
    pub topology_probe_acknowledgements: BTreeSet<String>,
    /// Authenticated peers that returned any topology ACK request for the
    /// active attempt, including a wrong nonce. This is deliberately broader
    /// than the valid-ACK set so protocol-invalid but reachable peers are not
    /// later classified as offline.
    pub topology_probe_responses: BTreeSet<String>,
    pub topology_probe_notify: Arc<Notify>,
    pub activated: bool,
    pub begun: bool,
    pub activation_digest: Option<[u8; 32]>,
    pub active_dealers: Vec<ParticipantRef>,
    pub prepared_at: Option<Instant>,
    pub hard_deadline: Option<Instant>,
    pub last_progress_at: Instant,
    pub public_contributions:
        HashMap<PublicPhase, BTreeMap<ParticipantRef, network::SignedPayload>>,
    pub public_phase_started_at: HashMap<PublicPhase, Instant>,
    /// Soft-stall gating: node_id -> repair/retry failure streak against that
    /// peer. Fresh DKG's `CommitteeScope` is always `Current`, so `node_id`
    /// alone is unambiguous here.
    pub(crate) peer_no_progress: HashMap<u32, PeerNoProgressInfo>,
    /// Set once a `SoftStalledDkgAttempt` has been successfully queued for this attempt, so
    /// repeated soft-stall scan ticks (this attempt is still alive while the drain worker
    /// hasn't processed the event yet) don't keep re-publishing duplicates into the bounded
    /// channel and potentially crowding out other attempts' events.
    pub(crate) soft_stall_reported: bool,
    public_repairs: HashMap<PublicPhase, PublicRepairState>,
    pub(crate) publishing_public_phases: HashSet<PublicPhase>,
    pub published_public_phases: HashSet<PublicPhase>,
    pub(crate) publishing_public_messages: HashSet<MessageId>,
    pub published_public_messages: HashSet<MessageId>,
    pub outbound_private_messages: HashMap<MessageId, Vec<u8>>,
    pub acknowledged_private_messages: HashSet<MessageId>,
    /// Authenticated participants that opened an inbound private exchange for
    /// this attempt. A later protocol or ACK failure must not turn that peer's
    /// missing completion into an offline observation.
    pub private_peer_responses: BTreeSet<ParticipantRef>,
    pub processing_message_ids: HashSet<MessageId>,
    pub processed_message_ids: HashSet<MessageId>,
    pub topic_task: Option<tokio::task::AbortHandle>,
    attempt_cancel_tx: watch::Sender<bool>,
    /// The leader's record of each follower's first signed control-plane
    /// acknowledgement (Prepared/Activated/Begun) per (follower_node_key,
    /// message_kind) for this attempt, so a later conflicting signed answer
    /// to the identical request is provable as equivocation rather than
    /// trusted on the leader's own word. No separate TTL pruning needed here
    /// (unlike a node-wide cache) because transport state is configured
    /// exactly once per attempt and is torn down with the session.
    pub(crate) control_ack_receipts: HashMap<(String, &'static str), ([u8; 32], ControlSignature)>,
}

impl Default for DkgSessionTransportState {
    fn default() -> Self {
        let (attempt_cancel_tx, _) = watch::channel(false);
        Self {
            ceremony_id: None,
            attempt_id: None,
            committee_digest: None,
            config_digest: None,
            topic_id: None,
            leader_node_key: None,
            leader_peer_route: None,
            participant_routes: Vec::new(),
            committees: None,
            topic: None,
            topology_probe_nonce: None,
            topology_probe_acknowledgements: BTreeSet::new(),
            topology_probe_responses: BTreeSet::new(),
            topology_probe_notify: Arc::new(Notify::new()),
            activated: false,
            begun: false,
            activation_digest: None,
            active_dealers: Vec::new(),
            prepared_at: None,
            hard_deadline: None,
            last_progress_at: Instant::now(),
            public_contributions: HashMap::new(),
            public_phase_started_at: HashMap::new(),
            peer_no_progress: HashMap::new(),
            soft_stall_reported: false,
            public_repairs: HashMap::new(),
            publishing_public_phases: HashSet::new(),
            published_public_phases: HashSet::new(),
            publishing_public_messages: HashSet::new(),
            published_public_messages: HashSet::new(),
            outbound_private_messages: HashMap::new(),
            acknowledged_private_messages: HashSet::new(),
            private_peer_responses: BTreeSet::new(),
            processing_message_ids: HashSet::new(),
            processed_message_ids: HashSet::new(),
            topic_task: None,
            attempt_cancel_tx,
            control_ack_receipts: HashMap::new(),
        }
    }
}

impl Drop for DkgSessionTransportState {
    fn drop(&mut self) {
        if let Some(task) = self.topic_task.take() {
            task.abort();
        }
    }
}

/// Reshare-specific parameters stored in session state during an active reshare ceremony.
///
/// Set by the coordinator when a `SessionInit { kind: SessionKind::Reshare { .. } }` is
/// received.  `generate_polynomial` reads these to construct `DkgMode::Reshare`.
///
/// `Drop` zeroes `old_share` whenever this struct is dropped — whether at the end of
/// `generate_polynomial` (via `.take()`), session expiry, or error paths.
pub struct ReshareParams<ShareValue: Zeroize> {
    /// This node's current secret share value, pre-loaded from local storage at session
    /// init time.  `None` for pure `Receiver` nodes (they have no old share).
    pub old_share: Option<ShareValue>,
    /// Node IDs of the old committee members participating in this reshare.
    pub participating_ids: Vec<u32>,
    /// Threshold for the new committee.
    pub new_threshold: usize,
    /// Total nodes in the new committee.
    pub new_total_nodes: usize,
    /// Sorted chain node keys of the new committee (index = node_id - 1).
    pub new_peer_node_keys: Vec<String>,
    /// This node's index in the new committee (1-based).  `None` for pure Dealers
    /// that are not in the new committee.  Used to validate incoming share `to_id`.
    pub new_node_id: Option<u32>,
    /// Bulletin post ID of the ring's current entry.  Carried in the SessionInit so
    /// pure Receiver nodes (which have no local RingIndexEntry) can write their own
    /// entry after Phase 4 completes without recomputing the post ID.
    pub bulletin_post_id: String,
}

impl<ShareValue: Zeroize> Drop for ReshareParams<ShareValue> {
    fn drop(&mut self) {
        self.old_share.zeroize();
    }
}

#[cfg(test)]
impl<ShareValue: Zeroize + std::fmt::Debug> std::fmt::Debug for ReshareParams<ShareValue> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReshareParams")
            .field("old_share", &self.old_share.as_ref().map(|_| "<redacted>"))
            .field("participating_ids", &self.participating_ids)
            .field("new_threshold", &self.new_threshold)
            .field("new_total_nodes", &self.new_total_nodes)
            .field("new_peer_node_keys", &self.new_peer_node_keys)
            .field("new_node_id", &self.new_node_id)
            .field("bulletin_post_id", &self.bulletin_post_id)
            .finish()
    }
}

/// Unified state for a DKG session combining crypto state and protocol tracking
///
/// This struct holds both:
/// - The cryptographic DKG node (polynomial, commitments, shares)
/// - Protocol state (phase, connections, message deduplication)
pub struct DkgSessionState<D: Dkg> {
    // === Crypto State (the DKG node) ===
    /// The DKG node containing cryptographic state (polynomial, commitments, shares)
    pub node: D,

    // === Metadata ===
    /// When this session was created
    pub created_at: Instant,
    /// Protocol route fixed by the SessionInit that created this session.
    pub protocol_version: u64,

    // === Protocol State ===
    /// Current protocol phase
    pub phase: DkgPhase,
    /// When the current phase started (reset on every phase transition)
    pub phase_started_at: Instant,
    /// Participant identity and route mappings.
    pub(crate) routing: SessionRoutingState,
    /// Expected number of participants
    #[cfg(test)]
    pub total_participants: usize,
    /// Number of commitments received
    pub commitments_received: usize,
    /// Number of shares received
    pub shares_received: usize,
    /// Reshare-only data and selection progress.
    pub(crate) reshare: ReshareSessionState<D::ShareValue>,
    /// Fresh-only commit-reveal pre-round state.
    pub(crate) commit_reveal: CommitRevealState,
    /// Refresh/reshare-only: received signed commitments for on-failure equivocation audit.
    pub(crate) commitment_audit: CommitmentAuditState,
    /// Message ordering and deduplication state.
    pub(crate) pending: PendingDeliveryState<D::ShareValue>,
    /// This node's signed commitment evidence for Refresh/Reshare share reports.
    pub(crate) local_signed_commitment: Option<SignedDkgCommitment>,
    /// Cached non-secret binding data for Refresh/Reshare DKG report evidence.
    pub(crate) report_evidence_binding: Option<DkgReportEvidenceBinding>,
    /// What kind of ceremony this session is running (Fresh, Refresh, or Reshare).
    ///
    /// Drives `generate_polynomial` mode selection and Phase 4 storage/bulletin behaviour.
    pub kind: SessionKind,
    /// Seconds between automatic PSS refresh ceremonies for this ring.
    /// Stored here during the session so Phase 4 can write it into `RingPayload`.
    pub pss_interval: u64,
    /// Optional policy that externally governs ring updates.
    /// Stored here during fresh DKG so Phase 4 can write it into `RingPayload`.
    pub policy_id: Option<String>,
    /// Extra parameters required only for Reshare sessions.  `None` for Fresh and Refresh.
    /// Refresh candidate/result staging.
    pub(crate) refresh: RefreshSessionState,
    /// Per-session-instance nonce this node signs into every commitment it broadcasts
    /// this attempt. Generated once here so an honest node signing via both the phase1
    /// and lazy paths produces identical commitment bytes; a fresh instance (retry) gets
    /// a new nonce so honest retries cannot be framed as equivocation.
    pub(crate) session_nonce: [u8; 16],
    /// Per-session network streams and send serialization.
    pub(crate) transport: DkgSessionTransportState,
    /// Owns active metrics for exactly the lifetime of this ceremony.
    metrics_guard: Option<metrics::DkgSessionMetricsGuard>,
}

impl<D: Dkg> DkgSessionState<D> {
    /// Create a new DKG session state with the given DKG node
    pub fn new(node: D, _total_participants: usize) -> Self {
        Self {
            node,
            created_at: Instant::now(),
            protocol_version: network::V0.version,
            phase: DkgPhase::Initializing,
            phase_started_at: Instant::now(),
            routing: SessionRoutingState::default(),
            #[cfg(test)]
            total_participants: _total_participants,
            commitments_received: 0,
            shares_received: 0,
            reshare: ReshareSessionState::default(),
            commit_reveal: CommitRevealState::default(),
            commitment_audit: CommitmentAuditState::default(),
            pending: PendingDeliveryState::default(),
            local_signed_commitment: None,
            report_evidence_binding: None,
            kind: SessionKind::Fresh,
            pss_interval: 0,
            policy_id: None,
            refresh: RefreshSessionState::default(),
            session_nonce: rand::random::<[u8; 16]>(),
            transport: DkgSessionTransportState::default(),
            metrics_guard: None,
        }
    }

    fn ceremony_kind(&self) -> metrics::DkgCeremonyKind {
        match &self.kind {
            SessionKind::Fresh => metrics::DkgCeremonyKind::Fresh,
            SessionKind::Refresh { .. } => metrics::DkgCeremonyKind::Refresh,
            SessionKind::Reshare { .. } => metrics::DkgCeremonyKind::Reshare,
        }
    }

    /// Move to a new protocol phase and observe the phase actually being
    /// exited. Both state-machine claims and explicit phase initiators use this
    /// path so an idempotent follow-up cannot double-count the transition.
    pub(crate) fn transition_phase(&mut self, phase: DkgPhase) {
        if self.phase == phase {
            return;
        }
        metrics::record_dkg_phase_duration(
            self.ceremony_kind(),
            self.phase.as_metric_label(),
            self.phase_started_at.elapsed().as_secs_f64(),
        );
        self.phase = phase;
        self.phase_started_at = Instant::now();
        self.transport.last_progress_at = Instant::now();
    }

    /// Generate the polynomial for this session.
    ///
    /// Mode is derived from `kind`:
    /// - `Fresh`   → `DkgMode::Fresh` (new random secret)
    /// - `Refresh` → `DkgMode::Refresh` (zero constant term, same secret)
    /// - `Reshare` → `DkgMode::Reshare` (unweighted old share; errors if `old_share` is
    ///   `None`, which only happens for pure `Receiver` nodes — they must not call this)
    pub fn generate_polynomial(&mut self) -> Result<(), DkgError> {
        let mode = match &self.kind {
            SessionKind::Fresh => DkgMode::Fresh,
            SessionKind::Refresh { .. } => DkgMode::Refresh,
            SessionKind::Reshare { .. } => {
                let p = self.reshare.params.as_mut().ok_or_else(|| {
                    DkgError::Generic(
                        "Reshare session is missing reshare_params — this is a bug".to_string(),
                    )
                })?;
                // Move old_share out of the Option (leaving None) so it is dropped
                // as soon as generate_polynomial returns, rather than sitting in
                // session state for the remainder of the ceremony.
                let old_share = p.old_share.take().ok_or_else(|| {
                    DkgError::Generic(
                        "Reshare: Receiver nodes cannot generate a polynomial".to_string(),
                    )
                })?;
                DkgMode::Reshare {
                    old_share,
                    participating_ids: p.participating_ids.clone(),
                    new_threshold: p.new_threshold,
                    new_total_nodes: p.new_total_nodes,
                    new_node_id: p.new_node_id,
                }
            }
        };
        self.node
            .generate_polynomial(mode)
            .map_err(|e| DkgError::Crypto(format!("Failed to generate polynomial: {}", e)))
    }

    /// Expected number of commitment coefficients from peer polynomials.
    ///
    /// For Reshare, dealers use `new_threshold` (new committee degree); for all
    /// other kinds the old/current threshold applies.
    pub fn expected_commitment_size(&self) -> usize {
        if let Some(ref p) = self.reshare.params {
            p.new_threshold
        } else {
            self.node.threshold()
        }
    }

    /// Peer IDs of the dealers this node never heard from in the stalled phase — the crash signal
    /// for a stalled refresh/reshare session (see [`AbandonedPssSession`]). A dealer that dies
    /// after `SessionInit` never broadcasts its commitment; a dealer that dies after committing
    /// never sends this node its Phase 2 share. Returns empty for `Fresh` (fresh DKG has no
    /// finalized ring to anchor an offline report against).
    ///
    /// Refresh: every current-committee member is a dealer. Reshare: the participating
    /// old-committee members are the dealers. Over-attribution is harmless — the downstream
    /// `node_offline` report is gated by the co-signer reachability probe.
    pub(crate) fn missing_dealer_peer_ids(&self, stalled_phase: DkgPhase) -> Vec<String> {
        let dealer_node_ids: Vec<u32> = match &self.kind {
            SessionKind::Fresh => return Vec::new(),
            SessionKind::Refresh { .. } => (1..=self.routing.peer_node_keys.len() as u32).collect(),
            SessionKind::Reshare { .. } => match &self.reshare.params {
                Some(params) => params.participating_ids.clone(),
                None => (1..=self.routing.peer_node_keys.len() as u32).collect(),
            },
        };

        if stalled_phase == DkgPhase::Phase2Shares
            && matches!(self.kind, SessionKind::Reshare { .. })
            && self.node.role() == DkgRole::Dealer
        {
            return Vec::new();
        }

        let own_node_id = self.node.node_id();
        dealer_node_ids
            .into_iter()
            .filter(|node_id| *node_id != own_node_id)
            .filter(|node_id| match stalled_phase {
                DkgPhase::Phase1Commitments => !self
                    .commitment_audit
                    .received_commitments
                    .contains_key(node_id),
                DkgPhase::Phase2Shares => !self.commitment_audit.received_shares.contains(node_id),
                _ => false,
            })
            .filter_map(|node_id| self.routing.node_id_to_peer_id.get(&node_id).cloned())
            .collect()
    }

    /// Fresh-only. Committee members this node has not yet heard from in the
    /// current crypto phase, as (node_id, node_key) pairs for client display
    /// via `GetDkgSessionStatus`. Unlike `missing_dealer_peer_ids` (peer_id,
    /// for internal `node_offline` attribution), this returns chain signing
    /// keys — the identity form the external caller already has from
    /// `RingPayload.peer_node_keys` and can act on to swap in a different
    /// node.
    ///
    /// Diffs `transport.public_contributions` for Phase0/Phase1 rather than
    /// `commit_reveal.received_hashes`: both are populated from the same
    /// write path, but using `public_contributions` uniformly means "missing"
    /// is defined identically to what the repair loop itself is failing to
    /// fetch — an abort's attribution can never disagree with what repair was
    /// actually struggling with. Phase2 has no public-plane equivalent, so it
    /// diffs `commitment_audit.received_shares`, which (despite a stale
    /// "Refresh/reshare-only" doc comment on the parent field) is populated
    /// unconditionally for Fresh too.
    pub(crate) fn missing_fresh_participants(&self) -> Vec<MissingDkgParticipant> {
        if !matches!(self.kind, SessionKind::Fresh) {
            return Vec::new();
        }
        let own_node_id = self.node.node_id();
        let total_nodes = self.node.total_nodes() as u32;
        let missing_ids: Vec<u32> = match self.phase {
            DkgPhase::Phase0CommitmentHashes => (1..=total_nodes)
                .filter(|id| *id != own_node_id)
                .filter(|id| {
                    !self
                        .transport
                        .public_contributions
                        .get(&PublicPhase::CommitmentHashes)
                        .is_some_and(|c| c.contains_key(&ParticipantRef::current(*id)))
                })
                .collect(),
            DkgPhase::Phase1Commitments => (1..=total_nodes)
                .filter(|id| *id != own_node_id)
                .filter(|id| {
                    !self
                        .transport
                        .public_contributions
                        .get(&PublicPhase::Commitments)
                        .is_some_and(|c| c.contains_key(&ParticipantRef::current(*id)))
                })
                .collect(),
            DkgPhase::Phase2Shares => (1..=total_nodes)
                .filter(|id| *id != own_node_id)
                .filter(|id| !self.commitment_audit.received_shares.contains(id))
                .collect(),
            _ => Vec::new(),
        };
        if missing_ids.is_empty() {
            return Vec::new();
        }
        let node_key_by_id: HashMap<u32, String> =
            match canonical_node_id_assignments_from_node_keys(&self.routing.peer_node_keys) {
                Ok(assignments) => assignments.into_iter().map(|(key, id)| (id, key)).collect(),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        peer_node_keys_len = self.routing.peer_node_keys.len(),
                        "missing_fresh_participants: failed to derive canonical node-id \
                         assignments from routing.peer_node_keys"
                    );
                    return Vec::new();
                }
            };
        if node_key_by_id.len() < total_nodes as usize {
            tracing::warn!(
                peer_node_keys_len = self.routing.peer_node_keys.len(),
                total_nodes,
                "missing_fresh_participants: routing.peer_node_keys does not cover the full \
                 committee; some missing participants may go unattributed"
            );
        }
        missing_ids
            .into_iter()
            .filter_map(|id| {
                node_key_by_id
                    .get(&id)
                    .cloned()
                    .map(|node_key| MissingDkgParticipant {
                        node_id: id,
                        node_key,
                    })
            })
            .collect()
    }

    /// Whether this node is the canonical leader of its own session, derived
    /// purely from local state (own node ID, sorted committee key list, and
    /// the leader key recorded at Prepare time) — no external "own node key"
    /// parameter needed.
    pub(crate) fn is_local_leader(&self) -> bool {
        let Some(leader) = self.transport.leader_node_key.as_deref() else {
            return false;
        };
        let own_node_id = self.node.node_id();
        match canonical_node_id_assignments_from_node_keys(&self.routing.peer_node_keys) {
            Ok(assignments) => assignments
                .into_iter()
                .any(|(key, id)| id == own_node_id && key == leader),
            Err(_) => false,
        }
    }

    /// Node IDs currently past the soft-stall gate: repair/private-exchange
    /// retries against that peer have failed at least `min_attempts` times,
    /// spanning at least `threshold` of elapsed time since the first failure.
    pub(crate) fn soft_stalled_peer_ids(
        &self,
        threshold: Duration,
        min_attempts: u32,
    ) -> HashSet<u32> {
        let now = Instant::now();
        self.transport
            .peer_no_progress
            .iter()
            .filter(|(_, info)| {
                info.consecutive_failures >= min_attempts
                    && now.duration_since(info.first_failure_at) >= threshold
            })
            .map(|(node_id, _)| *node_id)
            .collect()
    }
}

#[cfg(test)]
impl<D: Dkg> DkgSessionState<D> {
    pub fn all_commitments_received(&self) -> bool {
        self.commitments_received >= (self.total_participants - 1)
    }

    pub fn all_shares_received(&self) -> bool {
        self.shares_received >= (self.total_participants - 1)
    }
}

/// Global session state manager
pub struct SessionStateManager<D: Dkg> {
    /// session_id -> session state
    pub(crate) states: Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
    /// Ring public key strings mapped to their active in-progress PSS ceremony
    /// session IDs. Cleared on Phase 4 success or session cleanup/expiration so
    /// that a new ceremony can be initiated after failure.
    rings_pss: Arc<RwLock<HashMap<String, RingPssOwner>>>,
    /// Exact reshare bulletin updates this node is ready to sign, with the
    /// staged (or already-promoted) share material backing each. A
    /// successfully completed attempt's marker deliberately outlives its
    /// session (see `finish_removed_session`), so entries are aged out by
    /// `expiration_worker` on a timer rather than tied to any session's
    /// lifecycle.
    reshare_signature_ready:
        Arc<RwLock<HashMap<ReshareSignatureReadyKey, ReshareSignatureReadyMaterial>>>,
    shutdown_tx: watch::Sender<bool>,
    background_tasks: StdMutex<Vec<JoinHandle<()>>>,
    /// Receiver for stalled refresh/reshare sessions published by the expiration sweep for
    /// offline-report attribution. Taken once via [`SessionStateManager::take_stall_report_receiver`]
    /// at node startup; the sender lives inside the expiration worker.
    stall_report_rx: StdMutex<Option<mpsc::Receiver<AbandonedPssSession>>>,
    /// Ceremony-keyed leader singleflight locks. A node manages at most the
    /// bounded local-ring limit, so retaining one small lock per seen ceremony
    /// avoids duplicate-attempt races without serializing unrelated rings. Kept
    /// as its own `Arc` (rather than folded into a plain field) because
    /// `CeremonyStartGuard` needs to hold an owned clone independent of this
    /// manager for its detached `Drop` cleanup task.
    ceremony_start_locks: Arc<TokioMutex<HashMap<u128, Arc<TokioMutex<()>>>>>,
    /// Recently completed public-result commits. Refresh result application
    /// removes the ceremony state, so this bounded, short-lived receipt cache
    /// lets an authenticated leader safely retry after an ACK is lost.
    public_commit_receipts:
        TokioMutex<HashMap<(CeremonyId, AttemptId, MessageId), (Vec<u8>, Instant)>>,
    /// Prepared PSS attempts retained briefly for authenticated offline relay
    /// validation after abort/cleanup races with the detached reporting task.
    offline_relay_receipts: TokioMutex<HashMap<AttemptKey, DkgOfflineRelayReceipt>>,
    /// Ceremony/subject claims made at terminal transport boundaries. This
    /// suppresses repeated work from later boundaries before a detached report
    /// task is spawned; Vera session deduplication remains authoritative.
    offline_candidate_dedup: StdMutex<HashMap<(CeremonyId, String), Instant>>,
    /// Node-wide cap shared by inbound and outbound private DKG pair exchanges,
    /// including ceremonies for different rings. A resource limit on the DKG
    /// subsystem as a whole, not any one session, so it lives here rather than
    /// on `DkgSessionState`.
    private_exchange_permits: Arc<tokio::sync::Semaphore>,
    /// Receiver for Fresh DKG attempts the soft-stall scan has detected as
    /// genuinely stuck. Taken once via [`SessionStateManager::take_soft_stall_receiver`]
    /// at node startup; the sender lives inside the expiration worker.
    soft_stall_rx: StdMutex<Option<mpsc::Receiver<SoftStalledDkgAttempt>>>,
    /// Short-lived Fresh-DKG failure attribution, queried by
    /// `GetDkgSessionStatus`. Populated at every point a Fresh attempt is
    /// torn down for cause (barrier abort, soft-stall, hard-deadline). Kept
    /// separate from `states` deliberately (see `FailedDkgSessionRecord`),
    /// and aged out independently on `DKG_FAILED_SESSION_RECORD_TTL`, swept
    /// in `expiration_worker`.
    failed_sessions: Arc<RwLock<HashMap<u128, (FailedDkgSessionRecord, Instant)>>>,
}

mod commitments;
mod lifecycle;
mod peer_mapping;
mod private_messages;
mod public_phase;
mod receipts;
mod ring_pss;
mod sessions;
mod teardown;
mod transport_config;

impl<D: Dkg + 'static> Default for SessionStateManager<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Dkg> Drop for SessionStateManager<D> {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

#[cfg(test)]
impl<D: Dkg + 'static> SessionStateManager<D> {
    pub async fn session_count(&self) -> usize {
        self.states.read().await.len()
    }

    pub async fn set_session_kind(&self, session_id: &u128, kind: SessionKind) {
        self.with_state_mut(session_id, |s| s.kind = kind).await;
    }
}

#[cfg(test)]
mod tests;
