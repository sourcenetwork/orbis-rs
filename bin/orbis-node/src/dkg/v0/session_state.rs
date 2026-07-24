//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, peer information, and the cryptographic DKG node state.
//!
//! `DkgSessionState` combines both the protocol state (phase tracking, connections,
//! message deduplication) and the cryptographic state (the DKG node itself) into
//! a single unified structure.

use crate::constants::{
    DKG_ATTEMPT_TIMEOUT, DKG_COMPLETED_SESSION_TTL, MAX_DKG_SESSIONS,
    SESSION_EXPIRATION_CHECK_INTERVAL,
};
use crate::dkg::v0::coordinator::evidence::commitments_prove_equivocation;
use crate::dkg::v0::error::DkgError;
#[cfg(test)]
use crate::dkg::v0::helpers::bidirectional_node_peer_maps;
use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment, SignedDkgShare};
use crate::metrics;
use crate::ring_state::RingShareBundle;
use crate::sign::v0::messages::RefreshHealthCheckStatement;
use crypto::r#trait::{DistributedShare, Dkg, DkgMode, DkgRole};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

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
    session_id: u128,
    message_id: crate::dkg::v0::transport::MessageId,
}

impl<D: Dkg + 'static> TransportMessageClaimGuard<D> {
    pub(crate) fn new(
        session_state: Arc<SessionStateManager<D>>,
        session_id: u128,
        message_id: crate::dkg::v0::transport::MessageId,
    ) -> Self {
        Self {
            session_state: Some(session_state),
            session_id,
            message_id,
        }
    }

    /// Release the claim on the normal-completion path and disarm the
    /// cancellation fallback in `Drop`.
    pub(crate) async fn finish(mut self, success: bool) {
        if let Some(session_state) = self.session_state.take() {
            session_state
                .finish_transport_message(&self.session_id, self.message_id, success)
                .await;
        }
    }
}

impl<D: Dkg + 'static> Drop for TransportMessageClaimGuard<D> {
    fn drop(&mut self) {
        // Only reached if `finish` was never called, i.e. this guard's task
        // was cancelled between claiming the message and completing it.
        if let Some(session_state) = self.session_state.take() {
            let session_id = self.session_id;
            let message_id = self.message_id;
            tokio::spawn(async move {
                session_state
                    .finish_transport_message(&session_id, message_id, false)
                    .await;
            });
        }
    }
}

/// Exact reshare bulletin update that this node is ready to sign.
///
/// A node records this only after it has locally persisted the new reshare bundle.
/// The hashes bind readiness to one bulletin pre-state and one final payload, so a
/// later or different update must earn its own readiness marker.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReshareSignatureReadyKey {
    pub ring_key: String,
    pub session_id: u128,
    pub ring_id: String,
    pub current_ring_sha256: String,
    pub finalized_ring_sha256: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicContributionRecordOutcome {
    Recorded,
    DuplicateSame,
    ConflictingDuplicate,
    MissingSession,
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
    pub ceremony_id: Option<crate::dkg::v0::transport::CeremonyId>,
    pub attempt_id: Option<crate::dkg::v0::transport::AttemptId>,
    pub committee_digest: Option<[u8; 32]>,
    pub config_digest: Option<[u8; 32]>,
    pub topic_id: Option<network::TopicId>,
    pub leader_node_key: Option<String>,
    pub leader_peer_route: Option<String>,
    pub participant_routes: Vec<String>,
    pub committees: Option<crate::dkg::v0::transport::CeremonyConfig>,
    pub topic: Option<Arc<dyn network::Topic>>,
    pub topology_probe_nonce: Option<[u8; 32]>,
    pub topology_probe_acknowledgements: BTreeSet<String>,
    pub topology_probe_notify: Arc<Notify>,
    pub activated: bool,
    pub begun: bool,
    pub activation_digest: Option<[u8; 32]>,
    pub active_dealers: Vec<crate::dkg::v0::transport::ParticipantRef>,
    pub prepared_at: Option<Instant>,
    pub hard_deadline: Option<Instant>,
    pub last_progress_at: Instant,
    pub public_contributions: HashMap<
        crate::dkg::v0::transport::PublicPhase,
        BTreeMap<crate::dkg::v0::transport::ParticipantRef, network::SignedPayload>,
    >,
    pub public_phase_started_at: HashMap<crate::dkg::v0::transport::PublicPhase, Instant>,
    pub published_public_phases: HashSet<crate::dkg::v0::transport::PublicPhase>,
    pub published_public_messages: HashSet<crate::dkg::v0::transport::MessageId>,
    pub outbound_private_messages: HashMap<crate::dkg::v0::transport::MessageId, Vec<u8>>,
    pub acknowledged_private_messages: HashSet<crate::dkg::v0::transport::MessageId>,
    pub processing_message_ids: HashSet<crate::dkg::v0::transport::MessageId>,
    pub processed_message_ids: HashSet<crate::dkg::v0::transport::MessageId>,
    pub topic_task: Option<tokio::task::AbortHandle>,
}

impl Default for DkgSessionTransportState {
    fn default() -> Self {
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
            published_public_phases: HashSet::new(),
            published_public_messages: HashSet::new(),
            outbound_private_messages: HashMap::new(),
            acknowledged_private_messages: HashSet::new(),
            processing_message_ids: HashSet::new(),
            processed_message_ids: HashSet::new(),
            topic_task: None,
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
    rings_pss: Arc<RwLock<HashMap<String, u128>>>,
    /// Exact reshare bulletin updates this node is ready to sign.
    reshare_signature_ready: Arc<RwLock<HashSet<ReshareSignatureReadyKey>>>,
    shutdown_tx: watch::Sender<bool>,
    background_tasks: StdMutex<Vec<JoinHandle<()>>>,
    /// Receiver for stalled refresh/reshare sessions published by the expiration sweep for
    /// offline-report attribution. Taken once via [`SessionStateManager::take_stall_report_receiver`]
    /// at node startup; the sender lives inside the expiration worker.
    stall_report_rx: StdMutex<Option<mpsc::UnboundedReceiver<AbandonedPssSession>>>,
}

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Create a new SessionStateManager and spawn background tasks
    pub fn new() -> Self {
        let states = Arc::new(RwLock::new(HashMap::new()));
        let rings_pss = Arc::new(RwLock::new(HashMap::new()));
        let reshare_signature_ready = Arc::new(RwLock::new(HashSet::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut background_tasks = Vec::new();

        // Spawn background expiration task (handles abandoned sessions). It owns the sole
        // sender for the stall-report channel, so the receiver stays open for the worker's life.
        let (stall_report_tx, stall_report_rx) = mpsc::unbounded_channel();
        let states_clone = states.clone();
        let pss_clone = rings_pss.clone();
        let ready_clone = reshare_signature_ready.clone();
        background_tasks.push(tokio::spawn(async move {
            Self::expiration_worker(
                states_clone,
                pss_clone,
                ready_clone,
                shutdown_rx,
                stall_report_tx,
            )
            .await;
        }));

        Self {
            states,
            rings_pss,
            reshare_signature_ready,
            shutdown_tx,
            background_tasks: StdMutex::new(background_tasks),
            stall_report_rx: StdMutex::new(Some(stall_report_rx)),
        }
    }

    /// Take the receiver for stalled-PSS-session offline-report attribution. Returns `Some`
    /// exactly once (the first caller); subsequent calls return `None`. Called at node startup
    /// to spawn the drain worker. If no one takes it, the sweep's published events accumulate
    /// unread in the channel — harmless, just never turned into reports.
    pub fn take_stall_report_receiver(
        &self,
    ) -> Option<mpsc::UnboundedReceiver<AbandonedPssSession>> {
        self.stall_report_rx
            .lock()
            .expect("stall_report_rx mutex poisoned")
            .take()
    }

    /// Background task that periodically removes expired sessions
    ///
    /// Active sessions are removed only at their hard attempt deadline. Completed
    /// sessions are retained only for `DKG_COMPLETED_SESSION_TTL`.
    async fn expiration_worker(
        states: Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
        rings_pss: Arc<RwLock<HashMap<String, u128>>>,
        reshare_signature_ready: Arc<RwLock<HashSet<ReshareSignatureReadyKey>>>,
        mut shutdown_rx: watch::Receiver<bool>,
        stall_report_tx: mpsc::UnboundedSender<AbandonedPssSession>,
    ) {
        let mut interval = tokio::time::interval(SESSION_EXPIRATION_CHECK_INTERVAL);

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                _ = interval.tick() => {}
            }

            let now = Instant::now();
            let mut states = states.write().await;
            let initial_count = states.len();

            // Collect session IDs to remove (expired or stalled)
            let mut to_remove_ids: Vec<u128> = Vec::new();
            let mut completed_ids: HashSet<u128> = HashSet::new();
            for (session_id, state) in states.iter() {
                let phase_age = now.duration_since(state.phase_started_at);
                if state.phase == DkgPhase::Phase4Complete {
                    if phase_age >= DKG_COMPLETED_SESSION_TTL {
                        tracing::warn!(
                            session_id = session_id,
                            completed_age_secs = phase_age.as_secs(),
                            "SessionStateManager: Removing retained completed DKG session"
                        );
                        to_remove_ids.push(*session_id);
                        completed_ids.insert(*session_id);
                    }
                    continue;
                }
                let hard_deadline = state
                    .transport
                    .hard_deadline
                    .unwrap_or(state.created_at + DKG_ATTEMPT_TIMEOUT);
                if now >= hard_deadline {
                    tracing::warn!(
                        session_id = session_id,
                        phase = ?state.phase,
                        attempt_id = ?state.transport.attempt_id,
                        "SessionStateManager: Removing DKG attempt at hard deadline"
                    );
                    to_remove_ids.push(*session_id);

                    // A refresh/reshare that stalled while collecting commitments or shares
                    // means one or more dealers went silent. Publish the dealers we never heard
                    // from so the stall-report worker can attempt `node_offline` reports (the
                    // co-signer reachability probe filters to dealers that are actually unreachable).
                    if matches!(
                        state.phase,
                        DkgPhase::Phase1Commitments | DkgPhase::Phase2Shares
                    ) {
                        let missing_peer_ids = state.missing_dealer_peer_ids(state.phase);
                        if !missing_peer_ids.is_empty() {
                            let _ = stall_report_tx.send(AbandonedPssSession {
                                session_id: *session_id,
                                kind: state.kind.clone(),
                                ring_id: state.routing.ring_id.clone(),
                                protocol_version: state.protocol_version,
                                missing_peer_ids,
                            });
                        }
                    }
                }
            }

            // Remove sessions (connections are per-peer and never closed here)
            let mut ring_claims_to_clear: Vec<(String, u128)> = Vec::new();
            let mut removed_ids: HashSet<u128> = HashSet::new();
            for session_id in to_remove_ids {
                if let Some(mut state) = states.remove(&session_id) {
                    removed_ids.insert(session_id);
                    if let Some(guard) = state.metrics_guard.take() {
                        if completed_ids.contains(&session_id) {
                            guard.complete();
                        } else {
                            guard.abandon();
                        }
                    }
                    if let Some(k) = state.kind.ring_key() {
                        ring_claims_to_clear.push((k.to_string(), session_id));
                    }
                }
            }

            // Clear in-progress PSS claims for expired sessions.
            if !ring_claims_to_clear.is_empty() {
                let mut pss = rings_pss.write().await;
                for (key, session_id) in &ring_claims_to_clear {
                    if pss.get(key).copied() == Some(*session_id) {
                        pss.remove(key);
                        tracing::debug!(
                            ring_key = %key,
                            session_id = session_id,
                            "SessionStateManager: Cleared in-progress PSS claim on expiration"
                        );
                    }
                }
            }

            if !removed_ids.is_empty() {
                reshare_signature_ready
                    .write()
                    .await
                    .retain(|k| !removed_ids.contains(&k.session_id));
            }

            let removed = initial_count - states.len();
            if removed > 0 {
                tracing::info!(
                    removed = removed,
                    remaining = states.len(),
                    "SessionStateManager: Expired session cleanup complete"
                );
            }
        }
    }

    /// Atomically claim the active PSS session for a ring.
    ///
    /// This lets concurrent refresh/reshare starters converge on one session ID:
    /// callers racing to start the same deterministic session get
    /// `AlreadyClaimedBySameSession`, while genuinely conflicting ceremonies get
    /// `Conflict`.
    pub async fn claim_ring_pss_session(
        &self,
        ring_pk_hex: &str,
        session_id: u128,
    ) -> RingPssClaimOutcome {
        let mut claims = self.rings_pss.write().await;
        match claims.get(ring_pk_hex).copied() {
            None => {
                claims.insert(ring_pk_hex.to_string(), session_id);
                RingPssClaimOutcome::Claimed
            }
            Some(existing) if existing == session_id => {
                RingPssClaimOutcome::AlreadyClaimedBySameSession
            }
            Some(existing) => RingPssClaimOutcome::Conflict {
                active_session_id: existing,
            },
        }
    }

    /// Returns `true` if a PSS ceremony is currently in progress for this ring.
    pub async fn is_ring_pss_active(&self, ring_pk_key: &str) -> bool {
        self.rings_pss.read().await.contains_key(ring_pk_key)
    }

    /// Return the deterministic session currently claiming this ring, if any.
    /// The production scheduler uses this to distinguish a new refresh from a
    /// harmless tick that observes the already-active attempt.
    pub async fn active_ring_pss_session(&self, ring_pk_key: &str) -> Option<u128> {
        self.rings_pss.read().await.get(ring_pk_key).copied()
    }

    /// Mark one exact reshare bulletin update as ready to sign.
    pub async fn mark_reshare_signature_ready(&self, key: ReshareSignatureReadyKey) {
        self.reshare_signature_ready.write().await.insert(key);
    }

    /// Returns true iff this node has locally completed the exact reshare update.
    pub async fn is_reshare_signature_ready(&self, key: &ReshareSignatureReadyKey) -> bool {
        self.reshare_signature_ready.read().await.contains(key)
    }

    /// Clear the in-progress PSS claim for a ring (called on setup failure before a
    /// session exists, or when force-clearing state).
    pub async fn unmark_ring_pss(&self, ring_pk_hex: &str) {
        self.rings_pss.write().await.remove(ring_pk_hex);
    }

    /// Clear the in-progress PSS claim only if this exact session still owns it.
    pub async fn unmark_ring_pss_if_matches(&self, ring_pk_hex: &str, session_id: u128) {
        let mut claims = self.rings_pss.write().await;
        if claims.get(ring_pk_hex).copied() == Some(session_id) {
            claims.remove(ring_pk_hex);
        }
    }

    /// Stop and join the manager's background cleanup workers.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        let tasks = self
            .background_tasks
            .lock()
            .expect("session background task mutex poisoned")
            .drain(..)
            .collect::<Vec<_>>();
        for task in tasks {
            let _ = task.await;
        }
    }

    /// Execute a function with read-only access to a session state
    pub async fn with_state<F, R>(&self, session_id: &u128, f: F) -> Option<R>
    where
        F: FnOnce(&DkgSessionState<D>) -> R,
    {
        let states = self.states.read().await;
        states.get(session_id).map(f)
    }

    /// Execute a function with mutable access to a session state
    pub async fn with_state_mut<F, R>(&self, session_id: &u128, f: F) -> Option<R>
    where
        F: FnOnce(&mut DkgSessionState<D>) -> R,
    {
        let mut states = self.states.write().await;
        states.get_mut(session_id).map(f)
    }

    /// Create a new DKG session.
    ///
    /// Returns:
    /// - `CreateSessionOutcome::Created` on success.
    /// - `CreateSessionOutcome::AlreadyExists` if a concurrent handler already created
    ///   the session (safe to ignore).
    /// - `CreateSessionOutcome::LimitReached` if `MAX_DKG_SESSIONS` is already at
    ///   capacity (must NOT be silently ignored — callers that marked a ring as
    ///   in-progress PSS before calling this must unmark it on this outcome).
    ///
    /// Create a new DKG session, optionally initializing it via `init_fn` before
    /// the write lock is released.
    ///
    /// `init_fn` is called on the newly created state while the map's write lock is
    /// still held, so the session is never visible to other tasks in a
    /// partially-initialized state (e.g. with `kind = Fresh` and `reshare_params = None`
    /// when this is actually a Reshare session). Pass `|_| {}` when no extra
    /// initialization is needed.
    pub async fn create_session<F>(
        &self,
        session_id: u128,
        node: D,
        total_participants: usize,
        init_fn: F,
    ) -> CreateSessionOutcome
    where
        F: FnOnce(&mut DkgSessionState<D>),
    {
        if total_participants == 0 {
            tracing::warn!(
                session_id = session_id,
                "Cannot create DKG session with zero participants"
            );
            return CreateSessionOutcome::InvalidParticipantCount;
        }

        let mut states = self.states.write().await;

        // Check if session already exists to avoid overwriting existing state
        if states.contains_key(&session_id) {
            tracing::debug!(
                session_id = session_id,
                "DKG session already exists for session_id"
            );
            return CreateSessionOutcome::AlreadyExists;
        }

        // Enforce maximum concurrent session limit to prevent resource exhaustion
        if states.len() >= MAX_DKG_SESSIONS {
            tracing::warn!(
                session_id = session_id,
                active_sessions = states.len(),
                max_sessions = MAX_DKG_SESSIONS,
                "DKG session limit reached, rejecting new session"
            );
            return CreateSessionOutcome::LimitReached;
        }

        let mut new_state = DkgSessionState::new(node, total_participants);
        init_fn(&mut new_state);
        let ceremony_kind = new_state.ceremony_kind();
        new_state.metrics_guard = Some(metrics::DkgSessionMetricsGuard::new(ceremony_kind));
        states.insert(session_id, new_state);
        CreateSessionOutcome::Created
    }

    /// Check if a session exists
    pub async fn session_exists(&self, session_id: &u128) -> bool {
        self.states.read().await.contains_key(session_id)
    }

    #[cfg(test)]
    pub async fn set_peer_ids(&self, session_id: &u128, peer_ids: Vec<String>) {
        self.with_state_mut(session_id, |s| s.routing.peer_ids = peer_ids)
            .await;
    }

    #[cfg(test)]
    pub async fn set_peer_node_keys(&self, session_id: &u128, peer_node_keys: Vec<String>) {
        self.with_state_mut(session_id, |s| s.routing.peer_node_keys = peer_node_keys)
            .await;
    }

    /// Stage a refresh bundle while waiting for the post-refresh health-check result.
    pub async fn set_refresh_health_check_candidate(
        &self,
        session_id: &u128,
        candidate: RefreshHealthCheckCandidate,
    ) {
        self.with_state_mut(session_id, |s| s.refresh.candidate = Some(candidate))
            .await;
    }

    /// Load the staged refresh bundle, if this session still has one.
    pub async fn refresh_health_check_candidate(
        &self,
        session_id: &u128,
    ) -> Option<RefreshHealthCheckCandidate> {
        self.with_state(session_id, |s| s.refresh.candidate.clone())
            .await
            .flatten()
    }

    /// Discard any staged refresh bundle for this session.
    pub async fn clear_refresh_health_check_candidate(&self, session_id: &u128) {
        self.with_state_mut(session_id, |s| s.refresh.candidate = None)
            .await;
    }

    /// Store a refresh health-check result that arrived before Phase 4 staged its candidate.
    pub async fn store_pending_refresh_health_check_result(
        &self,
        session_id: &u128,
        result: PendingRefreshHealthCheckResult,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.refresh.pending_result.is_some() {
                return false;
            }
            state.refresh.pending_result = Some(result);
            true
        })
        .await
    }

    /// Remove and return an early refresh health-check result, if one was queued.
    pub async fn take_pending_refresh_health_check_result(
        &self,
        session_id: &u128,
    ) -> Option<PendingRefreshHealthCheckResult> {
        self.with_state_mut(session_id, |s| s.refresh.pending_result.take())
            .await
            .flatten()
    }

    /// Store the PSS refresh interval for this session so Phase 4 can persist it.
    pub async fn get_peer_ids(&self, session_id: &u128) -> Option<Vec<String>> {
        self.with_state(session_id, |s| s.routing.peer_ids.clone())
            .await
    }

    pub async fn get_peer_node_keys(&self, session_id: &u128) -> Option<Vec<String>> {
        self.with_state(session_id, |s| s.routing.peer_node_keys.clone())
            .await
    }

    pub async fn ring_id_for_session(&self, session_id: &u128) -> Option<String> {
        self.with_state(session_id, |s| s.routing.ring_id.clone())
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn configure_transport(
        &self,
        session_id: &u128,
        ceremony_id: crate::dkg::v0::transport::CeremonyId,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        committee_digest: [u8; 32],
        config_digest: [u8; 32],
        topic_id: network::TopicId,
        leader_node_key: String,
        leader_peer_route: String,
        participant_routes: Vec<String>,
        committees: crate::dkg::v0::transport::CeremonyConfig,
        topic: Arc<dyn network::Topic>,
    ) -> TransportConfigureOutcome {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if let Some(existing) = transport.attempt_id {
                return if existing == attempt_id
                    && transport.ceremony_id == Some(ceremony_id)
                    && transport.config_digest == Some(config_digest)
                {
                    TransportConfigureOutcome::AlreadyConfigured
                } else {
                    TransportConfigureOutcome::ConflictingAttempt
                };
            }
            let now = Instant::now();
            transport.ceremony_id = Some(ceremony_id);
            transport.attempt_id = Some(attempt_id);
            transport.committee_digest = Some(committee_digest);
            transport.config_digest = Some(config_digest);
            transport.topic_id = Some(topic_id);
            transport.leader_node_key = Some(leader_node_key);
            transport.leader_peer_route = Some(leader_peer_route);
            transport.participant_routes = participant_routes;
            transport.committees = Some(committees);
            transport.topic = Some(topic);
            transport.prepared_at = Some(now);
            transport.last_progress_at = now;
            transport.hard_deadline = Some(now + crate::constants::DKG_ATTEMPT_TIMEOUT);
            TransportConfigureOutcome::Configured
        })
        .await
        .unwrap_or(TransportConfigureOutcome::MissingSession)
    }

    pub(crate) async fn activate_transport(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        activation_digest: [u8; 32],
        active_dealers: Vec<crate::dkg::v0::transport::ParticipantRef>,
    ) -> TransportActivationOutcome {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return TransportActivationOutcome::StaleAttempt;
            }
            if state.transport.activated {
                return if state.transport.activation_digest == Some(activation_digest)
                    && state.transport.active_dealers == active_dealers
                {
                    TransportActivationOutcome::AlreadyActivated
                } else {
                    TransportActivationOutcome::StaleAttempt
                };
            }
            if let Some(params) = state.reshare.params.as_mut() {
                params.participating_ids =
                    active_dealers.iter().map(|dealer| dealer.node_id).collect();
            }
            state.transport.activated = true;
            state.transport.activation_digest = Some(activation_digest);
            state.transport.active_dealers = active_dealers;
            state.transport.last_progress_at = Instant::now();
            TransportActivationOutcome::Activated
        })
        .await
        .unwrap_or(TransportActivationOutcome::MissingSession)
    }

    /// Claim the one transition from an activated transport barrier into
    /// cryptographic work. The claim is attempt-scoped so a retransmitted
    /// `Begin` request can be acknowledged without regenerating contributions
    /// or private shares.
    pub(crate) async fn begin_transport(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        activation_digest: [u8; 32],
    ) -> TransportBeginOutcome {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return TransportBeginOutcome::StaleAttempt;
            }
            if !transport.activated {
                return TransportBeginOutcome::NotActivated;
            }
            if transport.activation_digest != Some(activation_digest) {
                return TransportBeginOutcome::StaleAttempt;
            }
            if transport.begun {
                return TransportBeginOutcome::AlreadyBegun;
            }
            transport.begun = true;
            transport.last_progress_at = Instant::now();
            TransportBeginOutcome::Begun
        })
        .await
        .unwrap_or(TransportBeginOutcome::MissingSession)
    }

    pub(crate) async fn transport_configuration(
        &self,
        session_id: &u128,
    ) -> Option<(
        crate::dkg::v0::transport::CeremonyId,
        crate::dkg::v0::transport::AttemptId,
        [u8; 32],
    )> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            Some((
                transport.ceremony_id?,
                transport.attempt_id?,
                transport.config_digest?,
            ))
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_attempt(
        &self,
        session_id: &u128,
    ) -> Option<crate::dkg::v0::transport::AttemptId> {
        self.with_state(session_id, |state| state.transport.attempt_id)
            .await
            .flatten()
    }

    pub(crate) async fn transport_hard_deadline(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
    ) -> Option<Instant> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id))
                .then_some(state.transport.hard_deadline)
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_preparation_deadline(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
    ) -> Option<Instant> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            (transport.attempt_id == Some(attempt_id))
                .then(|| {
                    transport
                        .prepared_at
                        .map(|prepared_at| prepared_at + crate::constants::DKG_PREPARATION_TIMEOUT)
                })
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_topic(
        &self,
        session_id: &u128,
    ) -> Option<Arc<dyn network::Topic>> {
        self.with_state(session_id, |state| state.transport.topic.clone())
            .await
            .flatten()
    }

    pub(crate) async fn transport_committees(
        &self,
        session_id: &u128,
    ) -> Option<crate::dkg::v0::transport::CeremonyConfig> {
        self.with_state(session_id, |state| state.transport.committees.clone())
            .await
            .flatten()
    }

    pub(crate) async fn replace_transport_topic(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        topic: Arc<dyn network::Topic>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return false;
            }
            state.transport.topic = Some(topic);
            state.transport.last_progress_at = Instant::now();
            true
        })
        .await
    }

    pub(crate) async fn set_transport_topic_task(
        &self,
        session_id: &u128,
        task: tokio::task::AbortHandle,
    ) -> Option<()> {
        self.with_state_mut(session_id, |state| {
            if let Some(previous) = state.transport.topic_task.replace(task) {
                previous.abort();
            }
        })
        .await
    }

    pub(crate) async fn begin_topology_probe(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        nonce: [u8; 32],
        self_peer: String,
    ) -> Option<Arc<Notify>> {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return None;
            }
            transport.topology_probe_nonce = Some(nonce);
            transport.topology_probe_acknowledgements.clear();
            transport.topology_probe_acknowledgements.insert(self_peer);
            transport.last_progress_at = Instant::now();
            Some(transport.topology_probe_notify.clone())
        })
        .await
        .flatten()
    }

    pub(crate) async fn record_topology_probe(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        nonce: [u8; 32],
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return false;
            }
            if state
                .transport
                .topology_probe_nonce
                .is_some_and(|existing| existing != nonce)
            {
                return false;
            }
            state.transport.topology_probe_nonce = Some(nonce);
            state.transport.last_progress_at = Instant::now();
            true
        })
        .await
    }

    pub(crate) async fn record_topology_probe_ack(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        nonce: [u8; 32],
        peer: String,
    ) -> TopologyAckRecordOutcome {
        let outcome = self
            .with_state_mut(session_id, |state| {
                let transport = &mut state.transport;
                if transport.attempt_id != Some(attempt_id) {
                    return TopologyAckRecordOutcome::StaleAttempt;
                }
                if transport.topology_probe_nonce != Some(nonce) {
                    return TopologyAckRecordOutcome::WrongNonce;
                }
                if !transport.topology_probe_acknowledgements.insert(peer) {
                    return TopologyAckRecordOutcome::Duplicate;
                }
                transport.last_progress_at = Instant::now();
                transport.topology_probe_notify.notify_waiters();
                TopologyAckRecordOutcome::Recorded
            })
            .await
            .unwrap_or(TopologyAckRecordOutcome::MissingSession);
        outcome
    }

    pub(crate) async fn topology_probe_acknowledgements(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        nonce: [u8; 32],
    ) -> Option<BTreeSet<String>> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            (transport.attempt_id == Some(attempt_id)
                && transport.topology_probe_nonce == Some(nonce))
            .then(|| transport.topology_probe_acknowledgements.clone())
        })
        .await
        .flatten()
    }

    pub(crate) async fn record_public_contribution(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        phase: crate::dkg::v0::transport::PublicPhase,
        origin: crate::dkg::v0::transport::ParticipantRef,
        contribution: network::SignedPayload,
    ) -> PublicContributionRecordOutcome {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return PublicContributionRecordOutcome::ConflictingDuplicate;
            }
            let transport = &mut state.transport;
            match transport
                .public_contributions
                .get(&phase)
                .and_then(|contributions| contributions.get(&origin))
            {
                Some(existing) if existing == &contribution => {
                    PublicContributionRecordOutcome::DuplicateSame
                }
                Some(_) => PublicContributionRecordOutcome::ConflictingDuplicate,
                None => {
                    transport
                        .public_phase_started_at
                        .entry(phase)
                        .or_insert_with(Instant::now);
                    transport
                        .public_contributions
                        .entry(phase)
                        .or_default()
                        .insert(origin, contribution);
                    transport.last_progress_at = Instant::now();
                    PublicContributionRecordOutcome::Recorded
                }
            }
        })
        .await
        .unwrap_or(PublicContributionRecordOutcome::MissingSession)
    }

    pub(crate) async fn public_contributions(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        phase: crate::dkg::v0::transport::PublicPhase,
    ) -> Option<BTreeMap<crate::dkg::v0::transport::ParticipantRef, network::SignedPayload>> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id)).then(|| {
                state
                    .transport
                    .public_contributions
                    .get(&phase)
                    .cloned()
                    .unwrap_or_default()
            })
        })
        .await
        .flatten()
    }

    pub(crate) async fn public_phase_collection_elapsed(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        phase: crate::dkg::v0::transport::PublicPhase,
    ) -> Option<std::time::Duration> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id))
                .then(|| {
                    state
                        .transport
                        .public_phase_started_at
                        .get(&phase)
                        .map(Instant::elapsed)
                })
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn claim_public_phase_publish(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        phase: crate::dkg::v0::transport::PublicPhase,
        expected: usize,
    ) -> bool {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id)
                || transport
                    .public_contributions
                    .get(&phase)
                    .map_or(0, BTreeMap::len)
                    != expected
                || transport.published_public_phases.contains(&phase)
            {
                return false;
            }
            transport.published_public_phases.insert(phase);
            true
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn claim_public_message_publish(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        message_id: crate::dkg::v0::transport::MessageId,
    ) -> bool {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            transport.attempt_id == Some(attempt_id)
                && transport.published_public_messages.insert(message_id)
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn transport_active_dealers(
        &self,
        session_id: &u128,
    ) -> Option<Vec<crate::dkg::v0::transport::ParticipantRef>> {
        self.with_state(session_id, |state| state.transport.active_dealers.clone())
            .await
    }

    pub(crate) async fn transport_info(
        &self,
        session_id: &u128,
    ) -> Option<(
        crate::dkg::v0::transport::CeremonyId,
        crate::dkg::v0::transport::AttemptId,
        [u8; 32],
        String,
        bool,
    )> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            Some((
                transport.ceremony_id?,
                transport.attempt_id?,
                transport.committee_digest?,
                transport.leader_node_key.clone()?,
                transport.activated,
            ))
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_participant_routes(
        &self,
        session_id: &u128,
    ) -> Option<Vec<String>> {
        self.with_state(session_id, |state| {
            state.transport.participant_routes.clone()
        })
        .await
    }

    pub(crate) async fn transport_leader_route(&self, session_id: &u128) -> Option<String> {
        self.with_state(session_id, |state| {
            state.transport.leader_peer_route.clone()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_repair_due(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        stall_interval: std::time::Duration,
    ) -> bool {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            transport.attempt_id == Some(attempt_id)
                && transport.activated
                && transport.last_progress_at.elapsed() >= stall_interval
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn cache_private_message(
        &self,
        session_id: &u128,
        message_id: crate::dkg::v0::transport::MessageId,
        exact_bytes: Vec<u8>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            match state.transport.outbound_private_messages.get(&message_id) {
                Some(existing) => existing == &exact_bytes,
                None => {
                    state
                        .transport
                        .outbound_private_messages
                        .insert(message_id, exact_bytes);
                    true
                }
            }
        })
        .await
    }

    pub(crate) async fn acknowledge_private_message(
        &self,
        session_id: &u128,
        attempt_id: crate::dkg::v0::transport::AttemptId,
        message_id: crate::dkg::v0::transport::MessageId,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return false;
            }
            state
                .transport
                .acknowledged_private_messages
                .insert(message_id);
            state.transport.last_progress_at = Instant::now();
            true
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn private_message(
        &self,
        session_id: &u128,
        message_id: crate::dkg::v0::transport::MessageId,
    ) -> Option<Vec<u8>> {
        self.with_state(session_id, |state| {
            state
                .transport
                .outbound_private_messages
                .get(&message_id)
                .cloned()
        })
        .await
        .flatten()
    }

    pub(crate) async fn private_message_for_recipient(
        &self,
        session_id: &u128,
        recipient: crate::dkg::v0::transport::ParticipantRef,
    ) -> Option<Vec<u8>> {
        self.with_state(session_id, |state| {
            state
                .transport
                .outbound_private_messages
                .values()
                .find(|bytes| {
                    crate::dkg::v0::transport::decode::<
                        crate::dkg::v0::transport::DkgPrivateMessage,
                    >(bytes, 2 * 1024 * 1024)
                    .is_ok_and(|message| {
                        matches!(
                            message,
                            crate::dkg::v0::transport::DkgPrivateMessage::ShareDelivery {
                                to,
                                ..
                            } if to == recipient
                        )
                    })
                })
                .cloned()
        })
        .await
        .flatten()
    }

    pub(crate) async fn private_message_acknowledged(
        &self,
        session_id: &u128,
        message_id: crate::dkg::v0::transport::MessageId,
    ) -> bool {
        self.with_state(session_id, |state| {
            state
                .transport
                .acknowledged_private_messages
                .contains(&message_id)
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn claim_transport_message(
        &self,
        session_id: &u128,
        message_id: crate::dkg::v0::transport::MessageId,
    ) -> MessageProcessingClaim {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.processed_message_ids.contains(&message_id) {
                MessageProcessingClaim::AlreadyProcessed
            } else if !transport.processing_message_ids.insert(message_id) {
                MessageProcessingClaim::AlreadyProcessing
            } else {
                MessageProcessingClaim::Claimed
            }
        })
        .await
        .unwrap_or(MessageProcessingClaim::MissingSession)
    }

    pub(crate) async fn finish_transport_message(
        &self,
        session_id: &u128,
        message_id: crate::dkg::v0::transport::MessageId,
        success: bool,
    ) {
        let _ = self
            .with_state_mut(session_id, |state| {
                let transport = &mut state.transport;
                transport.processing_message_ids.remove(&message_id);
                if success {
                    transport.processed_message_ids.insert(message_id);
                }
            })
            .await;
    }

    /// Set node_id to peer_id mappings for efficient routing
    #[cfg(test)]
    pub async fn set_node_peer_mappings(
        &self,
        session_id: &u128,
        node_id_to_peer_id: HashMap<u32, String>,
    ) {
        let (node_to_peer, peer_to_node) = bidirectional_node_peer_maps(node_id_to_peer_id);
        self.with_state_mut(session_id, |state| {
            state.routing.node_id_to_peer_id = node_to_peer;
            state.routing.peer_id_to_node_id = peer_to_node;
        })
        .await;
    }

    /// Get peer_id for a node_id
    pub async fn get_peer_id_for_node(&self, session_id: &u128, node_id: u32) -> Option<String> {
        self.with_state(session_id, |s| {
            s.routing.node_id_to_peer_id.get(&node_id).cloned()
        })
        .await
        .flatten()
    }

    pub(crate) async fn peer_id_for_participant(
        &self,
        session_id: &u128,
        participant: crate::dkg::v0::transport::ParticipantRef,
    ) -> Option<String> {
        self.with_state(session_id, |state| match participant.scope {
            crate::dkg::v0::transport::CommitteeScope::Current => state
                .routing
                .node_id_to_peer_id
                .get(&participant.node_id)
                .cloned(),
            crate::dkg::v0::transport::CommitteeScope::Next => state
                .routing
                .reshare_new_node_id_to_peer_id
                .get(&participant.node_id)
                .cloned(),
        })
        .await
        .flatten()
    }

    /// Store a share whose sender commitment has not arrived yet.
    ///
    /// Returns `Some(true)` when this is the first pending share for the sender,
    /// `Some(false)` when a pending share from that sender already exists, and
    /// `None` when the session is gone.
    pub async fn store_pending_share_waiting_for_commitment(
        &self,
        session_id: &u128,
        share: DistributedShare<D::ShareValue>,
        report_evidence: Option<SignedDkgShare>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            let from_node_id = share.from_id;
            if state
                .pending
                .pending_shares_waiting_for_commitment
                .contains_key(&from_node_id)
            {
                return false;
            }
            state.pending.pending_shares_waiting_for_commitment.insert(
                from_node_id,
                PendingDkgShare {
                    share,
                    report_evidence,
                },
            );
            true
        })
        .await
    }

    /// Remove and return a pending share that was waiting on `from_node_id`'s commitment.
    pub async fn take_pending_share_waiting_for_commitment(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<PendingDkgShare<D::ShareValue>> {
        self.with_state_mut(session_id, |s| {
            s.pending
                .pending_shares_waiting_for_commitment
                .remove(&from_node_id)
        })
        .await
        .flatten()
    }

    pub async fn record_commitment_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
        commitment_hash: [u8; 32],
    ) -> Option<CommitmentHashRecordOutcome> {
        self.with_state_mut(session_id, |state| {
            match state.commit_reveal.received_hashes.get(&from_node_id) {
                Some(existing) if existing == &commitment_hash => {
                    CommitmentHashRecordOutcome::DuplicateSame
                }
                Some(existing) => CommitmentHashRecordOutcome::Mismatch {
                    existing: *existing,
                },
                None => {
                    state
                        .commit_reveal
                        .received_hashes
                        .insert(from_node_id, commitment_hash);
                    CommitmentHashRecordOutcome::Recorded
                }
            }
        })
        .await
    }

    pub async fn get_commitment_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<[u8; 32]> {
        self.with_state(session_id, |state| {
            state
                .commit_reveal
                .received_hashes
                .get(&from_node_id)
                .copied()
        })
        .await
        .flatten()
    }

    pub async fn mark_commitment_hash_broadcast_complete(&self, session_id: &u128) {
        self.with_state_mut(session_id, |state| {
            state.commit_reveal.own_hash_broadcast_complete = true;
        })
        .await;
    }

    /// Refresh/reshare only: remember the signed commitment received from `dealer_id`
    /// so it can be revealed if the ceremony later fails an equivocation-consistent check.
    pub async fn store_received_commitment(
        &self,
        session_id: &u128,
        dealer_id: u32,
        signed_commitment: SignedDkgCommitment,
    ) {
        self.with_state_mut(session_id, |state| {
            state
                .commitment_audit
                .received_commitments
                .insert(dealer_id, signed_commitment);
        })
        .await;
    }

    /// Snapshot of every signed commitment this node received, for the on-failure
    /// equivocation-audit reveal broadcast.
    pub async fn received_commitments_snapshot(
        &self,
        session_id: &u128,
    ) -> Option<Vec<SignedDkgCommitment>> {
        self.with_state(session_id, |state| {
            state
                .commitment_audit
                .received_commitments
                .values()
                .cloned()
                .collect()
        })
        .await
    }

    /// Compare peer-revealed commitments against what we received: return the first
    /// dealer for which a revealed commitment's bytes differ from ours (equivocation).
    /// Dealers we never received a commitment from are ignored.
    /// Return the two conflicting commitments (`ours`, `reveal`) for the first dealer that
    /// equivocated, so the caller can build an equivocation report. Equivocation requires
    /// the SAME per-attempt nonce with different bytes; a different nonce means an honest
    /// retry (or evasion), not equivocation.
    pub async fn find_conflicting_commitment_pair(
        &self,
        session_id: &u128,
        revealed: &[SignedDkgCommitment],
    ) -> Option<(u32, SignedDkgCommitment, SignedDkgCommitment)> {
        self.with_state(session_id, |state| {
            revealed.iter().find_map(|reveal| {
                let dealer_id = reveal.statement.from_node_id;
                let ours = state
                    .commitment_audit
                    .received_commitments
                    .get(&dealer_id)?;
                commitments_prove_equivocation(ours, reveal)
                    .then(|| (dealer_id, ours.clone(), reveal.clone()))
            })
        })
        .await
        .flatten()
    }

    pub async fn store_pending_commitment_waiting_for_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
        commitment: Vec<u8>,
        report_evidence: Option<SignedDkgCommitment>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state
                .pending
                .pending_commitments_waiting_for_hash
                .contains_key(&from_node_id)
            {
                return false;
            }
            state.pending.pending_commitments_waiting_for_hash.insert(
                from_node_id,
                PendingDkgCommitment {
                    commitment,
                    report_evidence,
                },
            );
            true
        })
        .await
    }

    pub async fn take_pending_commitment_waiting_for_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<PendingDkgCommitment> {
        self.with_state_mut(session_id, |state| {
            state
                .pending
                .pending_commitments_waiting_for_hash
                .remove(&from_node_id)
        })
        .await
        .flatten()
    }

    pub async fn update_phase(&self, session_id: &u128, phase: DkgPhase) {
        self.with_state_mut(session_id, |state| {
            state.transition_phase(phase);
        })
        .await;
    }

    pub async fn increment_commitments(&self, session_id: &u128) {
        self.with_state_mut(session_id, |s| s.commitments_received += 1)
            .await;
    }

    #[cfg(test)]
    pub async fn increment_shares(&self, session_id: &u128) {
        self.with_state_mut(session_id, |s| s.shares_received += 1)
            .await;
    }

    /// Record a successfully verified Phase 2 share from `dealer_id`.
    pub async fn record_received_share(&self, session_id: &u128, dealer_id: u32) {
        self.with_state_mut(session_id, |state| {
            if state.commitment_audit.received_shares.insert(dealer_id) {
                state.shares_received += 1;
            }
        })
        .await;
    }

    /// Remove a session and free its memory.
    ///
    /// Called after DKG Phase 4 completes. The session data is no longer needed
    /// since the private share is stored in local storage and ring info is on
    /// the bulletin.
    ///
    /// Listener-owned topic and acknowledgement tasks are cancelled here. Pair
    /// streams are ceremony-scoped and close after their delivery contract is
    /// acknowledged; bounded pooled peer connections remain available.
    pub async fn remove_session(&self, session_id: &u128) {
        self.remove_session_with_outcome(session_id, false).await;
    }

    /// Remove a successfully completed session and balance its active metrics.
    pub async fn complete_session(&self, session_id: &u128) {
        self.remove_session_with_outcome(session_id, true).await;
    }

    async fn remove_session_with_outcome(&self, session_id: &u128, completed: bool) {
        let ring_key_to_clear = {
            let mut states = self.states.write().await;
            if let Some(mut state) = states.remove(session_id) {
                if let Some(guard) = state.metrics_guard.take() {
                    if completed {
                        guard.complete();
                    } else {
                        guard.abandon();
                    }
                }
                tracing::debug!(
                    session_id = session_id,
                    "SessionStateManager: Removed session"
                );
                state.kind.ring_key().map(|k| k.to_string())
            } else {
                return;
            }
        };

        // Clear the in-progress PSS claim so future ceremonies can proceed.
        if let Some(key) = ring_key_to_clear {
            self.unmark_ring_pss_if_matches(&key, *session_id).await;
            tracing::debug!(
                session_id = session_id,
                ring_key = %key,
                "SessionStateManager: Cleared in-progress PSS claim on remove_session"
            );
        }

        self.reshare_signature_ready
            .write()
            .await
            .retain(|k| k.session_id != *session_id);
    }
}

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
mod tests {
    use super::*;
    use crate::dkg::v0::messages::SessionKind;
    use crypto::r#trait::DkgRole;
    use crypto::DkgImpl;
    use crypto::ScalarField as Fr;
    use std::sync::Arc;

    /// Create a minimal DkgImpl node for state-manager tests.
    /// The state manager stores the node but never calls protocol methods on it,
    /// so any valid construction is fine here.
    fn make_node(id: u32) -> DkgImpl {
        *DkgImpl::new(id, 2, 3, 0, DkgRole::Standard).expect("DkgImpl::new failed")
    }

    // =========================================================================
    // Session creation
    // =========================================================================

    #[tokio::test]
    async fn test_create_session_success() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let ok = mgr.create_session(1, make_node(1), 3, |_| {}).await;
        assert_eq!(
            ok,
            CreateSessionOutcome::Created,
            "first create should succeed"
        );
        assert_eq!(mgr.session_count().await, 1);
    }

    #[tokio::test]
    async fn background_workers_shutdown_cleanly() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        tokio::time::timeout(std::time::Duration::from_millis(250), mgr.shutdown())
            .await
            .expect("background workers should stop promptly");
        assert!(mgr
            .background_tasks
            .lock()
            .expect("background task mutex")
            .is_empty());
    }

    #[tokio::test]
    async fn test_create_session_rejects_duplicate_id() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert_eq!(
            mgr.create_session(42, make_node(1), 3, |_| {}).await,
            CreateSessionOutcome::Created
        );
        let dup = mgr.create_session(42, make_node(2), 3, |_| {}).await;
        assert_eq!(
            dup,
            CreateSessionOutcome::AlreadyExists,
            "duplicate session_id should be rejected"
        );
        assert_eq!(mgr.session_count().await, 1, "count must not increment");
    }

    #[tokio::test]
    async fn test_create_session_rejects_zero_participants() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let ok = mgr.create_session(1, make_node(1), 0, |_| {}).await;
        assert_eq!(
            ok,
            CreateSessionOutcome::InvalidParticipantCount,
            "zero participants should be rejected"
        );
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_limit_enforcement() {
        let mgr = SessionStateManager::<DkgImpl>::new();

        for i in 0..MAX_DKG_SESSIONS as u128 {
            let ok = mgr.create_session(i, make_node(1), 3, |_| {}).await;
            assert_eq!(
                ok,
                CreateSessionOutcome::Created,
                "create should succeed for session {}",
                i
            );
        }

        // One beyond the limit must be rejected
        let rejected = mgr
            .create_session(MAX_DKG_SESSIONS as u128, make_node(1), 3, |_| {})
            .await;
        assert_eq!(
            rejected,
            CreateSessionOutcome::LimitReached,
            "create should fail at session limit"
        );
        assert_eq!(mgr.session_count().await, MAX_DKG_SESSIONS);
    }

    // =========================================================================
    // Session existence and removal
    // =========================================================================

    #[tokio::test]
    async fn test_session_exists_and_remove() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert!(!mgr.session_exists(&7).await);

        mgr.create_session(7, make_node(1), 3, |_| {}).await;
        assert!(mgr.session_exists(&7).await);

        mgr.remove_session(&7).await;
        assert!(!mgr.session_exists(&7).await);
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_remove_session_clears_reshare_signature_ready_markers() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let ready_key = ReshareSignatureReadyKey {
            ring_key: "ring".to_string(),
            session_id: 7,
            ring_id: "post".to_string(),
            current_ring_sha256: "current".to_string(),
            finalized_ring_sha256: "updated".to_string(),
        };

        mgr.create_session(7, make_node(1), 3, |_| {}).await;
        mgr.mark_reshare_signature_ready(ready_key.clone()).await;
        assert!(mgr.is_reshare_signature_ready(&ready_key).await);

        mgr.remove_session(&7).await;

        assert!(!mgr.is_reshare_signature_ready(&ready_key).await);
    }

    #[tokio::test]
    async fn test_session_count_tracks_multiple() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3, |_| {}).await;
        mgr.create_session(2, make_node(1), 3, |_| {}).await;
        mgr.create_session(3, make_node(1), 3, |_| {}).await;
        assert_eq!(mgr.session_count().await, 3);

        mgr.remove_session(&2).await;
        assert_eq!(mgr.session_count().await, 2);
    }

    // =========================================================================
    // with_state / with_state_mut
    // =========================================================================

    #[tokio::test]
    async fn test_with_state_returns_none_for_missing_session() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let result = mgr.with_state(&99, |s| s.total_participants).await;
        assert!(
            result.is_none(),
            "should return None for non-existent session"
        );
    }

    #[tokio::test]
    async fn test_with_state_returns_value_for_existing_session() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(5, make_node(1), 7, |_| {}).await;
        let participants = mgr.with_state(&5, |s| s.total_participants).await;
        assert_eq!(participants, Some(7));
    }

    // =========================================================================
    // Phase tracking
    // =========================================================================

    #[tokio::test]
    async fn test_phase_update_changes_phase_and_resets_timer() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3, |_| {}).await;
        let phase_histogram = crate::metrics::DKG_PHASE_DURATION_SECONDS
            .with_label_values(&["fresh", "initializing"]);
        let observations_before = phase_histogram.get_sample_count();

        // Capture a timestamp just before the update; monotonic time guarantees
        // phase_started_at set inside update_phase will be >= this value.
        let before_update = std::time::Instant::now();
        mgr.update_phase(&1, DkgPhase::Phase1Commitments).await;
        assert_eq!(
            phase_histogram.get_sample_count(),
            observations_before + 1,
            "the phase that was exited must be observed exactly once"
        );
        mgr.update_phase(&1, DkgPhase::Phase1Commitments).await;
        assert_eq!(
            phase_histogram.get_sample_count(),
            observations_before + 1,
            "an idempotent phase update must not emit a second observation"
        );

        let (phase, started_at) = mgr
            .with_state(&1, |s| (s.phase, s.phase_started_at))
            .await
            .expect("session 1 should exist");
        assert_eq!(phase, DkgPhase::Phase1Commitments);
        assert!(
            started_at >= before_update,
            "phase_started_at should be reset to >= the time update_phase was called"
        );
    }

    // =========================================================================
    // Commitment and share counters
    // =========================================================================

    #[tokio::test]
    async fn test_increment_commitment_and_share_counters() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        // 3 participants: need 2 from others (total - 1)
        mgr.create_session(1, make_node(1), 3, |_| {}).await;

        mgr.increment_commitments(&1).await;
        let all = mgr
            .with_state(&1, |s| s.all_commitments_received())
            .await
            .unwrap();
        assert!(!all, "one commitment is not enough for 3 participants");

        mgr.increment_commitments(&1).await;
        let all = mgr
            .with_state(&1, |s| s.all_commitments_received())
            .await
            .unwrap();
        assert!(
            all,
            "two commitments should satisfy 3-participant threshold"
        );

        mgr.increment_shares(&1).await;
        mgr.increment_shares(&1).await;
        let all_shares = mgr
            .with_state(&1, |s| s.all_shares_received())
            .await
            .unwrap();
        assert!(all_shares);
    }

    // =========================================================================
    // Peer IDs
    // =========================================================================

    #[tokio::test]
    async fn test_set_and_get_peer_ids() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3, |_| {}).await;

        let peers = vec!["peer-a".to_string(), "peer-b".to_string()];
        mgr.set_peer_ids(&1, peers.clone()).await;

        let got = mgr.get_peer_ids(&1).await;
        assert_eq!(got, Some(peers));
    }

    #[tokio::test]
    async fn test_pending_share_waiting_for_commitment_is_drained_once() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(3, make_node(1), 3, |_| {}).await;

        let share = DistributedShare {
            from_id: 2,
            to_id: 1,
            value: Fr::from(42u64),
            nonce: [7u8; 16],
            session_id: 3,
        };

        assert_eq!(
            mgr.store_pending_share_waiting_for_commitment(&3, share.clone(), None)
                .await,
            Some(true)
        );
        assert_eq!(
            mgr.store_pending_share_waiting_for_commitment(&3, share, None)
                .await,
            Some(false),
            "a duplicate early share from the same sender should not replace the first"
        );

        let drained = mgr
            .take_pending_share_waiting_for_commitment(&3, 2)
            .await
            .expect("pending share should be present");
        assert_eq!(drained.share.from_id, 2);
        assert_eq!(drained.share.to_id, 1);
        assert!(
            mgr.take_pending_share_waiting_for_commitment(&3, 2)
                .await
                .is_none(),
            "pending share should only drain once"
        );
    }

    #[tokio::test]
    async fn test_commitment_hash_recording_detects_duplicates_and_mismatches() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(33, make_node(1), 3, |_| {}).await;

        assert_eq!(
            mgr.record_commitment_hash(&33, 2, [1; 32]).await,
            Some(CommitmentHashRecordOutcome::Recorded)
        );
        assert_eq!(mgr.get_commitment_hash(&33, 2).await, Some([1; 32]));
        assert_eq!(
            mgr.record_commitment_hash(&33, 2, [1; 32]).await,
            Some(CommitmentHashRecordOutcome::DuplicateSame)
        );
        assert_eq!(
            mgr.record_commitment_hash(&33, 2, [2; 32]).await,
            Some(CommitmentHashRecordOutcome::Mismatch { existing: [1; 32] })
        );
    }

    fn signed_commitment(
        dealer_id: u32,
        commitment: Vec<u8>,
        session_nonce: [u8; 16],
    ) -> SignedDkgCommitment {
        use crate::reporting::v0::types::{
            CommitteeScope as ReportingCommitteeScope, DkgCommitmentStatement,
            DKG_COMMITMENT_DOMAIN,
        };
        SignedDkgCommitment {
            statement: DkgCommitmentStatement {
                domain: DKG_COMMITMENT_DOMAIN.to_string(),
                chain_id: "chain".to_string(),
                ring_id: "ring".to_string(),
                ring_pk: "ring-pk".to_string(),
                ring_state_sha256: "00".repeat(32),
                protocol_version: 0,
                request_id: "1".to_string(),
                signed_at: 100,
                responder_node_key: format!("dealer-{dealer_id}"),
                origin_protocol: "pss_reshare".to_string(),
                accused_committee_scope: ReportingCommitteeScope::Current,
                signing_committee_scope: ReportingCommitteeScope::Current,
                from_node_id: dealer_id,
                commitment,
                session_nonce,
                crypto_backend: "dkg/test".to_string(),
            },
            signature: vec![0; 64],
        }
    }

    #[tokio::test]
    async fn missing_dealer_peer_ids_reports_silent_refresh_dealers() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        // Own node_id = 1 in a 3-member refresh committee.
        mgr.create_session(80, make_node(1), 3, |_| {}).await;
        mgr.set_session_kind(
            &80,
            SessionKind::Refresh {
                ring_pk_hex: "rk".to_string(),
            },
        )
        .await;
        mgr.set_peer_node_keys(&80, vec!["k1".into(), "k2".into(), "k3".into()])
            .await;
        mgr.set_node_peer_mappings(
            &80,
            HashMap::from([
                (1, "peer1".to_string()),
                (2, "peer2".to_string()),
                (3, "peer3".to_string()),
            ]),
        )
        .await;

        // Only node 2's commitment arrived; node 3 stayed silent (node 1 is self).
        mgr.store_received_commitment(&80, 2, signed_commitment(2, vec![1, 2, 3], [0u8; 16]))
            .await;
        let missing = mgr
            .with_state(&80, |s| {
                s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
            })
            .await
            .unwrap();
        assert_eq!(missing, vec!["peer3".to_string()]);

        // Once node 3's commitment also arrives, nothing is attributed.
        mgr.store_received_commitment(&80, 3, signed_commitment(3, vec![4, 5, 6], [0u8; 16]))
            .await;
        let missing = mgr
            .with_state(&80, |s| {
                s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
            })
            .await
            .unwrap();
        assert!(missing.is_empty(), "no dealer is silent once all commit");
    }

    #[tokio::test]
    async fn missing_dealer_peer_ids_reports_silent_phase2_share_dealers() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        // Own node_id = 1 in a 3-member refresh committee.
        mgr.create_session(82, make_node(1), 3, |_| {}).await;
        mgr.set_session_kind(
            &82,
            SessionKind::Refresh {
                ring_pk_hex: "rk".to_string(),
            },
        )
        .await;
        mgr.set_peer_node_keys(&82, vec!["k1".into(), "k2".into(), "k3".into()])
            .await;
        mgr.set_node_peer_mappings(
            &82,
            HashMap::from([
                (1, "peer1".to_string()),
                (2, "peer2".to_string()),
                (3, "peer3".to_string()),
            ]),
        )
        .await;

        // Both dealers committed, so a commitment stall would not accuse either peer.
        mgr.store_received_commitment(&82, 2, signed_commitment(2, vec![1, 2, 3], [0u8; 16]))
            .await;
        mgr.store_received_commitment(&82, 3, signed_commitment(3, vec![4, 5, 6], [0u8; 16]))
            .await;
        let missing_commitments = mgr
            .with_state(&82, |s| {
                s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
            })
            .await
            .unwrap();
        assert!(
            missing_commitments.is_empty(),
            "commitment tracking should not accuse a dealer that committed"
        );

        // Node 2's share was accepted; node 3 committed but never sent its Phase 2 share.
        mgr.record_received_share(&82, 2).await;
        let missing_shares = mgr
            .with_state(&82, |s| s.missing_dealer_peer_ids(DkgPhase::Phase2Shares))
            .await
            .unwrap();
        assert_eq!(missing_shares, vec!["peer3".to_string()]);
    }

    #[tokio::test]
    async fn missing_dealer_peer_ids_empty_for_fresh_dkg() {
        // Fresh DKG has no finalized ring to anchor an offline report against, so even a
        // session missing every peer's commitment must not attribute anyone.
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(81, make_node(1), 3, |_| {}).await; // default kind = Fresh
        mgr.set_peer_node_keys(&81, vec!["k1".into(), "k2".into(), "k3".into()])
            .await;
        mgr.set_node_peer_mappings(
            &81,
            HashMap::from([
                (1, "peer1".to_string()),
                (2, "peer2".to_string()),
                (3, "peer3".to_string()),
            ]),
        )
        .await;

        let missing = mgr
            .with_state(&81, |s| {
                s.missing_dealer_peer_ids(DkgPhase::Phase1Commitments)
            })
            .await
            .unwrap();
        assert!(
            missing.is_empty(),
            "fresh DKG must not produce offline attribution"
        );
    }

    #[tokio::test]
    async fn test_find_conflicting_commitment_pair() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(50, make_node(1), 3, |_| {}).await;

        let nonce_a = [1u8; 16];
        mgr.store_received_commitment(&50, 2, signed_commitment(2, vec![1, 2, 3], nonce_a))
            .await;
        mgr.store_received_commitment(&50, 3, signed_commitment(3, vec![4, 5, 6], nonce_a))
            .await;

        // A reveal matching what we stored → no conflict.
        let matching_reveal = [signed_commitment(2, vec![1, 2, 3], nonce_a)];
        assert_eq!(
            mgr.find_conflicting_commitment_pair(&50, &matching_reveal)
                .await
                .map(|(dealer_id, _, _)| dealer_id),
            None
        );
        // A reveal for a dealer we never received from → ignored.
        let unknown_dealer_reveal = [signed_commitment(9, vec![9, 9], nonce_a)];
        assert_eq!(
            mgr.find_conflicting_commitment_pair(&50, &unknown_dealer_reveal)
                .await
                .map(|(dealer_id, _, _)| dealer_id),
            None
        );
        // Different bytes but a DIFFERENT nonce → honest retry, NOT equivocation (not framed).
        let retry_reveal = [signed_commitment(2, vec![7, 7, 7], [2u8; 16])];
        assert_eq!(
            mgr.find_conflicting_commitment_pair(&50, &retry_reveal)
                .await
                .map(|(dealer_id, _, _)| dealer_id),
            None
        );
        // Different bytes with the SAME nonce for dealer 2 → equivocation; returns the pair.
        let conflicting_reveal = [signed_commitment(2, vec![7, 7, 7], nonce_a)];
        let (dealer_id, ours, reveal) = mgr
            .find_conflicting_commitment_pair(&50, &conflicting_reveal)
            .await
            .expect("equivocation detected");
        assert_eq!(dealer_id, 2);
        assert_eq!(ours.statement.commitment, vec![1, 2, 3]);
        assert_eq!(reveal.statement.commitment, vec![7, 7, 7]);
    }

    #[tokio::test]
    async fn test_pending_commitment_waiting_for_hash_is_drained_once() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(34, make_node(1), 3, |_| {}).await;

        assert_eq!(
            mgr.store_pending_commitment_waiting_for_hash(&34, 2, vec![1, 2, 3], None)
                .await,
            Some(true)
        );
        assert_eq!(
            mgr.store_pending_commitment_waiting_for_hash(&34, 2, vec![4, 5, 6], None)
                .await,
            Some(false),
            "a duplicate early commitment from the same sender should not replace the first"
        );

        let drained = mgr
            .take_pending_commitment_waiting_for_hash(&34, 2)
            .await
            .expect("pending commitment should be present");
        assert_eq!(drained.commitment, vec![1, 2, 3]);
        assert!(
            mgr.take_pending_commitment_waiting_for_hash(&34, 2)
                .await
                .is_none(),
            "pending commitment should only drain once"
        );
    }

    #[tokio::test]
    async fn test_pending_refresh_health_check_result_is_drained_once() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(4, make_node(1), 3, |_| {}).await;

        let result = PendingRefreshHealthCheckResult {
            from_node_id: 1,
            statement: RefreshHealthCheckStatement {
                domain: "health-check".to_string(),
                session_id: 4,
                ring_pk: "ring".to_string(),
                public_polynomial_sha256: "poly".to_string(),
                peer_node_keys_sha256: "peers".to_string(),
                threshold: 2,
                total_participants: 3,
            },
            signature: None,
        };

        assert_eq!(
            mgr.store_pending_refresh_health_check_result(&4, result.clone())
                .await,
            Some(true)
        );
        assert_eq!(
            mgr.store_pending_refresh_health_check_result(&4, result)
                .await,
            Some(false),
            "a duplicate early health-check result should not replace the first"
        );

        let drained = mgr
            .take_pending_refresh_health_check_result(&4)
            .await
            .expect("pending health-check result should be present");
        assert_eq!(drained.from_node_id, 1);
        assert_eq!(drained.statement.session_id, 4);
        assert!(
            mgr.take_pending_refresh_health_check_result(&4)
                .await
                .is_none(),
            "pending health-check result should only drain once"
        );
    }

    #[tokio::test]
    async fn test_create_session_can_publish_routing_maps_atomically() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(5, make_node(1), 3, |state| {
            state.routing.peer_ids = vec!["old-a".to_string(), "old-b".to_string()];
            state.routing.peer_node_keys = vec!["node-a".to_string(), "node-b".to_string()];
            state.routing.ring_id = "ring-id".to_string();
            state.pss_interval = 60;

            state.routing.node_id_to_peer_id =
                HashMap::from([(1, "old-a".to_string()), (2, "old-b".to_string())]);
            state.routing.peer_id_to_node_id =
                HashMap::from([("old-a".to_string(), 1), ("old-b".to_string(), 2)]);
            state.routing.reshare_new_node_id_to_peer_id =
                HashMap::from([(1, "new-a".to_string()), (2, "new-b".to_string())]);
            state.routing.reshare_new_peer_id_to_node_id =
                HashMap::from([("new-a".to_string(), 1), ("new-b".to_string(), 2)]);
        })
        .await;

        let snapshot = mgr
            .with_state(&5, |state| {
                (
                    state.routing.peer_ids.clone(),
                    state.routing.peer_node_keys.clone(),
                    state.routing.ring_id.clone(),
                    state.pss_interval,
                    state.routing.node_id_to_peer_id.clone(),
                    state.routing.peer_id_to_node_id.clone(),
                    state.routing.reshare_new_node_id_to_peer_id.clone(),
                    state.routing.reshare_new_peer_id_to_node_id.clone(),
                )
            })
            .await
            .expect("session should exist");

        assert_eq!(snapshot.0, vec!["old-a", "old-b"]);
        assert_eq!(snapshot.1, vec!["node-a", "node-b"]);
        assert_eq!(snapshot.2, "ring-id");
        assert_eq!(snapshot.3, 60);
        assert_eq!(snapshot.4.get(&2), Some(&"old-b".to_string()));
        assert_eq!(snapshot.5.get("old-a"), Some(&1));
        assert_eq!(snapshot.6.get(&1), Some(&"new-a".to_string()));
        assert_eq!(snapshot.7.get("new-b"), Some(&2));
    }

    // =========================================================================
    // Concurrent access
    // =========================================================================

    #[tokio::test]
    async fn test_concurrent_create_same_id() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        let m1 = mgr.clone();
        let m2 = mgr.clone();
        let node1 = make_node(1);
        let node2 = make_node(2);

        let (r1, r2) = tokio::join!(
            async move { m1.create_session(42, node1, 3, |_| {}).await },
            async move { m2.create_session(42, node2, 3, |_| {}).await },
        );

        // The RwLock serialises the two writes; exactly one must win
        assert_ne!(r1, r2, "exactly one concurrent create should succeed");
        assert_eq!(mgr.session_count().await, 1);
    }

    // =========================================================================
    // Expiration worker    // =========================================================================
    // Expiration worker
    // =========================================================================

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_sessions_at_hard_deadline() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(20, make_node(1), 3, |_| {}).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&20) {
                s.transport.hard_deadline = Some(Instant::now());
            }
        }

        // Drive the tokio interval timer past the expiration check interval
        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&20).await,
            "session at its hard deadline should be removed by the expiration worker"
        );
    }

    #[tokio::test]
    async fn private_retransmission_keeps_exact_cached_bytes() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(21, make_node(1), 3, |_| {}).await;
        let attempt = crate::dkg::v0::transport::AttemptId([7; 32]);
        {
            let mut states = mgr.states.write().await;
            let state = states.get_mut(&21).expect("session");
            state.transport.attempt_id = Some(attempt);
        }
        let message_id = crate::dkg::v0::transport::MessageId([9; 32]);
        let exact = vec![1, 2, 3, 4, 5];
        assert_eq!(
            mgr.cache_private_message(&21, message_id, exact.clone())
                .await,
            Some(true)
        );
        assert_eq!(
            mgr.cache_private_message(&21, message_id, exact.clone())
                .await,
            Some(true),
            "an identical reconnect must reuse the retained bytes"
        );
        assert_eq!(
            mgr.cache_private_message(&21, message_id, vec![5, 4, 3, 2, 1])
                .await,
            Some(false),
            "the same message ID must reject regenerated or conflicting bytes"
        );
        assert_eq!(mgr.private_message(&21, message_id).await, Some(exact));
    }

    #[tokio::test]
    async fn public_duplicates_are_idempotent_and_conflicts_are_rejected() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(22, make_node(1), 3, |_| {}).await;
        let attempt = crate::dkg::v0::transport::AttemptId([7; 32]);
        {
            let mut states = mgr.states.write().await;
            states.get_mut(&22).expect("session").transport.attempt_id = Some(attempt);
        }
        let phase = crate::dkg::v0::transport::PublicPhase::Commitments;
        let origin = crate::dkg::v0::transport::ParticipantRef::current(2);
        let exact = network::SignedPayload {
            origin: vec![1; 32],
            signature: vec![2; 64],
            data: vec![3; 16],
        };
        assert_eq!(
            mgr.record_public_contribution(&22, attempt, phase, origin, exact.clone())
                .await,
            PublicContributionRecordOutcome::Recorded
        );
        assert_eq!(
            mgr.record_public_contribution(&22, attempt, phase, origin, exact.clone())
                .await,
            PublicContributionRecordOutcome::DuplicateSame
        );
        let mut conflicting = exact.clone();
        conflicting.data[0] ^= 1;
        assert_eq!(
            mgr.record_public_contribution(&22, attempt, phase, origin, conflicting)
                .await,
            PublicContributionRecordOutcome::ConflictingDuplicate
        );
        assert_eq!(
            mgr.public_contributions(&22, attempt, phase)
                .await
                .expect("attempt")
                .get(&origin),
            Some(&exact)
        );
        assert_eq!(
            mgr.record_public_contribution(
                &22,
                crate::dkg::v0::transport::AttemptId([8; 32]),
                phase,
                crate::dkg::v0::transport::ParticipantRef::current(3),
                exact,
            )
            .await,
            PublicContributionRecordOutcome::ConflictingDuplicate,
            "a stale attempt cannot populate the active attempt"
        );
    }

    #[tokio::test]
    async fn topology_acknowledgements_are_scoped_and_idempotent() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(23, make_node(1), 3, |_| {}).await;
        let ceremony = crate::dkg::v0::transport::CeremonyId(23);
        let attempt = crate::dkg::v0::transport::AttemptId([7; 32]);
        let nonce = [9; 32];
        {
            let mut states = mgr.states.write().await;
            let transport = &mut states.get_mut(&23).expect("session").transport;
            transport.ceremony_id = Some(ceremony);
            transport.attempt_id = Some(attempt);
        }

        mgr.begin_topology_probe(&23, attempt, nonce, "leader".into())
            .await
            .expect("probe state");
        assert_eq!(
            mgr.record_topology_probe_ack(&23, attempt, nonce, "peer-a".into())
                .await,
            TopologyAckRecordOutcome::Recorded
        );
        assert_eq!(
            mgr.record_topology_probe_ack(&23, attempt, nonce, "peer-a".into())
                .await,
            TopologyAckRecordOutcome::Duplicate
        );
        assert_eq!(
            mgr.record_topology_probe_ack(&23, attempt, [8; 32], "peer-b".into())
                .await,
            TopologyAckRecordOutcome::WrongNonce
        );
        assert_eq!(
            mgr.record_topology_probe_ack(
                &23,
                crate::dkg::v0::transport::AttemptId([6; 32]),
                nonce,
                "peer-b".into(),
            )
            .await,
            TopologyAckRecordOutcome::StaleAttempt
        );
        assert_eq!(
            mgr.topology_probe_acknowledgements(&23, attempt, nonce)
                .await
                .expect("ack set"),
            BTreeSet::from(["leader".to_string(), "peer-a".to_string()])
        );
    }

    #[tokio::test]
    async fn activation_and_begin_are_idempotent_and_gate_stall_repair() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(24, make_node(1), 3, |_| {}).await;
        let attempt = crate::dkg::v0::transport::AttemptId([4; 32]);
        {
            let mut states = mgr.states.write().await;
            states.get_mut(&24).expect("session").transport.attempt_id = Some(attempt);
        }

        assert!(
            !mgr.transport_repair_due(&24, attempt, crate::constants::DKG_REPAIR_STALL_INTERVAL)
                .await
        );
        assert_eq!(
            mgr.begin_transport(&24, attempt, [8; 32]).await,
            TransportBeginOutcome::NotActivated
        );
        assert_eq!(
            mgr.activate_transport(&24, attempt, [8; 32], Vec::new())
                .await,
            TransportActivationOutcome::Activated
        );
        assert_eq!(
            mgr.activate_transport(&24, attempt, [8; 32], Vec::new())
                .await,
            TransportActivationOutcome::AlreadyActivated
        );
        assert_eq!(
            mgr.begin_transport(&24, attempt, [9; 32]).await,
            TransportBeginOutcome::StaleAttempt
        );
        assert_eq!(
            mgr.begin_transport(&24, attempt, [8; 32]).await,
            TransportBeginOutcome::Begun
        );
        assert_eq!(
            mgr.begin_transport(&24, attempt, [8; 32]).await,
            TransportBeginOutcome::AlreadyBegun
        );
        assert_eq!(
            mgr.begin_transport(&24, crate::dkg::v0::transport::AttemptId([5; 32]), [8; 32],)
                .await,
            TransportBeginOutcome::StaleAttempt
        );
        assert!(
            !mgr.transport_repair_due(&24, attempt, crate::constants::DKG_REPAIR_STALL_INTERVAL)
                .await
        );

        {
            let mut states = mgr.states.write().await;
            states
                .get_mut(&24)
                .expect("session")
                .transport
                .last_progress_at = Instant::now() - crate::constants::DKG_REPAIR_STALL_INTERVAL;
        }
        assert!(
            mgr.transport_repair_due(&24, attempt, crate::constants::DKG_REPAIR_STALL_INTERVAL)
                .await
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_attempt_at_hard_deadline() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(30, make_node(1), 3, |_| {}).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&30) {
                s.phase = DkgPhase::Phase1Commitments;
                s.transport.hard_deadline = Some(Instant::now());
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&30).await,
            "session at the attempt hard deadline should be removed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_preserves_attempt_before_hard_deadline() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(31, make_node(1), 3, |_| {}).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&31) {
                assert_eq!(s.phase, DkgPhase::Initializing);
                s.phase_started_at = Instant::now()
                    - (crate::constants::DKG_PREPARATION_TIMEOUT
                        + std::time::Duration::from_secs(10));
                s.transport.hard_deadline = Some(Instant::now() + DKG_ATTEMPT_TIMEOUT);
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            mgr.session_exists(&31).await,
            "phase age must not override the attempt hard deadline"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_keeps_recent_completed_sessions() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(40, make_node(1), 3, |_| {}).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&40) {
                s.phase = DkgPhase::Phase4Complete;
                s.phase_started_at = Instant::now()
                    - (DKG_COMPLETED_SESSION_TTL - std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            mgr.session_exists(&40).await,
            "recent Phase4Complete sessions should retain their cleanup grace period"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_completed_sessions_past_ttl() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        let ready_key = ReshareSignatureReadyKey {
            ring_key: "ring_complete".to_string(),
            session_id: 42,
            ring_id: "post".to_string(),
            current_ring_sha256: "current".to_string(),
            finalized_ring_sha256: "updated".to_string(),
        };

        mgr.create_session(42, make_node(1), 3, |_| {}).await;
        mgr.set_session_kind(
            &42,
            SessionKind::Reshare {
                ring_pk_hex: "ring_complete".to_string(),
                new_peer_node_keys: vec!["node".to_string()],
                new_threshold: 1,
                bulletin_post_id: "post".to_string(),
            },
        )
        .await;
        assert_eq!(
            mgr.claim_ring_pss_session("ring_complete", 42).await,
            RingPssClaimOutcome::Claimed
        );
        mgr.mark_reshare_signature_ready(ready_key.clone()).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&42) {
                s.phase = DkgPhase::Phase4Complete;
                s.phase_started_at = Instant::now()
                    - (DKG_COMPLETED_SESSION_TTL + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&42).await,
            "Phase4Complete sessions must be removed after their maximum TTL"
        );
        assert_eq!(
            mgr.claim_ring_pss_session("ring_complete", 43).await,
            RingPssClaimOutcome::Claimed,
            "completed-session expiration must release the PSS claim"
        );
        assert!(
            !mgr.is_reshare_signature_ready(&ready_key).await,
            "completed-session expiration must remove readiness markers"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_phase4_at_attempt_hard_deadline() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(41, make_node(1), 3, |_| {}).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&41) {
                s.phase = DkgPhase::Phase4Completing;
                s.transport.hard_deadline = Some(Instant::now());
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&41).await,
            "Phase4Completing sessions must not outlive the attempt hard deadline"
        );
    }

    // =========================================================================
    // rings_pss: claim / unmark
    // =========================================================================

    #[tokio::test]
    async fn test_claim_returns_claimed_first_call() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 11).await,
            RingPssClaimOutcome::Claimed,
            "first claim should succeed (ring not yet in progress)"
        );
    }

    #[tokio::test]
    async fn test_claim_returns_same_session_for_duplicate() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 11).await,
            RingPssClaimOutcome::Claimed
        );
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 11).await,
            RingPssClaimOutcome::AlreadyClaimedBySameSession,
            "duplicate claim for same session should be idempotent"
        );
    }

    #[tokio::test]
    async fn test_claim_returns_conflict_for_different_session() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 11).await,
            RingPssClaimOutcome::Claimed
        );
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 22).await,
            RingPssClaimOutcome::Conflict {
                active_session_id: 11
            },
            "different session should conflict"
        );
        assert_eq!(
            mgr.claim_ring_pss_session("ring_xyz", 22).await,
            RingPssClaimOutcome::Claimed,
            "different ring should be claimable independently"
        );
    }

    #[tokio::test]
    async fn test_unmark_if_matches_preserves_other_session() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 11).await,
            RingPssClaimOutcome::Claimed
        );
        mgr.unmark_ring_pss_if_matches("ring_abc", 22).await;
        assert_eq!(mgr.active_ring_pss_session("ring_abc").await, Some(11));
        mgr.unmark_ring_pss_if_matches("ring_abc", 11).await;
        assert_eq!(mgr.active_ring_pss_session("ring_abc").await, None);
        assert_eq!(
            mgr.claim_ring_pss_session("ring_abc", 33).await,
            RingPssClaimOutcome::Claimed,
            "after matching unmark the ring should be claimable again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_clears_ring_pss_flag() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());

        // Create a refresh session and mark the ring as in-progress (PSS).
        mgr.create_session(60, make_node(1), 3, |_| {}).await;
        mgr.set_session_kind(
            &60,
            SessionKind::Refresh {
                ring_pk_hex: "ring_expire".to_string(),
            },
        )
        .await;
        assert_eq!(
            mgr.claim_ring_pss_session("ring_expire", 60).await,
            RingPssClaimOutcome::Claimed
        );

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&60) {
                s.transport.hard_deadline = Some(Instant::now());
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&60).await,
            "expired session should be removed"
        );
        assert_eq!(
            mgr.claim_ring_pss_session("ring_expire", 61).await,
            RingPssClaimOutcome::Claimed,
            "rings_pss claim should be cleared after session expiration"
        );
    }

    // =========================================================================
    // TransportMessageClaimGuard
    // =========================================================================

    #[tokio::test]
    async fn transport_claim_guard_finish_marks_processed() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        let session_id = 100u128;
        mgr.create_session(session_id, make_node(1), 3, |_| {})
            .await;
        let message_id = crate::dkg::v0::transport::MessageId([1u8; 32]);

        assert_eq!(
            mgr.claim_transport_message(&session_id, message_id).await,
            MessageProcessingClaim::Claimed
        );
        let guard = TransportMessageClaimGuard::new(mgr.clone(), session_id, message_id);
        guard.finish(true).await;

        assert_eq!(
            mgr.claim_transport_message(&session_id, message_id).await,
            MessageProcessingClaim::AlreadyProcessed,
            "finish(true) should mark the message processed, not just release the claim"
        );
    }

    #[tokio::test]
    async fn transport_claim_guard_releases_claim_when_dropped_without_finish() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        let session_id = 101u128;
        mgr.create_session(session_id, make_node(1), 3, |_| {})
            .await;
        let message_id = crate::dkg::v0::transport::MessageId([2u8; 32]);

        assert_eq!(
            mgr.claim_transport_message(&session_id, message_id).await,
            MessageProcessingClaim::Claimed
        );
        // A concurrent retry of the exact same message sees it as in-flight.
        assert_eq!(
            mgr.claim_transport_message(&session_id, message_id).await,
            MessageProcessingClaim::AlreadyProcessing
        );

        // Simulate the future driving processing being cancelled (e.g. by an
        // outer `tokio::time::timeout`) after the claim succeeded but before
        // `finish` ran: build the guard and drop it without calling `finish`.
        let guard = TransportMessageClaimGuard::new(mgr.clone(), session_id, message_id);
        drop(guard);

        // `Drop` releases the claim via a spawned task rather than
        // synchronously; poll until it lands instead of assuming one yield
        // is enough.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if mgr.claim_transport_message(&session_id, message_id).await
                    == MessageProcessingClaim::Claimed
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect(
            "a dropped guard must release the claim as failed, not leave the message \
             stuck in AlreadyProcessing for the rest of the attempt",
        );
    }
}
