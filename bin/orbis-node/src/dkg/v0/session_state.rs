//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, peer information, and the cryptographic DKG node state.
//!
//! `DkgSessionState` combines both the protocol state (phase tracking, connections,
//! message deduplication) and the cryptographic state (the DKG node itself) into
//! a single unified structure.

use crate::constants::{
    DKG_COMPLETED_SESSION_TTL, DKG_PHASE4_COMPLETION_TIMEOUT, DKG_PHASE_TIMEOUT, MAX_DKG_SESSIONS,
    SESSION_EXPIRATION_CHECK_INTERVAL, SESSION_TTL,
};
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment, SignedDkgShare};
use crate::metrics;
use crate::ring_state::RingShareBundle;
use crate::sign::v0::messages::RefreshHealthCheckStatement;
use crypto::r#trait::{DistributedShare, Dkg, DkgMode};
use network::Connection;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

/// DKG Protocol Phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgPhase {
    /// Initialization - session created, waiting to start
    Initializing,
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

/// DKG Message Type for deduplication (more efficient than String)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DkgMessageType {
    Commitment,
    Share,
    DkgInvalidShareEvidence,
    ReshareShareAck,
    ReshareParticipantSet,
    RefreshHealthCheckResult,
    Complaint,
    SessionInit,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageProcessingClaim {
    Claimed,
    AlreadyProcessed,
    AlreadyProcessing,
    MissingSession,
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

pub(crate) struct MessageTrackingState<ShareValue: Zeroize> {
    pub pending_shares_waiting_for_commitment: HashMap<u32, PendingDkgShare<ShareValue>>,
    pub processed: HashSet<(u128, u32, DkgMessageType)>,
    pub processing: HashSet<(u128, u32, DkgMessageType)>,
}

impl<ShareValue: Zeroize> Default for MessageTrackingState<ShareValue> {
    fn default() -> Self {
        Self {
            pending_shares_waiting_for_commitment: HashMap::new(),
            processed: HashSet::new(),
            processing: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PendingDkgShare<ShareValue: Zeroize> {
    pub share: DistributedShare<ShareValue>,
    pub report_evidence: Option<SignedDkgShare>,
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

#[derive(Default)]
pub(crate) struct SessionTransportState {
    pub peer_streams: HashMap<String, Arc<dyn Connection>>,
    pub peer_send_locks: HashMap<String, Arc<Mutex<()>>>,
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
    /// Monotonic generation assigned when this session state instance is created.
    ///
    /// Lets callers distinguish a stale removed session from a newer session that
    /// reused the same externally-visible `session_id`.
    pub generation: u64,

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
    /// Message ordering and deduplication state.
    pub(crate) messages: MessageTrackingState<D::ShareValue>,
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
    /// Per-session network streams and send serialization.
    pub(crate) transport: SessionTransportState,
    /// Owns active metrics for exactly the lifetime of this ceremony.
    metrics_guard: Option<metrics::DkgSessionMetricsGuard>,
}

impl<D: Dkg> DkgSessionState<D> {
    /// Create a new DKG session state with the given DKG node
    pub fn new(node: D, _total_participants: usize, generation: u64) -> Self {
        Self {
            generation,
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
            messages: MessageTrackingState::default(),
            local_signed_commitment: None,
            report_evidence_binding: None,
            kind: SessionKind::Fresh,
            pss_interval: 0,
            policy_id: None,
            refresh: RefreshSessionState::default(),
            transport: SessionTransportState::default(),
            metrics_guard: None,
        }
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

/// Guard that automatically cleans up a DKG session on drop unless defused.
///
/// This implements the RAII pattern for session cleanup. Create a guard when
/// starting a session operation, and call `defuse()` when the operation completes
/// successfully. If the guard is dropped without being defused (e.g., due to an
/// early return or error), it will automatically queue the session for cleanup.
///
/// # Example
/// ```ignore
/// let guard = state_manager.cleanup_guard(session_id);
/// // ... do work that might fail ...
/// guard.defuse(); // Session completed successfully, don't clean up
/// ```
pub struct SessionCleanupGuard {
    cleanup_tx: mpsc::UnboundedSender<u128>,
    session_id: u128,
    defused: Arc<AtomicBool>,
}

impl SessionCleanupGuard {
    fn new(cleanup_tx: mpsc::UnboundedSender<u128>, session_id: u128) -> Self {
        Self {
            cleanup_tx,
            session_id,
            defused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Prevent cleanup from running when the guard is dropped.
    /// Call this when the session completes successfully.
    pub fn defuse(self) {
        self.defused.store(true, Ordering::SeqCst);
    }
}

impl Drop for SessionCleanupGuard {
    fn drop(&mut self) {
        if !self.defused.load(Ordering::SeqCst) {
            // Queue cleanup - the background task will handle it
            if self.cleanup_tx.send(self.session_id).is_err() {
                tracing::warn!(
                    session_id = self.session_id,
                    "SessionCleanupGuard: Failed to queue session cleanup (receiver dropped)"
                );
            } else {
                tracing::debug!(
                    session_id = self.session_id,
                    "SessionCleanupGuard: Queued session for cleanup on error path"
                );
            }
        }
    }
}

/// Global session state manager
pub struct SessionStateManager<D: Dkg> {
    /// session_id -> session state
    pub(crate) states: Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
    /// Channel for queueing session cleanup requests
    cleanup_tx: mpsc::UnboundedSender<u128>,
    /// Monotonic counter used to stamp each newly created in-memory session state.
    next_session_generation: AtomicU64,
    /// Ring public key strings mapped to their active in-progress PSS ceremony
    /// session IDs. Cleared on Phase 4 success or session cleanup/expiration so
    /// that a new ceremony can be initiated after failure.
    rings_pss: Arc<RwLock<HashMap<String, u128>>>,
    /// Exact reshare bulletin updates this node is ready to sign.
    reshare_signature_ready: Arc<RwLock<HashSet<ReshareSignatureReadyKey>>>,
    shutdown_tx: watch::Sender<bool>,
    background_tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Create a new SessionStateManager and spawn background tasks
    pub fn new() -> Self {
        let (cleanup_tx, cleanup_rx) = mpsc::unbounded_channel();
        let states = Arc::new(RwLock::new(HashMap::new()));
        let rings_pss = Arc::new(RwLock::new(HashMap::new()));
        let reshare_signature_ready = Arc::new(RwLock::new(HashSet::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut background_tasks = Vec::new();

        // Spawn background cleanup task (handles guard-triggered cleanup)
        let states_clone = states.clone();
        let pss_clone = rings_pss.clone();
        let ready_clone = reshare_signature_ready.clone();
        let cleanup_shutdown = shutdown_rx.clone();
        background_tasks.push(tokio::spawn(async move {
            Self::cleanup_worker(
                states_clone,
                cleanup_rx,
                pss_clone,
                ready_clone,
                cleanup_shutdown,
            )
            .await;
        }));

        // Spawn background expiration task (handles abandoned sessions)
        let states_clone = states.clone();
        let pss_clone = rings_pss.clone();
        let ready_clone = reshare_signature_ready.clone();
        background_tasks.push(tokio::spawn(async move {
            Self::expiration_worker(states_clone, pss_clone, ready_clone, shutdown_rx).await;
        }));

        Self {
            states,
            cleanup_tx,
            next_session_generation: AtomicU64::new(1),
            rings_pss,
            reshare_signature_ready,
            shutdown_tx,
            background_tasks: StdMutex::new(background_tasks),
        }
    }

    /// Background task that processes cleanup requests from guards
    async fn cleanup_worker(
        states: Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
        mut rx: mpsc::UnboundedReceiver<u128>,
        rings_pss: Arc<RwLock<HashMap<String, u128>>>,
        reshare_signature_ready: Arc<RwLock<HashSet<ReshareSignatureReadyKey>>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        loop {
            let session_id = tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                session_id = rx.recv() => {
                    let Some(session_id) = session_id else {
                        break;
                    };
                    session_id
                }
            };
            let mut states = states.write().await;
            if let Some(mut state) = states.remove(&session_id) {
                if let Some(guard) = state.metrics_guard.take() {
                    guard.abandon();
                }
                // If this was a refresh or reshare session, unblock the ring.
                if let Some(ring_key) = state.kind.ring_key() {
                    let mut claims = rings_pss.write().await;
                    if claims.get(ring_key).copied() == Some(session_id) {
                        claims.remove(ring_key);
                        tracing::debug!(
                            session_id = session_id,
                            ring_key = %ring_key,
                            "SessionStateManager: Cleared in-progress PSS claim on cleanup"
                        );
                    }
                }
                reshare_signature_ready
                    .write()
                    .await
                    .retain(|k| k.session_id != session_id);
                tracing::debug!(
                    session_id = session_id,
                    "SessionStateManager: Cleaned up abandoned session"
                );
            }
        }
        tracing::debug!("SessionStateManager: Cleanup worker shutting down");
    }

    /// Background task that periodically removes expired sessions
    ///
    /// Active sessions older than `SESSION_TTL` and completed sessions retained
    /// longer than `DKG_COMPLETED_SESSION_TTL` are removed to prevent memory leaks.
    async fn expiration_worker(
        states: Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
        rings_pss: Arc<RwLock<HashMap<String, u128>>>,
        reshare_signature_ready: Arc<RwLock<HashSet<ReshareSignatureReadyKey>>>,
        mut shutdown_rx: watch::Receiver<bool>,
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
                let age = now.duration_since(state.created_at);
                if age > SESSION_TTL {
                    tracing::warn!(
                        session_id = session_id,
                        age_secs = age.as_secs(),
                        phase = ?state.phase,
                        "SessionStateManager: Removing expired DKG session"
                    );
                    to_remove_ids.push(*session_id);
                    continue;
                }
                let phase_timeout = match state.phase {
                    DkgPhase::Phase4Completing => DKG_PHASE4_COMPLETION_TIMEOUT,
                    _ => DKG_PHASE_TIMEOUT,
                };
                if phase_age > phase_timeout {
                    tracing::warn!(
                        session_id = session_id,
                        phase = ?state.phase,
                        phase_age_secs = phase_age.as_secs(),
                        "SessionStateManager: Removing DKG session stalled in phase"
                    );
                    to_remove_ids.push(*session_id);
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

    #[cfg(any(test, feature = "unsafe-testing"))]
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

    /// Create a cleanup guard for a session.
    ///
    /// The guard will automatically clean up the session when dropped unless
    /// `defuse()` is called. Use this to ensure sessions are cleaned up on
    /// error paths without manual cleanup code.
    pub fn cleanup_guard(&self, session_id: u128) -> SessionCleanupGuard {
        SessionCleanupGuard::new(self.cleanup_tx.clone(), session_id)
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

        let generation = self.next_session_generation.fetch_add(1, Ordering::SeqCst);
        let mut new_state = DkgSessionState::new(node, total_participants, generation);
        init_fn(&mut new_state);
        let ceremony_kind = match &new_state.kind {
            SessionKind::Fresh => metrics::DkgCeremonyKind::Fresh,
            SessionKind::Refresh { .. } => metrics::DkgCeremonyKind::Refresh,
            SessionKind::Reshare { .. } => metrics::DkgCeremonyKind::Reshare,
        };
        new_state.metrics_guard = Some(metrics::DkgSessionMetricsGuard::new(ceremony_kind));
        states.insert(session_id, new_state);
        CreateSessionOutcome::Created
    }

    /// Check if a session exists
    pub async fn session_exists(&self, session_id: &u128) -> bool {
        let states = self.states.read().await;
        states.contains_key(session_id)
    }

    pub async fn set_peer_ids(&self, session_id: &u128, peer_ids: Vec<String>) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.routing.peer_ids = peer_ids;
        }
    }

    pub async fn set_peer_node_keys(&self, session_id: &u128, peer_node_keys: Vec<String>) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.routing.peer_node_keys = peer_node_keys;
        }
    }

    pub async fn set_ring_id(&self, session_id: &u128, ring_id: String) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.routing.ring_id = ring_id;
        }
    }

    /// Stage a refresh bundle while waiting for the post-refresh health-check result.
    pub async fn set_refresh_health_check_candidate(
        &self,
        session_id: &u128,
        candidate: RefreshHealthCheckCandidate,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.refresh.candidate = Some(candidate);
        }
    }

    /// Load the staged refresh bundle, if this session still has one.
    pub async fn refresh_health_check_candidate(
        &self,
        session_id: &u128,
    ) -> Option<RefreshHealthCheckCandidate> {
        let states = self.states.read().await;
        states
            .get(session_id)
            .and_then(|state| state.refresh.candidate.clone())
    }

    /// Discard any staged refresh bundle for this session.
    pub async fn clear_refresh_health_check_candidate(&self, session_id: &u128) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.refresh.candidate = None;
        }
    }

    /// Store a refresh health-check result that arrived before Phase 4 staged its candidate.
    pub async fn store_pending_refresh_health_check_result(
        &self,
        session_id: &u128,
        result: PendingRefreshHealthCheckResult,
    ) -> Option<bool> {
        let mut states = self.states.write().await;
        let state = states.get_mut(session_id)?;
        if state.refresh.pending_result.is_some() {
            return Some(false);
        }
        state.refresh.pending_result = Some(result);
        Some(true)
    }

    /// Remove and return an early refresh health-check result, if one was queued.
    pub async fn take_pending_refresh_health_check_result(
        &self,
        session_id: &u128,
    ) -> Option<PendingRefreshHealthCheckResult> {
        let mut states = self.states.write().await;
        states.get_mut(session_id)?.refresh.pending_result.take()
    }

    /// Store the PSS refresh interval for this session so Phase 4 can persist it.
    pub async fn set_pss_interval(&self, session_id: &u128, interval: u64) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.pss_interval = interval;
        }
    }

    pub async fn get_peer_ids(&self, session_id: &u128) -> Option<Vec<String>> {
        let states = self.states.read().await;
        states.get(session_id).map(|s| s.routing.peer_ids.clone())
    }

    pub async fn get_peer_node_keys(&self, session_id: &u128) -> Option<Vec<String>> {
        let states = self.states.read().await;
        states
            .get(session_id)
            .map(|s| s.routing.peer_node_keys.clone())
    }

    pub async fn ring_id_for_session(&self, session_id: &u128) -> Option<String> {
        let states = self.states.read().await;
        states.get(session_id).map(|s| s.routing.ring_id.clone())
    }

    /// Set node_id to peer_id mappings for efficient routing
    pub async fn set_node_peer_mappings(
        &self,
        session_id: &u128,
        node_id_to_peer_id: HashMap<u32, String>,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            // Build both maps in a single pass to avoid cloning
            let mut node_to_peer = HashMap::new();
            let mut peer_to_node = HashMap::new();
            for (node_id, peer_id) in node_id_to_peer_id {
                node_to_peer.insert(node_id, peer_id.clone());
                peer_to_node.insert(peer_id, node_id);
            }
            state.routing.node_id_to_peer_id = node_to_peer;
            state.routing.peer_id_to_node_id = peer_to_node;
        }
    }

    /// Get peer_id for a node_id
    pub async fn get_peer_id_for_node(&self, session_id: &u128, node_id: u32) -> Option<String> {
        let states = self.states.read().await;
        states
            .get(session_id)?
            .routing
            .node_id_to_peer_id
            .get(&node_id)
            .cloned()
    }

    /// Atomically claim a message for processing.
    pub async fn try_claim_message_processing(
        &self,
        session_id: &u128,
        from_node_id: u32,
        message_type: DkgMessageType,
    ) -> MessageProcessingClaim {
        let mut states = self.states.write().await;
        let Some(state) = states.get_mut(session_id) else {
            return MessageProcessingClaim::MissingSession;
        };

        let key = (*session_id, from_node_id, message_type);
        if state.messages.processed.contains(&key) {
            return MessageProcessingClaim::AlreadyProcessed;
        }
        if !state.messages.processing.insert(key) {
            return MessageProcessingClaim::AlreadyProcessing;
        }
        MessageProcessingClaim::Claimed
    }

    /// Finish a previously claimed message, marking it processed only on success.
    pub async fn finish_message_processing(
        &self,
        session_id: &u128,
        from_node_id: u32,
        message_type: DkgMessageType,
        processed: bool,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            let key = (*session_id, from_node_id, message_type);
            state.messages.processing.remove(&key);
            if processed {
                state.messages.processed.insert(key);
            }
        }
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
        let mut states = self.states.write().await;
        let state = states.get_mut(session_id)?;
        let from_node_id = share.from_id;
        if state
            .messages
            .pending_shares_waiting_for_commitment
            .contains_key(&from_node_id)
        {
            return Some(false);
        }
        state.messages.pending_shares_waiting_for_commitment.insert(
            from_node_id,
            PendingDkgShare {
                share,
                report_evidence,
            },
        );
        Some(true)
    }

    /// Remove and return a pending share that was waiting on `from_node_id`'s commitment.
    pub async fn take_pending_share_waiting_for_commitment(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<PendingDkgShare<D::ShareValue>> {
        let mut states = self.states.write().await;
        states
            .get_mut(session_id)?
            .messages
            .pending_shares_waiting_for_commitment
            .remove(&from_node_id)
    }

    pub async fn update_phase(&self, session_id: &u128, phase: DkgPhase) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.phase = phase;
            state.phase_started_at = Instant::now();
        }
    }

    pub async fn increment_commitments(&self, session_id: &u128) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.commitments_received += 1;
        }
    }

    pub async fn increment_shares(&self, session_id: &u128) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.shares_received += 1;
        }
    }

    /// Get the cached outbound stream to a peer for this session, if one exists.
    pub async fn get_peer_stream(
        &self,
        session_id: &u128,
        peer_id: &str,
    ) -> Option<Arc<dyn Connection>> {
        let states = self.states.read().await;
        states
            .get(session_id)?
            .transport
            .peer_streams
            .get(peer_id)
            .cloned()
    }

    /// Cache an outbound stream to a peer for this session.
    pub async fn store_peer_stream(
        &self,
        session_id: &u128,
        peer_id: String,
        stream: Arc<dyn Connection>,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.transport.peer_streams.insert(peer_id, stream);
        }
    }

    /// Remove the cached outbound stream to a peer for this session, if any.
    pub async fn remove_peer_stream(&self, session_id: &u128, peer_id: &str) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.transport.peer_streams.remove(peer_id);
        }
    }

    /// Get or create the per-peer outbound send lock for this session.
    pub async fn get_or_create_peer_send_lock(
        &self,
        session_id: &u128,
        peer_id: &str,
    ) -> Option<(Arc<Mutex<()>>, u64)> {
        let mut states = self.states.write().await;
        let state = states.get_mut(session_id)?;
        let lock = state
            .transport
            .peer_send_locks
            .entry(peer_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        Some((lock, state.generation))
    }

    /// Remove a session and free its memory.
    ///
    /// Called after DKG Phase 4 completes. The session data is no longer needed
    /// since the private share is stored in local storage and ring info is on
    /// the bulletin.
    ///
    /// Per-session streams in `peer_streams` are dropped here (FIN sent on drop).
    /// Per-peer QUIC connections in `peer_connections` are NOT closed — they remain
    /// open in the pool for future sessions.
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
    pub async fn get_session_generation(&self, session_id: &u128) -> Option<u64> {
        let states = self.states.read().await;
        states.get(session_id).map(|s| s.generation)
    }

    pub async fn session_count(&self) -> usize {
        self.states.read().await.len()
    }

    pub async fn set_session_kind(&self, session_id: &u128, kind: SessionKind) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.kind = kind;
        }
    }

    pub async fn is_message_processed(
        &self,
        session_id: &u128,
        from_node_id: u32,
        message_type: DkgMessageType,
    ) -> bool {
        let states = self.states.read().await;
        if let Some(state) = states.get(session_id) {
            state
                .messages
                .processed
                .contains(&(*session_id, from_node_id, message_type))
        } else {
            false
        }
    }

    pub async fn mark_message_processed(
        &self,
        session_id: &u128,
        from_node_id: u32,
        message_type: DkgMessageType,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state
                .messages
                .processed
                .insert((*session_id, from_node_id, message_type));
        }
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

        // Capture a timestamp just before the update; monotonic time guarantees
        // phase_started_at set inside update_phase will be >= this value.
        let before_update = std::time::Instant::now();
        mgr.update_phase(&1, DkgPhase::Phase1Commitments).await;

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

    // =========================================================================
    // Message deduplication
    // =========================================================================

    #[tokio::test]
    async fn test_message_dedup() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3, |_| {}).await;

        // Not yet processed
        assert!(
            !mgr.is_message_processed(&1, 2, DkgMessageType::Commitment)
                .await
        );

        mgr.mark_message_processed(&1, 2, DkgMessageType::Commitment)
            .await;

        // Now processed
        assert!(
            mgr.is_message_processed(&1, 2, DkgMessageType::Commitment)
                .await
        );

        // Different type from same node — not processed
        assert!(!mgr.is_message_processed(&1, 2, DkgMessageType::Share).await);

        // Same type, different node — not processed
        assert!(
            !mgr.is_message_processed(&1, 3, DkgMessageType::Commitment)
                .await
        );
    }

    #[tokio::test]
    async fn test_message_processing_claim_blocks_concurrent_duplicate() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(2, make_node(1), 3, |_| {}).await;

        assert_eq!(
            mgr.try_claim_message_processing(&2, 3, DkgMessageType::Share)
                .await,
            MessageProcessingClaim::Claimed
        );
        assert_eq!(
            mgr.try_claim_message_processing(&2, 3, DkgMessageType::Share)
                .await,
            MessageProcessingClaim::AlreadyProcessing
        );

        mgr.finish_message_processing(&2, 3, DkgMessageType::Share, true)
            .await;
        assert_eq!(
            mgr.try_claim_message_processing(&2, 3, DkgMessageType::Share)
                .await,
            MessageProcessingClaim::AlreadyProcessed
        );
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
    // Cleanup guard (RAII)
    // =========================================================================

    #[tokio::test]
    async fn test_cleanup_guard_removes_session_on_drop() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(10, make_node(1), 3, |_| {}).await;
        assert!(mgr.session_exists(&10).await);

        {
            let _guard = mgr.cleanup_guard(10);
            // guard dropped here without defuse — queues cleanup
        }

        // Yield to let the cleanup worker receive from the channel and remove the session
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&10).await,
            "session should be removed after guard drop"
        );
    }

    #[tokio::test]
    async fn test_cleanup_guard_defuse_prevents_cleanup() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(11, make_node(1), 3, |_| {}).await;

        let guard = mgr.cleanup_guard(11);
        guard.defuse(); // signals success — no cleanup should happen

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            mgr.session_exists(&11).await,
            "session should still exist after defused guard"
        );
    }

    // =========================================================================
    // Expiration worker
    // =========================================================================

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_sessions_past_ttl() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(20, make_node(1), 3, |_| {}).await;

        // Backdate created_at past SESSION_TTL (std::time::Instant, not tokio time)
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&20) {
                s.created_at = Instant::now() - (SESSION_TTL + std::time::Duration::from_secs(10));
            }
        }

        // Drive the tokio interval timer past the expiration check interval
        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&20).await,
            "session past SESSION_TTL should be removed by the expiration worker"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_stalled_phase() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(30, make_node(1), 3, |_| {}).await;

        // Move to Phase1Commitments and backdate phase_started_at past DKG_PHASE_TIMEOUT
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&30) {
                s.phase = DkgPhase::Phase1Commitments;
                s.phase_started_at =
                    Instant::now() - (DKG_PHASE_TIMEOUT + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&30).await,
            "session stalled past DKG_PHASE_TIMEOUT should be removed"
        );
    }

    /// Regression test for bug where `Initializing` sessions were exempt from
    /// `DKG_PHASE_TIMEOUT` and could hold a `rings_pss` lock for up to SESSION_TTL
    /// (30 min) instead of DKG_PHASE_TIMEOUT (2 min).
    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_stalled_initializing_session() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(31, make_node(1), 3, |_| {}).await;

        // Session stays in Initializing; backdate phase_started_at past DKG_PHASE_TIMEOUT.
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&31) {
                assert_eq!(s.phase, DkgPhase::Initializing);
                s.phase_started_at =
                    Instant::now() - (DKG_PHASE_TIMEOUT + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&31).await,
            "Initializing session stalled past DKG_PHASE_TIMEOUT should be removed"
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
    async fn test_expiration_worker_removes_stalled_phase4_completing_session() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(41, make_node(1), 3, |_| {}).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&41) {
                s.phase = DkgPhase::Phase4Completing;
                s.phase_started_at = Instant::now()
                    - (crate::constants::DKG_PHASE4_COMPLETION_TIMEOUT
                        + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&41).await,
            "stalled Phase4Completing sessions should be removed by the expiration worker"
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

    #[tokio::test]
    async fn test_cleanup_guard_clears_ring_pss_flag() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());

        // Create a refresh session and mark the ring as in-progress (PSS).
        mgr.create_session(50, make_node(1), 3, |_| {}).await;
        mgr.set_session_kind(
            &50,
            SessionKind::Refresh {
                ring_pk_hex: "ring_cleanup".to_string(),
            },
        )
        .await;
        assert_eq!(
            mgr.claim_ring_pss_session("ring_cleanup", 50).await,
            RingPssClaimOutcome::Claimed,
            "ring should be claimable before any cleanup"
        );
        assert_eq!(
            mgr.claim_ring_pss_session("ring_cleanup", 50).await,
            RingPssClaimOutcome::AlreadyClaimedBySameSession,
            "same session should remain idempotent while in progress"
        );

        // Drop a cleanup guard without defusing — worker removes session + flag.
        {
            let _guard = mgr.cleanup_guard(50);
        }

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(
            mgr.claim_ring_pss_session("ring_cleanup", 51).await,
            RingPssClaimOutcome::Claimed,
            "rings_pss claim should be cleared after cleanup guard fires"
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

        // Backdate created_at past SESSION_TTL so the expiration worker evicts it.
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&60) {
                s.created_at = Instant::now() - (SESSION_TTL + std::time::Duration::from_secs(10));
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
}
