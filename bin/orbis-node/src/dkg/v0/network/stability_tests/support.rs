#[allow(unused_imports)]
use super::super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct ScriptedBroadcastTopic {
    pub(super) id: network::TopicId,
    pub(super) calls: AtomicUsize,
    pub(super) fail_on_calls: BTreeSet<usize>,
    pub(super) observed: tokio::sync::Mutex<Vec<Bytes>>,
}

impl ScriptedBroadcastTopic {
    pub(super) fn new(fail_on_calls: impl IntoIterator<Item = usize>) -> Self {
        Self {
            id: network::TopicId::new([42; 32]),
            calls: AtomicUsize::new(0),
            fail_on_calls: fail_on_calls.into_iter().collect(),
            observed: tokio::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Topic for ScriptedBroadcastTopic {
    fn id(&self) -> network::TopicId {
        self.id
    }

    async fn broadcast(&self, data: Bytes) -> network::Result<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.observed.lock().await.push(data);
        if self.fail_on_calls.contains(&call) {
            return Err(network::NetworkError::Connection(format!(
                "scripted broadcast failure on call {call}"
            )));
        }
        Ok(())
    }

    async fn recv(&self) -> network::Result<PubSubEvent> {
        std::future::pending().await
    }
}

pub(super) fn pending_reshare_ring() -> RingPayload {
    RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "authoritative-ring-key".to_string(),
        peer_node_keys: vec!["current-b".to_string(), "current-a".to_string()],
        new_peer_node_keys: Some(vec!["next-b".to_string(), "next-a".to_string()]),
        new_threshold: Some(2),
        threshold: 2,
        pss_interval: 60,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    }
}

pub(super) fn resolved_next_routes() -> Vec<NodeRoute> {
    vec![
        NodeRoute {
            node_key: "next-b".to_string(),
            peer_id: format!("{}@127.0.0.1:9002", "bb".repeat(32)),
        },
        NodeRoute {
            node_key: "next-a".to_string(),
            peer_id: format!("{}@127.0.0.1:9001", "aa".repeat(32)),
        },
    ]
}

pub(super) fn valid_next_transport_committee() -> CommitteeConfig {
    let resolved = resolved_next_routes();
    CommitteeConfig {
        // Transport order need not match Vera order, but each route
        // must remain bound to its node key.
        node_keys: vec!["next-a".to_string(), "next-b".to_string()],
        peer_routes: vec![resolved[1].peer_id.clone(), resolved[0].peer_id.clone()],
        node_id_assignments: HashMap::from([("next-a".to_string(), 1), ("next-b".to_string(), 2)]),
        threshold: 2,
    }
}

pub(super) fn offline_relay_committees() -> CeremonyConfig {
    let route = |byte: u8, port: u16| format!("{}@127.0.0.1:{port}", hex::encode([byte; 32]));
    CeremonyConfig {
        current: CommitteeConfig {
            node_keys: vec!["current-a".into(), "current-b".into()],
            peer_routes: vec![route(1, 9101), route(2, 9102)],
            node_id_assignments: HashMap::from([("current-a".into(), 1), ("current-b".into(), 2)]),
            threshold: 2,
        },
        next: Some(CommitteeConfig {
            node_keys: vec!["next-a".into(), "next-b".into()],
            peer_routes: vec![route(3, 9201), route(4, 9202)],
            node_id_assignments: HashMap::from([("next-a".into(), 1), ("next-b".into(), 2)]),
            threshold: 2,
        }),
    }
}

pub(super) fn tracker_peer(byte: u8) -> PeerId {
    PeerId::from_bytes(&[byte; 32])
}

/// Removes its test database file on drop, including when a test panics
/// partway through (e.g. a failed `assert!`) — unlike a cleanup call
/// placed at the end of the test body, which such a panic would skip.
pub(super) struct TestDbCleanup(String);

impl Drop for TestDbCleanup {
    fn drop(&mut self) {
        crate::helpers::test_helpers::cleanup_db(&self.0);
    }
}

/// Build a single-node test `AppState` with a session pre-configured as if
/// `configure_transport`/`activate_transport` had already run, then sign a
/// contribution from `origin` using that same node's own endpoint identity
/// so `verify_signed_contribution`'s route-authentication step succeeds
/// and only the phase/scope authorization matrix is under test.
pub(super) async fn contribution_test_state(
    db_name: &str,
    session_id: u128,
    kind: SessionKind,
    active_dealers: Vec<ParticipantRef>,
    origin: ParticipantRef,
) -> (
    Arc<AppState<crypto::DkgImpl>>,
    CeremonyId,
    AttemptId,
    [u8; 32],
    TestDbCleanup,
) {
    let db_cleanup = TestDbCleanup(crate::helpers::test_helpers::test_db_path(db_name));
    let state = Arc::new(create_test_app_state_default(db_name).await);
    let node = *{
        use crypto::r#trait::Dkg as _;
        crypto::DkgImpl::new(1, 2, 3, 0, crypto::r#trait::DkgRole::Standard)
            .expect("construct DkgImpl for test session")
    };
    assert_eq!(
        state
            .dkg_session_state
            .create_session(session_id, node, 3, |_| {})
            .await,
        CreateSessionOutcome::Created
    );

    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId([9u8; 32]);
    let committee_digest = [3u8; 32];
    let local_peer_hex = hex::encode(state.network.local_peer_id().as_bytes());

    {
        let mut states = state.dkg_session_state.states.write().await;
        let session = states
            .get_mut(&session_id)
            .expect("session was just created");
        session.kind = kind;
        session.transport.ceremony_id = Some(ceremony_id);
        session.transport.attempt_id = Some(attempt_id);
        session.transport.committee_digest = Some(committee_digest);
        session.transport.leader_node_key = Some("test-leader".to_string());
        session.transport.active_dealers = active_dealers;
        session.routing.ring_id = "test-ring-post".to_string();
        session
            .routing
            .node_id_to_peer_id
            .insert(origin.node_id, local_peer_hex.clone());
        session
            .routing
            .reshare_new_node_id_to_peer_id
            .insert(origin.node_id, local_peer_hex);
    }

    (state, ceremony_id, attempt_id, committee_digest, db_cleanup)
}

pub(super) async fn sign_contribution(
    state: &Arc<AppState<crypto::DkgImpl>>,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    committee_digest: [u8; 32],
    origin: ParticipantRef,
    payload: DkgPublicPayload,
) -> network::SignedPayload {
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        attempt_id,
        "test-ring-post".to_string(),
        committee_digest,
        origin,
        payload,
    )
    .expect("construct contribution");
    let encoded = transport::encode(&contribution).expect("encode contribution");
    state
        .network
        .pubsub()
        .expect("pubsub enabled")
        .sign(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, encoded.into())
        .await
        .expect("sign contribution with local endpoint identity")
}

pub(super) fn repair_test_prepare(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    member_count: u32,
) -> PrepareSession {
    let node_keys: Vec<_> = (1..=member_count)
        .map(|node_id| format!("repair-node-{node_id}"))
        .collect();
    let peer_routes: Vec<_> = (1..=member_count)
        .map(|node_id| format!("repair-route-{node_id}"))
        .collect();
    let node_id_assignments = node_keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key.clone(), index as u32 + 1))
        .collect();
    PrepareSession {
        ceremony_id,
        attempt_id,
        config_digest: [4; 32],
        topic_id: [5; 32],
        leader_node_key: node_keys[0].clone(),
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys,
                peer_routes,
                node_id_assignments,
                threshold: 1,
            },
            next: None,
        },
        kind: SessionKind::Refresh {
            ring_pk_hex: "test-ring".to_string(),
        },
        pss_interval: 0,
        policy_id: None,
        ring_id: "test-ring-post".to_string(),
        report_signature: None,
    }
}

pub(super) fn refresh_health_payload(session_id: u128) -> DkgPublicPayload {
    DkgPublicPayload::RefreshHealthCheckResult {
        statement: crate::sign::v0::messages::RefreshHealthCheckStatement {
            domain: crate::sign::v0::messages::REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
            session_id,
            ring_pk: "test-ring".to_string(),
            public_polynomial_sha256: "00".repeat(32),
            peer_node_keys_sha256: "11".repeat(32),
            threshold: 1,
            total_participants: 2,
        },
        signature: None,
    }
}

pub(super) fn reshare_participant_set_payload(dealers: &[u32]) -> DkgPublicPayload {
    DkgPublicPayload::ReshareParticipantSet {
        selected_dealers: dealers
            .iter()
            .copied()
            .map(ParticipantRef::current)
            .collect(),
    }
}

pub(super) async fn bind_test_origin_to_local_peer(
    state: &Arc<AppState<crypto::DkgImpl>>,
    session_id: u128,
    origin: ParticipantRef,
) {
    let local_peer_hex = hex::encode(state.network.local_peer_id().as_bytes());
    let mut states = state.dkg_session_state.states.write().await;
    let session = states.get_mut(&session_id).expect("repair test session");
    match origin.scope {
        CommitteeScope::Current => {
            session
                .routing
                .node_id_to_peer_id
                .insert(origin.node_id, local_peer_hex);
        }
        CommitteeScope::Next => {
            session
                .routing
                .reshare_new_node_id_to_peer_id
                .insert(origin.node_id, local_peer_hex);
        }
    }
}

pub(super) struct ScriptedPublicRepairRequester {
    pub(super) responses:
        tokio::sync::Mutex<HashMap<String, std::collections::VecDeque<Result<DkgControlMessage>>>>,
    pub(super) requests: tokio::sync::Mutex<Vec<(String, &'static str)>>,
}

impl ScriptedPublicRepairRequester {
    pub(super) fn new(
        responses: HashMap<String, std::collections::VecDeque<Result<DkgControlMessage>>>,
    ) -> Self {
        Self {
            responses: tokio::sync::Mutex::new(responses),
            requests: tokio::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl PublicRepairRequester for ScriptedPublicRepairRequester {
    async fn request(&self, peer: &str, request: DkgControlMessage) -> PublicRepairRequestOutcome {
        self.requests
            .lock()
            .await
            .push((peer.to_string(), request.metric_label()));
        let result = self
            .responses
            .lock()
            .await
            .get_mut(peer)
            .and_then(std::collections::VecDeque::pop_front)
            .unwrap_or_else(|| {
                Err(DkgError::NetworkConnection(format!(
                    "script has no response for {peer}"
                )))
            });
        let offline = matches!(
            &result,
            Err(DkgError::NetworkConnection(_)) | Err(DkgError::NetworkCommunication(_))
        );
        PublicRepairRequestOutcome { result, offline }
    }
}

pub(super) fn fresh_commitment_bytes(origin_node_id: u32, session_id: u128) -> Vec<u8> {
    use crypto::r#trait::{Dkg as _, DkgMode, DkgRole};

    let mut sender = *crypto::DkgImpl::new(origin_node_id, 2, 3, session_id, DkgRole::Standard)
        .expect("construct fresh commitment sender");
    sender
        .generate_polynomial(DkgMode::Fresh)
        .expect("generate fresh commitment");
    crate::dkg::v0::helpers::serialize_commitment_coefficients(&sender.commitment().coefficients)
        .expect("serialize fresh commitment")
}

pub(super) fn verified_test_contribution(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    committee_digest: [u8; 32],
    origin: ParticipantRef,
    payload: DkgPublicPayload,
) -> VerifiedPublicContribution {
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        attempt_id,
        "test-ring-post".to_string(),
        committee_digest,
        origin,
        payload,
    )
    .expect("construct test contribution");
    VerifiedPublicContribution {
        signed: SignedPayload {
            origin: vec![origin.node_id as u8; 32],
            signature: vec![origin.node_id as u8; 64],
            data: transport::encode(&contribution).expect("encode test contribution"),
        },
        contribution,
    }
}

pub(super) fn assembled_contribution(
    origin: ParticipantRef,
    message_byte: u8,
) -> VerifiedPublicContribution {
    let message_id = MessageId([message_byte; 32]);
    let contribution = DkgPublicContribution {
        ceremony_id: CeremonyId(900),
        attempt_id: AttemptId([9; 32]),
        ring_id: "batch-test-ring".into(),
        committee_digest: [8; 32],
        origin,
        signed_at: 1_700_000_000,
        message_id,
        payload: DkgPublicPayload::Commitment {
            commitment: vec![message_byte],
            report_evidence: None,
        },
    };
    VerifiedPublicContribution {
        signed: SignedPayload {
            origin: vec![origin.node_id as u8; 32],
            signature: vec![message_byte; 64],
            data: vec![message_byte; 8],
        },
        contribution,
    }
}

pub(super) fn assembled_manifest(
    contributions: &[VerifiedPublicContribution],
    chunk_count: u32,
    complete: bool,
) -> PhaseManifest {
    let ids = contributions
        .iter()
        .map(|verified| {
            (
                verified.contribution.origin,
                verified.contribution.message_id,
            )
        })
        .collect();
    PhaseManifest {
        ceremony_id: CeremonyId(900),
        attempt_id: AttemptId([9; 32]),
        phase: PublicPhase::Commitments,
        phase_root: transport::phase_root(
            CeremonyId(900),
            AttemptId([9; 32]),
            PublicPhase::Commitments,
            &ids,
        ),
        contribution_ids: ids,
        chunk_count,
        complete,
        signed_at: 1_700_000_000,
    }
}

pub(super) fn sample_leader_delivery(tag: u8) -> PublicLeaderDelivery {
    PublicLeaderDelivery {
        origin: vec![tag; 32],
        delivery_id: [tag; 16],
        signature: vec![tag; 64],
        data: vec![tag; 8],
    }
}

pub(super) fn retained_repair_contribution(node_id: u8, data_len: usize) -> SignedPayload {
    SignedPayload {
        origin: vec![node_id; 32],
        signature: vec![node_id; 64],
        data: vec![255; data_len],
    }
}

/// Build a `PrepareSession` for a single-node (self-leader) fresh-DKG
/// committee, mirroring `coordinate_fresh`'s own construction exactly so
/// this exercises the same struct shape a retried leader-to-self or
/// leader-to-follower Prepare uses in production.
pub(super) async fn fresh_self_prepare(
    state: &Arc<AppState<crypto::DkgImpl>>,
    ring_id: &str,
    node_key: &str,
    ceremony_id: CeremonyId,
) -> PrepareSession {
    let leader = transport::canonical_leader(std::slice::from_ref(&node_key.to_string()))
        .expect("single-member committee has a canonical leader")
        .to_string();
    let attempt_id = AttemptId::random();
    let committee_digest =
        transport::ceremony_committee_digest(std::slice::from_ref(&node_key.to_string()), None);
    let resolved =
        resolve_node_routes(&state.bulletin, std::slice::from_ref(&node_key.to_string()))
            .await
            .expect("resolve self Vera route");
    let peer_ids = peer_ids_from_routes(&resolved);
    let assignments =
        canonical_node_id_assignments_from_node_keys(std::slice::from_ref(&node_key.to_string()))
            .expect("canonical node-ID assignment for a single-member committee");
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        ring_id,
        &committee_digest,
        ceremony_id,
        attempt_id,
    );
    let mut prepare = PrepareSession {
        ceremony_id,
        attempt_id,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: leader,
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: vec![node_key.to_string()],
                peer_routes: peer_ids,
                node_id_assignments: assignments,
                threshold: 1,
            },
            next: None,
        },
        kind: SessionKind::Fresh,
        pss_interval: 60,
        policy_id: Some("test-policy".to_string()),
        ring_id: ring_id.to_string(),
        report_signature: None,
    };
    prepare.config_digest =
        transport::config_digest(&prepare).expect("compute config digest for test Prepare");
    prepare
}

pub(super) fn fresh_test_ring(node_key: &str, threshold: u32) -> RingPayload {
    RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![node_key.to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold,
        pss_interval: 60,
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    }
}
