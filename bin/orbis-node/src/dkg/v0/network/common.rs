use super::*;

pub(super) const MAX_CONTROL_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

pub(super) const INITIAL_CONTROL_RETRY_BACKOFF: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicBatchMode {
    Complete,
    Incremental,
}

pub(super) fn public_batch_mode(kind: &SessionKind, phase: PublicPhase) -> Option<PublicBatchMode> {
    match (kind, phase) {
        (SessionKind::Fresh, PublicPhase::CommitmentHashes | PublicPhase::Commitments)
        | (
            SessionKind::Refresh { .. },
            PublicPhase::Commitments | PublicPhase::RefreshHealthCheck,
        )
        | (SessionKind::Reshare { .. }, PublicPhase::ReshareParticipantSet) => {
            Some(PublicBatchMode::Complete)
        }
        (
            SessionKind::Refresh { .. } | SessionKind::Reshare { .. },
            PublicPhase::CommitmentAudit,
        )
        | (SessionKind::Reshare { .. }, PublicPhase::Commitments) => {
            Some(PublicBatchMode::Incremental)
        }
        _ => None,
    }
}

pub(super) fn authenticated_public_event_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-authenticated-public-event-v1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(super) async fn expected_public_origins<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> BTreeSet<ParticipantRef>
where
    D: CoordinatorDkg,
{
    if phase == PublicPhase::RefreshHealthCheck {
        return prepare
            .current_participant(&prepare.leader_node_key)
            .into_iter()
            .collect();
    }
    if phase == PublicPhase::ReshareParticipantSet {
        return BTreeSet::from([ParticipantRef::next(1)]);
    }
    if matches!(prepare.kind, SessionKind::Reshare { .. }) && phase == PublicPhase::CommitmentAudit
    {
        return prepare
            .committees
            .next
            .as_ref()
            .into_iter()
            .flat_map(|next| next.node_id_assignments.values().copied())
            .map(ParticipantRef::next)
            .collect();
    }
    if matches!(prepare.kind, SessionKind::Reshare { .. }) && phase == PublicPhase::Commitments {
        return state
            .dkg_session_state
            .transport_active_dealers(&prepare.ceremony_id.0)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
    }
    prepare
        .committees
        .current
        .node_id_assignments
        .values()
        .copied()
        .map(ParticipantRef::current)
        .collect()
}

pub(super) fn peer_matches_route(peer: &PeerId, route: &str) -> bool {
    hex::encode(peer.as_bytes()) == extract_node_part(route).to_lowercase()
}

pub(super) fn participant_for_peer_route(
    committees: &CeremonyConfig,
    scope: CommitteeScope,
    peer: &str,
) -> Option<ParticipantRef> {
    let peer = extract_node_part(peer).to_lowercase();
    let committee = committees.committee(scope)?;
    committee
        .peer_routes
        .iter()
        .position(|route| extract_node_part(route).to_lowercase() == peer)
        .and_then(|index| committee.node_keys.get(index))
        .and_then(|node_key| committee.participant(scope, node_key))
}

pub(super) fn participant_for_transport_peer(
    committees: &CeremonyConfig,
    peer: &str,
) -> Option<ParticipantRef> {
    participant_for_peer_route(committees, CommitteeScope::Next, peer)
        .or_else(|| participant_for_peer_route(committees, CommitteeScope::Current, peer))
}
