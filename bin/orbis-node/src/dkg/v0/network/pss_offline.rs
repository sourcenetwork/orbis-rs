use super::*;

pub(super) struct OfflineRelayRejectionGuard {
    pub(super) stage: PssOfflineStage,
    pub(super) accepted: bool,
}

impl OfflineRelayRejectionGuard {
    pub(super) fn new(stage: PssOfflineStage) -> Self {
        Self {
            stage,
            accepted: false,
        }
    }

    pub(super) fn accept(&mut self) {
        self.accepted = true;
    }
}

impl Drop for OfflineRelayRejectionGuard {
    fn drop(&mut self) {
        if !self.accepted {
            crate::metrics::record_pss_offline_observation(
                self.stage.as_metric_label(),
                "relay_rejected",
            );
        }
    }
}

pub(super) fn validate_offline_relay_claim(
    committees: &CeremonyConfig,
    leader_node_key: &str,
    recipient_node_key: &str,
    sender: &PeerId,
    stage: PssOfflineStage,
    accused: &[ParticipantRef],
) -> Result<String> {
    if !committees
        .current
        .node_keys
        .iter()
        .any(|key| key == recipient_node_key)
    {
        return Err(DkgError::Unauthorized(
            "offline-candidate relay recipient is not a current signer".into(),
        ));
    }
    let next = committees
        .next
        .as_ref()
        .ok_or_else(|| DkgError::InvalidState("reshare relay has no next committee".into()))?;
    let sender_node_key = next
        .node_keys
        .iter()
        .zip(&next.peer_routes)
        .find_map(|(node_key, route)| peer_matches_route(sender, route).then_some(node_key.clone()))
        .ok_or_else(|| {
            DkgError::Unauthorized("offline-candidate observer is not in the next committee".into())
        })?;
    if committees
        .current
        .node_keys
        .iter()
        .any(|key| key == &sender_node_key)
    {
        return Err(DkgError::Unauthorized(
            "current committee members must report offline candidates directly".into(),
        ));
    }
    if stage.requires_canonical_leader() && leader_node_key != sender_node_key {
        return Err(DkgError::Unauthorized(
            "offline-candidate observer is not entitled to the leader-only stage".into(),
        ));
    }
    if matches!(
        stage,
        PssOfflineStage::StartForward
            | PssOfflineStage::RefreshResultStage
            | PssOfflineStage::RefreshResultCommit
    ) {
        return Err(DkgError::Unauthorized(
            "offline-candidate stage is inconsistent with a pure-new reshare observer".into(),
        ));
    }
    if accused.is_empty() || accused.len() > MAX_DKG_COMMITTEE_SIZE {
        return Err(DkgError::InvalidInput(
            "offline-candidate relay size is outside the committee bound".into(),
        ));
    }
    let mut canonical_accused = accused.to_vec();
    canonical_accused.sort_unstable();
    canonical_accused.dedup();
    if canonical_accused != accused
        || canonical_accused
            .iter()
            .any(|participant| committees.route(*participant).is_none())
        || canonical_accused
            .iter()
            .any(|participant| committees.node_key(*participant) == Some(&sender_node_key))
    {
        return Err(DkgError::Unauthorized(
            "offline-candidate participants are noncanonical or outside the ceremony".into(),
        ));
    }
    let leader = next
        .participant(CommitteeScope::Next, leader_node_key)
        .ok_or_else(|| DkgError::InvalidState("reshare leader assignment is missing".into()))?;
    match stage {
        PssOfflineStage::TopologyAck
        | PssOfflineStage::PublicContribution
        | PssOfflineStage::PublicRepairLeader
            if canonical_accused.as_slice() != [leader] =>
        {
            return Err(DkgError::Unauthorized(
                "offline-candidate stage may accuse only the canonical leader".into(),
            ));
        }
        PssOfflineStage::ReshareShareAck
            if canonical_accused.as_slice() != [ParticipantRef::next(1)] =>
        {
            return Err(DkgError::Unauthorized(
                "reshare share-ACK observation may accuse only the selector".into(),
            ));
        }
        _ => {}
    }
    Ok(sender_node_key)
}

pub(super) async fn validate_offline_relay_transition<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ceremony_id: CeremonyId,
    kind: &SessionKind,
    ring_id: &str,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let SessionKind::Reshare {
        ring_pk_hex,
        new_peer_node_keys,
        new_threshold,
        bulletin_post_id,
    } = kind
    else {
        return Err(DkgError::Unauthorized(
            "offline-candidate relay is only valid for reshare".into(),
        ));
    };
    if bulletin_post_id != ring_id {
        return Err(DkgError::Unauthorized(
            "offline-candidate relay ring binding is inconsistent".into(),
        ));
    }
    let ring = read_ring_for_route(&*state.bulletin, ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (pending_keys, pending_threshold) = pending_reshare_parameters(&ring, ring_pk_hex)?;
    if pending_keys != *new_peer_node_keys || pending_threshold != *new_threshold {
        return Err(DkgError::Unauthorized(
            "offline-candidate relay targets a superseded reshare transition".into(),
        ));
    }
    let expected_ceremony = CeremonyId(derive_reshare_session_id(
        ring_pk_hex,
        ring_id,
        &ring.peer_node_keys,
        &pending_keys,
        pending_threshold,
    )?);
    if expected_ceremony != ceremony_id {
        return Err(DkgError::Unauthorized(
            "offline-candidate relay ceremony binding is stale".into(),
        ));
    }
    Ok(())
}

pub(super) fn private_failure_is_unreachable(
    io_failed: bool,
    busy_retry_after: Option<Duration>,
) -> bool {
    io_failed && busy_retry_after.is_none()
}

pub(super) fn terminal_offline_candidate(
    last_failure_was_unreachable: bool,
    peer_proved_reachable: bool,
) -> bool {
    last_failure_was_unreachable && !peer_proved_reachable
}

pub(crate) async fn spawn_pss_offline_for_attempt<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    stage: PssOfflineStage,
    accused: impl IntoIterator<Item = ParticipantRef>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let accused: Vec<_> = accused.into_iter().collect();
    if accused.is_empty() {
        return;
    }
    let snapshot = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (
                session.kind.clone(),
                session.routing.ring_id.clone(),
                session.protocol_version,
                session.transport.committees.clone(),
            )
        })
        .await;
    let Ok((kind, ring_id, protocol_version, Some(committees))) = snapshot else {
        crate::metrics::record_pss_offline_observation(stage.as_metric_label(), "seed_missing");
        return;
    };
    spawn_pss_offline_observations(
        state.clone(),
        routes,
        PssOfflineObservationSeed::new(
            attempt.ceremony_id,
            Some(attempt.attempt_id),
            kind,
            ring_id,
            protocol_version,
            stage,
            committees,
            accused,
        ),
    );
}

#[derive(Debug)]
pub(crate) struct PeerDeliveryFailure {
    pub(super) error: DkgError,
    pub(super) unreachable: bool,
    pub(super) reachable: bool,
}

impl PeerDeliveryFailure {
    pub(crate) fn is_unreachable(&self) -> bool {
        self.unreachable
    }

    pub(crate) fn error(&self) -> &DkgError {
        &self.error
    }

    pub(crate) fn proves_reachable(&self) -> bool {
        self.reachable
    }
}
