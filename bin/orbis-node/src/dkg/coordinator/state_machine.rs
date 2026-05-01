use crate::dkg::messages::SessionKind;
use crate::dkg::session_state::DkgPhase;
use crypto::r#trait::DkgRole;

/// Protocol events that can advance the local coordinator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dkg::coordinator) enum DkgEvent {
    CommitmentRecorded,
    ShareRecorded { from_node_id: u32 },
    ReshareParticipantSetAccepted,
    Phase2SharesDistributed { local_node_id: u32 },
    ReadinessChanged,
}

impl DkgEvent {
    pub(in crate::dkg::coordinator) fn evaluates_phase4(self) -> bool {
        matches!(
            self,
            Self::ShareRecorded { .. }
                | Self::ReshareParticipantSetAccepted
                | Self::ReadinessChanged
        )
    }
}

/// Side effects selected by the state machine and executed outside the state lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::dkg::coordinator) enum DkgCommand {
    InitiatePhase2Shares,
    AckValidReshareShare { dealer_id: u32 },
    CompletePhase4,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(in crate::dkg::coordinator) struct Transition {
    pub next_phase: Option<DkgPhase>,
    pub commands: Vec<DkgCommand>,
}

#[derive(Debug, Clone)]
pub(in crate::dkg::coordinator) struct SessionSnapshot {
    pub kind: SessionKind,
    pub phase: DkgPhase,
    pub role: DkgRole,
    pub node_id: u32,
    pub total_nodes: usize,
    pub threshold: usize,
    pub has_polynomial: bool,
    pub commitments_received: usize,
    pub shares_received: usize,
    pub reshare_selected_dealers: bool,
    pub secret_share_available: bool,
    pub aggregate_public_key_available: bool,
}

impl SessionSnapshot {
    pub(in crate::dkg::coordinator) fn is_reshare(&self) -> bool {
        matches!(self.kind, SessionKind::Reshare { .. })
    }

    pub(in crate::dkg::coordinator) fn phase1_expected_commitments(&self) -> Option<usize> {
        if self.is_reshare() {
            return None;
        }
        Some(match self.role {
            DkgRole::Receiver => self.total_nodes,
            _ => self.total_nodes.saturating_sub(1),
        })
    }

    pub(in crate::dkg::coordinator) fn phase4_expected_shares(&self) -> usize {
        match self.role {
            DkgRole::Receiver => self.total_nodes,
            _ => self.total_nodes.saturating_sub(1),
        }
    }

    fn should_initiate_phase2(&self) -> bool {
        if matches!(
            self.phase,
            DkgPhase::Phase2Shares | DkgPhase::Phase4Completing | DkgPhase::Phase4Complete
        ) {
            return false;
        }
        if self.role != DkgRole::Receiver && !self.has_polynomial {
            return false;
        }
        if self.role == DkgRole::Receiver {
            return false;
        }
        self.phase1_expected_commitments()
            .is_some_and(|expected| self.commitments_received >= expected)
    }

    fn should_ack_valid_reshare_share(&self) -> bool {
        self.is_reshare() && matches!(self.role, DkgRole::Receiver | DkgRole::DealerReceiver)
    }

    pub(in crate::dkg::coordinator) fn should_complete_phase4(&self) -> bool {
        if matches!(
            self.phase,
            DkgPhase::Phase4Completing | DkgPhase::Phase4Complete
        ) {
            return false;
        }
        if self.is_reshare() && matches!(self.role, DkgRole::Receiver | DkgRole::DealerReceiver) {
            return self.reshare_selected_dealers
                && self.secret_share_available
                && self.aggregate_public_key_available;
        }
        self.shares_received >= self.phase4_expected_shares() && self.aggregate_public_key_available
    }
}

pub(in crate::dkg::coordinator) fn transition(
    snapshot: &SessionSnapshot,
    event: DkgEvent,
) -> Transition {
    let mut transition = Transition::default();

    match event {
        DkgEvent::CommitmentRecorded => {
            if snapshot.should_initiate_phase2() {
                transition.next_phase = Some(DkgPhase::Phase2Shares);
                transition.commands.push(DkgCommand::InitiatePhase2Shares);
            }
        }
        DkgEvent::ShareRecorded { from_node_id } => {
            if snapshot.should_ack_valid_reshare_share() {
                transition.commands.push(DkgCommand::AckValidReshareShare {
                    dealer_id: from_node_id,
                });
            }
            push_phase4_if_ready(snapshot, &mut transition);
        }
        DkgEvent::ReshareParticipantSetAccepted | DkgEvent::ReadinessChanged => {
            push_phase4_if_ready(snapshot, &mut transition);
        }
        DkgEvent::Phase2SharesDistributed { local_node_id } => {
            if snapshot.role == DkgRole::DealerReceiver {
                transition.commands.push(DkgCommand::AckValidReshareShare {
                    dealer_id: local_node_id,
                });
            }
            if snapshot.role == DkgRole::Dealer {
                transition.next_phase = Some(DkgPhase::Phase4Completing);
                transition.commands.push(DkgCommand::CompletePhase4);
            }
        }
    }

    transition
}

fn push_phase4_if_ready(snapshot: &SessionSnapshot, transition: &mut Transition) {
    if snapshot.should_complete_phase4() {
        transition.next_phase = Some(DkgPhase::Phase4Completing);
        transition.commands.push(DkgCommand::CompletePhase4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> SessionSnapshot {
        SessionSnapshot {
            kind: SessionKind::Fresh,
            phase: DkgPhase::Phase1Commitments,
            role: DkgRole::Standard,
            node_id: 1,
            total_nodes: 3,
            threshold: 2,
            has_polynomial: true,
            commitments_received: 2,
            shares_received: 0,
            reshare_selected_dealers: false,
            secret_share_available: false,
            aggregate_public_key_available: false,
        }
    }

    #[test]
    fn commitment_can_trigger_phase2() {
        let transition = transition(&snapshot(), DkgEvent::CommitmentRecorded);

        assert_eq!(transition.next_phase, Some(DkgPhase::Phase2Shares));
        assert_eq!(transition.commands, vec![DkgCommand::InitiatePhase2Shares]);
    }

    #[test]
    fn reshare_share_ack_is_commanded_for_receivers() {
        let mut snapshot = snapshot();
        snapshot.kind = SessionKind::Reshare {
            ring_pk_hex: "ring".to_string(),
            next_peer_ids: vec!["a".to_string(), "b".to_string()],
            new_threshold: 2,
            bulletin_post_id: "post".to_string(),
        };
        snapshot.role = DkgRole::Receiver;

        let transition = transition(&snapshot, DkgEvent::ShareRecorded { from_node_id: 7 });

        assert_eq!(
            transition.commands,
            vec![DkgCommand::AckValidReshareShare { dealer_id: 7 }]
        );
    }

    #[test]
    fn reshare_readiness_can_trigger_phase4() {
        let mut snapshot = snapshot();
        snapshot.kind = SessionKind::Reshare {
            ring_pk_hex: "ring".to_string(),
            next_peer_ids: vec!["a".to_string(), "b".to_string()],
            new_threshold: 2,
            bulletin_post_id: "post".to_string(),
        };
        snapshot.role = DkgRole::DealerReceiver;
        snapshot.reshare_selected_dealers = true;
        snapshot.secret_share_available = true;
        snapshot.aggregate_public_key_available = true;

        let transition = transition(&snapshot, DkgEvent::ReshareParticipantSetAccepted);

        assert_eq!(transition.next_phase, Some(DkgPhase::Phase4Completing));
        assert_eq!(transition.commands, vec![DkgCommand::CompletePhase4]);
    }

    #[test]
    fn dealer_completes_after_distributing_shares() {
        let mut snapshot = snapshot();
        snapshot.kind = SessionKind::Reshare {
            ring_pk_hex: "ring".to_string(),
            next_peer_ids: vec!["a".to_string(), "b".to_string()],
            new_threshold: 2,
            bulletin_post_id: "post".to_string(),
        };
        snapshot.role = DkgRole::Dealer;

        let transition = transition(
            &snapshot,
            DkgEvent::Phase2SharesDistributed { local_node_id: 3 },
        );

        assert_eq!(transition.next_phase, Some(DkgPhase::Phase4Completing));
        assert_eq!(transition.commands, vec![DkgCommand::CompletePhase4]);
    }

    #[test]
    fn phase4_completing_is_not_reclaimed() {
        let mut snapshot = snapshot();
        snapshot.phase = DkgPhase::Phase4Completing;
        snapshot.shares_received = 2;
        snapshot.aggregate_public_key_available = true;

        let transition = transition(&snapshot, DkgEvent::ReadinessChanged);

        assert_eq!(transition.next_phase, None);
        assert!(transition.commands.is_empty());
    }
}
