use super::*;
use crate::dkg::v0::coordinator::evidence::{
    queue_or_relay_equivocation, verify_commitment_evidence,
};
use crate::dkg::v0::messages::SignedDkgCommitment;
use crypto::SignImpl;
use std::collections::HashSet;

fn bounded_unique_reveals(
    revealed: Vec<SignedDkgCommitment>,
    max_reveals: usize,
) -> Vec<SignedDkgCommitment> {
    let accepted_capacity = max_reveals.min(revealed.len());
    let mut seen_dealer_ids = HashSet::with_capacity(accepted_capacity);
    let mut accepted = Vec::with_capacity(accepted_capacity);

    for reveal in revealed {
        if accepted.len() >= max_reveals {
            break;
        }

        if seen_dealer_ids.insert(reveal.statement.from_node_id) {
            accepted.push(reveal);
        }
    }

    accepted
}

pub(crate) async fn preflight_commitment_audit_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let is_fresh = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| matches!(state.kind, SessionKind::Fresh))
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    if is_fresh {
        return Err(DkgError::ProtocolError(
            "CommitmentAudit is only valid for Refresh/Reshare DKG sessions".to_string(),
        ));
    }
    Ok(())
}

/// Apply a typed public commitment audit contribution.
///
/// A peer whose refresh/reshare ceremony failed an equivocation-consistent phase4 check
/// reveals the signed commitments it received. We re-verify each dealer signature and
/// compare against the commitments we received; if any dealer signed two different
/// commitments (same session nonce, different bytes) that dealer equivocated → we log it
/// and queue/relay a threshold-signed equivocation report. We never abort here (the
/// ceremony is already aborting via the phase4 check) and always return `Ok(())`. Trust
/// is per-commitment (the dealer's signature), so a lying revealer cannot forge attribution.
pub async fn handle_commitment_audit_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    revealed: Vec<SignedDkgCommitment>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    preflight_commitment_audit_message(coord, attempt).await?;
    let committee_size = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| state.node.total_nodes())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    // Keep only reveals that are genuinely signed by the claimed dealer and bound to this
    // session/ring; a reveal that fails verification is not evidence of anything.
    let bounded_reveals = bounded_unique_reveals(revealed, committee_size);
    let mut verified: Vec<SignedDkgCommitment> = Vec::with_capacity(bounded_reveals.len());
    for reveal in bounded_reveals {
        let dealer_id = reveal.statement.from_node_id;
        let commitment = reveal.statement.commitment.clone();
        match verify_commitment_evidence(coord, attempt, dealer_id, &commitment, Some(reveal)).await
        {
            Ok(Some(evidence)) => verified.push(evidence),
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(
                    session_id = session_id,
                    dealer_node_id = dealer_id,
                    error = %error,
                    "DKG Coordinator: ignoring unverifiable commitment in audit reveal"
                );
            }
        }
    }

    if let Some((dealer_node_id, ours, reveal)) = coord
        .app_state
        .dkg_session_state
        .find_conflicting_commitment_pair_for_attempt(attempt, &verified)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?
    {
        tracing::error!(
            session_id = session_id,
            dealer_node_id = dealer_node_id,
            responder_node_key = %ours.statement.responder_node_key,
            "DKG commitment equivocation detected — dealer distributed conflicting commitments"
        );
        // Report it on-chain (threshold-signed). `ours` (locally received) anchors the
        // envelope. Best-effort: log-not-propagate so the ceremony's abort is unchanged.
        if let Err(error) = queue_or_relay_equivocation(coord, attempt, ours, reveal).await {
            tracing::warn!(
                session_id = session_id,
                dealer_node_id = dealer_node_id,
                error = %error,
                "Failed to queue/relay DKG equivocation report"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::v0::types::{
        CommitteeScope, DkgCommitmentStatement, DKG_COMMITMENT_DOMAIN,
    };

    fn reveal(dealer_id: u32, commitment: Vec<u8>) -> SignedDkgCommitment {
        SignedDkgCommitment {
            statement: DkgCommitmentStatement {
                domain: DKG_COMMITMENT_DOMAIN.to_string(),
                chain_id: "chain".to_string(),
                ring_id: "ring".to_string(),
                ring_pk: "ring-pk".to_string(),
                ring_state_sha256: "00".repeat(32),
                protocol_version: 0,
                request_id: "session".to_string(),
                signed_at: 100,
                responder_node_key: format!("dealer-{dealer_id}"),
                origin_protocol: "pss_refresh".to_string(),
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
                from_node_id: dealer_id,
                commitment,
                session_nonce: [0u8; 16],
                attempt_id: [9; 32],
                crypto_backend: "test".to_string(),
            },
            signature: vec![0; 64],
        }
    }

    #[test]
    fn bounded_unique_reveals_keeps_first_reveal_per_dealer_until_committee_size() {
        let bounded = bounded_unique_reveals(
            vec![
                reveal(2, vec![1]),
                reveal(2, vec![2]),
                reveal(3, vec![3]),
                reveal(4, vec![4]),
            ],
            2,
        );

        let dealer_ids: Vec<u32> = bounded
            .iter()
            .map(|reveal| reveal.statement.from_node_id)
            .collect();
        assert_eq!(dealer_ids, vec![2, 3]);
        assert_eq!(bounded[0].statement.commitment, vec![1]);
    }

    #[test]
    fn bounded_unique_reveals_accepts_none_when_committee_size_is_zero() {
        let bounded = bounded_unique_reveals(vec![reveal(2, vec![1])], 0);

        assert!(bounded.is_empty());
    }
}
