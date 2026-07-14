use super::*;
use crate::dkg::v0::coordinator::evidence::{
    queue_or_relay_equivocation, verify_commitment_evidence,
};
use crate::dkg::v0::messages::SignedDkgCommitment;
use crypto::SignImpl;

/// Handle a `DkgMessage::CommitmentAudit` — the on-failure equivocation audit.
///
/// A peer whose refresh/reshare ceremony failed an equivocation-consistent phase4 check
/// reveals the signed commitments it received. We re-verify each dealer signature and
/// compare against the commitments we received; if any dealer signed two different
/// commitments (same session nonce, different bytes) that dealer equivocated → we log it
/// and queue/relay a threshold-signed equivocation report. We never abort here (the
/// ceremony is already aborting via the phase4 check) and always return `Ok(None)`. Trust
/// is per-commitment (the dealer's signature), so a lying revealer cannot forge attribution.
pub async fn handle_commitment_audit_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    revealed: Vec<SignedDkgCommitment>,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let is_fresh = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Fresh)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if is_fresh {
        return Err(DkgError::ProtocolError(
            "CommitmentAudit is only valid for Refresh/Reshare DKG sessions".to_string(),
        ));
    }

    // Keep only reveals that are genuinely signed by the claimed dealer and bound to this
    // session/ring; a reveal that fails verification is not evidence of anything.
    let mut verified: Vec<SignedDkgCommitment> = Vec::with_capacity(revealed.len());
    for reveal in revealed {
        let dealer_id = reveal.statement.from_node_id;
        let commitment = reveal.statement.commitment.clone();
        match verify_commitment_evidence(coord, session_id, dealer_id, &commitment, Some(reveal))
            .await
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
        .find_conflicting_commitment_pair(&session_id, &verified)
        .await
    {
        tracing::error!(
            session_id = session_id,
            dealer_node_id = dealer_node_id,
            responder_node_key = %ours.statement.responder_node_key,
            "DKG commitment equivocation detected — dealer distributed conflicting commitments"
        );
        // Report it on-chain (threshold-signed). `ours` (locally received) anchors the
        // envelope. Best-effort: log-not-propagate so the ceremony's abort is unchanged.
        if let Err(error) = queue_or_relay_equivocation(coord, session_id, ours, reveal).await {
            tracing::warn!(
                session_id = session_id,
                dealer_node_id = dealer_node_id,
                error = %error,
                "Failed to queue/relay DKG equivocation report"
            );
        }
    }

    Ok(None)
}
