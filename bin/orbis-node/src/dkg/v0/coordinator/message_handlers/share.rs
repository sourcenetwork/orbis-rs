use super::*;
use crate::dkg::v0::coordinator::evidence::{
    queue_or_relay_invalid_share, share_evidence_proves_failure, verify_share_evidence,
};
use crypto::error::CryptoError;
use crypto::SignImpl;

/// Apply a typed private share delivery.
///
/// Validates the share is addressed to this node, deserializes it, passes it to the
/// crypto layer for verification against the sender's commitment, then checks whether
/// Phase 2 is complete.
#[cfg(test)]
pub async fn handle_share_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
    report_evidence: Option<SignedDkgShare>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if accept_share_message(
        coord,
        attempt,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        report_evidence,
    )
    .await?
    {
        drive_accepted_share(coord, attempt, from_node_id).await?;
    }

    Ok(())
}

/// Validate and durably record a private share without advancing the ceremony.
///
/// The private pair transport uses this before emitting its digest ACK. Phase
/// advancement is deliberately separate because the final share can enter
/// phase 4 and wait on Vera; transport acknowledgement must only cover
/// crypto validation and local state acceptance, not the rest of the ceremony.
pub(crate) async fn accept_share_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
    report_evidence: Option<SignedDkgShare>,
) -> Result<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    // Empty or wrong-length share bytes are not rejected here: `<D::ShareValue>::from_bytes`
    // below already checks length internally and fails gracefully (no panic risk) for
    // anything but the exact expected size, and a signed-but-wrong-length share is just as
    // attributable as a right-sized-but-invalid one (`require_dkg_share_verification_failure`
    // treats any decode failure the same way). Rejecting the length early, before the
    // evidence-verify-and-report path below, silently dropped that attributable case instead
    // of reporting it.

    // Validate this share is intended for us.
    // For reshare, incoming shares are addressed by new-committee index;
    // for fresh/refresh, shares are addressed by the session node_id.
    // Pure Dealers (reshare_params present but new_node_id is None) are not in
    // the new committee and must never accept incoming shares.
    let our_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| -> Result<u32> {
            if let Some(params) = state.reshare.params.as_ref() {
                params.new_node_id.ok_or_else(|| {
                    DkgError::ShareVerificationFailed(
                        "Reshare share received but this node is a pure Dealer with no new-committee assignment".to_string(),
                    )
                })
            } else {
                Ok(state.node.node_id())
            }
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    if to_node_id != our_node_id {
        return Err(DkgError::ShareVerificationFailed(format!(
            "Share intended for node {}, but we are node {}",
            to_node_id, our_node_id
        )));
    }

    let ignore_unselected_reshare_share = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state
                    .reshare
                    .selected_dealers
                    .as_ref()
                    .is_some_and(|selected| !selected.contains(&from_node_id))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    if ignore_unselected_reshare_share {
        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            "Reshare: ignoring straggler share from unselected dealer"
        );
        return Ok(false);
    }

    let share_val = match <D::ShareValue>::from_bytes(share_value.as_slice()) {
        Ok(value) => value,
        Err(e) => {
            // A signed but undeserializable share is still attributable bad crypto
            // (the length was already checked above, so this is a right-sized but
            // invalid encoding). Authenticate the evidence and, if it proves
            // failure, report the share instead of silently dropping it.
            let report_evidence = verify_share_evidence(
                coord,
                attempt,
                from_node_id,
                to_node_id,
                &share_value,
                nonce,
                report_evidence,
            )
            .await?;
            if let Some(report_evidence) = report_evidence {
                if share_evidence_proves_failure(&report_evidence) {
                    // Best-effort: a reporting-pipeline failure (capacity, registry
                    // lookup, relay) must never surface as this function's own
                    // error. This share is still rejected either way, and the
                    // caller uses that outcome to send the delivery's transport
                    // ACK — letting a report-queueing failure `?`-propagate here
                    // would withhold that ACK over something unrelated to
                    // whether the share itself was valid.
                    if let Err(error) =
                        queue_or_relay_invalid_share(coord, attempt, report_evidence).await
                    {
                        tracing::warn!(
                            from_node_id = from_node_id,
                            to_node_id = to_node_id,
                            session_id = session_id,
                            %error,
                            "DKG Coordinator: failed to queue/relay invalid_crypto_response report for undeserializable DKG share"
                        );
                    }
                    tracing::warn!(
                        from_node_id = from_node_id,
                        to_node_id = to_node_id,
                        session_id = session_id,
                        error = %e,
                        "DKG Coordinator: rejected undeserializable DKG share"
                    );
                    return Ok(false);
                }
            }
            return Err(DkgError::Deserialization(format!(
                "Failed to deserialize share value: {}",
                e
            )));
        }
    };
    let share = DistributedShare {
        from_id: from_node_id,
        to_id: to_node_id,
        value: share_val,
        nonce,
        session_id,
    };
    let report_evidence = verify_share_evidence(
        coord,
        attempt,
        from_node_id,
        to_node_id,
        &share_value,
        nonce,
        report_evidence,
    )
    .await?;

    let accepted = match try_receive_share(coord, attempt, share.clone()).await? {
        Ok(()) => {
            record_accepted_share_state(coord, attempt, from_node_id, to_node_id).await?;
            true
        }
        Err(CryptoError::CommitmentMissing(missing_node_id)) if missing_node_id == from_node_id => {
            let inserted = coord
                .app_state
                .dkg_session_state
                .store_pending_share_for_attempt(attempt, share, report_evidence)
                .await
                .map_err(|error| attempt_state_error(attempt, error))?;

            tracing::debug!(
                from_node_id = from_node_id,
                to_node_id = to_node_id,
                session_id = session_id,
                inserted = inserted,
                "DKG Coordinator: Share arrived before commitment; queued for replay"
            );
            false
        }
        Err(e) => {
            if let Some(report_evidence) = report_evidence {
                if share_evidence_proves_failure(&report_evidence) {
                    // Best-effort — see the matching comment above for why this
                    // must not `?`-propagate into this function's own result.
                    if let Err(error) =
                        queue_or_relay_invalid_share(coord, attempt, report_evidence).await
                    {
                        tracing::warn!(
                            from_node_id = from_node_id,
                            to_node_id = to_node_id,
                            session_id = session_id,
                            %error,
                            "DKG Coordinator: failed to queue/relay invalid_crypto_response report for bad DKG share"
                        );
                    }
                    tracing::warn!(
                        from_node_id = from_node_id,
                        to_node_id = to_node_id,
                        session_id = session_id,
                        error = %e,
                        "DKG Coordinator: rejected bad DKG share"
                    );
                    return Ok(false);
                }
            }
            return Err(DkgError::ShareVerificationFailed(format!(
                "Failed to receive share: {}",
                e
            )));
        }
    };

    Ok(accepted)
}

pub(super) async fn receive_and_record_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    share: DistributedShare<D::ShareValue>,
    report_evidence: Option<SignedDkgShare>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    let from_node_id = share.from_id;
    let to_node_id = share.to_id;

    match try_receive_share(coord, attempt, share).await? {
        Ok(()) => record_accepted_share(coord, attempt, from_node_id, to_node_id).await,
        Err(e) => {
            if let Some(report_evidence) = report_evidence {
                if share_evidence_proves_failure(&report_evidence) {
                    // Best-effort — see the matching comment in accept_share_message
                    // for why this must not `?`-propagate into this function's own result.
                    if let Err(error) =
                        queue_or_relay_invalid_share(coord, attempt, report_evidence).await
                    {
                        tracing::warn!(
                            from_node_id = from_node_id,
                            to_node_id = to_node_id,
                            session_id = session_id,
                            %error,
                            "DKG Coordinator: failed to queue/relay invalid_crypto_response report for pending bad DKG share"
                        );
                    }
                    tracing::warn!(
                        from_node_id = from_node_id,
                        to_node_id = to_node_id,
                        session_id = session_id,
                        error = %e,
                        "DKG Coordinator: rejected pending bad DKG share"
                    );
                    return Ok(());
                }
            }
            Err(DkgError::ShareVerificationFailed(format!(
                "Failed to receive share: {}",
                e
            )))
        }
    }
}

async fn try_receive_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    share: DistributedShare<D::ShareValue>,
) -> Result<std::result::Result<(), CryptoError>>
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| state.node.receive_share(share))
        .await
        .map_err(|error| attempt_state_error(attempt, error))
}

async fn record_accepted_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    to_node_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    record_accepted_share_state(coord, attempt, from_node_id, to_node_id).await?;
    drive_accepted_share(coord, attempt, from_node_id).await
}

async fn record_accepted_share_state<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    to_node_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    tracing::debug!(
        from_node_id = from_node_id,
        to_node_id = to_node_id,
        session_id = session_id,
        "DKG Coordinator: Received and verified share"
    );

    coord
        .app_state
        .dkg_session_state
        .record_received_share_for_attempt(attempt, from_node_id)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    Ok(())
}

pub(crate) async fn drive_accepted_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    phases::drive_event(
        coord,
        attempt,
        DkgEvent::ShareRecorded { from_node_id },
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::dkg::v0::session_state::DkgReportEvidenceBinding;
    use crate::helpers::test_helpers::{
        cleanup_db, create_test_app_state_with_bulletin, test_db_path,
    };
    use crate::reporting::v0::state::InFlightReportKey;
    use crate::reporting::v0::types::{
        CommitteeScope, DkgCommitmentStatement, DkgShareStatement, DKG_COMMITMENT_DOMAIN,
        DKG_SHARE_DOMAIN,
    };
    use bulletin::{dummy::DummyBulletin, r#trait::NodeInfo};
    use common::blockchain::{
        sign_node_message_with_hex_key, TEST_ACCOUNT_HEX_KEY, TEST_ACCOUNT_PUBKEY_HEX,
    };
    use crypto::r#trait::{Dkg as _, DkgRole};
    use crypto::DkgImpl;
    use std::sync::Arc;

    /// Sorts before `TEST_ACCOUNT_PUBKEY_HEX` (which starts with "02"), so
    /// `node_key_for_canonical_node_id(2, [placeholder, accused])` resolves
    /// canonical node_id 2 to the accused key.
    const NODE1_PLACEHOLDER_KEY: &str =
        "00000000000000000000000000000000000000000000000000000000000000";
    const RECEIVER_NODE_KEY: &str = "receiver-node-1";

    /// A fully-signed `SignedDkgShare` from node 2 ("accused",
    /// `TEST_ACCOUNT_PUBKEY_HEX`) to node 1 (this test's coordinator). The
    /// nested commitment is deliberately garbage too — any decode failure
    /// (commitment or share) counts as proof of a bad share per
    /// `share_evidence_proves_failure`, so this doesn't need real DKG crypto,
    /// only real secp256k1 signatures over the statements.
    fn signed_bad_share_evidence(session_id: u128, share_value: Vec<u8>) -> SignedDkgShare {
        let request_id = session_id.to_string();
        let commitment_statement = DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: request_id.clone(),
            signed_at: 100,
            responder_node_key: TEST_ACCOUNT_PUBKEY_HEX.to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            commitment: vec![0xFF; 5],
            session_nonce: [0u8; 16],
            attempt_id: [9; 32],
            crypto_backend: DkgImpl::name(),
        };
        let commitment_signature = sign_node_message_with_hex_key(
            TEST_ACCOUNT_HEX_KEY,
            &commitment_statement.canonical_bytes(),
        )
        .expect("sign nested commitment statement");

        let statement = DkgShareStatement {
            domain: DKG_SHARE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id,
            signed_at: 100,
            responder_node_key: TEST_ACCOUNT_PUBKEY_HEX.to_string(),
            receiver_node_key: RECEIVER_NODE_KEY.to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            to_node_id: 1,
            commitment_statement,
            commitment_signature,
            share_value,
            nonce: [3u8; 16],
            crypto_backend: DkgImpl::name(),
        };
        let signature =
            sign_node_message_with_hex_key(TEST_ACCOUNT_HEX_KEY, &statement.canonical_bytes())
                .expect("sign share statement");
        SignedDkgShare {
            statement,
            signature,
        }
    }

    /// Wires up a coordinator whose session takes the full evidence-verify-
    /// and-report path for a share from node 2 to node 1: this node is node 1
    /// and a current-route member (so reporting queues directly instead of
    /// relaying), and the accused's `NodeInfo` is seeded on the dummy bulletin
    /// so `queue_report`'s lookup succeeds.
    async fn coordinator_ready_to_report(
        db_name: &str,
        session_id: u128,
    ) -> (Arc<AppState<DkgImpl>>, AttemptKey) {
        let request_id = session_id.to_string();
        let bulletin = Arc::new(DummyBulletin::new().await.expect("dummy bulletin"));
        bulletin
            .set_node_info(
                TEST_ACCOUNT_PUBKEY_HEX.to_string(),
                NodeInfo {
                    peer_id: "accused-peer".to_string(),
                    controller_key: TEST_ACCOUNT_PUBKEY_HEX.to_string(),
                    whitelisted_policy_ids: vec![],
                    whitelisted_ring_ids: vec![],
                },
            )
            .expect("seed accused NodeInfo");
        let app_state =
            Arc::new(create_test_app_state_with_bulletin(true, bulletin, db_name).await);
        let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
        let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
        let attempt = AttemptKey::test(session_id);

        coordinator
            .create_session(attempt, 1, 2, 3, DkgRole::Standard, |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: "pk".to_string(),
                };
                state.report_evidence_binding = Some(DkgReportEvidenceBinding {
                    ring_id: "ring".to_string(),
                    ring_pk: "pk".to_string(),
                    ring_state_sha256: "00".repeat(32),
                    chain_id: "chain".to_string(),
                    protocol_version: 0,
                    request_id,
                    origin_protocol: "pss_refresh".to_string(),
                    current_node_keys: vec![
                        NODE1_PLACEHOLDER_KEY.to_string(),
                        TEST_ACCOUNT_PUBKEY_HEX.to_string(),
                    ],
                    receiver_node_keys: vec![RECEIVER_NODE_KEY.to_string()],
                });
                state
                    .routing
                    .node_id_to_peer_id
                    .insert(1, format!("{local_peer_hex}@127.0.0.1:1234"));
            })
            .await
            .expect("create session for report test");

        (app_state, attempt)
    }

    /// RPT-15: a wrong-length share must flow into the same evidence-verify-
    /// and-report path as any other undecodable share, not be silently
    /// dropped by an early length check.
    #[tokio::test]
    async fn accept_share_message_reports_wrong_length_share_like_any_other_decode_failure() {
        let db_name = "share_wrong_length_reports";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let (app_state, attempt) = coordinator_ready_to_report(db_name, 5001).await;
        let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);

        // Deliberately the wrong length for a real share value.
        let bad_share_value = vec![0x11; 3];
        let evidence = signed_bad_share_evidence(5001, bad_share_value.clone());

        let accepted = accept_share_message(
            &coordinator,
            attempt,
            2,
            1,
            bad_share_value,
            [3u8; 16],
            Some(evidence),
        )
        .await
        .expect("a decode-failure share is rejected, not a hard error");

        assert!(!accepted, "an undeserializable share must not be accepted");
        assert_eq!(
            app_state.reporting_state.in_flight_count(),
            1,
            "the wrong-length share must reach the same reporting path as any other \
             undecodable share, not be silently dropped"
        );

        cleanup_db(&db_path);
    }

    /// RPT-14: a reporting-pipeline failure (capacity exhausted) must never
    /// surface as `accept_share_message`'s own error — the caller uses this
    /// function's `Ok`/`Err` split to decide whether to send the private
    /// delivery's transport ACK, and that must depend only on whether the
    /// share itself was valid, not on reporting capacity.
    #[tokio::test]
    async fn accept_share_message_does_not_propagate_reporting_capacity_failure() {
        let db_name = "share_reporting_capacity_exhausted";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let (app_state, attempt) = coordinator_ready_to_report(db_name, 5002).await;
        let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);

        // Fill every in-flight report slot with a task that never completes, so
        // the next queue attempt synchronously hits CapacityReached before ever
        // touching the (also-unavailable-in-this-test) chain.
        for i in 0..128 {
            let claimed = app_state
                .reporting_state
                .spawn(
                    InFlightReportKey {
                        report_type: "node_offline",
                        ring_id: "filler-ring".to_string(),
                        subject_key: format!("filler-{i}"),
                    },
                    std::future::pending::<()>(),
                )
                .await
                .expect("filler slot should be claimed");
            assert!(claimed, "each filler key must be distinct");
        }
        assert_eq!(app_state.reporting_state.in_flight_count(), 128);

        let bad_share_value = vec![0x22; 3];
        let evidence = signed_bad_share_evidence(5002, bad_share_value.clone());

        let accepted = accept_share_message(
            &coordinator,
            attempt,
            2,
            1,
            bad_share_value,
            [3u8; 16],
            Some(evidence),
        )
        .await
        .expect(
            "a reporting-capacity hiccup must never surface as this function's own \
             error — the share is still cleanly rejected either way",
        );

        assert!(!accepted, "an undeserializable share must not be accepted");
        // Every slot is still held by a filler task; the real report attempt
        // must have failed to queue at all, not squeezed in as a 129th entry.
        assert_eq!(app_state.reporting_state.in_flight_count(), 128);

        cleanup_db(&db_path);
    }
}
