use super::*;

pub(in crate::dkg::coordinator) async fn check_and_trigger_phase4<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    drive_event(coord, session_id, DkgEvent::ReadinessChanged, None).await
}
pub(in crate::dkg::coordinator) async fn initiate_phase4_completion<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
) -> Result<()>
where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: Starting Phase 4 completion"
    );

    let (kind, pss_interval, dkg_role, reshare_new_peer_ids, reshare_bulletin_post_id) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (
                state.kind.clone(),
                state.pss_interval,
                state.node.role(),
                state
                    .reshare_params
                    .as_ref()
                    .map(|p| p.new_peer_ids.clone()),
                state
                    .reshare_params
                    .as_ref()
                    .map(|p| p.bulletin_post_id.clone()),
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    // Pure Dealer nodes don't compute a secret share — they just clean up.
    // Because they are leaving the ring, delete the local secret share and
    // remove the ring from the index so the PSS scheduler ignores it.
    if dkg_role == DkgRole::Dealer {
        let ring_key = kind.ring_key().map(|k| k.to_string());
        return ring_storage::cleanup_departing_dealer(coord, session_id, ring_key).await;
    }

    // Compute final secret share, aggregate public key, and data for bulletin.
    let (node_id, aggregate_pk, final_share_bytes, threshold, pub_poly_bytes) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            tracing::debug!(
                node_id = state.node.node_id(),
                "DKG Coordinator: Computing secret share"
            );

            let final_share = state
                .node
                .compute_secret_share()
                .map_err(|e| DkgError::Crypto(format!("Failed to compute secret share: {}", e)))?;

            tracing::debug!(
                node_id = state.node.node_id(),
                "DKG Coordinator: Successfully computed secret share"
            );

            let aggregate_pk = state.node.compute_aggregate_public_key().map_err(|e| {
                DkgError::Crypto(format!("Failed to compute aggregate public key: {}", e))
            })?;

            tracing::debug!(
                node_id = state.node.node_id(),
                "DKG Coordinator: Computed aggregate public key"
            );

            let final_share_bytes = CryptoSerialize::to_bytes(&final_share).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize final share: {}", e))
            })?;

            let pub_poly = state.node.compute_public_polynomial().map_err(|e| {
                DkgError::Crypto(format!("Failed to compute public polynomial: {}", e))
            })?;
            let pub_poly_bytes = CryptoSerialize::to_bytes(&pub_poly).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize public polynomial: {}", e))
            })?;

            Ok::<_, DkgError>((
                state.node.node_id(),
                aggregate_pk,
                final_share_bytes,
                state.node.threshold(),
                pub_poly_bytes,
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    // Compute storage_key — the canonical local-storage key used by sign/pre for share lookup.
    // For Refresh and Reshare this is the ORIGINAL ring's key (unchanged secret → same pk).
    let storage_key = kind
        .ring_key()
        .map(|k| k.to_string())
        .unwrap_or_else(|| aggregate_pk.to_string());

    // Write share + polynomial as a single encrypted bundle.
    // Atomicity: both fields land in one set_encrypted call, so a crash leaves the
    // entry either fully written or absent — never partially updated.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    persist_ring_bundle(
        &coord.app_state.local_storage,
        &kind,
        &final_share_bytes,
        &pub_poly_bytes,
        &aggregate_pk,
        now_secs,
        session_id,
        |old, delta| D::combine_pub_poly_bytes(old, delta).map_err(|e| e.to_string()),
    )?;

    tracing::debug!(
        session_id = session_id,
        "DKG Coordinator: Stored RingShareBundle (share + polynomial) atomically"
    );

    // For Reshare: write a RingIndexEntry so the PSS scheduler can discover this ring.
    // Receiver and DealerReceiver nodes use the bulletin_post_id carried in the SessionInit
    // (they had no prior index entry).  Dealers have already left and skip this entirely.
    if matches!(kind, SessionKind::Reshare { .. }) && dkg_role != DkgRole::Dealer {
        if let Some(post_id) = &reshare_bulletin_post_id {
            ring_storage::add_ring_index_entry(&coord.app_state, &storage_key, post_id.clone())
                .await?;
            tracing::info!(
                session_id = session_id,
                ring_pk = %storage_key,
                "Reshare: wrote RingIndexEntry for new-committee node"
            );
        }
    }

    // For fresh DKG: cache the RingPayload locally and append a RingIndexEntry so the
    // PSS scheduler can discover this ring.
    //
    // For Refresh: bulletin entry is unchanged; polynomial updated in RingShareBundle above.
    // For Reshare: bulletin is updated below by new-committee node 1.
    if matches!(kind, SessionKind::Fresh) {
        let peer_ids = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .unwrap_or_default();

        let bulletin_post_id = ring_storage::fresh_ring_index_post_id(
            &coord.app_state,
            &aggregate_pk,
            peer_ids,
            threshold,
            pss_interval,
        )?;
        ring_storage::add_ring_index_entry(&coord.app_state, &storage_key, bulletin_post_id)
            .await?;
    }

    // Clear the in-progress ceremony flag now that Phase 4 has succeeded.
    // For Reshare non-Dealers the bulletin update still happens below (node 1
    // must sign and post), so defer the unmark until after that completes.
    // Error paths are handled by check_and_trigger_phase4 → remove_session.
    if let Some(ring_key) = kind.ring_key() {
        if !matches!(kind, SessionKind::Reshare { .. }) {
            coord
                .app_state
                .dkg_session_state
                .unmark_ring_pss(ring_key)
                .await;
        }
    }

    let ring_pk_bytes = CryptoSerialize::to_bytes(&aggregate_pk).map_err(|e| {
        DkgError::Serialization(format!("Failed to serialize aggregate public key: {}", e))
    })?;

    tracing::info!(
        aggregate_pk = ?aggregate_pk,
        ring_key_hex = hex::encode(&ring_pk_bytes),
        node_id = node_id,
        "Phase 4: DKG complete! Final share computed"
    );

    // Node 1 of the OLD committee posts the RingPayload for fresh DKG.
    if node_id == 1 && matches!(kind, SessionKind::Fresh) {
        ring_storage::post_fresh_ring_payload(
            coord,
            session_id,
            &ring_pk_bytes,
            threshold,
            pss_interval,
        )
        .await?;
    }

    // For Reshare: node 1 of the NEW committee posts the updated RingPayload with the
    // new peer_ids and new threshold. The ring_pk remains the same (same secret).
    reshare::bulletin_update::update_bulletin_if_selector(
        coord,
        session_id,
        &kind,
        dkg_role,
        &storage_key,
        &ring_pk_bytes,
        &pub_poly_bytes,
        reshare_new_peer_ids.as_deref(),
        reshare_bulletin_post_id.as_deref(),
    )
    .await?;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase4Complete)
        .await;

    // All new-committee Reshare nodes defer cleanup to a background task that
    // polls the bulletin until new_peer_ids is cleared, then releases the PSS
    // claim and removes the session. Node 1 already posted the update so its
    // first poll succeeds immediately; non-node-1 nodes wait for node 1 to post.
    // This single path prevents the PSS scheduler from re-triggering a duplicate
    // reshare on any node while node 1 is still signing.
    if matches!(kind, SessionKind::Reshare { .. }) {
        let ring_key = kind.ring_key().map(|k| k.to_string());
        let bulletin_post_id = reshare_bulletin_post_id.clone();
        reshare::cleanup::spawn_bulletin_finalized_cleanup(
            coord.app_state.clone(),
            ring_key,
            session_id,
            bulletin_post_id,
        );
        return Ok(());
    }

    coord.remove_session(session_id).await;
    metrics::record_dkg_session_completed();

    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: Session cleanup complete"
    );

    Ok(())
}
