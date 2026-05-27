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

    let (
        kind,
        pss_interval,
        policy_id,
        dkg_role,
        reshare_new_peer_node_keys,
        reshare_bulletin_post_id,
    ) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (
                state.kind.clone(),
                state.pss_interval,
                state.policy_id.clone(),
                state.node.role(),
                state
                    .reshare_params
                    .as_ref()
                    .map(|p| p.new_peer_node_keys.clone()),
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

    let is_fresh = matches!(kind, SessionKind::Fresh);
    let is_reshare_receiver =
        matches!(kind, SessionKind::Reshare { .. }) && dkg_role == DkgRole::Receiver;
    if is_reshare_receiver {
        let storage_key = kind
            .ring_key()
            .ok_or_else(|| DkgError::InvalidState("Reshare session missing ring key".to_string()))?
            .to_string();
        ring_storage::preflight_new_ring_capacity(&coord.app_state, &storage_key).await?;
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

    let adds_new_local_ring = is_fresh || is_reshare_receiver;
    if is_fresh {
        ring_storage::preflight_new_ring_capacity(&coord.app_state, &storage_key).await?;
    }

    // Write share + polynomial as a single encrypted bundle.
    // Atomicity: both fields land in one set_encrypted call, so a crash leaves the
    // entry either fully written or absent — never partially updated.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut ring_pk_bytes = CryptoSerialize::to_bytes(&aggregate_pk).map_err(|e| {
        DkgError::Serialization(format!("Failed to serialize aggregate public key: {}", e))
    })?;

    let refresh_candidate = if matches!(kind, SessionKind::Refresh { .. }) {
        let staged_bundle = build_refresh_ring_bundle(
            &coord.app_state.local_storage,
            &storage_key,
            &final_share_bytes,
            &pub_poly_bytes,
            now_secs,
            session_id,
            |old, delta| D::combine_pub_poly_bytes(old, delta).map_err(|e| e.to_string()),
        )?;
        let staged_pub_poly_bytes = hex::decode(&staged_bundle.public_polynomial).map_err(|e| {
            DkgError::Deserialization(format!(
                "Refresh: failed to decode staged public polynomial: {}",
                e
            ))
        })?;
        let staged_pub_poly = <D::PubPoly>::from_bytes(&staged_pub_poly_bytes).map_err(|e| {
            DkgError::Deserialization(format!(
                "Refresh: failed to deserialize staged public polynomial: {}",
                e
            ))
        })?;
        ring_pk_bytes = CryptoSerialize::to_bytes(&staged_pub_poly.eval(0)).map_err(|e| {
            DkgError::Serialization(format!(
                "Refresh: failed to serialize staged aggregate public key: {}",
                e
            ))
        })?;
        let peer_ids = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .unwrap_or_default();
        let candidate = RefreshHealthCheckCandidate {
            ring_key: storage_key.clone(),
            ring_pk_hex: hex::encode(&ring_pk_bytes),
            bundle: staged_bundle,
            peer_node_keys: coord
                .app_state
                .dkg_session_state
                .get_peer_node_keys(&session_id)
                .await
                .unwrap_or_default(),
            peer_ids,
            threshold,
        };
        coord
            .app_state
            .dkg_session_state
            .set_refresh_health_check_candidate(&session_id, candidate.clone())
            .await;
        tracing::info!(
            session_id = session_id,
            ring_key = %storage_key,
            "Refresh: staged RingShareBundle pending health-check result"
        );
        Some(candidate)
    } else {
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
        None
    };

    // For Reshare: write a RingIndexEntry so the PSS scheduler can discover this ring.
    // Receiver and DealerReceiver nodes use the bulletin_post_id carried in the SessionInit
    // (they had no prior index entry).  Dealers have already left and skip this entirely.
    if matches!(kind, SessionKind::Reshare { .. }) && dkg_role != DkgRole::Dealer {
        if let Some(post_id) = &reshare_bulletin_post_id {
            if let Err(e) =
                ring_storage::add_ring_index_entry(&coord.app_state, &storage_key, post_id.clone())
                    .await
            {
                cleanup_new_ring_bundle_after_index_failure(
                    &coord.app_state.local_storage,
                    &storage_key,
                    adds_new_local_ring,
                );
                return Err(e);
            }
            tracing::info!(
                session_id = session_id,
                ring_pk = %storage_key,
                "Reshare: wrote RingIndexEntry for new-committee node"
            );
        }
    }

    // For fresh DKG: post the RingPayload to the bulletin (node 1 only) and write a
    // RingIndexEntry on all nodes so the PSS scheduler can discover this ring.
    //
    // Node 1 posts first so the chain-assigned ring_id can be read from the tx
    // response; all other nodes compute the ring_id locally via generate_ring_id.
    //
    // For Refresh: bulletin entry is unchanged; polynomial updated in RingShareBundle above.
    // For Reshare: bulletin is updated below by new-committee node 1.
    if is_fresh {
        let bulletin_post_id = if node_id == 1 {
            // Post to the chain
            ring_storage::post_fresh_ring_payload(
                coord,
                session_id,
                &ring_pk_bytes,
                threshold,
                pss_interval,
                policy_id.clone(),
            )
            .await?
        } else {
            // Non-selector nodes use the pre-created ring_id carried through SessionInit.
            coord
                .app_state
                .dkg_session_state
                .get_ring_id(&session_id)
                .await
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    DkgError::Bulletin("Fresh DKG session is missing ring_id".to_string())
                })?
        };

        if let Err(e) =
            ring_storage::add_ring_index_entry(&coord.app_state, &storage_key, bulletin_post_id)
                .await
        {
            cleanup_new_ring_bundle_after_index_failure(
                &coord.app_state.local_storage,
                &storage_key,
                adds_new_local_ring,
            );
            return Err(e);
        }
    }

    tracing::info!(
        aggregate_pk = ?aggregate_pk,
        ring_key_hex = hex::encode(&ring_pk_bytes),
        node_id = node_id,
        "Phase 4: DKG complete! Final share computed"
    );

    if let Some(candidate) = refresh_candidate {
        if node_id == 1 {
            if let Err(e) =
                refresh_health_check::run_selector(coord, session_id, &ring_pk_bytes, &candidate)
                    .await
            {
                tracing::warn!(
                    session_id = session_id,
                    error = %e,
                    "Refresh health check selector failed"
                );
            }
        } else {
            tracing::info!(
                session_id = session_id,
                "Refresh: waiting for node 1 health-check result before promoting staged bundle"
            );
        }
        return Ok(());
    }

    // Clear the in-progress ceremony flag now that Phase 4 has succeeded.
    // For Reshare non-Dealers the bulletin update still happens below (node 1
    // must sign and post), so defer the unmark until after that completes.
    // Error paths are handled by check_and_trigger_phase4 → remove_session.
    if let Some(ring_key) = kind.ring_key() {
        if matches!(kind, SessionKind::Fresh) {
            coord
                .app_state
                .dkg_session_state
                .unmark_ring_pss(ring_key)
                .await;
        }
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
        reshare_new_peer_node_keys.as_deref(),
        reshare_bulletin_post_id.as_deref(),
    )
    .await?;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase4Complete)
        .await;

    // All new-committee Reshare nodes defer cleanup to a background task that
    // polls the bulletin until new_peer_node_keys is cleared, then releases the PSS
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
    if matches!(kind, SessionKind::Refresh { .. }) {
        metrics::record_refresh_session_completed();
    }

    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: Session cleanup complete"
    );

    Ok(())
}

fn cleanup_new_ring_bundle_after_index_failure(
    storage: &impl LocalStorage,
    storage_key: &str,
    should_cleanup: bool,
) {
    if !should_cleanup {
        return;
    }

    if let Err(e) = storage.delete(LocalStorageKeys::RingKey(storage_key.to_string())) {
        tracing::error!(
            ring_key = %storage_key,
            error = %e,
            "Phase 4: failed to delete new RingShareBundle after RingIndex write failure"
        );
    }
}
