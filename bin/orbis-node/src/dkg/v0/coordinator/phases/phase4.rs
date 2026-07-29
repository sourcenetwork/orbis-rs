use super::*;

pub async fn check_and_trigger_phase4<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    drive_event(coord, attempt, DkgEvent::ReadinessChanged, None).await
}
pub async fn initiate_phase4_completion<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: Starting Phase 4 completion"
    );

    let (kind, dkg_role, reshare_new_peer_node_keys, reshare_bulletin_post_id) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            (
                state.kind.clone(),
                state.node.role(),
                state
                    .reshare
                    .params
                    .as_ref()
                    .map(|p| p.new_peer_node_keys.clone()),
                state
                    .reshare
                    .params
                    .as_ref()
                    .map(|p| p.bulletin_post_id.clone()),
            )
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    // Pure Dealer nodes don't compute a secret share — they just clean up.
    // Because they are leaving the ring, delete the local secret share and
    // remove the ring from the index so the PSS scheduler ignores it.
    if dkg_role == DkgRole::Dealer {
        let ring_key = kind.ring_key().map(|k| k.to_string());
        return ring_storage::cleanup_departing_dealer(coord, attempt, ring_key).await;
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
        .with_attempt_state(attempt, |state| {
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
        .map_err(|error| attempt_state_error(attempt, error))??;

    // Compute storage_key — the canonical local-storage key used by sign/pre for share lookup.
    // For Refresh and Reshare this is the ORIGINAL ring's key (unchanged secret → same pk).
    let storage_key = kind
        .ring_key()
        .map(|k| k.to_string())
        .unwrap_or_else(|| aggregate_pk.to_string());

    if matches!(kind, SessionKind::Reshare { .. })
        && !public_key_matches_storage_key(&aggregate_pk, &storage_key)
    {
        // Equivocation-consistent failure: reveal our received commitments so peers can
        // attribute an equivocating dealer (diagnostic; the ceremony aborts regardless).
        if let Err(error) = broadcast_commitment_audit(coord, attempt).await {
            tracing::debug!(
                session_id = session_id,
                error = %error,
                "DKG Coordinator: failed to broadcast commitment-audit reveal"
            );
        }
        return Err(DkgError::Crypto(format!(
            "Reshare: computed aggregate public key {} does not match the ring's existing key {}; \
             aborting before persisting shifted ring state",
            aggregate_pk, storage_key
        )));
    }

    let adds_new_local_ring = is_fresh || is_reshare_receiver;
    if is_fresh {
        ring_storage::preflight_new_ring_capacity(&coord.app_state, &storage_key).await?;
    }
    let fresh_ring_id = if is_fresh {
        let ring_id = coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |state| state.routing.ring_id.clone())
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        if ring_id.is_empty() {
            return Err(DkgError::Bulletin(format!(
                "Fresh DKG session {} is missing ring_id",
                session_id
            )));
        }
        Some(ring_id)
    } else {
        None
    };

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
        // A refresh must not change the ring's public key. Received refresh commitments
        // are individually checked for an identity constant term, but this end-to-end
        // guard catches any residual drift before the candidate is staged — the health
        // check verifies self-consistently under the *staged* key and cannot see a shift.
        let staged_pk = staged_pub_poly.eval(0);
        if !public_key_matches_storage_key(&staged_pk, &storage_key) {
            // Equivocation-consistent failure: reveal received commitments for attribution.
            if let Err(error) = broadcast_commitment_audit(coord, attempt).await {
                tracing::debug!(
                    session_id = session_id,
                    error = %error,
                    "DKG Coordinator: failed to broadcast commitment-audit reveal"
                );
            }
            return Err(DkgError::Crypto(format!(
                "Refresh: staged ring public key {} does not match the ring's existing key {}; \
                 aborting refresh before staging",
                staged_pk, storage_key
            )));
        }
        ring_pk_bytes = CryptoSerialize::to_bytes(&staged_pk).map_err(|e| {
            DkgError::Serialization(format!(
                "Refresh: failed to serialize staged aggregate public key: {}",
                e
            ))
        })?;
        let peer_ids = coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |state| state.routing.peer_ids.clone())
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        let peer_node_keys = coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |state| state.routing.peer_node_keys.clone())
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        if peer_node_keys.is_empty() {
            return Err(DkgError::InvalidState(format!(
                "Refresh Phase 4 session {} has empty peer_node_keys",
                session_id
            )));
        }
        let candidate = RefreshHealthCheckCandidate {
            ring_key: storage_key.clone(),
            ring_pk_hex: hex::encode(&ring_pk_bytes),
            bundle: staged_bundle,
            peer_node_keys,
            peer_ids,
            threshold,
        };
        coord
            .app_state
            .dkg_session_state
            .with_attempt_state_mut(attempt, |state| {
                state.refresh.candidate = Some(candidate.clone())
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        tracing::info!(
            session_id = session_id,
            ring_key = %storage_key,
            "Refresh: staged RingShareBundle pending health-check result"
        );
        refresh_health_check::apply_pending_result_if_present(coord, attempt).await?;
        Some(candidate)
    } else {
        coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |_| {
                persist_ring_bundle(
                    &coord.app_state.local_storage,
                    &kind,
                    &final_share_bytes,
                    &pub_poly_bytes,
                    &aggregate_pk,
                    now_secs,
                    session_id,
                    |old, delta| D::combine_pub_poly_bytes(old, delta).map_err(|e| e.to_string()),
                )
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))??;

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
            ring_storage::add_ring_index_entry(&coord.app_state, &storage_key, post_id.clone())
                .await
                .inspect_err(|_| {
                    cleanup_new_ring_bundle_after_index_failure(
                        &coord.app_state.local_storage,
                        &storage_key,
                        adds_new_local_ring,
                    );
                })?;
            tracing::info!(
                session_id = session_id,
                ring_pk = %storage_key,
                "Reshare: wrote RingIndexEntry for new-committee node"
            );
        }
    }

    // For fresh DKG: write the RingIndexEntry first, then confirm on the bulletin.
    // Writing the index before the chain post means that if the chain post fails,
    // the node still has its share and index entry intact — the orphaned entry is
    // harmless (PSS will reconcile it) and is far better than the inverse: having
    // confirmed on-chain while the local state was cleaned up.
    // For Refresh: bulletin entry is unchanged; polynomial updated in RingShareBundle above.
    // For Reshare: bulletin is updated below by new-committee node 1.
    if let Some(ring_id) = fresh_ring_id {
        ring_storage::add_ring_index_entry(&coord.app_state, &storage_key, ring_id.clone())
            .await
            .inspect_err(|_| {
                cleanup_new_ring_bundle_after_index_failure(
                    &coord.app_state.local_storage,
                    &storage_key,
                    adds_new_local_ring,
                );
            })?;

        ring_storage::post_fresh_ring_finalization(coord, &ring_id, &ring_pk_bytes)
            .await
            .inspect_err(|error| {
                tracing::error!(
                    ring_id = %ring_id,
                    ring_pk = %hex::encode(&ring_pk_bytes),
                    error = %error,
                    "Phase 4: FinalizeRing chain post failed after local state was written. \
                     This node holds a valid share and index entry but has not confirmed \
                     on-chain. The ring will remain pending until another participant \
                     retries or operator intervention. Local state is preserved."
                );
            })?;
    }

    tracing::info!(
        aggregate_pk = ?aggregate_pk,
        ring_key_hex = hex::encode(&ring_pk_bytes),
        node_id = node_id,
        "Phase 4: DKG complete! Final share computed"
    );

    if let Some(candidate) = refresh_candidate {
        if node_id == 1 {
            let _ = refresh_health_check::run_selector(coord, attempt, &ring_pk_bytes, &candidate)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        session_id = session_id,
                        error = %error,
                        "Refresh health check selector failed"
                    );
                });
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
                .unmark_ring_pss_for_attempt(ring_key, attempt)
                .await;
        }
    }

    // For Reshare: node 1 of the NEW committee posts the updated RingPayload with the
    // new peer_ids and new threshold. The ring_pk remains the same (same secret).
    reshare::bulletin_update::update_bulletin_if_selector(
        coord,
        attempt,
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
        .update_phase_for_attempt(attempt, DkgPhase::Phase4Complete)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

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
            attempt,
            bulletin_post_id,
            false,
        );
        return Ok(());
    }

    coord
        .app_state
        .dkg_session_state
        .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
        .await;

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

    let _ = storage
        .delete(LocalStorageKeys::RingKey(storage_key.to_string()))
        .inspect_err(|error| {
            tracing::error!(
                ring_key = %storage_key,
                error = %error,
                "Phase 4: failed to delete new RingShareBundle after RingIndex write failure"
            );
        });
}

/// Best-effort: on an equivocation-consistent phase4 failure, reveal the signed
/// commitments this node received to the other receivers, who compare them against
/// their own to attribute an equivocating dealer. Diagnostic only — never changes the
/// abort outcome, and send failures are ignored.
async fn broadcast_commitment_audit<D>(coord: &DkgCoordinator<D>, attempt: AttemptKey) -> Result<()>
where
    D: CoordinatorDkg + Send + Sync,
{
    let revealed = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            state
                .commitment_audit
                .received_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    if revealed.is_empty() {
        return Ok(());
    }

    submit_public_contribution(
        coord,
        attempt,
        DkgPublicPayload::CommitmentAudit { revealed },
    )
    .await
}
