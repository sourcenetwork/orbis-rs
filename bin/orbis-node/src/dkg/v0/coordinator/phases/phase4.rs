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

    // Reshare PET: fully self-contained, resolving the ring directly by
    // `ring_id` rather than through the main-ring index. Handled before the
    // generic Dealer check below, since a departing PET Dealer's cleanup
    // must not touch the main-ring storage/index machinery
    // `ring_storage::cleanup_departing_dealer` assumes.
    if let SessionKind::ResharePet { ring_id, .. } = &kind {
        return complete_reshare_pet_phase4(coord, attempt, ring_id, dkg_role).await;
    }

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

    // Fresh DKG and reshare produce a usable ring key. The identity is never a
    // valid signing/PRE key: accepting it would make Jubjub Schnorr signatures
    // forgeable. Refresh/RefreshPet are excluded because their delta polynomial
    // intentionally has an identity constant term; the combined key is checked
    // below (Refresh: against the staged key; RefreshPet: no equivalent check
    // exists yet since it isn't staged — see the PET refresh doc comment).
    if !matches!(
        kind,
        SessionKind::Refresh { .. } | SessionKind::RefreshPet { .. }
    ) && D::public_key_is_identity(&aggregate_pk)
    {
        return Err(DkgError::Crypto(
            "DKG produced the identity aggregate public key; aborting before persistence"
                .to_string(),
        ));
    }

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

    // Reshare no longer writes a bundle to disk at this point (it's staged in
    // memory and only promoted after chain confirmation, see below), so there's
    // never anything on disk to roll back if its RingIndexEntry write fails.
    let adds_new_local_ring = is_fresh;
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

    let mut reshare_staged_bundle: Option<RingShareBundle> = None;
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
        let (peer_ids, peer_node_keys) = coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |state| {
                (
                    state.routing.peer_ids.clone(),
                    state.routing.peer_node_keys.clone(),
                )
            })
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
    } else if matches!(kind, SessionKind::Reshare { .. }) {
        // Reshare: stage the newly computed share in memory rather than writing
        // it to disk immediately. For a continuing (DealerReceiver) node, disk
        // still holds the OLD, chain-recognized share; overwriting it now —
        // before the chain has confirmed this reshare — would silently strand
        // this node on unrecognized key material if the finalize never lands
        // (leader crash, partition, or a future cancel). The staged bundle is
        // only written to disk once `wait_for_reshare_bulletin_finalized`
        // observes chain confirmation; see `reshare/cleanup.rs`.
        reshare_staged_bundle = Some(RingShareBundle {
            share_bytes: Zeroizing::new(final_share_bytes.clone()),
            public_polynomial: hex::encode(&pub_poly_bytes),
            last_pss: now_secs,
        });
        None
    } else if let SessionKind::RefreshPet { ring_id } = &kind {
        // PET refresh: no staging/health-check (see the ceremony's own doc
        // comment), but still guard against the same class of drift Refresh's
        // staged-key check catches — a cheating dealer's non-zero-constant-term
        // delta could otherwise silently move the ring's PET checking key.
        // `build_refresh_pet_ring_bundle` doesn't carry a `D` type param to do
        // this itself, so it's done here, symmetrically with Refresh's own
        // external check, just against the old PET key directly (PET's storage
        // key is `ring_id`, not a public-key string, so
        // `public_key_matches_storage_key` doesn't apply).
        let old_pet_bundle =
            RingShareBundle::load_by_pet_ring_key(&coord.app_state.local_storage, ring_id)
                .map_err(|e| {
                    DkgError::Storage(format!("Refresh PET: failed to load old PET bundle: {}", e))
                })?;
        let old_pet_poly_bytes = hex::decode(&old_pet_bundle.public_polynomial).map_err(|e| {
            DkgError::Deserialization(format!(
                "Refresh PET: failed to decode old PET polynomial hex: {}",
                e
            ))
        })?;
        let old_pet_pk = <D::PubPoly>::from_bytes(&old_pet_poly_bytes)
            .map_err(|e| {
                DkgError::Deserialization(format!(
                    "Refresh PET: failed to deserialize old PET polynomial: {}",
                    e
                ))
            })?
            .eval(0);

        let new_bundle = build_refresh_pet_ring_bundle(
            &coord.app_state.local_storage,
            ring_id,
            &final_share_bytes,
            &pub_poly_bytes,
            now_secs,
            session_id,
            |old, delta| D::combine_pub_poly_bytes(old, delta).map_err(|e| e.to_string()),
        )?;
        let new_pet_poly_bytes = hex::decode(&new_bundle.public_polynomial).map_err(|e| {
            DkgError::Deserialization(format!(
                "Refresh PET: failed to decode new PET polynomial hex: {}",
                e
            ))
        })?;
        let new_pet_pk = <D::PubPoly>::from_bytes(&new_pet_poly_bytes)
            .map_err(|e| {
                DkgError::Deserialization(format!(
                    "Refresh PET: failed to deserialize new PET polynomial: {}",
                    e
                ))
            })?
            .eval(0);
        if new_pet_pk.to_string() != old_pet_pk.to_string() {
            return Err(DkgError::Crypto(format!(
                "Refresh PET: combined PET checking key {} does not match the ring's existing \
                 PET key {}; aborting before persistence",
                new_pet_pk, old_pet_pk
            )));
        }

        coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |_| ())
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        new_bundle
            .save_by_pet_ring_key(&coord.app_state.local_storage, ring_id)
            .map_err(|e| {
                DkgError::Storage(format!("Refresh PET: failed to store new bundle: {}", e))
            })?;

        tracing::info!(
            session_id = session_id,
            ring_id = %ring_id,
            "Refresh PET: Phase 4 complete — RingShareBundle updated atomically"
        );
        None
    } else {
        // Fresh DKG only, now: no old material at risk for a brand-new ring, so
        // persisting immediately is fine and intentional (see the fresh_ring_id
        // comment below about orphaned-but-harmless local state).
        //
        // Confirm the attempt is still live before doing the write, but don't
        // hold the session-state lock across it: `persist_ring_bundle` is a
        // synchronous encrypted-storage write, and `with_attempt_state` holds
        // a read lock over the whole session map for the closure's duration,
        // which would stall every other session's write-lock acquisition for
        // as long as the disk write takes.
        coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |_| ())
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
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

        // A requires_pet ring holds this main key locally rather than
        // submitting MsgFinalizeRing on its own: both ceremonies' results are
        // submitted together in one combined finalize once the PET checking
        // key's own ceremony also completes (see the FreshPet branch of this
        // function). Ordinary rings are unaffected.
        let ring_payload =
            read_ring_for_route(&*coord.app_state.bulletin, &ring_id, coord.routes.version)
                .await
                .map_err(DkgError::ProtocolError)?;

        if ring_payload.requires_pet {
            // Only the canonical leader triggers the PET ceremony here. Every
            // participant reaches this same branch independently (each on its
            // own copy of the just-finished main-key `Fresh` ceremony), so
            // without this gate all three would race to call `start_fresh_pet`
            // at once — this was tried and confirmed to produce three separate
            // `PrepareSession`s (same ceremony_id, three different random
            // attempt_ids) for the same ring, none of which ever converges.
            // The other participants don't need to do anything here: they'll
            // receive the leader's `Prepare` broadcast over gossip once it
            // starts, exactly like joining any other ceremony they didn't
            // personally initiate.
            let is_leader = canonical_leader(&ring_payload.peer_node_keys)
                == Some(coord.app_state.node_key.as_str());
            if is_leader {
                start_fresh_pet(coord.app_state.clone(), coord.routes, ring_id.clone())
                    .await
                    .inspect_err(|error| {
                        tracing::error!(
                            ring_id = %ring_id,
                            error = %error,
                            "Phase 4: failed to start the ring's PET checking-key ceremony after \
                             the main key completed locally. This node holds a valid main-key \
                             share and index entry but has not submitted the (deferred, combined) \
                             finalize. The ring will remain pending until another participant \
                             retries or operator intervention. Local state is preserved."
                        );
                    })?;
            }
        } else {
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
    }

    // The PET checking key's own ceremony completing is where the deferred,
    // combined finalize actually gets submitted — covering both keys in one
    // MsgFinalizeRing. See the `requires_pet` branch above, which triggered
    // this ceremony instead of finalizing the main key on its own.
    if let SessionKind::FreshPet { ring_id } = &kind {
        match ring_storage::local_ring_pk_by_ring_id(&coord.app_state.local_storage, ring_id) {
            Ok(Some(main_ring_pk_str)) => {
                // `main_ring_pk_str` is `aggregate_pk.to_string()` — the local
                // storage key for the main key's `RingShareBundle`, not a hex
                // encoding of the key itself. Load the bundle and re-derive
                // the actual public key bytes (its public polynomial's
                // constant term) for the on-chain payload.
                let main_bundle = RingShareBundle::load_by_ring_key(
                    &coord.app_state.local_storage,
                    &main_ring_pk_str,
                )
                .map_err(DkgError::Bulletin)?;
                let main_pub_poly_bytes =
                    hex::decode(&main_bundle.public_polynomial).map_err(|e| {
                        DkgError::Deserialization(format!(
                            "FreshPet: failed to decode main key's stored public polynomial: {}",
                            e
                        ))
                    })?;
                let main_pub_poly =
                    <D::PubPoly>::from_bytes(&main_pub_poly_bytes).map_err(|e| {
                        DkgError::Deserialization(format!(
                        "FreshPet: failed to deserialize main key's stored public polynomial: {}",
                        e
                    ))
                    })?;
                let main_ring_pk_bytes = CryptoSerialize::to_bytes(&main_pub_poly.eval(0))
                    .map_err(|e| {
                        DkgError::Serialization(format!(
                            "FreshPet: failed to serialize main key: {}",
                            e
                        ))
                    })?;
                let main_ring_pk_hex = hex::encode(&main_ring_pk_bytes);
                ring_storage::post_fresh_pet_ring_finalization(
                    coord,
                    ring_id,
                    &main_ring_pk_hex,
                    &ring_pk_bytes,
                )
                .await
                .inspect_err(|error| {
                    tracing::error!(
                        ring_id = %ring_id,
                        main_ring_pk = %main_ring_pk_hex,
                        pet_pk = %hex::encode(&ring_pk_bytes),
                        error = %error,
                        "Phase 4: combined FinalizeRing chain post failed after local state \
                         was written. This node holds a valid PET-key share and index entry \
                         but has not confirmed on-chain. The ring will remain pending until \
                         another participant retries or operator intervention. Local state \
                         is preserved."
                    );
                })?;
            }
            Ok(None) => {
                tracing::error!(
                    ring_id = %ring_id,
                    pet_pk = %hex::encode(&ring_pk_bytes),
                    "Phase 4: PET checking-key ceremony completed locally, but this node has \
                     no local record of the ring's main key — cannot submit the combined \
                     finalize yet. This node holds a valid PET-key share; the ring will \
                     remain pending until this node's own main-key ceremony result is \
                     available (or operator intervention)."
                );
                return Err(DkgError::Bulletin(format!(
                    "Fresh PET DKG for ring {} completed locally with no local main-key record",
                    ring_id
                )));
            }
            Err(error) => return Err(error),
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
    //
    // `Fresh` never claims a ring_pss slot in the first place (session_init's
    // claim is gated on `kind.ring_key()`, which is `None` for `Fresh` — there
    // is no existing ring to protect against a concurrent refresh/reshare
    // before its key exists), so this branch is unreachable for it; that's
    // pre-existing, not something this change alters. `FreshPet` does claim
    // one (keyed by `ring_id`, same session_init path, now extended for free)
    // as a cheap safety net against an accidental duplicate PET ceremony for
    // the same ring, so it must release it here — immediately, the same as
    // this branch already does for Refresh's non-deferred cases, since
    // FreshPet has no "bulletin update below" step to wait for.
    if let Some(ring_key) = kind.ring_key() {
        if matches!(kind, SessionKind::Fresh | SessionKind::FreshPet { .. }) {
            coord
                .app_state
                .dkg_session_state
                .unmark_ring_pss_for_attempt(ring_key, attempt)
                .await;
        }
    }

    // For Reshare: node 1 of the NEW committee posts the updated RingPayload with the
    // new peer_ids and new threshold. The ring_pk remains the same (same secret).
    // Every non-Dealer node (not just node 1) gets back what it needs to later
    // promote or discard its own staged bundle once chain confirmation lands.
    let reshare_readiness = reshare::bulletin_update::update_bulletin_if_selector(
        coord,
        attempt,
        &kind,
        dkg_role,
        &storage_key,
        &ring_pk_bytes,
        &pub_poly_bytes,
        reshare_new_peer_node_keys.as_deref(),
        reshare_bulletin_post_id.as_deref(),
        reshare_staged_bundle,
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
    // reshare on any node while node 1 is still signing. It's also where each
    // node's own staged bundle gets promoted to disk (or discarded) — see
    // `reshare/cleanup.rs`.
    if matches!(kind, SessionKind::Reshare { .. }) {
        // dkg_role is Receiver or DealerReceiver here (Dealer already
        // returned at the top of this function), so update_bulletin_if_selector
        // always computes readiness info for a non-Dealer Reshare kind.
        let info = reshare_readiness.ok_or_else(|| {
            DkgError::InvalidState(
                "Reshare: non-Dealer node completed Phase 4 without readiness info from \
                 update_bulletin_if_selector"
                    .to_string(),
            )
        })?;
        let ring_key = kind.ring_key().map(|k| k.to_string());
        let bulletin_post_id = reshare_bulletin_post_id.clone();
        reshare::cleanup::spawn_bulletin_finalized_cleanup(
            coord.app_state.clone(),
            ring_key,
            attempt,
            bulletin_post_id,
            reshare::cleanup::ReshareCleanupOutcome::ContinuingCommittee(info),
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

/// Phase 4 completion for a ring's independent PET checking key's `Reshare`.
/// Stage 2 of the PSS-for-PET-key plan — deliberately simpler than the main
/// ring's own `Reshare` completion (`initiate_phase4_completion`'s Reshare
/// path, `reshare/bulletin_update.rs`, `reshare/cleanup.rs`): there is no
/// confirmation-driven promotion yet (that's Stage 3, gated on when the main
/// ring's own reshare bulletin update — deferred until this ceremony also
/// completes — actually confirms), so this only stages the result and
/// completes the attempt. A departing Dealer's old PET share is left in
/// place untouched; a stale, never-promoted `PendingReshareBundle` for an
/// abandoned attempt is superseded (never double-applied) by any later
/// attempt's own staging write, the same reasoning `RefreshPet`'s own
/// drift check relies on.
async fn complete_reshare_pet_phase4<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    ring_id: &str,
    dkg_role: DkgRole,
) -> Result<()>
where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();

    if dkg_role == DkgRole::Dealer {
        coord
            .app_state
            .dkg_session_state
            .update_phase_for_attempt(attempt, DkgPhase::Phase4Complete)
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        coord
            .app_state
            .dkg_session_state
            .unmark_ring_pss_for_attempt(ring_id, attempt)
            .await;
        coord
            .app_state
            .dkg_session_state
            .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
            .await;
        tracing::info!(
            session_id = session_id,
            ring_id = %ring_id,
            "Reshare PET Dealer: share distribution complete; old PET share retained \
             (Stage 2 — no confirmation-driven cleanup yet)"
        );
        return Ok(());
    }

    let (aggregate_pk, final_share_bytes, pub_poly_bytes) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            let final_share = state.node.compute_secret_share().map_err(|e| {
                DkgError::Crypto(format!(
                    "Reshare PET: failed to compute secret share: {}",
                    e
                ))
            })?;
            let aggregate_pk = state.node.compute_aggregate_public_key().map_err(|e| {
                DkgError::Crypto(format!(
                    "Reshare PET: failed to compute aggregate public key: {}",
                    e
                ))
            })?;
            let final_share_bytes = CryptoSerialize::to_bytes(&final_share).map_err(|e| {
                DkgError::Serialization(format!(
                    "Reshare PET: failed to serialize final share: {}",
                    e
                ))
            })?;
            let pub_poly = state.node.compute_public_polynomial().map_err(|e| {
                DkgError::Crypto(format!(
                    "Reshare PET: failed to compute public polynomial: {}",
                    e
                ))
            })?;
            let pub_poly_bytes = CryptoSerialize::to_bytes(&pub_poly).map_err(|e| {
                DkgError::Serialization(format!(
                    "Reshare PET: failed to serialize public polynomial: {}",
                    e
                ))
            })?;
            Ok::<_, DkgError>((aggregate_pk, final_share_bytes, pub_poly_bytes))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    if D::public_key_is_identity(&aggregate_pk) {
        return Err(DkgError::Crypto(
            "Reshare PET produced the identity checking key; aborting before persistence"
                .to_string(),
        ));
    }

    // Drift/equivocation guard, mirroring main Reshare's own
    // `public_key_matches_storage_key` check: the newly redistributed
    // checking key must equal the ring's known one. Unlike the main key
    // (whose identity string is already known from the wire, no bulletin
    // read needed), PET's only known-good identity is the bulletin's own
    // `pet_pk` — fetched fresh here rather than threaded through session
    // state, mirroring how `FreshPet`'s own phase4 branch already reads the
    // bulletin directly at completion time.
    let ring = read_ring_for_route(&*coord.app_state.bulletin, ring_id, coord.routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let old_pet_pk_hex = ring.pet_pk.clone().ok_or_else(|| {
        DkgError::InvalidState(format!(
            "Reshare PET: ring {} has no pet_pk on the bulletin at Phase 4 completion",
            ring_id
        ))
    })?;
    let new_pet_pk_bytes = CryptoSerialize::to_bytes(&aggregate_pk).map_err(|e| {
        DkgError::Serialization(format!(
            "Reshare PET: failed to serialize new checking key: {}",
            e
        ))
    })?;
    let new_pet_pk_hex = hex::encode(&new_pet_pk_bytes);
    if new_pet_pk_hex != old_pet_pk_hex {
        return Err(DkgError::Crypto(format!(
            "Reshare PET: computed checking key {} does not match the ring's existing PET key \
             {}; aborting before persisting staged bundle",
            new_pet_pk_hex, old_pet_pk_hex
        )));
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (expected_new_committee, expected_new_threshold) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            state
                .reshare
                .params
                .as_ref()
                .map(|p| (p.new_peer_node_keys.clone(), p.new_threshold as u32))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::InvalidState("Reshare PET session missing reshare_params".to_string())
        })?;

    let pending = PendingReshareBundle {
        bundle: RingShareBundle {
            share_bytes: Zeroizing::new(final_share_bytes),
            public_polynomial: hex::encode(&pub_poly_bytes),
            last_pss: now_secs,
        },
        bulletin_post_id: ring_id.to_string(),
        expected_new_committee,
        expected_new_threshold,
    };
    pending
        .save_pet(&coord.app_state.local_storage, ring_id)
        .map_err(|e| {
            DkgError::Storage(format!("Reshare PET: failed to stage new bundle: {}", e))
        })?;

    coord
        .app_state
        .dkg_session_state
        .update_phase_for_attempt(attempt, DkgPhase::Phase4Complete)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    coord
        .app_state
        .dkg_session_state
        .unmark_ring_pss_for_attempt(ring_id, attempt)
        .await;
    coord
        .app_state
        .dkg_session_state
        .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
        .await;

    tracing::info!(
        session_id = session_id,
        ring_id = %ring_id,
        "Reshare PET: Phase 4 complete — new PET bundle staged (not yet promoted; Stage 3 \
         of the PSS-for-PET-key plan adds confirmation-driven promotion)"
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
