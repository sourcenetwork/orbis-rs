use super::*;

/// Handle a `DkgMessage::SessionInit`.
///
/// Validates the session kind (Fresh/Refresh/Reshare), assigns this node's role
/// and node_id, and creates the session if it does not already exist.
/// For Fresh/Refresh, when this handler creates the session and this node is
/// `node_id == 1`, it also calls `initiate_phase1_commitments` so the protocol
/// starts even if the gRPC initiator is not a participant.
/// Returns `Ok(None)` — the caller should return this directly from `handle_message`.
pub(in crate::dkg::coordinator) async fn handle_session_init<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    threshold: u32,
    total_participants: u32,
    peer_ids: &[String],
    node_id_assignments: &HashMap<String, u32>,
    token_string: &str,
    kind: &SessionKind,
    pss_interval: Option<u64>,
    policy_id: Option<String>,
    namespace: String,
    sender_peer_id: &PeerId,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    let sender_hex = hex::encode(sender_peer_id.as_bytes());
    let mut pss_claim: Option<&str> = None;

    match kind {
        SessionKind::Refresh { ring_pk_hex } => {
            tracing::info!(
                session_id = session_id,
                ring_pk_hex = %ring_pk_hex,
                sender_peer_hex = %sender_hex,
                "DKG Coordinator: Refresh SessionInit received - pre-validation"
            );
            validate_refresh_session_init(
                ring_pk_hex,
                &sender_hex,
                &coord.app_state.local_storage,
                &coord.app_state.bulletin,
            )
            .await?;

            let ring_payload = load_refresh_ring_payload(
                ring_pk_hex,
                &coord.app_state.local_storage,
                &coord.app_state.bulletin,
            )
            .await?;

            if !peers::same_peer_set(peer_ids, &ring_payload.peer_ids) {
                return Err(DkgError::Unauthorized(format!(
                    "Refresh peer_ids do not match authoritative committee for ring {}",
                    ring_pk_hex
                )));
            }
            if threshold != ring_payload.threshold {
                return Err(DkgError::Unauthorized(format!(
                    "Refresh threshold {} does not match authoritative threshold {} for ring {}",
                    threshold, ring_payload.threshold, ring_pk_hex
                )));
            }
            if total_participants as usize != ring_payload.peer_ids.len() {
                return Err(DkgError::Unauthorized(format!(
                    "Refresh total_participants {} does not match authoritative committee size {} for ring {}",
                    total_participants,
                    ring_payload.peer_ids.len(),
                    ring_pk_hex
                )));
            }

            let bundle =
                RingShareBundle::load_by_ring_key(&coord.app_state.local_storage, ring_pk_hex)
                    .map_err(|e| {
                        DkgError::Unauthorized(format!(
                            "Refresh session validation requires current ring bundle for {}: {}",
                            ring_pk_hex, e
                        ))
                    })?;
            let expected_session_id = derive_refresh_session_id(
                ring_pk_hex,
                &ring_payload.peer_ids,
                ring_payload.threshold,
                &bundle.public_polynomial,
            );
            if session_id != expected_session_id {
                return Err(DkgError::Unauthorized(format!(
                    "Refresh session_id mismatch for ring {}: expected {}, got {}",
                    ring_pk_hex, expected_session_id, session_id
                )));
            }

            pss_claim = Some(ring_pk_hex.as_str());
        }
        SessionKind::Reshare {
            ring_pk_hex,
            new_peer_ids: reshare_new_peer_ids,
            new_threshold: reshare_new_threshold,
            bulletin_post_id: reshare_bulletin_post_id,
        } => {
            tracing::info!(
                session_id = session_id,
                ring_pk_hex = %ring_pk_hex,
                sender_peer_hex = %sender_hex,
                "DKG Coordinator: Reshare SessionInit received - pre-validation"
            );
            validate_reshare_session_init(
                ring_pk_hex,
                &sender_hex,
                reshare_new_peer_ids,
                *reshare_new_threshold,
                reshare_bulletin_post_id,
                &namespace,
                &coord.app_state.local_storage,
                &coord.app_state.bulletin,
            )
            .await?;

            let ring_payload = load_reshare_ring_payload(
                ring_pk_hex,
                reshare_bulletin_post_id,
                &namespace,
                &coord.app_state.local_storage,
                &coord.app_state.bulletin,
            )
            .await?;

            if !peers::same_peer_set(peer_ids, &ring_payload.peer_ids) {
                return Err(DkgError::Unauthorized(format!(
                    "Reshare old peer_ids do not match authoritative committee for ring {}",
                    ring_pk_hex
                )));
            }
            if threshold != ring_payload.threshold {
                return Err(DkgError::Unauthorized(format!(
                    "Reshare old threshold {} does not match authoritative threshold {} for ring {}",
                    threshold, ring_payload.threshold, ring_pk_hex
                )));
            }
            if total_participants as usize != ring_payload.peer_ids.len() {
                return Err(DkgError::Unauthorized(format!(
                    "Reshare total_participants {} does not match authoritative committee size {} for ring {}",
                    total_participants,
                    ring_payload.peer_ids.len(),
                    ring_pk_hex
                )));
            }

            if let Ok(bundle) =
                RingShareBundle::load_by_ring_key(&coord.app_state.local_storage, ring_pk_hex)
            {
                let authoritative_new_peer_ids = ring_payload
                    .new_peer_ids
                    .clone()
                    .unwrap_or_else(|| ring_payload.peer_ids.clone());
                let authoritative_new_threshold =
                    ring_payload.new_threshold.unwrap_or(ring_payload.threshold);
                let expected_session_id = derive_reshare_session_id(
                    ring_pk_hex,
                    reshare_bulletin_post_id,
                    &ring_payload.peer_ids,
                    &authoritative_new_peer_ids,
                    authoritative_new_threshold,
                    &bundle.public_polynomial,
                );
                if session_id != expected_session_id {
                    return Err(DkgError::Unauthorized(format!(
                        "Reshare session_id mismatch for ring {}: expected {}, got {}",
                        ring_pk_hex, expected_session_id, session_id
                    )));
                }
            }

            tracing::info!(
                session_id = session_id,
                ring_pk = %ring_pk_hex,
                sender_peer_hex = %sender_hex,
                "DKG Coordinator: Reshare SessionInit validated"
            );

            pss_claim = Some(ring_pk_hex.as_str());
        }
        SessionKind::Fresh => {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
                .as_secs();
            let token: BearerToken<DkgClaims> = resolve_jwt_did(
                token_string,
                current_time,
                MAX_TOKEN_LIFETIME_SECS,
                MAX_JWT_BYTES,
            )
            .map_err(|e| DkgError::Unauthorized(format!("JWT validation failed: {}", e)))?;
            validate_dkg_claims(
                &token,
                threshold,
                peer_ids,
                pss_interval,
                policy_id.as_deref(),
                &namespace,
            )?;
            tracing::info!(
                issuer = %token.issuer_id,
                threshold = threshold,
                policy_id = ?policy_id,
                "DKG Coordinator: SessionInit JWT validated successfully"
            );
        }
    }

    let canonical_node_id_assignments =
        peers::validate_node_id_assignments(peer_ids, node_id_assignments)?;

    let our_peer_id_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    // For Reshare, determine role and node_id from committee membership rather than
    // looking up node_id_assignments (which only covers the old committee).
    let (assigned_node_id, dkg_role, maybe_reshare_params) = if let SessionKind::Reshare {
        ring_pk_hex,
        new_peer_ids,
        new_threshold,
        bulletin_post_id,
    } = kind
    {
        // build_reshare_params errors if this node is not in either committee.
        let (node_id, role, params) = build_reshare_params(
            ring_pk_hex,
            peer_ids,
            new_peer_ids,
            *new_threshold,
            bulletin_post_id,
            &our_node_part,
            &coord.app_state.local_storage,
        )?;

        (node_id, role, Some(params))
    } else {
        // Fresh / Refresh: look up our node_id from the locally verified canonical assignments.
        let our_peer_id_key = our_peer_id_hex
            .split('@')
            .next()
            .unwrap_or(&our_peer_id_hex)
            .to_string();
        let node_id = canonical_node_id_assignments
            .get(&our_peer_id_key)
            .copied()
            .ok_or_else(|| {
                DkgError::InvalidInput(format!(
                    "Could not find our node_id in SessionInit. \
                         Our peer_id: {}, assignments: {:?}",
                    our_peer_id_key,
                    canonical_node_id_assignments.keys().collect::<Vec<_>>()
                ))
            })?;
        (node_id, DkgRole::Standard, None)
    };

    if let Some(ring_key) = pss_claim {
        match coord
            .app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_key, session_id)
            .await
        {
            RingPssClaimOutcome::Claimed => {
                tracing::info!(
                    session_id = session_id,
                    ring_key = %ring_key,
                    "DKG Coordinator: Claimed active PSS session for ring"
                );
            }
            RingPssClaimOutcome::AlreadyClaimedBySameSession => {
                tracing::debug!(
                    session_id = session_id,
                    ring_key = %ring_key,
                    "DKG Coordinator: Duplicate SessionInit for same PSS session"
                );
            }
            RingPssClaimOutcome::Conflict { active_session_id } => {
                return Err(DkgError::Unauthorized(format!(
                    "Ring {} already has conflicting in-progress PSS session {} (got {})",
                    ring_key, active_session_id, session_id
                )));
            }
        }
    }

    tracing::info!(
        assigned_node_id = assigned_node_id,
        role = ?dkg_role,
        kind = ?kind,
        "DKG Coordinator: Received SessionInit - assigned node_id"
    );

    // Build the init closure here so kind and reshare_params are set while the
    // state map's write lock is still held inside create_session — eliminating the
    // window where a Commitment could arrive and see kind=Fresh / reshare_params=None
    // on a Reshare session (which would cause expected_commitment_size() to return the
    // wrong threshold and reject the commitment permanently).
    // Also sort new_peer_ids in the stored kind so downstream code
    // (bulletin post, union building) always uses a canonical ordered list.
    let mut init_kind = kind.clone();
    if let SessionKind::Reshare {
        ref mut new_peer_ids,
        ..
    } = init_kind
    {
        new_peer_ids.sort();
    }
    let init_params = maybe_reshare_params;
    let init_policy_id = policy_id.filter(|s| !s.is_empty());

    // If session doesn't exist, create it.
    // Idempotent: treat "session already exists" from a concurrent handler as success.
    let mut session_created_here = false;
    if !coord
        .app_state
        .dkg_session_state
        .session_exists(&session_id)
        .await
    {
        match coord
            .create_session(
                session_id,
                assigned_node_id,
                threshold as usize,
                total_participants as usize,
                dkg_role,
                move |state| {
                    state.kind = init_kind;
                    state.policy_id = init_policy_id;
                    if let Some(params) = init_params {
                        state.reshare_params = Some(params);
                    }
                },
            )
            .await
        {
            Ok(()) => {
                session_created_here = true;
            }
            Err(DkgError::SessionAlreadyExists) => {
                tracing::debug!(
                    session_id = session_id,
                    "DKG Coordinator: Session already created by concurrent handler"
                );
            }
            Err(DkgError::MaxSessionsReached) => {
                // The ring PSS flag was marked before this call; since no session was
                // created there is nothing for the cleanup/expiration workers to find,
                // so we must unmark it here or it leaks until node restart.
                if let Some(ring_key) = kind.ring_key() {
                    coord
                        .app_state
                        .dkg_session_state
                        .unmark_ring_pss_if_matches(ring_key, session_id)
                        .await;
                    tracing::warn!(
                        session_id = session_id,
                        ring_key = %ring_key,
                        "DKG Coordinator: Unmarked ring PSS flag after session limit rejection"
                    );
                }
                return Err(DkgError::MaxSessionsReached);
            }
            Err(e) => {
                if let Some(ring_key) = kind.ring_key() {
                    coord
                        .app_state
                        .dkg_session_state
                        .unmark_ring_pss_if_matches(ring_key, session_id)
                        .await;
                }
                return Err(e);
            }
        }

        coord
            .app_state
            .dkg_session_state
            .set_pss_interval(&session_id, pss_interval)
            .await;

        coord
            .app_state
            .dkg_session_state
            .set_namespace(&session_id, namespace.clone())
            .await;
    }

    // For Reshare: peer_ids in session state = new committee. Old dealers only need
    // to broadcast commitments and shares to receivers; they do not need commitments
    // from other old-only dealers.
    let session_peer_ids = peers::session_peer_ids(kind, peer_ids);
    coord.set_peer_ids(&session_id, session_peer_ids).await;

    // Store old committee node_id → peer_id mappings for sender validation
    // (peer_id_to_node_id uses old committee IDs for all session kinds).
    let node_id_to_peer_id =
        peers::old_committee_node_peer_mappings(peer_ids, &canonical_node_id_assignments);
    coord
        .app_state
        .dkg_session_state
        .set_node_peer_mappings(&session_id, node_id_to_peer_id)
        .await;

    if matches!(kind, SessionKind::Reshare { .. }) {
        let new_peer_ids = coord
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| {
                state
                    .reshare_params
                    .as_ref()
                    .map(|p| p.new_peer_ids.clone())
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();
        let new_node_id_to_peer_id = peers::node_peer_mappings(&new_peer_ids);
        coord
            .app_state
            .dkg_session_state
            .set_reshare_new_peer_mappings(&session_id, new_node_id_to_peer_id)
            .await;
    }

    // When the gRPC initiator is not a participant, nobody calls
    // `initiate_phase1_commitments` from `service.rs`.  Node 1 (lowest sorted peer,
    // agreed via `node_id_assignments`) starts Phase 1 so peers are not stuck waiting
    // for the first commitment.
    if session_created_here
        && assigned_node_id == 1
        && matches!(kind, SessionKind::Fresh | SessionKind::Refresh { .. })
        && dkg_role != DkgRole::Receiver
    {
        let peer_ids_for_phase1 = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .unwrap_or_default();
        coord
            .initiate_phase1_commitments(session_id, &peer_ids_for_phase1)
            .await?;
    }

    // Reshare dealers do not need to wait for commitments from other old dealers.
    // Remote old-committee nodes start as soon as their SessionInit is processed,
    // broadcasting their commitment to the new committee and then sending shares.
    let session_init_from_self = *sender_peer_id == coord.app_state.network.local_peer_id();
    if session_created_here
        && matches!(kind, SessionKind::Reshare { .. })
        && dkg_role != DkgRole::Receiver
        && !session_init_from_self
    {
        let peer_ids_for_phase1 = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .unwrap_or_default();
        coord
            .initiate_phase1_commitments(session_id, &peer_ids_for_phase1)
            .await?;
    }

    tracing::info!(
        session_id = session_id,
        threshold = threshold,
        total_participants = total_participants,
        peer_count = peer_ids.len(),
        our_node_id = assigned_node_id,
        role = ?dkg_role,
        "DKG Coordinator: Session init"
    );

    Ok(None)
}
