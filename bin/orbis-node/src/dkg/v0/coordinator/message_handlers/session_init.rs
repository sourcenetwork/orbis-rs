use super::*;
use crate::dkg::v0::helpers::bidirectional_node_peer_maps;
use crate::helpers::protocol_version::read_ring_for_protocol;
use bulletin::r#trait::RingPayload;

/// Peer routing resolved and validated for one SessionInit, ready to seed session state.
///
/// Produced by the per-kind validation functions (`validate_fresh_init`,
/// `validate_refresh_init`, `validate_reshare_init`) so that
/// `handle_session_init` never sees a partially-resolved route set.
struct ResolvedSessionRoutes {
    /// Peer IDs of the old/current committee, resolved from NodeInfo routes.
    old_peer_ids: Vec<String>,
    /// Old/current committee node_id -> peer_id (used for sender validation in all kinds).
    old_node_id_to_peer_id: HashMap<u32, String>,
    /// Reshare only: peer IDs of the new committee (becomes the session peer list).
    new_peer_ids: Option<Vec<String>>,
    /// Reshare only: new committee node_id -> peer_id.
    new_node_id_to_peer_id: Option<HashMap<u32, String>>,
    /// Node keys stored in session state (new committee for Reshare, current otherwise).
    session_peer_node_keys: Vec<String>,
}

/// Check that a Refresh/Reshare SessionInit's committee parameters match the
/// authoritative ring payload.
///
/// `label` prefixes error messages ("Refresh" or "Reshare old" — the checks always
/// concern the old/current committee).
fn validate_committee_matches_ring(
    label: &str,
    ring_pk_hex: &str,
    ring_payload: &RingPayload,
    peer_node_keys: &[String],
    threshold: u32,
    total_participants: u32,
) -> Result<()> {
    if !peers::same_peer_set(peer_node_keys, &ring_payload.peer_node_keys) {
        return Err(DkgError::Unauthorized(format!(
            "{} peer_node_keys do not match authoritative committee for ring {}",
            label, ring_pk_hex
        )));
    }
    if threshold != ring_payload.threshold {
        return Err(DkgError::Unauthorized(format!(
            "{} threshold {} does not match authoritative threshold {} for ring {}",
            label, threshold, ring_payload.threshold, ring_pk_hex
        )));
    }
    if total_participants as usize != ring_payload.peer_node_keys.len() {
        return Err(DkgError::Unauthorized(format!(
            "{} total_participants {} does not match authoritative committee size {} for ring {}",
            label,
            total_participants,
            ring_payload.peer_node_keys.len(),
            ring_pk_hex
        )));
    }
    Ok(())
}

/// Validate a Refresh SessionInit against the authoritative ring and resolve its routes.
async fn validate_refresh_init<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    threshold: u32,
    total_participants: u32,
    peer_ids: &[String],
    peer_node_keys: &[String],
    ring_pk_hex: &str,
    sender_hex: &str,
) -> Result<ResolvedSessionRoutes>
where
    D: CoordinatorDkg,
{
    tracing::info!(
        session_id = session_id,
        ring_pk_hex = %ring_pk_hex,
        sender_peer_hex = %sender_hex,
        "DKG Coordinator: Refresh SessionInit received - pre-validation"
    );
    let ring_payload = validate_refresh_session_init_for_version(
        ring_pk_hex,
        &coord.app_state.local_storage,
        &coord.app_state.bulletin,
        coord.routes.version,
    )
    .await?;

    validate_committee_matches_ring(
        "Refresh",
        ring_pk_hex,
        &ring_payload,
        peer_node_keys,
        threshold,
        total_participants,
    )?;

    let routes = resolve_node_routes(&coord.app_state.bulletin, &ring_payload.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let route_peer_ids = peer_ids_from_routes(&routes);
    if !peers::same_peer_set(peer_ids, &route_peer_ids) {
        return Err(DkgError::Unauthorized(format!(
            "Refresh peer_ids do not match NodeInfo routes for ring {}",
            ring_pk_hex
        )));
    }
    let local_node_peer_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
    if node_key_for_peer(&routes, &local_node_peer_hex) != Some(coord.app_state.node_key.as_str()) {
        return Err(DkgError::Unauthorized(format!(
            "Local node {} with peer {} is not a member of ring {}",
            coord.app_state.node_key, local_node_peer_hex, ring_pk_hex
        )));
    }
    let route_assignments =
        canonical_node_id_assignments_from_node_keys(&ring_payload.peer_node_keys)
            .map_err(DkgError::InvalidInput)?;
    let route_map = peers::old_committee_node_peer_mappings(
        &ring_payload.peer_node_keys,
        &routes,
        &route_assignments,
    )?;

    let bundle = RingShareBundle::load_by_ring_key(&coord.app_state.local_storage, ring_pk_hex)
        .map_err(|e| {
            DkgError::Unauthorized(format!(
                "Refresh session validation requires current ring bundle for {}: {}",
                ring_pk_hex, e
            ))
        })?;
    let expected_session_id = derive_refresh_session_id(
        ring_pk_hex,
        &ring_payload.peer_node_keys,
        ring_payload.threshold,
        &bundle.public_polynomial,
    )?;
    if session_id != expected_session_id {
        return Err(DkgError::Unauthorized(format!(
            "Refresh session_id mismatch for ring {}: expected {}, got {}",
            ring_pk_hex, expected_session_id, session_id
        )));
    }

    Ok(ResolvedSessionRoutes {
        old_peer_ids: route_peer_ids,
        old_node_id_to_peer_id: route_map,
        new_peer_ids: None,
        new_node_id_to_peer_id: None,
        session_peer_node_keys: peer_node_keys.to_vec(),
    })
}

/// Validate a Reshare SessionInit against the authoritative ring and resolve routes
/// for both the old and new committees.
#[allow(clippy::too_many_arguments)]
async fn validate_reshare_init<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    threshold: u32,
    total_participants: u32,
    peer_ids: &[String],
    peer_node_keys: &[String],
    ring_pk_hex: &str,
    reshare_new_peer_node_keys: &[String],
    reshare_new_threshold: u32,
    reshare_bulletin_post_id: &str,
    sender_hex: &str,
) -> Result<ResolvedSessionRoutes>
where
    D: CoordinatorDkg,
{
    tracing::info!(
        session_id = session_id,
        ring_pk_hex = %ring_pk_hex,
        sender_peer_hex = %sender_hex,
        "DKG Coordinator: Reshare SessionInit received - pre-validation"
    );
    let ring_payload = validate_reshare_session_init_for_version(
        ring_pk_hex,
        reshare_new_peer_node_keys,
        reshare_new_threshold,
        reshare_bulletin_post_id,
        &coord.app_state.local_storage,
        &coord.app_state.bulletin,
        coord.routes.version,
    )
    .await?;

    validate_committee_matches_ring(
        "Reshare old",
        ring_pk_hex,
        &ring_payload,
        peer_node_keys,
        threshold,
        total_participants,
    )?;

    let authoritative_new_peer_node_keys = ring_payload
        .new_peer_node_keys
        .clone()
        .unwrap_or_else(|| ring_payload.peer_node_keys.clone());
    let authoritative_new_threshold = ring_payload.new_threshold.unwrap_or(ring_payload.threshold);
    if authoritative_new_peer_node_keys
        .iter()
        .any(|node_key| node_key == &coord.app_state.node_key)
    {
        let our_peer_id_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
        validate_dkg_node_authorization_for_committee(
            &coord.app_state.bulletin,
            &coord.app_state.node_key,
            &our_peer_id_hex,
            reshare_bulletin_post_id,
            &ring_payload,
            effective_new_peer_node_keys(&ring_payload),
            "Reshare",
        )
        .await?;
    }
    let expected_session_id = derive_reshare_session_id(
        ring_pk_hex,
        reshare_bulletin_post_id,
        &ring_payload.peer_node_keys,
        &authoritative_new_peer_node_keys,
        authoritative_new_threshold,
    )?;
    if session_id != expected_session_id {
        return Err(DkgError::Unauthorized(format!(
            "Reshare session_id mismatch for ring {}: expected {}, got {}",
            ring_pk_hex, expected_session_id, session_id
        )));
    }

    let old_routes = resolve_node_routes(&coord.app_state.bulletin, &ring_payload.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let old_route_peer_ids = peer_ids_from_routes(&old_routes);
    if !peers::same_peer_set(peer_ids, &old_route_peer_ids) {
        return Err(DkgError::Unauthorized(format!(
            "Reshare old peer_ids do not match NodeInfo routes for ring {}",
            ring_pk_hex
        )));
    }
    if node_key_for_peer(&old_routes, sender_hex).is_none() {
        return Err(DkgError::Unauthorized(format!(
            "Reshare initiator {} is not a member of ring {}",
            sender_hex, ring_pk_hex
        )));
    }
    let old_route_assignments =
        canonical_node_id_assignments_from_node_keys(&ring_payload.peer_node_keys)
            .map_err(DkgError::InvalidInput)?;
    let old_route_map = peers::old_committee_node_peer_mappings(
        &ring_payload.peer_node_keys,
        &old_routes,
        &old_route_assignments,
    )?;

    let new_routes = resolve_node_routes(&coord.app_state.bulletin, reshare_new_peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let new_route_peer_ids = peer_ids_from_routes(&new_routes);
    let new_route_assignments =
        canonical_node_id_assignments_from_node_keys(reshare_new_peer_node_keys)
            .map_err(DkgError::InvalidInput)?;
    let new_route_map = node_id_to_peer_id_from_routes(&new_routes, &new_route_assignments)
        .map_err(DkgError::InvalidInput)?;

    tracing::info!(
        session_id = session_id,
        ring_pk = %ring_pk_hex,
        sender_peer_hex = %sender_hex,
        "DKG Coordinator: Reshare SessionInit validated"
    );

    Ok(ResolvedSessionRoutes {
        old_peer_ids: old_route_peer_ids,
        old_node_id_to_peer_id: old_route_map,
        new_peer_ids: Some(new_route_peer_ids),
        new_node_id_to_peer_id: Some(new_route_map),
        session_peer_node_keys: reshare_new_peer_node_keys.to_vec(),
    })
}

/// Validate a Fresh DKG SessionInit (JWT, ring payload, committee authorization)
/// and resolve its routes.
#[allow(clippy::too_many_arguments)]
async fn validate_fresh_init<D>(
    coord: &DkgCoordinator<D>,
    threshold: u32,
    total_participants: u32,
    peer_ids: &[String],
    peer_node_keys: &[String],
    token_string: &str,
    pss_interval: u64,
    policy_id: Option<&str>,
    ring_id: &str,
) -> Result<ResolvedSessionRoutes>
where
    D: CoordinatorDkg,
{
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
        .as_secs();
    let token: BearerToken<DkgClaims> = resolve_jwt_did(
        token_string,
        current_time,
        MAX_TOKEN_LIFETIME_SECS,
        MAX_JWT_BYTES,
        JWT_CLOCK_SKEW_LEEWAY_SECS,
    )
    .map_err(|e| DkgError::Unauthorized(format!("JWT validation failed: {}", e)))?;
    validate_dkg_claims(&token, ring_id)?;

    let (bulletin_ring_payload, effective_routes) =
        read_ring_for_protocol(&*coord.app_state.bulletin, ring_id)
            .await
            .map_err(DkgError::ProtocolError)?;
    if effective_routes.version != coord.routes.version {
        return Err(DkgError::ProtocolError(format!(
            "fresh DKG for ring {} arrived on protocol version {}, but effective version is {}",
            ring_id, coord.routes.version, effective_routes.version
        )));
    }
    validate_fresh_dkg_ring_payload(ring_id, &bulletin_ring_payload)?;

    validate_fresh_session_init_params(
        ring_id,
        peer_node_keys,
        threshold,
        total_participants,
        pss_interval,
        policy_id,
        &bulletin_ring_payload,
    )?;

    let our_peer_id_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
    validate_dkg_node_authorization_for_committee(
        &coord.app_state.bulletin,
        &coord.app_state.node_key,
        &our_peer_id_hex,
        ring_id,
        &bulletin_ring_payload,
        &bulletin_ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await?;
    tracing::info!(
        issuer = %token.issuer_id,
        threshold = threshold,
        policy_id = ?policy_id,
        "DKG Coordinator: SessionInit JWT validated successfully"
    );

    let routes = resolve_node_routes(&coord.app_state.bulletin, peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let route_peer_ids = peer_ids_from_routes(&routes);
    if !peers::same_peer_set(peer_ids, &route_peer_ids) {
        return Err(DkgError::Unauthorized(format!(
            "Fresh peer_ids do not match NodeInfo routes for ring {}",
            ring_id
        )));
    }
    let route_assignments = canonical_node_id_assignments_from_node_keys(peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let route_map =
        peers::old_committee_node_peer_mappings(peer_node_keys, &routes, &route_assignments)?;

    Ok(ResolvedSessionRoutes {
        old_peer_ids: route_peer_ids,
        old_node_id_to_peer_id: route_map,
        new_peer_ids: None,
        new_node_id_to_peer_id: None,
        session_peer_node_keys: peer_node_keys.to_vec(),
    })
}

/// Handle a `DkgMessage::SessionInit`.
///
/// Validates the session kind (Fresh/Refresh/Reshare), assigns this node's role
/// and node_id, and creates the session if it does not already exist.
/// For Fresh/Refresh, when this handler creates the session and this node is
/// `node_id == 1`, it also calls `initiate_phase1_commitments` so the protocol
/// starts even if the gRPC initiator is not a participant.
/// Returns `Ok(None)` — the caller should return this directly from `handle_message`.
pub async fn handle_session_init<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    threshold: u32,
    total_participants: u32,
    peer_ids: &[String],
    peer_node_keys: &[String],
    node_id_assignments: &HashMap<String, u32>,
    token_string: &str,
    kind: &SessionKind,
    pss_interval: u64,
    policy_id: Option<String>,
    ring_id: String,
    sender_peer_id: &PeerId,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    let sender_hex = hex::encode(sender_peer_id.as_bytes());

    let resolved = match kind {
        SessionKind::Refresh { ring_pk_hex } => {
            validate_refresh_init(
                coord,
                session_id,
                threshold,
                total_participants,
                peer_ids,
                peer_node_keys,
                ring_pk_hex,
                &sender_hex,
            )
            .await?
        }
        SessionKind::Reshare {
            ring_pk_hex,
            new_peer_node_keys,
            new_threshold,
            bulletin_post_id,
        } => {
            validate_reshare_init(
                coord,
                session_id,
                threshold,
                total_participants,
                peer_ids,
                peer_node_keys,
                ring_pk_hex,
                new_peer_node_keys,
                *new_threshold,
                bulletin_post_id,
                &sender_hex,
            )
            .await?
        }
        SessionKind::Fresh => {
            validate_fresh_init(
                coord,
                threshold,
                total_participants,
                peer_ids,
                peer_node_keys,
                token_string,
                pss_interval,
                policy_id.as_deref(),
                &ring_id,
            )
            .await?
        }
    };

    let canonical_node_id_assignments =
        peers::validate_node_id_assignments(peer_node_keys, node_id_assignments)?;

    // For Reshare, determine role and node_id from committee membership rather than
    // looking up node_id_assignments (which only covers the old committee).
    let (assigned_node_id, dkg_role, maybe_reshare_params) = if let SessionKind::Reshare {
        ring_pk_hex,
        new_peer_node_keys,
        new_threshold,
        bulletin_post_id,
    } = kind
    {
        // build_reshare_params errors if this node is not in either committee.
        let (node_id, role, params) = build_reshare_params(
            ring_pk_hex,
            peer_node_keys,
            new_peer_node_keys,
            *new_threshold,
            bulletin_post_id,
            &coord.app_state.node_key,
            &coord.app_state.local_storage,
        )?;

        (node_id, role, Some(params))
    } else {
        // Fresh / Refresh: look up our node_id from the locally verified node-key assignments.
        let node_id = canonical_node_id_assignments
            .get(&coord.app_state.node_key)
            .copied()
            .ok_or_else(|| {
                DkgError::InvalidInput(format!(
                    "Could not find our node_id in SessionInit. \
                         Our node_key: {}, assignments: {:?}",
                    coord.app_state.node_key,
                    canonical_node_id_assignments.keys().collect::<Vec<_>>()
                ))
            })?;
        (node_id, DkgRole::Standard, None)
    };

    // Refresh/Reshare: claim the ring's active PSS slot before creating the session.
    if let Some(ring_key) = kind.ring_key() {
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
    // Also sort new_peer_node_keys in the stored kind so downstream code
    // (bulletin post, union building) always uses a canonical ordered list.
    let mut init_kind = kind.clone();
    if let SessionKind::Reshare {
        ref mut new_peer_node_keys,
        ..
    } = init_kind
    {
        new_peer_node_keys.sort();
    }
    let init_params = maybe_reshare_params;
    let init_policy_id = policy_id;

    // For Reshare: peer_ids in session state = new committee. Old dealers only need
    // to broadcast commitments and shares to receivers; they do not need commitments
    // from other old-only dealers.
    let init_peer_ids = resolved.new_peer_ids.unwrap_or(resolved.old_peer_ids);
    let session_peer_node_keys = resolved.session_peer_node_keys;

    // Old committee node_id -> peer_id mappings are used for sender validation
    // (peer_id_to_node_id uses old committee IDs for all session kinds).
    let (node_to_peer, peer_to_node) =
        bidirectional_node_peer_maps(resolved.old_node_id_to_peer_id);
    let (new_node_to_peer, new_peer_to_node) =
        bidirectional_node_peer_maps(resolved.new_node_id_to_peer_id.unwrap_or_default());

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
                    state.pss_interval = pss_interval;
                    state.routing.peer_ids = init_peer_ids;
                    state.routing.peer_node_keys = session_peer_node_keys;
                    state.routing.ring_id = ring_id;
                    state.routing.node_id_to_peer_id = node_to_peer;
                    state.routing.peer_id_to_node_id = peer_to_node;
                    state.routing.reshare_new_node_id_to_peer_id = new_node_to_peer;
                    state.routing.reshare_new_peer_id_to_node_id = new_peer_to_node;

                    if let Some(params) = init_params {
                        state.reshare.params = Some(params);
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
    }

    // When the gRPC initiator is not a participant, nobody calls the local start path
    // from `service.rs`:
    // - Fresh: every participant starts Phase 0 so all commitment hashes arrive before
    //   any commitment reveal.
    // - Refresh: node 1 (lowest sorted peer, agreed via `node_id_assignments`)
    //   starts Phase 1 so peers are not stuck waiting for the first commitment.
    // - Reshare: dealers do not need to wait for commitments from other old dealers.
    //   Remote old-committee nodes start as soon as their SessionInit is processed,
    //   broadcasting their commitment to the new committee and then sending shares.
    let session_init_from_self = *sender_peer_id == coord.app_state.network.local_peer_id();
    let starts_phase = match kind {
        SessionKind::Fresh => true,
        SessionKind::Refresh { .. } => assigned_node_id == 1,
        SessionKind::Reshare { .. } => !session_init_from_self,
    };
    if session_created_here && starts_phase && dkg_role != DkgRole::Receiver {
        let peer_ids_for_phase1 = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .unwrap_or_default();
        if matches!(kind, SessionKind::Fresh) {
            coord
                .initiate_phase0_commitment_hashes(session_id, &peer_ids_for_phase1)
                .await?;
        } else {
            coord
                .initiate_phase1_commitments(session_id, &peer_ids_for_phase1)
                .await?;
        }
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
