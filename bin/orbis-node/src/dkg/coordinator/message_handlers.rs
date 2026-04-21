use crate::constants::{MAX_COMMITMENT_COEFFICIENTS, MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    build_reshare_params, serialize_commitment_coefficients, session_not_found,
    validate_dkg_claims, validate_refresh_session_init, validate_reshare_session_init,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::DkgMessageType;
use crate::helpers::helpers::{extract_node_part, is_self_peer_id};

use authn::{resolve_jwt_did, BearerToken, DkgClaims};
use crypto::r#trait::{DistributedShare, Dkg, DkgRole};
use crypto::{
    CryptoDeserialize, GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    ScalarField as Fr, GROUP_POINT_SIZE as G1_COMPRESSED_SIZE, SCALAR_SIZE as FR_COMPRESSED_SIZE,
};
use network::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use super::DkgCoordinator;

/// Handle a `DkgMessage::SessionInit`.
///
/// Validates the session kind (Fresh/Refresh/Reshare), assigns this node's role
/// and node_id, and creates the session if it does not already exist.
/// For Fresh/Refresh, when this handler creates the session and this node is
/// `node_id == 1`, it also calls `initiate_phase1_commitments` so the protocol
/// starts even if the gRPC initiator is not a participant.
/// Returns `Ok(None)` — the caller should return this directly from `handle_message`.
pub(super) async fn handle_session_init<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    threshold: u32,
    total_participants: u32,
    peer_ids: &[String],
    node_id_assignments: &HashMap<String, u32>,
    token_string: &str,
    kind: &SessionKind,
    pss_interval: Option<u64>,
    sender_peer_id: &PeerId,
) -> Result<Option<DkgMessage>>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let sender_hex = hex::encode(sender_peer_id.as_bytes());

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
            if !coord
                .app_state
                .dkg_session_state
                .try_mark_ring_pss(ring_pk_hex)
                .await
            {
                return Err(DkgError::Unauthorized(
                    "Refresh already in progress for this ring".to_string(),
                ));
            }
            tracing::info!(
                session_id = session_id,
                ring_pk = %ring_pk_hex,
                sender_peer_hex = %sender_hex,
                "DKG Coordinator: Refresh SessionInit validated and ring marked refreshing"
            );
        }
        SessionKind::Reshare {
            ring_pk_hex,
            next_peer_ids: reshare_next_peer_ids,
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
                reshare_next_peer_ids,
                *reshare_new_threshold,
                reshare_bulletin_post_id,
                &coord.app_state.local_storage,
                &coord.app_state.bulletin,
            )
            .await?;
            tracing::info!(
                session_id = session_id,
                ring_pk = %ring_pk_hex,
                sender_peer_hex = %sender_hex,
                "DKG Coordinator: Reshare SessionInit validated"
            );
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
            validate_dkg_claims(&token, threshold, peer_ids, pss_interval)?;
            tracing::info!(
                issuer = %token.issuer_id,
                threshold = threshold,
                "DKG Coordinator: SessionInit JWT validated successfully"
            );
        }
    }

    let our_peer_id_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    // For Reshare, determine role and node_id from committee membership rather than
    // looking up node_id_assignments (which only covers the old committee).
    let (assigned_node_id, dkg_role, maybe_reshare_params) = if let SessionKind::Reshare {
        ring_pk_hex,
        next_peer_ids,
        new_threshold,
        bulletin_post_id,
    } = kind
    {
        // build_reshare_params errors if this node is not in either committee.
        let (node_id, role, params) = build_reshare_params(
            ring_pk_hex,
            peer_ids,
            next_peer_ids,
            *new_threshold,
            bulletin_post_id,
            &our_node_part,
            &coord.app_state.local_storage,
        )?;

        // Mark the ring as having an in-progress reshare.  Done here — after we know
        // this node is in at least one committee — so that the flag is never set for
        // nodes that are not participants (which would permanently block future
        // reshares for that ring on this node).
        if !coord
            .app_state
            .dkg_session_state
            .try_mark_ring_pss(ring_pk_hex)
            .await
        {
            return Err(DkgError::Unauthorized(
                "Reshare already in progress for this ring".to_string(),
            ));
        }
        tracing::info!(
            session_id = session_id,
            ring_pk = %ring_pk_hex,
            role = ?role,
            "DKG Coordinator: Reshare SessionInit validated and ring marked resharing"
        );

        (node_id, role, Some(params))
    } else {
        // Fresh / Refresh: look up our node_id from the initiator's assignments.
        let our_peer_id_key = our_peer_id_hex
            .split('@')
            .next()
            .unwrap_or(&our_peer_id_hex)
            .to_string();
        let node_id = node_id_assignments
            .get(&our_peer_id_key)
            .copied()
            .ok_or_else(|| {
                DkgError::InvalidInput(format!(
                    "Could not find our node_id in SessionInit. \
                         Our peer_id: {}, assignments: {:?}",
                    our_peer_id_key,
                    node_id_assignments.keys().collect::<Vec<_>>()
                ))
            })?;
        (node_id, DkgRole::Standard, None)
    };

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
    // Also sort next_peer_ids in the stored kind so downstream code
    // (bulletin post, union building) always uses a canonical ordered list.
    let mut init_kind = kind.clone();
    if let SessionKind::Reshare {
        ref mut next_peer_ids,
        ..
    } = init_kind
    {
        next_peer_ids.sort();
    }
    let init_params = maybe_reshare_params;

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
                        .unmark_ring_pss(ring_key)
                        .await;
                    tracing::warn!(
                        session_id = session_id,
                        ring_key = %ring_key,
                        "DKG Coordinator: Unmarked ring PSS flag after session limit rejection"
                    );
                }
                return Err(DkgError::MaxSessionsReached);
            }
            Err(e) => return Err(e),
        }

        coord
            .app_state
            .dkg_session_state
            .set_pss_interval(&session_id, pss_interval)
            .await;
    }

    // For Reshare: peer_ids in session state = new committee. Old dealers only need
    // to broadcast commitments and shares to receivers; they do not need commitments
    // from other old-only dealers.
    let session_peer_ids = if let SessionKind::Reshare { next_peer_ids, .. } = kind {
        let mut new_peers = next_peer_ids.clone();
        new_peers.sort();
        new_peers
    } else {
        peer_ids.to_vec()
    };
    coord.set_peer_ids(&session_id, session_peer_ids).await;

    // Store old committee node_id → peer_id mappings for sender validation
    // (peer_id_to_node_id uses old committee IDs for all session kinds).
    let mut node_id_to_peer_id = std::collections::HashMap::new();
    for (peer_id_key, node_id) in node_id_assignments {
        let full_peer_id = peer_ids
            .iter()
            .find(|pid| pid.split('@').next().unwrap_or(pid) == peer_id_key)
            .cloned()
            .unwrap_or_else(|| peer_id_key.clone());
        node_id_to_peer_id.insert(*node_id, full_peer_id);
    }
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
        let new_node_id_to_peer_id = new_peer_ids
            .iter()
            .enumerate()
            .map(|(idx, peer_id)| ((idx + 1) as u32, peer_id.clone()))
            .collect();
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

/// Handle a `DkgMessage::Commitment`.
///
/// Deserializes and stores the commitment, optionally triggers polynomial generation
/// for this node (if this is the first commitment received and we haven't yet
/// generated ours), then checks whether Phase 1 is complete.
pub(super) async fn handle_commitment_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<Option<DkgMessage>>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    tracing::debug!(
        from_node_id = from_node_id,
        session_id = session_id,
        commitment_bytes = commitment.len(),
        "DKG Coordinator: Received commitment"
    );

    if commitment.is_empty() {
        return Err(DkgError::CommitmentVerificationFailed(
            "Commitment cannot be empty".to_string(),
        ));
    }

    if commitment.len() % G1_COMPRESSED_SIZE != 0 {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Invalid commitment length: {} bytes is not a multiple of {} (G1 compressed size)",
            commitment.len(),
            G1_COMPRESSED_SIZE
        )));
    }

    let num_coefficients = commitment.len() / G1_COMPRESSED_SIZE;

    if num_coefficients > MAX_COMMITMENT_COEFFICIENTS {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Too many commitment coefficients: {} exceeds maximum {}",
            num_coefficients, MAX_COMMITMENT_COEFFICIENTS
        )));
    }

    // Get expected commitment size from session (= new_threshold for Reshare,
    // = old threshold for Fresh/Refresh).
    let expected_coeff_count = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| state.expected_commitment_size())
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if num_coefficients != expected_coeff_count {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Invalid number of commitment coefficients: got {}, expected {}",
            num_coefficients, expected_coeff_count
        )));
    }

    let mut commitment_coeffs = Vec::with_capacity(num_coefficients);
    for i in 0..num_coefficients {
        let start = i * G1_COMPRESSED_SIZE;
        let end = start + G1_COMPRESSED_SIZE;
        let coeff = <D::PublicKey>::from_bytes(&commitment[start..end]).map_err(|e| {
            DkgError::Deserialization(format!(
                "Failed to deserialize commitment coefficient {}: {}",
                i, e
            ))
        })?;
        commitment_coeffs.push(coeff);
    }

    let polynomial_commitment = PolynomialCommitment {
        coefficients: commitment_coeffs,
    };

    let need_to_generate_polynomial = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            state
                .node
                .receive_commitment(from_node_id, polynomial_commitment)
                .map_err(|e| DkgError::Crypto(format!("Failed to receive commitment: {}", e)))?;

            // Receiver nodes never generate a polynomial — they only accumulate
            // commitments to verify the shares they will receive.
            let generates_polynomial = state.node.role() != DkgRole::Receiver;
            Ok::<_, DkgError>(
                generates_polynomial && state.node.commitment().coefficients.is_empty(),
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .mark_message_processed(&session_id, from_node_id, DkgMessageType::Commitment)
        .await;

    coord
        .app_state
        .dkg_session_state
        .increment_commitments(&session_id)
        .await;

    // If this is the first commitment received and we haven't yet generated our
    // polynomial, generate it now and broadcast our commitment.
    if need_to_generate_polynomial {
        tracing::info!(
            "DKG Coordinator: First commitment received, generating our polynomial and sending commitment"
        );

        let generated_polynomial = coord
            .app_state
            .dkg_session_state
            .with_state_mut(&session_id, |state| {
                if !state.node.commitment().coefficients.is_empty() {
                    return Ok::<_, DkgError>(false);
                }
                state.generate_polynomial()?;
                Ok(true)
            })
            .await
            .ok_or_else(|| session_not_found(session_id))??;

        if !generated_polynomial {
            tracing::debug!(
                session_id = session_id,
                "Polynomial was already generated by a concurrent first-commitment path"
            );
        } else if let Some(peer_ids) = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
        {
            let (commitment_bytes, node_id, is_reshare, role) = coord
                .app_state
                .dkg_session_state
                .with_state(&session_id, |state| {
                    let bytes =
                        serialize_commitment_coefficients(&state.node.commitment().coefficients)?;
                    Ok::<_, DkgError>((
                        bytes,
                        state.node.node_id(),
                        matches!(state.kind, SessionKind::Reshare { .. }),
                        state.node.role(),
                    ))
                })
                .await
                .ok_or_else(|| session_not_found(session_id))??;

            let mut sent_count = 0;
            let mut expected_count = 0;
            for peer_id_str in &peer_ids {
                if is_self_peer_id(&coord.app_state.network, peer_id_str) {
                    continue;
                }
                expected_count += 1;

                let commitment_msg = DkgMessage::Commitment {
                    session_id,
                    from_node_id: node_id,
                    commitment: commitment_bytes.clone(),
                };

                match coord
                    .send_message_to_peer(peer_id_str, commitment_msg, Some(session_id))
                    .await
                {
                    Ok(_) => sent_count += 1,
                    Err(e) => {
                        tracing::error!(
                            peer_id = %peer_id_str,
                            error = %e,
                            "Failed to send commitment to peer"
                        );
                    }
                }
            }

            tracing::info!(
                sent = sent_count,
                expected = expected_count,
                "DKG Coordinator: Sent our commitment to peers"
            );

            if sent_count < expected_count && !is_reshare {
                tracing::error!(
                    sent = sent_count,
                    expected = expected_count,
                    session_id = session_id,
                    "DKG Coordinator: Could not send commitment to all peers - failing DKG to preserve expected redundancy"
                );
                coord.remove_session(session_id).await;
                tracing::debug!(
                    session_id = session_id,
                    "Cleaned up session after commitment send failure"
                );
                return Err(DkgError::NetworkCommunication(format!(
                    "Failed to send commitment to all peers: sent to {} of {}",
                    sent_count, expected_count
                )));
            }

            if sent_count < expected_count {
                tracing::warn!(
                    sent = sent_count,
                    expected = expected_count,
                    session_id = session_id,
                    "Reshare: commitment broadcast did not reach every new-committee peer; continuing until threshold selection or timeout"
                );
            }

            if is_reshare && role != DkgRole::Receiver {
                coord.initiate_phase2_shares(session_id, &peer_ids).await?;
            }
        }
    }

    if let Some(peer_ids) = coord
        .app_state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
    {
        coord
            .check_and_trigger_phase2(session_id, &peer_ids)
            .await?;
    }

    let is_reshare = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if is_reshare {
        // A selected dealer's commitment can arrive after the participant set;
        // retry Phase 4 because the public polynomial/aggregate key may now be unblocked.
        coord.check_and_trigger_phase4(session_id).await?;
    }

    Ok(None)
}

/// Handle a `DkgMessage::Share`.
///
/// Validates the share is addressed to this node, deserializes it, passes it to the
/// crypto layer for verification against the sender's commitment, then checks whether
/// Phase 2 is complete.
pub(super) async fn handle_share_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
) -> Result<Option<DkgMessage>>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    if share_value.is_empty() {
        return Err(DkgError::ShareVerificationFailed(
            "Share value cannot be empty".to_string(),
        ));
    }

    if share_value.len() != FR_COMPRESSED_SIZE {
        return Err(DkgError::ShareVerificationFailed(format!(
            "Invalid share value length: {} bytes, expected {}",
            share_value.len(),
            FR_COMPRESSED_SIZE
        )));
    }

    // Validate this share is intended for us.
    // For reshare, incoming shares are addressed by new-committee index;
    // for fresh/refresh, shares are addressed by the session node_id.
    let our_node_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            state
                .reshare_params
                .as_ref()
                .and_then(|p| p.new_node_id)
                .unwrap_or_else(|| state.node.node_id())
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if to_node_id != our_node_id {
        return Err(DkgError::ShareVerificationFailed(format!(
            "Share intended for node {}, but we are node {}",
            to_node_id, our_node_id
        )));
    }

    let ignore_unselected_reshare_share = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state
                    .reshare_selected_dealers
                    .as_ref()
                    .is_some_and(|selected| !selected.contains(&from_node_id))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if ignore_unselected_reshare_share {
        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            "Reshare: ignoring straggler share from unselected dealer"
        );
        coord
            .app_state
            .dkg_session_state
            .mark_message_processed(&session_id, from_node_id, DkgMessageType::Share)
            .await;
        return Ok(None);
    }

    // Commitment and share are delivered over the same persistent QUIC stream
    // (one stream per connection, opened lazily on first send).  QUIC guarantees
    // in-order delivery within a stream, so the commitment always arrives before
    // the share — no retry needed.
    let share_val = <D::ShareValue>::from_bytes(share_value.as_slice()).map_err(|e| {
        DkgError::Deserialization(format!("Failed to deserialize share value: {}", e))
    })?;
    let share = DistributedShare {
        from_id: from_node_id,
        to_id: to_node_id,
        value: share_val,
        nonce,
        session_id,
    };

    coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            state.node.receive_share(share).map_err(|e| {
                DkgError::ShareVerificationFailed(format!("Failed to receive share: {}", e))
            })
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    tracing::debug!(
        from_node_id = from_node_id,
        to_node_id = to_node_id,
        session_id = session_id,
        "DKG Coordinator: Received and verified share"
    );

    coord
        .app_state
        .dkg_session_state
        .mark_message_processed(&session_id, from_node_id, DkgMessageType::Share)
        .await;

    coord
        .app_state
        .dkg_session_state
        .increment_shares(&session_id)
        .await;

    record_and_ack_valid_reshare_share(coord, session_id, from_node_id).await?;

    coord.check_and_trigger_phase4(session_id).await?;

    Ok(None)
}

pub(super) async fn record_and_ack_valid_reshare_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    dealer_id: u32,
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let ack = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if !matches!(state.kind, SessionKind::Reshare { .. })
                || !matches!(
                    state.node.role(),
                    DkgRole::Receiver | DkgRole::DealerReceiver
                )
            {
                return Ok::<_, DkgError>(None);
            }

            if !state.reshare_valid_share_dealers.insert(dealer_id) {
                return Ok(None);
            }

            let params = state.reshare_params.as_ref().ok_or_else(|| {
                DkgError::Generic(
                    "Reshare session is missing reshare_params while acking share".to_string(),
                )
            })?;
            let receiver_node_id = params.new_node_id.ok_or_else(|| {
                DkgError::Generic(
                    "Reshare receiver is missing new_node_id while acking share".to_string(),
                )
            })?;
            let selector_peer_id = params.new_peer_ids.first().cloned().ok_or_else(|| {
                DkgError::InvalidInput("Reshare new committee is empty".to_string())
            })?;

            Ok(Some((receiver_node_id, selector_peer_id)))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    let Some((receiver_node_id, selector_peer_id)) = ack else {
        return Ok(());
    };

    if is_self_peer_id(&coord.app_state.network, &selector_peer_id) {
        handle_reshare_share_ack(coord, session_id, receiver_node_id, dealer_id).await?;
    } else {
        let ack_msg = DkgMessage::ReshareShareAck {
            session_id,
            receiver_node_id,
            dealer_id,
        };
        coord
            .send_message_to_peer(&selector_peer_id, ack_msg, Some(session_id))
            .await
            .map_err(|e| {
                DkgError::NetworkCommunication(format!(
                    "Reshare: failed to send valid-share acknowledgement to selector {}: {}",
                    selector_peer_id, e
                ))
            })?;
    }

    Ok(())
}

pub(super) async fn handle_reshare_share_ack<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    receiver_node_id: u32,
    dealer_id: u32,
) -> Result<Option<DkgMessage>>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let selection = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            let (new_peer_ids, local_new_node_id) = {
                let params = state.reshare_params.as_ref().ok_or_else(|| {
                    DkgError::Generic(
                        "Reshare ack received for session without reshare_params".to_string(),
                    )
                })?;
                (params.new_peer_ids.clone(), params.new_node_id.unwrap_or(0))
            };

            if local_new_node_id != 1 {
                return Err(DkgError::Unauthorized(
                    "ReshareShareAck delivered to a non-selector node".to_string(),
                ));
            }
            if receiver_node_id == 0 || receiver_node_id as usize > new_peer_ids.len() {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid reshare receiver_node_id {} for new committee size {}",
                    receiver_node_id,
                    new_peer_ids.len()
                )));
            }
            if dealer_id == 0 || dealer_id as usize > state.node.total_nodes() {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid reshare dealer_id {} for old committee size {}",
                    dealer_id,
                    state.node.total_nodes()
                )));
            }

            state
                .reshare_share_acks
                .entry(dealer_id)
                .or_insert_with(HashSet::new)
                .insert(receiver_node_id);

            let complete = state
                .reshare_share_acks
                .get(&dealer_id)
                .map(|acks| acks.len() == new_peer_ids.len())
                .unwrap_or(false);
            if complete && !state.reshare_dealer_completion_order.contains(&dealer_id) {
                state.reshare_dealer_completion_order.push(dealer_id);
            }

            if state.reshare_selected_dealers.is_none()
                && state.reshare_dealer_completion_order.len() >= state.node.threshold()
            {
                let selected: Vec<u32> = state
                    .reshare_dealer_completion_order
                    .iter()
                    .copied()
                    .take(state.node.threshold())
                    .collect();
                state
                    .node
                    .select_reshare_participants(selected.clone())
                    .map_err(|e| {
                        DkgError::Crypto(format!("Failed to select reshare participants: {}", e))
                    })?;
                state.reshare_selected_dealers = Some(selected.clone());
                return Ok(Some((selected, new_peer_ids)));
            }

            Ok(None)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    if let Some((selected_dealer_ids, new_peer_ids)) = selection {
        tracing::info!(
            session_id = session_id,
            selected_dealers = ?selected_dealer_ids,
            "Reshare: selector froze participant set"
        );

        for peer_id in &new_peer_ids {
            if is_self_peer_id(&coord.app_state.network, peer_id) {
                continue;
            }
            let msg = DkgMessage::ReshareParticipantSet {
                session_id,
                from_node_id: 1,
                selected_dealer_ids: selected_dealer_ids.clone(),
            };
            if let Err(e) = coord
                .send_message_to_peer(peer_id, msg, Some(session_id))
                .await
            {
                tracing::warn!(
                    session_id = session_id,
                    peer_id = %peer_id,
                    error = %e,
                    "Reshare: failed to broadcast selected participant set"
                );
            }
        }

        coord.check_and_trigger_phase4(session_id).await?;
    }

    Ok(None)
}

pub(super) async fn handle_reshare_participant_set<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    from_node_id: u32,
    selected_dealer_ids: Vec<u32>,
) -> Result<Option<DkgMessage>>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let accepted = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if from_node_id != 1 {
                return Err(DkgError::Unauthorized(format!(
                    "ReshareParticipantSet must come from new committee node 1, got {}",
                    from_node_id
                )));
            }
            if !matches!(state.kind, SessionKind::Reshare { .. }) {
                return Err(DkgError::InvalidInput(
                    "ReshareParticipantSet received for non-reshare session".to_string(),
                ));
            }
            if !matches!(
                state.node.role(),
                DkgRole::Receiver | DkgRole::DealerReceiver
            ) {
                return Err(DkgError::InvalidInput(
                    "ReshareParticipantSet received by node outside new committee".to_string(),
                ));
            }
            if selected_dealer_ids.len() != state.node.threshold() {
                return Err(DkgError::InvalidInput(format!(
                    "ReshareParticipantSet has {} dealers, expected old threshold {}",
                    selected_dealer_ids.len(),
                    state.node.threshold()
                )));
            }

            let mut canonical = selected_dealer_ids.clone();
            canonical.sort_unstable();
            canonical.dedup();
            if canonical.len() != selected_dealer_ids.len() {
                return Err(DkgError::InvalidInput(
                    "ReshareParticipantSet contains duplicate dealer IDs".to_string(),
                ));
            }
            for dealer_id in &selected_dealer_ids {
                if *dealer_id == 0 || *dealer_id as usize > state.node.total_nodes() {
                    return Err(DkgError::InvalidInput(format!(
                        "ReshareParticipantSet dealer ID {} is outside old committee 1..={}",
                        dealer_id,
                        state.node.total_nodes()
                    )));
                }
            }

            if let Some(existing) = &state.reshare_selected_dealers {
                let mut existing_canonical = existing.clone();
                existing_canonical.sort_unstable();
                if existing_canonical == canonical {
                    return Ok(false);
                }
                return Err(DkgError::InvalidInput(format!(
                    "Conflicting ReshareParticipantSet: existing {:?}, new {:?}",
                    existing, selected_dealer_ids
                )));
            }

            state
                .node
                .select_reshare_participants(selected_dealer_ids.clone())
                .map_err(|e| {
                    DkgError::Crypto(format!("Failed to select reshare participants: {}", e))
                })?;
            state.reshare_selected_dealers = Some(selected_dealer_ids.clone());
            Ok(true)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .mark_message_processed(
            &session_id,
            from_node_id,
            DkgMessageType::ReshareParticipantSet,
        )
        .await;

    if accepted {
        tracing::info!(
            session_id = session_id,
            selected_dealers = ?selected_dealer_ids,
            "Reshare: accepted participant set"
        );
        coord.check_and_trigger_phase4(session_id).await?;
    }

    Ok(None)
}
