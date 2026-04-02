use crate::constants::{MAX_COMMITMENT_COEFFICIENTS, MAX_TOKEN_LIFETIME_SECS};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    in_committee, node_index_in, serialize_commitment_coefficients, session_not_found,
    validate_dkg_claims, validate_refresh_session_init, validate_reshare_session_init,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::{DkgMessageType, ReshareParams};
use crate::helpers::helpers::{extract_node_part, is_self_peer_id};
use crate::ring_state::RingShareBundle;
use authn::{resolve_jwt_did, BearerToken, DkgClaims};
use crypto::r#trait::{DistributedShare, Dkg, DkgRole};
use crypto::{
    CryptoDeserialize, GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    ScalarField as Fr, GROUP_POINT_SIZE as G1_COMPRESSED_SIZE, SCALAR_SIZE as FR_COMPRESSED_SIZE,
};
use network::PeerId;
use std::collections::HashMap;
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
    peer_ids: &Vec<String>,
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
            let token: BearerToken<DkgClaims> =
                resolve_jwt_did(token_string, current_time, MAX_TOKEN_LIFETIME_SECS)
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
        let mut sorted_old = peer_ids.clone();
        sorted_old.sort();
        let mut sorted_new = next_peer_ids.clone();
        sorted_new.sort();

        let in_old = in_committee(&sorted_old, &our_node_part);
        let in_new = in_committee(&sorted_new, &our_node_part);

        // Role determines both what crypto this node performs and which node_id
        // namespace it uses.  Dealers use an OLD-committee index; Receivers use a
        // NEW-committee index; DealerReceivers use old for Phase 1/2 and new for
        // share routing/storage.  This dual-index design keeps the crypto layer
        // simple (one session_id, one node_id) at the cost of careful bookkeeping
        // in coordinator and ReshareParams.
        let role = match (in_old, in_new) {
            (true, true) => DkgRole::DealerReceiver,
            (true, false) => DkgRole::Dealer,
            (false, true) => DkgRole::Receiver,
            (false, false) => {
                return Err(DkgError::InvalidInput(
                    "Reshare SessionInit: this node is not in either committee".to_string(),
                ))
            }
        };

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

        // Dealers use their old-committee index for polynomial generation and share
        // routing to the new committee.  Pure Receivers have no old-committee index,
        // so they use their new-committee index as the session node_id (used only
        // for dedup and connection tracking — not for crypto output routing).
        let node_id = if in_old {
            node_index_in(&sorted_old, &our_node_part)
        } else {
            node_index_in(&sorted_new, &our_node_part)
        };

        // Pre-load old share for Dealer/DealerReceiver nodes.
        let old_share = if in_old {
            let bundle =
                RingShareBundle::load_by_ring_key(&coord.app_state.local_storage, ring_pk_hex)
                    .map_err(|e| {
                        DkgError::Storage(format!("Reshare: failed to load old share: {}", e))
                    })?;
            let pri = bundle.pri_share().map_err(|e| {
                DkgError::Deserialization(format!(
                    "Reshare: failed to deserialize old share: {}",
                    e
                ))
            })?;
            Some(pri.v)
        } else {
            None
        };

        // participating_ids = all old committee node IDs (full participation).
        let participating_ids: Vec<u32> = (1..=peer_ids.len() as u32).collect();

        let new_node_id = in_new.then(|| node_index_in(&sorted_new, &our_node_part));

        let params = ReshareParams {
            ring_key: ring_pk_hex.clone(),
            old_share,
            participating_ids,
            new_threshold: *new_threshold as usize,
            new_total_nodes: next_peer_ids.len(),
            new_peer_ids: sorted_new,
            new_node_id,
            bulletin_post_id: bulletin_post_id.clone(),
        };

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
            Err(e) => return Err(e),
        }

        // Set kind and reshare params atomically so that a commitment arriving
        // between the two writes never sees kind=Reshare with reshare_params=None.
        // Also sort next_peer_ids in the stored kind so downstream code
        // (bulletin post, union building) always uses a canonical ordered list.
        coord
            .app_state
            .dkg_session_state
            .with_state_mut(&session_id, |state| {
                let mut stored_kind = kind.clone();
                if let SessionKind::Reshare {
                    ref mut next_peer_ids,
                    ..
                } = stored_kind
                {
                    next_peer_ids.sort();
                }
                state.kind = stored_kind;
                if let Some(params) = maybe_reshare_params {
                    state.reshare_params = Some(params);
                }
            })
            .await;

        coord
            .app_state
            .dkg_session_state
            .set_pss_interval(&session_id, pss_interval)
            .await;
    }

    // For Reshare: peer_ids in session state = union(old, new) so that non-initiator
    // Dealer nodes know who to broadcast their commitment to.
    let session_peer_ids = if let SessionKind::Reshare { next_peer_ids, .. } = kind {
        let mut union: Vec<String> = peer_ids.clone();
        for p in next_peer_ids {
            if !union.contains(p) {
                union.push(p.clone());
            }
        }
        union
    } else {
        peer_ids.clone()
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

        coord
            .app_state
            .dkg_session_state
            .with_state_mut(&session_id, |state| state.generate_polynomial())
            .await
            .ok_or_else(|| session_not_found(session_id))??;

        if let Some(peer_ids) = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
        {
            let (commitment_bytes, node_id) = coord
                .app_state
                .dkg_session_state
                .with_state(&session_id, |state| {
                    let bytes =
                        serialize_commitment_coefficients(&state.node.commitment().coefficients)?;
                    Ok::<_, DkgError>((bytes, state.node.node_id()))
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

            if sent_count < expected_count {
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

    coord.check_and_trigger_phase4(session_id).await?;

    Ok(None)
}
