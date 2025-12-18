use crate::app_state::AppState;
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::error::DkgError;
use crate::dkg::messages::DkgMessage;
use crate::dkg_service::{dkg_service_server::DkgService, StartDkgRequest, StartDkgResponse};
use crate::helpers::helpers::{connect_to_peers, validate_all_peer_ids};
use network::DKG;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the DkgService
#[derive(Debug)]
pub struct DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone,
{
    pub state: AppState<D>,
}

impl<D> DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone,
{
    /// Create a new DkgServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<D> DkgService for DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            PolynomialCommitment = crypto::bls12_381::common::PolynomialCommitment,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    #[tracing::instrument(skip_all, fields(request))]
    async fn start_dkg(
        &self,
        request: Request<StartDkgRequest>,
    ) -> Result<Response<StartDkgResponse>, Status> {
        let req = request.into_inner();
        // TODO: Authentication, is user allowed to create a ring
        // TODO: Authenticate request info, fail if bad info ex: threshold > total_participants, participant_ids.len() != total_participants, duplicate participant IDs
        tracing::info!(
            session_id = %req.session_id,
            threshold = req.threshold,
            total_participants = req.total_participants,
            participant_ids = ?req.participant_ids,
            peer_ids = ?req.peer_ids,
            parameters = ?req.parameters,
            "Received StartDkg request"
        );

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // Convert session_id string to u64 using SHA-256 (cryptographic hash)
        // This allows string session IDs from the proto while DKGNode uses u64
        // Using SHA-256 prevents collision attacks that would be possible with DefaultHasher
        let hash = Sha256::digest(req.session_id.as_bytes());
        let session_id =
            u64::from_le_bytes(hash[..8].try_into().map_err(DkgError::HashConversion)?);

        // Create DKG coordinator (AppState clone is cheap - contains Arc types internally)
        let coordinator = DkgCoordinator::new(Arc::new(self.state.clone()));

        // Validate threshold and total_participants
        if req.threshold as usize > req.total_participants as usize {
            return Err(DkgError::InvalidInput(format!(
                "Threshold ({}) cannot be greater than total participants ({})",
                req.threshold, req.total_participants
            ))
            .into());
        }

        // Handle edge case: empty participants (for testing)
        // Return early without creating DKG session
        if req.total_participants == 0 {
            let response = StartDkgResponse {
                session_id: req.session_id.clone(),
                status: "started".to_string(),
                message: format!(
                    "DKG session started with threshold {} and {} participants",
                    req.threshold, req.total_participants
                ),
                created_at,
            };
            return Ok(Response::new(response));
        }

        // As the initiator, assign node_ids to all participants based on sorted peer list
        // This ensures all nodes agree on who has which node_id
        let our_peer_id_hex = hex::encode(self.state.network.local_peer_id().as_bytes());
        let mut all_peer_ids_for_assignments = vec![our_peer_id_hex.clone()];
        all_peer_ids_for_assignments.extend_from_slice(&req.peer_ids);

        // Build node_id assignments: peer_id -> node_id (1-indexed based on sorted order)
        let mut node_id_assignments = std::collections::HashMap::new();
        let mut sorted_peer_ids = all_peer_ids_for_assignments.clone();
        sorted_peer_ids.sort();

        for (idx, peer_id) in sorted_peer_ids.iter().enumerate() {
            let assigned_node_id = (idx + 1) as u32;
            // Extract just the hex part (before @) for consistent lookup
            let peer_id_key = peer_id.split('@').next().unwrap_or(peer_id).to_string();
            node_id_assignments.insert(peer_id_key, assigned_node_id);
        }

        // Get our assigned node_id
        let our_peer_id_key = our_peer_id_hex
            .split('@')
            .next()
            .unwrap_or(&our_peer_id_hex)
            .to_string();
        let our_assigned_node_id = node_id_assignments.get(&our_peer_id_key).ok_or_else(|| {
            DkgError::InvalidInput("Could not determine our node_id from assignments".to_string())
        })?;

        tracing::info!(
            our_node_id = our_assigned_node_id,
            total_participants = req.total_participants,
            "DKG Service (Initiator): Assigned node_ids"
        );

        // Create DKG session with assigned node_id
        coordinator
            .create_session(
                session_id,
                *our_assigned_node_id,
                req.threshold as usize,
                req.total_participants as usize,
            )
            .await?;

        // Store peer IDs in session state for later use (needed for Phase 2)
        coordinator
            .set_peer_ids(&session_id, req.peer_ids.clone())
            .await;

        // Store node_id to peer_id mappings for efficient routing
        // We'll do this after sending SessionInit, but for now the coordinator will handle it
        // when it processes the message (for consistency)

        // Connect to peer nodes using iroh network
        // Peer IDs should be in iroh PublicKey format: either "node_id" or "node_id@ip:port"
        // where node_id is the iroh public key string representation
        if !req.peer_ids.is_empty() {
            // Validate all peer IDs before attempting connections
            if let Err((invalid_peer_id, validation_error)) = validate_all_peer_ids(&req.peer_ids) {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid peer ID '{}': {}",
                    invalid_peer_id, validation_error
                ))
                .into());
            }

            let requested_peers = req.peer_ids.len();
            let connection_summary =
                connect_to_peers(&self.state.network, req.peer_ids.clone(), DKG).await;

            // Check if we successfully connected to all requested peers
            if connection_summary.successful < requested_peers {
                let error_msg = format!(
                    "Failed to connect to all required peers. Connected to {}/{} peers. Failed connections: {}",
                    connection_summary.successful,
                    requested_peers,
                    connection_summary.failed
                );
                tracing::error!(error = %error_msg, "Failed to connect to all peers");

                // Return gRPC error and end execution
                return Err(DkgError::NetworkConnection(error_msg).into());
            }

            // Send SessionInit message to all peers
            // Include all peer_ids (including our own) so non-initiators know who to send messages to
            // Get our own peer ID (hex-encoded)
            let mut all_peer_ids = vec![our_peer_id_hex.clone()];
            all_peer_ids.extend_from_slice(&req.peer_ids);

            // Store node_id to peer_id mappings for the initiator (we don't receive our own SessionInit)
            let mut node_id_to_peer_id = std::collections::HashMap::new();
            for (peer_id_key, node_id) in &node_id_assignments {
                // Find the full peer_id (with @address if present) from all_peer_ids
                let full_peer_id = all_peer_ids
                    .iter()
                    .find(|pid| pid.split('@').next().unwrap_or(pid) == peer_id_key)
                    .cloned()
                    .unwrap_or_else(|| peer_id_key.clone());
                node_id_to_peer_id.insert(*node_id, full_peer_id);
            }
            self.state
                .dkg_session_state
                .set_node_peer_mappings(&session_id, node_id_to_peer_id)
                .await;

            let participant_ids: Vec<u32> = (1..=req.total_participants as u32).collect();
            let session_init_msg = DkgMessage::SessionInit {
                session_id,
                threshold: req.threshold,
                total_participants: req.total_participants,
                participant_ids: participant_ids.clone(),
                peer_ids: all_peer_ids.clone(), // Include all peer_ids (including our own) so receivers know all participants
                node_id_assignments: node_id_assignments.clone(), // Assignments made by initiator
            };

            // Send SessionInit to all peers (they will create their sessions and start Phase 1)
            for peer_id_str in &req.peer_ids {
                if let Err(e) = coordinator
                    .send_message_to_peer(peer_id_str, session_init_msg.clone())
                    .await
                {
                    tracing::error!(peer_id = %peer_id_str, error = %e, "Failed to send SessionInit to peer");
                    // Continue with other peers
                }
            }

            // Initiate Phase 1: Generate polynomial and broadcast commitment
            // This happens for the initiator (Alice)
            if let Err(e) = coordinator
                .initiate_phase1_commitments(session_id, &req.peer_ids)
                .await
            {
                tracing::error!(error = %e, "Failed to initiate Phase 1");
                return Err(e.into());
            }

            tracing::info!("DKG Protocol: Phase 1 initiated, commitments broadcasted");
        }

        let response = StartDkgResponse {
            session_id: req.session_id.clone(),
            status: "started".to_string(),
            message: format!(
                "DKG session started with threshold {} and {} participants",
                req.threshold, req.total_participants
            ),
            created_at,
        };

        Ok(Response::new(response))
    }
}
