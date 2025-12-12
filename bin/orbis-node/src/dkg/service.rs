use crate::app_state::AppState;
use crate::crypto_service::{
    crypto_service_server::CryptoService, StartDkgRequest, StartDkgResponse,
};
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::messages::DkgMessage;
use crate::helpers::helpers::connect_to_peers;
use network::iroh::router::alpn::DKG;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the CryptoService
#[derive(Debug)]
pub struct CryptoServiceImpl {
    pub state: AppState,
}

impl CryptoServiceImpl {
    /// Create a new CryptoServiceImpl with shared application state
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl Default for CryptoServiceImpl {
    fn default() -> Self {
        // Default implementation requires async initialization, so this is a placeholder
        // In practice, use CryptoServiceImpl::new() with a properly initialized AppState
        panic!("Default implementation not supported. Use CryptoServiceImpl::new() with initialized AppState")
    }
}

#[tonic::async_trait]
impl CryptoService for CryptoServiceImpl {
    async fn start_dkg(
        &self,
        request: Request<StartDkgRequest>,
    ) -> Result<Response<StartDkgResponse>, Status> {
        let req = request.into_inner();
        // TODO: Authentication, is user allowed to create a ring

        println!("Received StartDkg request:");
        println!("  Session ID: {}", req.session_id);
        println!("  Threshold: {}", req.threshold);
        println!("  Total Participants: {}", req.total_participants);
        println!("  Participant IDs: {:?}", req.participant_ids);
        println!("  Peer IDs: {:?}", req.peer_ids);
        println!("  Parameters: {:?}", req.parameters);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // Convert session_id string to u64 by hashing it
        // This allows string session IDs from the proto while DKGNode uses u64
        let mut hasher = DefaultHasher::new();
        req.session_id.hash(&mut hasher);
        let session_id = hasher.finish();

        // Create DKG coordinator
        let app_state_arc = Arc::new(self.state.clone());
        let coordinator = DkgCoordinator::new(app_state_arc);

        // Validate threshold and total_participants
        if req.threshold as usize > req.total_participants as usize {
            return Err(Status::invalid_argument(format!(
                "Threshold ({}) cannot be greater than total participants ({})",
                req.threshold, req.total_participants
            )));
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

        // Get node_id from config
        let node_id = self.state.config.node_id;

        // Create DKG session
        coordinator
            .create_session(
                session_id,
                node_id,
                req.threshold as usize,
                req.total_participants as usize,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to create DKG session: {}", e)))?;

        // Store peer IDs in session state for later use (needed for Phase 2)
        coordinator
            .set_peer_ids(&session_id, req.peer_ids.clone())
            .await;

        // Connect to peer nodes using iroh network
        // Peer IDs should be in iroh PublicKey format: either "node_id" or "node_id@ip:port"
        // where node_id is the iroh public key string representation
        if !req.peer_ids.is_empty() {
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
                eprintln!("Error: {}", error_msg);

                // Return gRPC error and end execution
                return Err(Status::failed_precondition(error_msg));
            }

            // Send SessionInit message to all peers
            // Include all peer_ids (including our own) so non-initiators know who to send messages to
            // First, get our own peer ID and add it to the list
            use network::Network;
            let our_address = self
                .state
                .network
                .local_address()
                .expect("Failed to get local address");
            let our_sockets = self.state.network.endpoint().bound_sockets();
            let our_socket_addr = our_sockets
                .first()
                .expect("Endpoint should have at least one bound socket");
            let our_peer_id_with_addr = format!("{}@{}", our_address, our_socket_addr);

            // Combine our peer ID with the provided peer_ids for SessionInit
            let mut all_peer_ids = vec![our_peer_id_with_addr];
            all_peer_ids.extend_from_slice(&req.peer_ids);

            let participant_ids: Vec<u32> = (1..=req.total_participants as u32).collect();
            let session_init_msg = DkgMessage::SessionInit {
                session_id,
                threshold: req.threshold,
                total_participants: req.total_participants,
                participant_ids: participant_ids.clone(),
                peer_ids: all_peer_ids.clone(), // Include all peer_ids (including our own) so receivers know all participants
            };

            // Send SessionInit to all peers (they will create their sessions and start Phase 1)
            for peer_id_str in &req.peer_ids {
                if let Err(e) = coordinator
                    .send_message_to_peer(peer_id_str, session_init_msg.clone())
                    .await
                {
                    eprintln!("Failed to send SessionInit to peer {}: {}", peer_id_str, e);
                    // Continue with other peers
                }
            }

            // Initiate Phase 1: Generate polynomial and broadcast commitment
            // This happens for the initiator (Alice)
            if let Err(e) = coordinator
                .initiate_phase1_commitments(session_id, &req.peer_ids)
                .await
            {
                eprintln!("Failed to initiate Phase 1: {}", e);
                return Err(Status::internal(format!(
                    "Failed to initiate Phase 1: {}",
                    e
                )));
            }

            println!("DKG Protocol: Phase 1 initiated, commitments broadcasted");
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
