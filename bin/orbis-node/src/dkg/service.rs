use crate::app_state::AppState;
use crate::crypto_service::{
    crypto_service_server::CryptoService, EncryptionRequest, EncryptionResponse, StartDkgRequest,
    StartDkgResponse,
};
use crypto::bls12_381::dkg::DKGNode;
use network::{Network, PeerId};
use std::collections::HashMap;
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

        // Connect to peer nodes using iroh network
        // Peer IDs should be in iroh PublicKey format: either "node_id" or "node_id@ip:port"
        // where node_id is the iroh public key string representation
        if !req.peer_ids.is_empty() {
            println!("Connecting to {} peer nodes...", req.peer_ids.len());

            for peer_id_str in &req.peer_ids {
                // Convert peer ID string to PeerId
                // The network.connect() method will parse this as UTF-8 and then as iroh PublicKey
                let peer_id = PeerId::new(peer_id_str.as_bytes().to_vec());

                // Connect to the peer using the DKG protocol
                // The protocol name matches what's defined in router.rs (alpn::DKG)
                match self.state.network.connect(&peer_id, "orbis/dkg/0").await {
                    Ok(mut connection) => {
                        println!("  ✓ Connected to peer: {}", peer_id_str);
                        // Connection is established, can be used for DKG communication
                        // TODO: Store connection or use it for DKG protocol
                        drop(connection); // Close for now, will be managed properly later
                    }
                    Err(e) => {
                        eprintln!("  ✗ Failed to connect to peer {}: {}", peer_id_str, e);
                        // Continue with other peers even if one fails
                        // In a production system, you might want to track failed connections
                        // and retry or return an error if critical peers are unreachable
                    }
                }
            }
        }

        // // Store session in shared state
        // let session = DKGNode {
        //     session_id: req.session_id.clone(),
        //     threshold: req.threshold,
        //     total_participants: req.total_participants,
        //     participant_ids: req.participant_ids.clone(),
        //     status: "started".to_string(),
        //     created_at,
        //     parameters: req.parameters.clone(),
        // };
        // self.state.store_dkg_session(session).await;

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
