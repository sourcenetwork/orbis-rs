use tonic::{Request, Response, Status};

use super::crypto_service::{
    crypto_service_server::{CryptoService, CryptoServiceServer},
    EncryptionRequest, EncryptionResponse, StartDkgRequest, StartDkgResponse,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Implementation of the CryptoService
#[derive(Debug, Default)]
pub struct CryptoServiceImpl;

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
        println!("  Parameters: {:?}", req.parameters);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

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
    async fn request_encryption(
        &self,
        request: Request<EncryptionRequest>,
    ) -> Result<Response<EncryptionResponse>, Status> {
        let req = request.into_inner();

        println!("Received EncryptionRequest:");
        println!("  Key ID: {}", req.key_id);
        println!("  Plaintext length: {} bytes", req.plaintext.len());
        println!("  Algorithm: {}", req.encryption_algorithm);
        println!("  Metadata: {:?}", req.metadata);

        // TODO: Implement actual encryption logic here
        // For now, return a mock response
        let encrypted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // Generate a mock request ID
        let request_id = format!("encrypt-{}", encrypted_at);

        // For now, just echo back the plaintext as ciphertext (not secure!)
        // In production, you would encrypt the plaintext here
        let response = EncryptionResponse {
            request_id,
            ciphertext: req.plaintext, // TODO: Actually encrypt this
            nonce: vec![0u8; 12],      // TODO: Generate proper nonce
            algorithm_used: req.encryption_algorithm,
            encrypted_at,
        };

        Ok(Response::new(response))
    }
}
