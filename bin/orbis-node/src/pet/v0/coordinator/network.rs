use super::PetCoordinator;
use crate::constants::PEER_RESPONSE_TIMEOUT;
use crate::helpers::response_manager::ResponseStoreOutcome;
use crate::helpers::wire;
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::PetMessage;
use crypto::r#trait::{Dkg, Pet};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use network::Message as NetworkMessage;

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    /// Send a PET-check request to a peer and wait for the response on the
    /// same connection. Mirrors
    /// `pre::v0::coordinator::network::send_request_and_receive_response`
    /// exactly.
    pub(crate) async fn send_check_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: PetMessage,
        request_id: &str,
    ) -> Result<Option<PetMessage>> {
        if !matches!(&message, PetMessage::CheckRequest(_)) {
            return Err(PetError::ProtocolError(
                "send_check_request_and_receive_response requires a CheckRequest".to_string(),
            ));
        }

        let stream = self
            .app_state
            .peer_connection_pool
            .open_stream(
                &self.app_state.network,
                peer_id_str,
                self.routes.pet_check_alpn,
            )
            .await
            .map_err(|e| {
                PetError::NetworkConnection(format!(
                    "Failed to open stream to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let message_data = wire::encode(&message)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize message: {}", e)))?;

        stream
            .send(NetworkMessage::new(
                message_data,
                self.routes.pet_check_alpn,
            ))
            .await
            .map_err(|e| {
                PetError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, stream.recv())
            .await
            .map_err(|_| {
                PetError::Timeout(format!(
                    "Timed out waiting for response from peer {}",
                    peer_id_str
                ))
            })?
            .map_err(|e| {
                PetError::NetworkCommunication(format!(
                    "Failed to receive response from peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let response: PetMessage = wire::decode(&response_msg.data).map_err(|e| {
            PetError::Deserialization(format!("Failed to deserialize response: {}", e))
        })?;

        if response.request_id() != request_id {
            return Err(PetError::ProtocolError(format!(
                "Peer {} responded with mismatched request_id: expected {}, got {}",
                peer_id_str,
                request_id,
                response.request_id()
            )));
        }

        let authenticated_peer_id = stream.peer_id().clone();
        let authenticated_peer_hex = hex::encode(authenticated_peer_id.as_bytes());
        match response {
            response @ PetMessage::CheckResponse { .. } => {
                let store_outcome = self
                    .app_state
                    .pet_response_state
                    .store_response_for_version(
                        self.routes.version,
                        response.request_id(),
                        response.clone(),
                        authenticated_peer_id.as_bytes(),
                    )
                    .await;

                match store_outcome {
                    ResponseStoreOutcome::Stored => Ok(Some(response)),
                    ResponseStoreOutcome::MissingRequest => {
                        tracing::debug!(
                            peer = %peer_id_str,
                            authenticated_peer = %authenticated_peer_hex,
                            request_id = %response.request_id(),
                            "PET Coordinator: fast-path response arrived after response state cleanup; returning for verification"
                        );
                        Ok(Some(response))
                    }
                    ResponseStoreOutcome::UnexpectedOrDuplicatePeer => {
                        tracing::warn!(
                            peer = %peer_id_str,
                            authenticated_peer = %authenticated_peer_hex,
                            "PET Coordinator: rejecting fast-path response from unexpected or duplicate peer"
                        );
                        Ok(None)
                    }
                }
            }
            PetMessage::Error { error, .. } => {
                tracing::warn!(
                    peer = %peer_id_str,
                    error = %error,
                    "PET Coordinator: peer returned an error, skipping share"
                );
                Ok(None)
            }
            _ => {
                tracing::warn!(
                    peer = %peer_id_str,
                    "PET Coordinator: unexpected response type from peer, skipping"
                );
                Ok(None)
            }
        }
    }
}
