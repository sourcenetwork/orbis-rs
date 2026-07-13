use super::PreCoordinator;
use crate::constants::PEER_RESPONSE_TIMEOUT;
use crate::helpers::response_manager::ResponseStoreOutcome;
use crate::pre::v0::error::{PreError, Result};
use crate::pre::v0::messages::PreMessage;
use crypto::r#trait::{DistKeyShare, Dkg, ReencryptReply, Secret, ThresholdDealer};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use network::Message as NetworkMessage;
impl<D, T> PreCoordinator<D, T>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    T: ThresholdDealer<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            Secret = Secret,
            ReencryptReply = ReencryptReply<Fr, G1Affine>,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    /// Send a PRE request to a peer and wait for the response
    ///
    /// This method sends a request and waits for the response on the same connection,
    /// storing the response for later collection. Returns the reencryption response
    /// when one was received and stored; peer errors and unexpected message types
    /// are logged and returned as `Ok(None)`.
    pub async fn send_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: PreMessage,
        request_id: &str,
    ) -> Result<Option<PreMessage>> {
        if !matches!(&message, PreMessage::ReencryptRequest(_)) {
            return Err(PreError::ProtocolError(
                "send_request_and_receive_response requires a ReencryptRequest".to_string(),
            ));
        }

        let stream = self
            .app_state
            .peer_connection_pool
            .open_stream(
                &self.app_state.network,
                peer_id_str,
                self.routes.reencrypt_alpn,
            )
            .await
            .map_err(|e| {
                PreError::NetworkConnection(format!(
                    "Failed to open stream to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let message_data = serde_json::to_vec(&message)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize message: {}", e)))?;

        stream
            .send(NetworkMessage::new(
                message_data,
                self.routes.reencrypt_alpn,
            ))
            .await
            .map_err(|e| {
                PreError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Wait for response on the same stream with timeout
        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, stream.recv())
            .await
            .map_err(|_| {
                PreError::Timeout(format!(
                    "Timed out waiting for response from peer {}",
                    peer_id_str
                ))
            })?
            .map_err(|e| {
                PreError::NetworkCommunication(format!(
                    "Failed to receive response from peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Deserialize response
        let response: PreMessage = serde_json::from_slice(&response_msg.data).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize response: {}", e))
        })?;

        if response.request_id() != request_id {
            return Err(PreError::ProtocolError(format!(
                "Peer {} responded with mismatched request_id: expected {}, got {}",
                peer_id_str,
                request_id,
                response.request_id()
            )));
        }

        // Only store valid reencryption responses; log and drop peer errors
        let authenticated_peer_id = stream.peer_id().clone();
        let authenticated_peer_hex = hex::encode(authenticated_peer_id.as_bytes());
        match response {
            response @ PreMessage::ReencryptResponse { .. } => {
                match self
                    .app_state
                    .pre_response_state
                    .store_response_for_version(
                        self.routes.version,
                        response.request_id(),
                        response.clone(),
                        authenticated_peer_id.as_bytes(),
                    )
                    .await
                {
                    ResponseStoreOutcome::Stored | ResponseStoreOutcome::MissingRequest => {
                        Ok(Some(response))
                    }
                    ResponseStoreOutcome::UnexpectedOrDuplicatePeer => {
                        tracing::warn!(
                            peer = %peer_id_str,
                            authenticated_peer = %authenticated_peer_hex,
                            "PRE Coordinator: rejecting fast-path response from unexpected or duplicate peer"
                        );
                        Ok(None)
                    }
                }
            }
            PreMessage::Error { error, .. } => {
                tracing::warn!(
                    peer = %peer_id_str,
                    error = %error,
                    "PRE Coordinator: peer returned an error, skipping share"
                );
                Ok(None)
            }
            _ => {
                tracing::warn!(
                    peer = %peer_id_str,
                    "PRE Coordinator: unexpected response type from peer, skipping"
                );
                Ok(None)
            }
        }
    }
}
