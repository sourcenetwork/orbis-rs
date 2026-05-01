use super::SignCoordinator;
use crate::constants::PEER_RESPONSE_TIMEOUT;
use crate::sign::error::{Result, SignError};
use crate::sign::helpers::store_response;
use crate::sign::messages::SignMessage;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use network::Message as NetworkMessage;
use network::SIGN;

pub(crate) struct AuthenticatedSignMessage {
    pub(crate) message: SignMessage,
    pub(crate) sender_peer_hex: String,
}

impl<D, S> SignCoordinator<D, S>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    /// Send a Sign request to a peer and wait for the response
    ///
    /// This method sends a request and waits for the response on the same connection,
    /// storing the response for later collection. Returns the response when one
    /// matching the request round was received and stored; peer errors and
    /// unexpected message types are logged and returned as `Ok(None)`.
    pub(crate) async fn send_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: SignMessage,
        request_id: &str,
    ) -> Result<Option<AuthenticatedSignMessage>> {
        let expects_nonce_response = match &message {
            SignMessage::NonceRequest(_) => true,
            SignMessage::SignRequest(_) => false,
            _ => {
                return Err(SignError::ProtocolError(
                    "send_request_and_receive_response requires a NonceRequest or SignRequest"
                        .to_string(),
                ));
            }
        };

        let stream = self
            .app_state
            .peer_connection_pool
            .open_stream(&self.app_state.network, peer_id_str, SIGN)
            .await
            .map_err(|e| {
                SignError::NetworkConnection(format!(
                    "Failed to open stream to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let message_data = serde_json::to_vec(&message)
            .map_err(|e| SignError::Serialization(format!("Failed to serialize message: {}", e)))?;

        stream
            .send(NetworkMessage::new(message_data, SIGN))
            .await
            .map_err(|e| {
                SignError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Wait for response on the same stream with timeout
        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, stream.recv())
            .await
            .map_err(|_| {
                SignError::Timeout(format!(
                    "Timed out waiting for response from peer {}",
                    peer_id_str
                ))
            })?
            .map_err(|e| {
                SignError::NetworkCommunication(format!(
                    "Failed to receive response from peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Deserialize response
        let response: SignMessage = serde_json::from_slice(&response_msg.data).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize response: {}", e))
        })?;

        if response.request_id() != request_id {
            return Err(SignError::ProtocolError(format!(
                "Peer {} responded with mismatched request_id: expected {}, got {}",
                peer_id_str,
                request_id,
                response.request_id()
            )));
        }

        let authenticated_peer_id = stream.peer_id().clone();
        let authenticated_peer_hex = hex::encode(authenticated_peer_id.as_bytes());
        match response {
            response @ SignMessage::NonceResponse { .. } if expects_nonce_response => {
                let accepted = store_response(
                    response.clone(),
                    &authenticated_peer_id,
                    &self.app_state.sign_response_state,
                )
                .await;
                if accepted {
                    Ok(Some(AuthenticatedSignMessage {
                        message: response,
                        sender_peer_hex: authenticated_peer_hex,
                    }))
                } else {
                    tracing::warn!(
                        peer = %peer_id_str,
                        authenticated_peer = %authenticated_peer_hex,
                        "Sign Coordinator: rejecting fast-path nonce response from unexpected or duplicate peer"
                    );
                    Ok(None)
                }
            }
            response @ SignMessage::SignResponse { .. } if !expects_nonce_response => {
                let accepted = store_response(
                    response.clone(),
                    &authenticated_peer_id,
                    &self.app_state.sign_response_state,
                )
                .await;
                if accepted {
                    Ok(Some(AuthenticatedSignMessage {
                        message: response,
                        sender_peer_hex: authenticated_peer_hex,
                    }))
                } else {
                    tracing::warn!(
                        peer = %peer_id_str,
                        authenticated_peer = %authenticated_peer_hex,
                        "Sign Coordinator: rejecting fast-path signature response from unexpected or duplicate peer"
                    );
                    Ok(None)
                }
            }
            SignMessage::Error { error, .. } => {
                tracing::warn!(
                    peer = %peer_id_str,
                    error = %error,
                    "Sign Coordinator: peer returned an error, skipping response"
                );
                Ok(None)
            }
            _ => {
                tracing::warn!(
                    peer = %peer_id_str,
                    expected = if expects_nonce_response {
                        "NonceResponse"
                    } else {
                        "SignResponse"
                    },
                    "Sign Coordinator: unexpected response type from peer, skipping"
                );
                Ok(None)
            }
        }
    }
}
