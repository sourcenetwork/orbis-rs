use super::SignCoordinator;
use crate::app_state::PeerConnectionPool;
use crate::constants::PEER_RESPONSE_TIMEOUT;
use crate::helpers::response_manager::ResponseStoreOutcome;
use crate::helpers::wire;
use crate::sign::v0::error::{Result, SignError};
use crate::sign::v0::messages::SignMessage;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use network::{Message as NetworkMessage, Network, PeerId};
use std::{future::Future, sync::Arc};
use tokio::time::Instant;

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
        let deadline = Instant::now() + PEER_RESPONSE_TIMEOUT;
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

        let message_data = wire::encode(&message)
            .map_err(|e| SignError::Serialization(format!("Failed to serialize message: {}", e)))?;
        peer_exchange(
            &self.app_state.peer_connection_pool,
            &self.app_state.network,
            peer_id_str,
            self.routes.sign_alpn,
            NetworkMessage::new(message_data, self.routes.sign_alpn),
            deadline,
            |response, peer| {
                self.accept_response(
                    peer_id_str,
                    request_id,
                    expects_nonce_response,
                    response,
                    peer,
                )
            },
        )
        .await
    }

    async fn accept_response(
        &self,
        peer_id_str: &str,
        request_id: &str,
        expects_nonce_response: bool,
        response_msg: NetworkMessage,
        authenticated_peer_id: PeerId,
    ) -> Result<Option<AuthenticatedSignMessage>> {
        // Deserialize response
        let response: SignMessage = wire::decode(&response_msg.data).map_err(|e| {
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

        let authenticated_peer_hex = hex::encode(authenticated_peer_id.as_bytes());
        match response {
            response @ SignMessage::NonceResponse { .. } if expects_nonce_response => {
                match self
                    .app_state
                    .sign_response_state
                    .store_response_for_version(
                        self.routes.version,
                        response.request_id(),
                        response.clone(),
                        authenticated_peer_id.as_bytes(),
                    )
                    .await
                {
                    ResponseStoreOutcome::Stored | ResponseStoreOutcome::MissingRequest => {
                        Ok(Some(AuthenticatedSignMessage {
                            message: response,
                            sender_peer_hex: authenticated_peer_hex,
                        }))
                    }
                    ResponseStoreOutcome::UnexpectedOrDuplicatePeer => {
                        tracing::warn!(
                            peer = %peer_id_str,
                            authenticated_peer = %authenticated_peer_hex,
                            "Sign Coordinator: rejecting fast-path nonce response from unexpected or duplicate peer"
                        );
                        Ok(None)
                    }
                }
            }
            response @ SignMessage::SignResponse { .. } if !expects_nonce_response => {
                match self
                    .app_state
                    .sign_response_state
                    .store_response_for_version(
                        self.routes.version,
                        response.request_id(),
                        response.clone(),
                        authenticated_peer_id.as_bytes(),
                    )
                    .await
                {
                    ResponseStoreOutcome::Stored | ResponseStoreOutcome::MissingRequest => {
                        Ok(Some(AuthenticatedSignMessage {
                            message: response,
                            sender_peer_hex: authenticated_peer_hex,
                        }))
                    }
                    ResponseStoreOutcome::UnexpectedOrDuplicatePeer => {
                        tracing::warn!(
                            peer = %peer_id_str,
                            authenticated_peer = %authenticated_peer_hex,
                            "Sign Coordinator: rejecting fast-path signature response from unexpected or duplicate peer"
                        );
                        Ok(None)
                    }
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

async fn peer_exchange<T, F, Fut>(
    pool: &PeerConnectionPool,
    network: &Arc<dyn Network>,
    peer: &str,
    protocol: &[u8],
    request: NetworkMessage,
    deadline: Instant,
    accept_response: F,
) -> Result<T>
where
    F: FnOnce(NetworkMessage, PeerId) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut parent = None;
    let mut phase = "connecting";
    let exchange = tokio::time::timeout_at(deadline, async {
        let (stream, _) = pool
            .open_stream_observed(network, peer, protocol, |connection| {
                parent = connection.cloned();
                phase = if connection.is_some() {
                    "opening"
                } else {
                    "connecting"
                };
            })
            .await
            .map_err(|error| {
                SignError::NetworkConnection(format!(
                    "Failed to open stream to peer {peer}: {error}"
                ))
            })?;
        phase = "sending";
        stream.send(request).await.map_err(|error| {
            SignError::NetworkCommunication(format!(
                "Failed to send message to peer {peer}: {error}"
            ))
        })?;
        phase = "receiving";
        let response = stream.recv().await.map_err(|error| {
            SignError::NetworkCommunication(format!(
                "Failed to receive response from peer {peer}: {error}"
            ))
        })?;
        phase = "validating";
        accept_response(response, stream.peer_id().clone()).await
    })
    .await;
    let _ = parent;
    exchange.map_err(|_| {
        SignError::Timeout(format!("Peer exchange timed out while {phase} for {peer}"))
    })?
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
