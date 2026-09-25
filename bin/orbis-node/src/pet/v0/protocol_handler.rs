//! PET Protocol Handler
//!
//! Implements `MessageCoordinator` for `PetCoordinator`, plugging it into the
//! generic `GenericProtocolHandler` loop defined in `helpers::protocol_handler`
//! — mirrors `pre::v0::protocol_handler` exactly.

use crate::helpers::protocol_handler::MessageCoordinator;
use crate::pet::v0::coordinator::PetCoordinator;
use crate::pet::v0::messages::PetMessage;
use async_trait::async_trait;
use network::PeerId;

#[async_trait]
impl<D, P> MessageCoordinator for PetCoordinator<D, P>
where
    D: crypto::r#trait::Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    P: crypto::r#trait::Pet<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Send
        + Sync
        + 'static,
{
    type Msg = PetMessage;

    fn protocol_name(&self) -> &'static str {
        "PET"
    }

    fn message_id(msg: &PetMessage) -> String {
        msg.request_id().to_string()
    }

    fn make_error(&self, id: &str, error: String) -> PetMessage {
        PetMessage::Error {
            request_id: id.to_string(),
            error,
        }
    }

    /// `CheckResponse` messages are stored for the initiating coordinator;
    /// all other messages are routed to `handle_message`.
    async fn try_store_response(&self, msg: PetMessage, peer_id: &PeerId) -> Option<PetMessage> {
        if let PetMessage::CheckResponse { .. } = &msg {
            tracing::debug!(
                request_id = %msg.request_id(),
                from_node_id = ?msg.sender_node_id(),
                sender_peer = %hex::encode(peer_id.as_bytes()),
                "PET Coordinator: Storing response"
            );
            self.app_state
                .pet_response_state
                .store_response_for_version(
                    self.routes.version,
                    msg.request_id(),
                    msg.clone(),
                    peer_id.as_bytes(),
                )
                .await;
            None
        } else {
            Some(msg)
        }
    }

    async fn route_message(
        &self,
        msg: PetMessage,
        _peer_id: &PeerId,
    ) -> anyhow::Result<Option<PetMessage>> {
        self.handle_message(msg).await.map_err(anyhow::Error::from)
    }
}
