//! PRE Protocol Handler
//!
//! Implements `MessageCoordinator` for `PreCoordinator`, plugging it into the
//! generic `GenericProtocolHandler` loop defined in `helpers::protocol_handler`.

use crate::helpers::protocol_handler::MessageCoordinator;
use crate::pre::coordinator::PreCoordinator;
use crate::pre::messages::PreMessage;
use async_trait::async_trait;
use network::PeerId;

#[async_trait]
impl<D, T> MessageCoordinator for PreCoordinator<D, T>
where
    D: crypto::r#trait::Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    T: crypto::r#trait::ThresholdDealer<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            Secret = crypto::r#trait::Secret,
            ReencryptReply = crypto::r#trait::ReencryptReply<
                crypto::ScalarField,
                crypto::GroupAffine,
            >,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    type Msg = PreMessage;

    fn protocol_name(&self) -> &'static str {
        "PRE"
    }

    fn message_id(msg: &PreMessage) -> String {
        msg.request_id().to_string()
    }

    fn make_error(&self, id: &str, error: String) -> PreMessage {
        PreMessage::Error {
            request_id: id.to_string(),
            error,
        }
    }

    /// `ReencryptResponse` messages are stored for the initiating coordinator;
    /// all other messages are routed to `handle_message`.
    async fn try_store_response(&self, msg: PreMessage, peer_id: &PeerId) -> Option<PreMessage> {
        if let PreMessage::ReencryptResponse { .. } = &msg {
            self.store_response(msg, peer_id).await;
            None
        } else {
            Some(msg)
        }
    }

    async fn route_message(
        &self,
        msg: PreMessage,
        _peer_id: &PeerId,
    ) -> anyhow::Result<Option<PreMessage>> {
        self.handle_message(msg).await.map_err(anyhow::Error::from)
    }
}
