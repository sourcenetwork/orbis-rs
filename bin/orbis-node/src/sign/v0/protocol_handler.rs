//! Sign Protocol Handler
//!
//! Implements `MessageCoordinator` for `SignCoordinator`, plugging it into the
//! generic `GenericProtocolHandler` loop defined in `helpers::protocol_handler`.

use crate::helpers::protocol_handler::MessageCoordinator;
use crate::sign::v0::coordinator::SignCoordinator;
use crate::sign::v0::helpers::store_response;
use crate::sign::v0::messages::SignMessage;
use async_trait::async_trait;
use network::PeerId;

#[async_trait]
impl<D, S> MessageCoordinator for SignCoordinator<D, S>
where
    D: crypto::r#trait::Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: crypto::r#trait::ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = crypto::SignaturePoint,
            SigShare = crypto::r#trait::PubShare<crypto::SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    type Msg = SignMessage;

    fn protocol_name(&self) -> &'static str {
        "Sign"
    }

    fn message_id(msg: &SignMessage) -> String {
        msg.request_id().to_string()
    }

    fn make_error(&self, id: &str, error: String) -> SignMessage {
        SignMessage::Error {
            request_id: id.to_string(),
            error,
        }
    }

    /// `SignResponse` and `NonceResponse` messages are stored for the initiating
    /// coordinator; all other messages are routed to `handle_message`.
    async fn try_store_response(&self, msg: SignMessage, peer_id: &PeerId) -> Option<SignMessage> {
        if matches!(
            &msg,
            SignMessage::SignResponse { .. } | SignMessage::NonceResponse { .. }
        ) {
            store_response(
                self.routes.version,
                msg,
                peer_id,
                &self.app_state.sign_response_state,
            )
            .await;
            None
        } else {
            Some(msg)
        }
    }

    async fn route_message(
        &self,
        msg: SignMessage,
        peer_id: &PeerId,
    ) -> anyhow::Result<Option<SignMessage>> {
        self.handle_message(msg, peer_id)
            .await
            .map_err(anyhow::Error::from)
    }
}
