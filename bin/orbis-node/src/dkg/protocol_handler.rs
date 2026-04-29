//! DKG Protocol Handler
//!
//! Implements `MessageCoordinator` for `DkgCoordinator`, plugging it into the
//! generic `GenericProtocolHandler` loop defined in `helpers::protocol_handler`.

use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::messages::DkgMessage;
use crate::helpers::protocol_handler::MessageCoordinator;
use async_trait::async_trait;
use network::PeerId;

#[async_trait]
impl<D> MessageCoordinator for DkgCoordinator<D>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type Msg = DkgMessage;

    fn protocol_name(&self) -> &'static str {
        "DKG"
    }

    fn message_id(msg: &DkgMessage) -> String {
        msg.session_id().to_string()
    }

    fn make_error(&self, _id: &str, error: String) -> DkgMessage {
        DkgMessage::Error {
            session_id: 0,
            error,
        }
    }

    /// DKG has no stored-response shortcut — all messages go through `route_message`.
    async fn try_store_response(&self, msg: DkgMessage, _peer_id: &PeerId) -> Option<DkgMessage> {
        Some(msg)
    }

    async fn route_message(
        &self,
        msg: DkgMessage,
        peer_id: &PeerId,
    ) -> anyhow::Result<Option<DkgMessage>> {
        self.handle_message(msg, peer_id)
            .await
            .map_err(anyhow::Error::from)
    }
}
