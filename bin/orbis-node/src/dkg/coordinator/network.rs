use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::DkgMessage;
use crate::metrics;
use crypto::r#trait::Dkg;
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment, ScalarField as Fr,
};
use network::{Connection as NetworkConnection, Message as NetworkMessage, DKG};
use std::sync::Arc;

use super::DkgCoordinator;

/// Send a DKG message to a peer.
///
/// When `session_id` is `Some`, the stream is cached in the session state so that
/// all messages within a session to the same peer travel on the same QUIC stream.
/// This preserves QUIC's within-stream ordering guarantee
/// (SessionInit → Commitment → Share arrive in order at the receiver).
///
/// When `session_id` is `None`, a fresh stream is opened and dropped after the send.
///
/// On connection-open failure the cached connection is evicted and a new one
/// is established before retrying.
pub(super) async fn send_message_to_peer<D>(
    coord: &DkgCoordinator<D>,
    peer_id_str: &str,
    message: DkgMessage,
    session_id: Option<u64>,
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let message_type = match &message {
        DkgMessage::SessionInit { .. } => "session_init",
        DkgMessage::Commitment { .. } => "commitment",
        DkgMessage::Share { .. } => "share",
        DkgMessage::Complaint { .. } => "complaint",
        DkgMessage::Error { .. } => "error",
    };

    let message_data = serde_json::to_vec(&message)
        .map_err(|e| DkgError::Serialization(format!("Failed to serialize message: {}", e)))?;

    let session_state = &coord.app_state.dkg_session_state;

    let stream: Arc<dyn NetworkConnection> = if let Some(sid) = session_id {
        if let Some(cached) = session_state.get_peer_stream(&sid, peer_id_str).await {
            cached
        } else {
            let new_stream = Arc::from(coord.open_stream_to_peer(peer_id_str).await?);
            session_state
                .store_peer_stream(&sid, peer_id_str.to_string(), Arc::clone(&new_stream))
                .await;
            new_stream
        }
    } else {
        Arc::from(coord.open_stream_to_peer(peer_id_str).await?)
    };

    stream
        .send(NetworkMessage::new(message_data, DKG))
        .await
        .map_err(|e| {
            DkgError::NetworkCommunication(format!("Failed to send to peer {}: {}", peer_id_str, e))
        })?;

    metrics::record_dkg_message_sent(message_type);
    Ok(())
}

/// Open a QUIC stream to a peer, evicting and reconnecting the cached connection on failure.
pub(super) async fn open_stream_to_peer<D>(
    coord: &DkgCoordinator<D>,
    peer_id_str: &str,
) -> Result<Box<dyn network::Connection>>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    coord
        .app_state
        .peer_connection_pool
        .open_stream(&coord.app_state.network, peer_id_str, DKG)
        .await
        .map_err(|e| {
            DkgError::NetworkConnection(format!(
                "Failed to open stream to peer {}: {}",
                peer_id_str, e
            ))
        })
}
