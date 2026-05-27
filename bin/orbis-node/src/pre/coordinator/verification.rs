use super::PreCoordinator;
use crate::pre::error::Result;
use crate::pre::messages::PreMessage;
use crypto::r#trait::{
    CryptoDeserialize, DistKeyShare, Dkg, PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use std::collections::HashSet;
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
    pub(crate) fn verify_peer_response(
        dealer: &T,
        response: PreMessage,
        rdr_pk: &D::PublicKey,
        pub_poly: &D::PubPoly,
        enc_cmt: &D::PublicKey,
        derivation: Option<&[u8]>,
        expected_node_id: Option<u32>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Result<Option<PubShare<D::PublicKey>>> {
        let PreMessage::ReencryptResponse {
            from_node_id,
            share: share_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            ..
        } = response
        else {
            return Ok(None);
        };

        if seen_node_ids.contains(&from_node_id) {
            return Ok(None);
        }

        if let Some(expected_node_id) = expected_node_id {
            if from_node_id != expected_node_id {
                tracing::error!(
                    from_node_id = from_node_id,
                    expected_node_id = expected_node_id,
                    "PRE Coordinator: authenticated peer claimed the wrong node_id"
                );
                return Ok(None);
            }
        }

        let share_v = match <D::PublicKey>::from_bytes(&share_bytes[..]) {
            Ok(share_v) => share_v,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "PRE Coordinator: Failed to deserialize share"
                );
                return Ok(None);
            }
        };

        let challenge = match <D::ShareValue>::from_bytes(&challenge_bytes[..]) {
            Ok(challenge) => challenge,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "PRE Coordinator: Failed to deserialize challenge"
                );
                return Ok(None);
            }
        };

        let proof = match <D::ShareValue>::from_bytes(&proof_bytes[..]) {
            Ok(proof) => proof,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "PRE Coordinator: Failed to deserialize proof"
                );
                return Ok(None);
            }
        };

        let reply = ReencryptReply {
            share: PubShare {
                i: from_node_id,
                v: share_v,
            },
            challenge,
            proof,
        };

        match dealer.verify(rdr_pk, pub_poly, enc_cmt, &reply, derivation) {
            Ok(_) => {
                tracing::debug!(
                    from_node_id = from_node_id,
                    "PRE Coordinator: Verified share"
                );
                seen_node_ids.insert(reply.share.i);
                Ok(Some(reply.share.clone()))
            }
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "PRE Coordinator: Failed to verify share"
                );
                Ok(None)
            }
        }
    }
}
