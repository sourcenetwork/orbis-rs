use super::SignCoordinator;
use crate::sign::error::Result;
use crate::sign::messages::SignMessage;
use crypto::r#trait::{CryptoDeserialize, DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use std::collections::HashSet;
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
    pub(crate) fn verify_peer_signature_response(
        signer: &S,
        response: SignMessage,
        message: &[u8],
        pub_poly: &D::PubPoly,
        signing_commitments: &[(u32, S::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Result<Option<PubShare<SigShareInner>>> {
        let SignMessage::SignResponse {
            from_node_id,
            sig_share: sig_share_bytes,
            ..
        } = response
        else {
            return Ok(None);
        };

        if seen_node_ids.contains(&from_node_id) {
            return Ok(None);
        }

        let sig_share_v = match SigShareInner::from_bytes(&sig_share_bytes[..]) {
            Ok(sig_share_v) => sig_share_v,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "Sign Coordinator: Failed to deserialize sig_share"
                );
                seen_node_ids.insert(from_node_id);
                return Ok(None);
            }
        };

        let sig_share = PubShare {
            i: from_node_id,
            v: sig_share_v,
        };

        match signer.verify_share(
            message,
            pub_poly,
            &sig_share,
            signing_commitments,
            derivation,
            metadata,
        ) {
            Ok(_) => {
                tracing::debug!(
                    from_node_id = from_node_id,
                    "Sign Coordinator: Verified share"
                );
                seen_node_ids.insert(sig_share.i);
                Ok(Some(sig_share))
            }
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "Sign Coordinator: Failed to verify share"
                );
                Ok(None)
            }
        }
    }

    pub(crate) fn parse_peer_nonce_response(
        response: SignMessage,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Result<Option<(u32, S::NonceCommitment)>> {
        let SignMessage::NonceResponse {
            from_node_id,
            nonce_commitment,
            ..
        } = response
        else {
            return Ok(None);
        };

        if seen_node_ids.contains(&from_node_id) {
            return Ok(None);
        }

        let commitment = match <S::NonceCommitment>::from_bytes(&nonce_commitment) {
            Ok(commitment) => commitment,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "Sign Coordinator: Failed to deserialize nonce commitment"
                );
                seen_node_ids.insert(from_node_id);
                return Ok(None);
            }
        };

        seen_node_ids.insert(from_node_id);
        Ok(Some((from_node_id, commitment)))
    }
}
