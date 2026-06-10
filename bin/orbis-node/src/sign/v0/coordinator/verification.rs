use super::SignCoordinator;
use crate::sign::v0::messages::SignMessage;
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
        expected_node_id: u32,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Option<PubShare<SigShareInner>> {
        let SignMessage::SignResponse {
            from_node_id,
            sig_share: sig_share_bytes,
            ..
        } = response
        else {
            return None;
        };

        if from_node_id != expected_node_id {
            tracing::error!(
                from_node_id = from_node_id,
                expected_node_id = expected_node_id,
                "Sign Coordinator: signature response node_id does not match authenticated peer"
            );
            return None;
        }

        if seen_node_ids.contains(&from_node_id) {
            return None;
        }

        let sig_share_v = SigShareInner::from_bytes(&sig_share_bytes[..])
            .inspect_err(|error| {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "Sign Coordinator: Failed to deserialize sig_share"
                );
                seen_node_ids.insert(from_node_id);
            })
            .ok()?;

        let sig_share = PubShare {
            i: from_node_id,
            v: sig_share_v,
        };

        signer
            .verify_share(
                message,
                pub_poly,
                &sig_share,
                signing_commitments,
                derivation,
                metadata,
            )
            .inspect_err(|error| {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "Sign Coordinator: Failed to verify share"
                );
            })
            .ok()?;

        tracing::debug!(
            from_node_id = from_node_id,
            "Sign Coordinator: Verified share"
        );
        seen_node_ids.insert(sig_share.i);
        Some(sig_share)
    }

    pub(crate) fn parse_peer_nonce_response(
        response: SignMessage,
        expected_node_id: u32,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Option<(u32, S::NonceCommitment)> {
        let SignMessage::NonceResponse {
            from_node_id,
            nonce_commitment,
            ..
        } = response
        else {
            return None;
        };

        if from_node_id != expected_node_id {
            tracing::error!(
                from_node_id = from_node_id,
                expected_node_id = expected_node_id,
                "Sign Coordinator: nonce response node_id does not match authenticated peer"
            );
            return None;
        }

        if seen_node_ids.contains(&from_node_id) {
            return None;
        }

        let commitment = <S::NonceCommitment>::from_bytes(&nonce_commitment)
            .inspect_err(|error| {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "Sign Coordinator: Failed to deserialize nonce commitment"
                );
                seen_node_ids.insert(from_node_id);
            })
            .ok()?;

        seen_node_ids.insert(from_node_id);
        Some((from_node_id, commitment))
    }
}
