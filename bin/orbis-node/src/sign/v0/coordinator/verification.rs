use super::SignCoordinator;
use crate::reporting::v0::observation::InvalidCryptoResponseObservation;
use crate::reporting::v0::types::{
    CommitteeScope, InvalidCryptoResponse, SignResponseStatement, CHAIN_BLOCK_GRACE_SECS,
    REPORT_TTL_SECS, SIGN_RESPONSE_DOMAIN,
};
use crate::sign::v0::messages::SignMessage;
use common::blockchain::verify_node_message;
use crypto::r#trait::{CryptoDeserialize, DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub(crate) struct SignResponseReportContext {
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub origin_protocol: String,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub message: Vec<u8>,
    pub signing_commitments: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub metadata: Option<Vec<u8>>,
}

pub(crate) enum PeerSignatureVerification {
    Verified(PubShare<SigShareInner>),
    InvalidCrypto(Box<InvalidCryptoResponseObservation>),
    Rejected,
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
    pub(crate) fn verify_peer_signature_response(
        signer: &S,
        response: SignMessage,
        message: &[u8],
        pub_poly: &D::PubPoly,
        signing_commitments: &[(u32, S::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
        expected_node_id: u32,
        report_context: Option<&SignResponseReportContext>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> PeerSignatureVerification {
        let SignMessage::SignResponse {
            from_node_id,
            sig_share: sig_share_bytes,
            signed_at,
            response_signature,
            ..
        } = response
        else {
            return PeerSignatureVerification::Rejected;
        };

        if from_node_id != expected_node_id {
            tracing::error!(
                from_node_id = from_node_id,
                expected_node_id = expected_node_id,
                "Sign Coordinator: signature response node_id does not match authenticated peer"
            );
            return PeerSignatureVerification::Rejected;
        }

        if seen_node_ids.contains(&from_node_id) {
            return PeerSignatureVerification::Rejected;
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
            .ok();
        let Some(sig_share_v) = sig_share_v else {
            return PeerSignatureVerification::Rejected;
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
            Ok(()) => {
                tracing::debug!(
                    from_node_id = from_node_id,
                    "Sign Coordinator: Verified share"
                );
                seen_node_ids.insert(sig_share.i);
                PeerSignatureVerification::Verified(sig_share)
            }
            Err(error) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "Sign Coordinator: Failed to verify share"
                );
                seen_node_ids.insert(sig_share.i);

                let Some(report_context) = report_context else {
                    return PeerSignatureVerification::Rejected;
                };

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if signed_at > now.saturating_add(CHAIN_BLOCK_GRACE_SECS)
                    || now.saturating_sub(signed_at) > REPORT_TTL_SECS
                {
                    tracing::warn!(
                        from_node_id = from_node_id,
                        signed_at = signed_at,
                        now = now,
                        "Sign Coordinator: rejecting bad share with implausible signed_at"
                    );
                    return PeerSignatureVerification::Rejected;
                }

                let statement = SignResponseStatement {
                    domain: SIGN_RESPONSE_DOMAIN.to_string(),
                    chain_id: report_context.chain_id.clone(),
                    ring_id: report_context.ring_id.clone(),
                    ring_pk: report_context.ring_pk.clone(),
                    ring_state_sha256: report_context.ring_state_sha256.clone(),
                    protocol_version: report_context.protocol_version,
                    request_id: report_context.request_id.clone(),
                    signed_at,
                    responder_node_key: report_context.accused_node_key.clone(),
                    origin_protocol: report_context.origin_protocol.clone(),
                    accused_committee_scope: report_context.accused_committee_scope,
                    signing_committee_scope: report_context.signing_committee_scope,
                    from_node_id,
                    message: report_context.message.clone(),
                    signing_commitments: report_context.signing_commitments.clone(),
                    derivation: report_context.derivation.clone(),
                    metadata: report_context.metadata.clone(),
                    sig_share: sig_share_bytes,
                    crypto_backend: S::name(),
                };

                if let Err(error) = verify_node_message(
                    &report_context.accused_node_key,
                    &statement.canonical_bytes(),
                    &response_signature,
                ) {
                    tracing::warn!(
                        from_node_id = from_node_id,
                        accused_node_key = %report_context.accused_node_key,
                        error = %error,
                        "Sign Coordinator: rejecting bad share with invalid node signature"
                    );
                    return PeerSignatureVerification::Rejected;
                }

                PeerSignatureVerification::InvalidCrypto(Box::new(
                    InvalidCryptoResponseObservation {
                        ring_id: report_context.ring_id.clone(),
                        accused_node_key: report_context.accused_node_key.clone(),
                        accused_peer_id: report_context.accused_peer_id.clone(),
                        observed_at: signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
                        evidence: InvalidCryptoResponse::Sign {
                            statement,
                            response_signature,
                        },
                    },
                ))
            }
        }
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
