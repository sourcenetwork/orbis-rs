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

// The fixtures craft signature shares directly (no nonce round), which only
// the non-interactive BLS backend supports; FROST shares require the
// commitment set from round 1.
#[cfg(all(test, feature = "bls12-381"))]
mod tests {
    use super::*;
    use common::blockchain::{sign_node_message_with_hex_key, ChainConfig, TxSigner};
    use crypto::r#trait::{CryptoSerialize, DkgRole, PriShare};
    use crypto::test_helper::DKGCoordinator;
    use crypto::{DkgImpl, ScalarField, SignImpl};

    struct VerifyFixture {
        signer: SignImpl,
        pub_poly: <DkgImpl as Dkg>::PubPoly,
        message: Vec<u8>,
        responder_node_key: String,
        signing_key_hex: String,
        ring_state_sha256: String,
        request_id: String,
        valid_sig_share: Vec<u8>,
        invalid_sig_share: Vec<u8>,
        from_node_id: u32,
    }

    fn verify_fixture() -> VerifyFixture {
        let mut coordinator = DKGCoordinator::new(
            |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role: DkgRole| {
                <DkgImpl as Dkg>::new(id, threshold, total_nodes, session_id, role)
            },
            3,
            2,
        )
        .unwrap();
        let (_, shares, pub_poly) = coordinator.run_dkg().unwrap();
        let responder_share = shares
            .into_iter()
            .find(|share| share.i == 2)
            .expect("node 2 share");
        let signer = SignImpl::new();
        let message = b"sign verifier report fixture".to_vec();
        let valid_share = signer
            .sign(
                &DistKeyShare {
                    pri_share: PriShare {
                        i: responder_share.i,
                        v: responder_share.v,
                    },
                },
                &message,
                &pub_poly,
                None,
                &[],
                None,
                None,
            )
            .unwrap();
        // A share produced with a corrupted secret stays well-formed and
        // deserializable but fails verification against the ring polynomial —
        // the same misbehavior the docker test injects by corrupting the
        // stored ring share.
        let invalid_share = signer
            .sign(
                &DistKeyShare {
                    pri_share: PriShare {
                        i: responder_share.i,
                        v: responder_share.v + ScalarField::from(1u64),
                    },
                },
                &message,
                &pub_poly,
                None,
                &[],
                None,
                None,
            )
            .unwrap();
        let signing_key_hex =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let responder_node_key = TxSigner::from_hex_key(&signing_key_hex, ChainConfig::local())
            .unwrap()
            .public_key_hex();

        VerifyFixture {
            signer,
            pub_poly,
            message,
            responder_node_key,
            signing_key_hex,
            ring_state_sha256: "00".repeat(32),
            request_id: "sign-verifier-test-request".to_string(),
            valid_sig_share: CryptoSerialize::to_bytes(&valid_share.v).unwrap(),
            invalid_sig_share: CryptoSerialize::to_bytes(&invalid_share.v).unwrap(),
            from_node_id: responder_share.i,
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signed_response(
        fixture: &VerifyFixture,
        sig_share: Vec<u8>,
        from_node_id: u32,
        signed_at: u64,
        signature_valid: bool,
    ) -> SignMessage {
        let statement = SignResponseStatement {
            domain: SIGN_RESPONSE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: fixture.ring_state_sha256.clone(),
            protocol_version: 0,
            request_id: fixture.request_id.clone(),
            signed_at,
            responder_node_key: fixture.responder_node_key.clone(),
            origin_protocol: "sign".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id,
            message: fixture.message.clone(),
            signing_commitments: Vec::new(),
            derivation: None,
            metadata: None,
            sig_share: sig_share.clone(),
            crypto_backend: SignImpl::name(),
        };
        let mut response_signature =
            sign_node_message_with_hex_key(&fixture.signing_key_hex, &statement.canonical_bytes())
                .unwrap();
        if !signature_valid {
            response_signature[0] ^= 0x01;
        }

        SignMessage::SignResponse {
            request_id: fixture.request_id.clone(),
            from_node_id,
            sig_share,
            signed_at,
            response_signature,
        }
    }

    fn report_context(fixture: &VerifyFixture) -> SignResponseReportContext {
        SignResponseReportContext {
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: fixture.ring_state_sha256.clone(),
            protocol_version: 0,
            request_id: fixture.request_id.clone(),
            accused_node_key: fixture.responder_node_key.clone(),
            accused_peer_id: "accused-peer".to_string(),
            origin_protocol: "sign".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            message: fixture.message.clone(),
            signing_commitments: Vec::new(),
            derivation: None,
            metadata: None,
        }
    }

    #[test]
    fn signed_invalid_sign_shares_are_reported_but_malformed_or_unsigned_are_rejected() {
        let fixture = verify_fixture();
        let context = report_context(&fixture);

        // A valid share is accepted.
        let mut seen = HashSet::new();
        let valid = signed_response(
            &fixture,
            fixture.valid_sig_share.clone(),
            fixture.from_node_id,
            unix_now(),
            true,
        );
        assert!(matches!(
            SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
                &fixture.signer,
                valid,
                &fixture.message,
                &fixture.pub_poly,
                &[],
                None,
                None,
                fixture.from_node_id,
                Some(&context),
                &mut seen,
            ),
            PeerSignatureVerification::Verified(_)
        ));
        assert!(seen.contains(&fixture.from_node_id));

        // A node_id mismatch with the authenticated peer is rejected outright.
        let mut seen = HashSet::new();
        let wrong_node_id = signed_response(
            &fixture,
            fixture.invalid_sig_share.clone(),
            fixture.from_node_id + 1,
            unix_now(),
            true,
        );
        assert!(matches!(
            SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
                &fixture.signer,
                wrong_node_id,
                &fixture.message,
                &fixture.pub_poly,
                &[],
                None,
                None,
                fixture.from_node_id,
                Some(&context),
                &mut seen,
            ),
            PeerSignatureVerification::Rejected
        ));
        assert!(seen.is_empty());

        // Malformed share bytes are corruption-in-transit, not provable misbehavior.
        let mut seen = HashSet::new();
        let malformed = signed_response(
            &fixture,
            vec![1, 2, 3],
            fixture.from_node_id,
            unix_now(),
            true,
        );
        assert!(matches!(
            SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
                &fixture.signer,
                malformed,
                &fixture.message,
                &fixture.pub_poly,
                &[],
                None,
                None,
                fixture.from_node_id,
                Some(&context),
                &mut seen,
            ),
            PeerSignatureVerification::Rejected
        ));
        assert!(seen.contains(&fixture.from_node_id));

        // A bad share whose node signature does not verify is rejected, not reported.
        let mut seen = HashSet::new();
        let unsigned = signed_response(
            &fixture,
            fixture.invalid_sig_share.clone(),
            fixture.from_node_id,
            unix_now(),
            false,
        );
        assert!(matches!(
            SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
                &fixture.signer,
                unsigned,
                &fixture.message,
                &fixture.pub_poly,
                &[],
                None,
                None,
                fixture.from_node_id,
                Some(&context),
                &mut seen,
            ),
            PeerSignatureVerification::Rejected
        ));
        assert!(seen.contains(&fixture.from_node_id));

        // A bad share that is honestly signed becomes an invalid-crypto observation.
        let mut seen = HashSet::new();
        let now = unix_now();
        let invalid = signed_response(
            &fixture,
            fixture.invalid_sig_share.clone(),
            fixture.from_node_id,
            now,
            true,
        );
        let result = SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
            &fixture.signer,
            invalid,
            &fixture.message,
            &fixture.pub_poly,
            &[],
            None,
            None,
            fixture.from_node_id,
            Some(&context),
            &mut seen,
        );
        let PeerSignatureVerification::InvalidCrypto(observation) = result else {
            panic!("signed invalid sign share should produce report observation");
        };
        assert_eq!(observation.ring_id, "ring");
        assert_eq!(observation.accused_node_key, fixture.responder_node_key);
        let InvalidCryptoResponse::Sign { statement, .. } = &observation.evidence else {
            panic!("Sign observation must carry Sign evidence");
        };
        assert_eq!(statement.sig_share, fixture.invalid_sig_share);
        assert_eq!(statement.signed_at, now);
        assert_eq!(statement.origin_protocol, "sign");
        assert_eq!(
            observation.observed_at,
            now - CHAIN_BLOCK_GRACE_SECS,
            "observation must anchor the envelope to the evidence timestamp"
        );
        assert!(seen.contains(&fixture.from_node_id));
    }

    #[test]
    fn responses_with_implausible_signed_at_are_rejected_even_with_valid_signatures() {
        let fixture = verify_fixture();
        let context = report_context(&fixture);

        // Future timestamp beyond the skew allowance: honestly signed bad share —
        // still rejected, so pre-signed future evidence can't be minted.
        let mut seen = HashSet::new();
        let future = signed_response(
            &fixture,
            fixture.invalid_sig_share.clone(),
            fixture.from_node_id,
            unix_now() + CHAIN_BLOCK_GRACE_SECS + 240,
            true,
        );
        assert!(matches!(
            SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
                &fixture.signer,
                future,
                &fixture.message,
                &fixture.pub_poly,
                &[],
                None,
                None,
                fixture.from_node_id,
                Some(&context),
                &mut seen,
            ),
            PeerSignatureVerification::Rejected
        ));

        // Stale timestamp: a signed bad share older than the report TTL is
        // rejected instead of becoming a (never-signable) report observation.
        let mut seen = HashSet::new();
        let stale = signed_response(
            &fixture,
            fixture.invalid_sig_share.clone(),
            fixture.from_node_id,
            unix_now() - REPORT_TTL_SECS - 240,
            true,
        );
        assert!(matches!(
            SignCoordinator::<DkgImpl, SignImpl>::verify_peer_signature_response(
                &fixture.signer,
                stale,
                &fixture.message,
                &fixture.pub_poly,
                &[],
                None,
                None,
                fixture.from_node_id,
                Some(&context),
                &mut seen,
            ),
            PeerSignatureVerification::Rejected
        ));
    }
}
