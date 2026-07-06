use super::PreCoordinator;
use crate::pre::v0::messages::PreMessage;
use crate::reporting::v0::observation::InvalidCryptoResponseObservation;
use crate::reporting::v0::types::{
    InvalidCryptoResponse, PreReencryptResponseStatement, CHAIN_BLOCK_GRACE_SECS,
    PRE_REENCRYPT_RESPONSE_DOMAIN, REPORT_TTL_SECS,
};
use common::blockchain::verify_node_message;
use crypto::r#trait::{
    CryptoDeserialize, DistKeyShare, Dkg, PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct PreResponseReportContext<'a> {
    pub chain_id: &'a str,
    pub ring_id: &'a str,
    pub ring_pk: &'a str,
    pub ring_state_sha256: &'a str,
    pub protocol_version: u64,
    pub request_id: &'a str,
    pub accused_node_key: &'a str,
    pub accused_peer_id: &'a str,
    pub object_id: &'a str,
    pub rdr_pk: &'a [u8],
    pub derivation: Option<&'a [u8]>,
}

pub(crate) enum PeerResponseVerification<PublicKey> {
    Verified(PubShare<PublicKey>),
    InvalidProof(Box<InvalidCryptoResponseObservation>),
    Rejected,
}

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
        expected_node_id: u32,
        report_context: &PreResponseReportContext<'_>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> PeerResponseVerification<D::PublicKey> {
        let PreMessage::ReencryptResponse {
            from_node_id,
            share: share_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            response_signature,
            ..
        } = response
        else {
            return PeerResponseVerification::Rejected;
        };

        if seen_node_ids.contains(&from_node_id) {
            return PeerResponseVerification::Rejected;
        }

        if from_node_id != expected_node_id {
            tracing::error!(
                from_node_id = from_node_id,
                expected_node_id = expected_node_id,
                "PRE Coordinator: authenticated peer claimed the wrong node_id"
            );
            return PeerResponseVerification::Rejected;
        }

        // Reject responses timestamped outside the plausible window before doing
        // any crypto: evidence older than the report TTL could never be reported,
        // and a future timestamp would let the responder pre-sign evidence that
        // stays reportable later. A responder gaming this check only excludes
        // itself — the response is dropped like an unsigned one.
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
                "PRE Coordinator: rejecting response with implausible signed_at"
            );
            return PeerResponseVerification::Rejected;
        }

        let statement = PreReencryptResponseStatement {
            domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: report_context.chain_id.to_string(),
            ring_id: report_context.ring_id.to_string(),
            ring_pk: report_context.ring_pk.to_string(),
            ring_state_sha256: report_context.ring_state_sha256.to_string(),
            protocol_version: report_context.protocol_version,
            request_id: report_context.request_id.to_string(),
            signed_at,
            responder_node_key: report_context.accused_node_key.to_string(),
            object_id: report_context.object_id.to_string(),
            rdr_pk: report_context.rdr_pk.to_vec(),
            derivation: report_context.derivation.map(ToOwned::to_owned),
            from_node_id,
            share: share_bytes.clone(),
            challenge: challenge_bytes.clone(),
            proof: proof_bytes.clone(),
            crypto_backend: T::name(),
        };

        if let Err(error) = verify_node_message(
            report_context.accused_node_key,
            &statement.canonical_bytes(),
            &response_signature,
        ) {
            tracing::warn!(
                from_node_id = from_node_id,
                accused_node_key = %report_context.accused_node_key,
                error = %error,
                "PRE Coordinator: rejecting response with invalid node signature"
            );
            return PeerResponseVerification::Rejected;
        }

        let share_v = <D::PublicKey>::from_bytes(&share_bytes[..])
            .inspect_err(|error| {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "PRE Coordinator: Failed to deserialize share"
                );
            })
            .ok();
        let Some(share_v) = share_v else {
            return PeerResponseVerification::Rejected;
        };

        let challenge = <D::ShareValue>::from_bytes(&challenge_bytes[..])
            .inspect_err(|error| {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "PRE Coordinator: Failed to deserialize challenge"
                );
            })
            .ok();
        let Some(challenge) = challenge else {
            return PeerResponseVerification::Rejected;
        };

        let proof = <D::ShareValue>::from_bytes(&proof_bytes[..])
            .inspect_err(|error| {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %error,
                    "PRE Coordinator: Failed to deserialize proof"
                );
            })
            .ok();
        let Some(proof) = proof else {
            return PeerResponseVerification::Rejected;
        };

        let reply = ReencryptReply {
            share: PubShare {
                i: from_node_id,
                v: share_v,
            },
            challenge,
            proof,
        };

        if let Err(error) = dealer.verify(rdr_pk, pub_poly, enc_cmt, &reply, derivation) {
            tracing::error!(
                from_node_id = from_node_id,
                error = %error,
                "PRE Coordinator: Failed to verify share"
            );
            seen_node_ids.insert(reply.share.i);
            return PeerResponseVerification::InvalidProof(Box::new(
                InvalidCryptoResponseObservation {
                    ring_id: report_context.ring_id.to_string(),
                    accused_node_key: report_context.accused_node_key.to_string(),
                    accused_peer_id: report_context.accused_peer_id.to_string(),
                    // Pin the envelope to the evidence: validators and the
                    // chain require observed_at == signed_at - grace, which
                    // makes the envelope's fixed TTL expiry the evidence expiry.
                    observed_at: signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
                    evidence: InvalidCryptoResponse::Pre {
                        statement,
                        response_signature,
                    },
                },
            ));
        }

        tracing::debug!(
            from_node_id = from_node_id,
            "PRE Coordinator: Verified share"
        );
        seen_node_ids.insert(reply.share.i);
        PeerResponseVerification::Verified(reply.share.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pre::v0::messages::PreMessage;
    use crate::reporting::v0::types::PRE_REENCRYPT_RESPONSE_DOMAIN;
    use common::blockchain::{sign_node_message_with_hex_key, ChainConfig, TxSigner};
    use crypto::r#trait::{CryptoSerialize, DkgRole};
    use crypto::test_helper::DKGCoordinator;
    use crypto::{DkgImpl, PreImpl, ScalarField};

    struct VerifyFixture {
        dealer: PreImpl,
        rdr_pk: <DkgImpl as Dkg>::PublicKey,
        pub_poly: <DkgImpl as Dkg>::PubPoly,
        enc_cmt: <DkgImpl as Dkg>::PublicKey,
        responder_node_key: String,
        signing_key_hex: String,
        ring_state_sha256: String,
        request_id: String,
        object_id: String,
        share: Vec<u8>,
        challenge: Vec<u8>,
        valid_proof: Vec<u8>,
        invalid_proof: Vec<u8>,
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
        let (aggregate_pk, shares, pub_poly) = coordinator.run_dkg().unwrap();
        let (_, encrypted_secret, _) =
            PreImpl::encrypt_secret(&aggregate_pk, b"verifier report fixture", None, None).unwrap();
        let enc_cmt = <DkgImpl as Dkg>::PublicKey::from_bytes(&encrypted_secret.enc_cmt).unwrap();
        let (_, rdr_pk) = PreImpl::generate_keypair();
        let responder_share = shares
            .into_iter()
            .find(|share| share.i == 2)
            .expect("node 2 share");
        let dealer = PreImpl::new();
        let reply = dealer
            .reencrypt(
                &DistKeyShare {
                    pri_share: responder_share,
                },
                &encrypted_secret,
                &rdr_pk,
                None,
            )
            .unwrap();
        let signing_key_hex =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let responder_node_key = TxSigner::from_hex_key(&signing_key_hex, ChainConfig::local())
            .unwrap()
            .public_key_hex();

        VerifyFixture {
            dealer,
            rdr_pk,
            pub_poly,
            enc_cmt,
            responder_node_key,
            signing_key_hex,
            ring_state_sha256: "00".repeat(32),
            request_id: "pre-verifier-test-request".to_string(),
            object_id: "pre-verifier-test-object".to_string(),
            share: CryptoSerialize::to_bytes(&reply.share.v).unwrap(),
            challenge: CryptoSerialize::to_bytes(&reply.challenge).unwrap(),
            valid_proof: CryptoSerialize::to_bytes(&reply.proof).unwrap(),
            invalid_proof: CryptoSerialize::to_bytes(&(reply.proof + ScalarField::from(1u64)))
                .unwrap(),
            from_node_id: reply.share.i,
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_response(
        fixture: &VerifyFixture,
        share: Vec<u8>,
        challenge: Vec<u8>,
        proof: Vec<u8>,
        from_node_id: u32,
        signed_at: u64,
        signature_valid: bool,
    ) -> PreMessage {
        let statement = PreReencryptResponseStatement {
            domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: fixture.ring_state_sha256.clone(),
            protocol_version: 0,
            request_id: fixture.request_id.clone(),
            signed_at,
            responder_node_key: fixture.responder_node_key.clone(),
            object_id: fixture.object_id.clone(),
            rdr_pk: CryptoSerialize::to_bytes(&fixture.rdr_pk).unwrap(),
            derivation: None,
            from_node_id,
            share: share.clone(),
            challenge: challenge.clone(),
            proof: proof.clone(),
            crypto_backend: PreImpl::name(),
        };
        let mut response_signature =
            sign_node_message_with_hex_key(&fixture.signing_key_hex, &statement.canonical_bytes())
                .unwrap();
        if !signature_valid {
            response_signature[0] ^= 0x01;
        }

        PreMessage::ReencryptResponse {
            request_id: fixture.request_id.clone(),
            from_node_id,
            share,
            challenge,
            proof,
            signed_at,
            response_signature,
        }
    }

    fn report_context<'a>(
        fixture: &'a VerifyFixture,
        rdr_pk_bytes: &'a [u8],
    ) -> PreResponseReportContext<'a> {
        PreResponseReportContext {
            chain_id: "chain",
            ring_id: "ring",
            ring_pk: "ring-pk",
            ring_state_sha256: &fixture.ring_state_sha256,
            protocol_version: 0,
            request_id: &fixture.request_id,
            accused_node_key: &fixture.responder_node_key,
            accused_peer_id: "accused-peer",
            object_id: &fixture.object_id,
            rdr_pk: rdr_pk_bytes,
            derivation: None,
        }
    }

    #[test]
    fn signed_invalid_pre_proofs_are_reported_but_malformed_or_unsigned_are_rejected() {
        let fixture = verify_fixture();
        let rdr_pk_bytes = CryptoSerialize::to_bytes(&fixture.rdr_pk).unwrap();
        let context = report_context(&fixture, &rdr_pk_bytes);

        let mut seen = HashSet::new();
        let invalid_signature = signed_response(
            &fixture,
            fixture.share.clone(),
            fixture.challenge.clone(),
            fixture.valid_proof.clone(),
            fixture.from_node_id,
            unix_now(),
            false,
        );
        assert!(matches!(
            PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
                &fixture.dealer,
                invalid_signature,
                &fixture.rdr_pk,
                &fixture.pub_poly,
                &fixture.enc_cmt,
                None,
                fixture.from_node_id,
                &context,
                &mut seen,
            ),
            PeerResponseVerification::Rejected
        ));
        assert!(seen.is_empty());

        let mut seen = HashSet::new();
        let wrong_node_id = signed_response(
            &fixture,
            fixture.share.clone(),
            fixture.challenge.clone(),
            fixture.valid_proof.clone(),
            fixture.from_node_id + 1,
            unix_now(),
            true,
        );
        assert!(matches!(
            PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
                &fixture.dealer,
                wrong_node_id,
                &fixture.rdr_pk,
                &fixture.pub_poly,
                &fixture.enc_cmt,
                None,
                fixture.from_node_id,
                &context,
                &mut seen,
            ),
            PeerResponseVerification::Rejected
        ));
        assert!(seen.is_empty());

        let mut seen = HashSet::new();
        let malformed_share = signed_response(
            &fixture,
            vec![1, 2, 3],
            fixture.challenge.clone(),
            fixture.valid_proof.clone(),
            fixture.from_node_id,
            unix_now(),
            true,
        );
        assert!(matches!(
            PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
                &fixture.dealer,
                malformed_share,
                &fixture.rdr_pk,
                &fixture.pub_poly,
                &fixture.enc_cmt,
                None,
                fixture.from_node_id,
                &context,
                &mut seen,
            ),
            PeerResponseVerification::Rejected
        ));
        assert!(seen.is_empty());

        let mut seen = HashSet::new();
        let now = unix_now();
        let invalid_proof = signed_response(
            &fixture,
            fixture.share.clone(),
            fixture.challenge.clone(),
            fixture.invalid_proof.clone(),
            fixture.from_node_id,
            now,
            true,
        );
        let result = PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
            &fixture.dealer,
            invalid_proof,
            &fixture.rdr_pk,
            &fixture.pub_poly,
            &fixture.enc_cmt,
            None,
            fixture.from_node_id,
            &context,
            &mut seen,
        );
        let PeerResponseVerification::InvalidProof(observation) = result else {
            panic!("signed invalid PRE proof should produce report observation");
        };
        assert_eq!(observation.ring_id, "ring");
        assert_eq!(observation.accused_node_key, fixture.responder_node_key);
        let InvalidCryptoResponse::Pre { statement, .. } = &observation.evidence else {
            panic!("PRE observation must carry PRE evidence");
        };
        assert_eq!(statement.proof, fixture.invalid_proof);
        assert_eq!(statement.signed_at, now);
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
        let rdr_pk_bytes = CryptoSerialize::to_bytes(&fixture.rdr_pk).unwrap();
        let context = report_context(&fixture, &rdr_pk_bytes);

        // Future timestamp beyond the skew allowance: correctly signed, valid
        // proof — still rejected, so pre-signed future evidence can't be minted.
        let mut seen = HashSet::new();
        let future = signed_response(
            &fixture,
            fixture.share.clone(),
            fixture.challenge.clone(),
            fixture.valid_proof.clone(),
            fixture.from_node_id,
            unix_now() + CHAIN_BLOCK_GRACE_SECS + 240,
            true,
        );
        assert!(matches!(
            PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
                &fixture.dealer,
                future,
                &fixture.rdr_pk,
                &fixture.pub_poly,
                &fixture.enc_cmt,
                None,
                fixture.from_node_id,
                &context,
                &mut seen,
            ),
            PeerResponseVerification::Rejected
        ));
        assert!(seen.is_empty());

        // Stale timestamp: a signed invalid proof older than the report TTL is
        // rejected instead of becoming a (never-signable) report observation.
        let mut seen = HashSet::new();
        let stale = signed_response(
            &fixture,
            fixture.share.clone(),
            fixture.challenge.clone(),
            fixture.invalid_proof.clone(),
            fixture.from_node_id,
            unix_now() - REPORT_TTL_SECS - 240,
            true,
        );
        assert!(matches!(
            PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
                &fixture.dealer,
                stale,
                &fixture.rdr_pk,
                &fixture.pub_poly,
                &fixture.enc_cmt,
                None,
                fixture.from_node_id,
                &context,
                &mut seen,
            ),
            PeerResponseVerification::Rejected
        ));
        assert!(seen.is_empty());
    }
}
