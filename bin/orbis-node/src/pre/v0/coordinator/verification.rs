use super::PreCoordinator;
use crate::pre::v0::messages::PreMessage;
use crate::reporting::v0::observation::InvalidCryptoResponseObservation;
use crate::reporting::v0::types::{
    InvalidCryptoResponse, PreReencryptResponseStatement, ReportedDocumentEvidence,
    CHAIN_BLOCK_GRACE_SECS, PRE_REENCRYPT_RESPONSE_DOMAIN, REPORT_TTL_SECS,
};
use common::blockchain::verify_node_message;
use crypto::r#trait::{
    CryptoDeserialize, DistKeyShare, Dkg, PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct PreResponseReportContext {
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub object_id: String,
    pub rdr_pk: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    /// The document's ACP timestamp (`DocumentPayload.timestamp`) — carried through to the
    /// signed `PreReencryptResponseStatement` so the inline-document evidence, when present, can
    /// be recomputed against `object_id` via `generate_document_id`.
    pub timestamp: Option<u64>,
    /// Set when this request's document was supplied inline rather than read from the bulletin.
    /// `invalid_crypto_response` reports are normally verified by re-reading the document from
    /// the bulletin by `object_id` (`require_pre_proof_verification_failure`,
    /// `reporting/v0/registry.rs`) — this carries the document instead (out-of-band via
    /// `ReportSigningContext`, never the on-chain envelope) so the report is still verifiable
    /// even though the document was never posted to the bulletin. The signed statement itself
    /// keeps only the `document_inline` bool.
    pub inline_document: Option<ReportedDocumentEvidence>,
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
        report_context: &PreResponseReportContext,
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
            chain_id: report_context.chain_id.clone(),
            ring_id: report_context.ring_id.clone(),
            ring_pk: report_context.ring_pk.clone(),
            ring_state_sha256: report_context.ring_state_sha256.clone(),
            protocol_version: report_context.protocol_version,
            request_id: report_context.request_id.clone(),
            signed_at,
            responder_node_key: report_context.accused_node_key.clone(),
            origin_protocol: "pre".to_string(),
            object_id: report_context.object_id.clone(),
            rdr_pk: report_context.rdr_pk.clone(),
            derivation: report_context.derivation.clone(),
            from_node_id,
            share: share_bytes.clone(),
            challenge: challenge_bytes.clone(),
            proof: proof_bytes.clone(),
            crypto_backend: T::name(),
            timestamp: report_context.timestamp,
            document_inline: report_context.inline_document.is_some(),
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
            return Self::report_invalid_pre_response(
                report_context,
                statement,
                response_signature,
                signed_at,
                from_node_id,
                seen_node_ids,
            );
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
            return Self::report_invalid_pre_response(
                report_context,
                statement,
                response_signature,
                signed_at,
                from_node_id,
                seen_node_ids,
            );
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
            return Self::report_invalid_pre_response(
                report_context,
                statement,
                response_signature,
                signed_at,
                from_node_id,
                seen_node_ids,
            );
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
            return Self::report_invalid_pre_response(
                report_context,
                statement,
                response_signature,
                signed_at,
                from_node_id,
                seen_node_ids,
            );
        }

        tracing::debug!(
            from_node_id = from_node_id,
            "PRE Coordinator: Verified share"
        );
        seen_node_ids.insert(reply.share.i);
        PeerResponseVerification::Verified(reply.share.clone())
    }

    /// Build an invalid-crypto observation for a response whose node signature
    /// has already been verified. A signed response whose share/challenge/proof
    /// cannot be deserialized is still attributable bad crypto, so a decode
    /// failure is treated the same as a proof that fails verification rather than
    /// being silently dropped. Co-signers reach the same conclusion because
    /// deserialization of the signed bytes is deterministic
    /// (see `require_pre_proof_verification_failure`).
    fn report_invalid_pre_response(
        report_context: &PreResponseReportContext,
        statement: PreReencryptResponseStatement,
        response_signature: Vec<u8>,
        signed_at: u64,
        from_node_id: u32,
        seen_node_ids: &mut HashSet<u32>,
    ) -> PeerResponseVerification<G1Affine> {
        seen_node_ids.insert(from_node_id);
        PeerResponseVerification::InvalidProof(Box::new(InvalidCryptoResponseObservation {
            ring_id: report_context.ring_id.clone(),
            accused_node_key: report_context.accused_node_key.clone(),
            accused_peer_id: report_context.accused_peer_id.clone(),
            // Pin the envelope to the evidence: observed_at == signed_at - grace.
            observed_at: signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
            evidence: InvalidCryptoResponse::Pre {
                statement,
                response_signature,
            },
            // Out-of-band for the co-signers when the request was inline; the ciphertext never
            // enters the threshold-signed envelope.
            inline_document: report_context.inline_document.clone(),
        }))
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
            origin_protocol: "pre".to_string(),
            object_id: fixture.object_id.clone(),
            rdr_pk: CryptoSerialize::to_bytes(&fixture.rdr_pk).unwrap(),
            derivation: None,
            from_node_id,
            share: share.clone(),
            challenge: challenge.clone(),
            proof: proof.clone(),
            crypto_backend: PreImpl::name(),
            timestamp: None,
            document_inline: false,
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

    fn report_context(fixture: &VerifyFixture, rdr_pk_bytes: &[u8]) -> PreResponseReportContext {
        PreResponseReportContext {
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "ring-pk".to_string(),
            ring_state_sha256: fixture.ring_state_sha256.clone(),
            protocol_version: 0,
            request_id: fixture.request_id.clone(),
            accused_node_key: fixture.responder_node_key.clone(),
            accused_peer_id: "accused-peer".to_string(),
            object_id: fixture.object_id.clone(),
            rdr_pk: rdr_pk_bytes.to_vec(),
            derivation: None,
            timestamp: None,
            inline_document: None,
        }
    }

    #[test]
    fn signed_invalid_or_malformed_pre_proofs_are_reported_but_unsigned_are_rejected() {
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

        // A malformed-but-signed share is attributable bad crypto: the responder
        // signed a statement whose share cannot be decoded, so it is reported
        // rather than dropped.
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
        let malformed_result = PreCoordinator::<DkgImpl, PreImpl>::verify_peer_response(
            &fixture.dealer,
            malformed_share,
            &fixture.rdr_pk,
            &fixture.pub_poly,
            &fixture.enc_cmt,
            None,
            fixture.from_node_id,
            &context,
            &mut seen,
        );
        let PeerResponseVerification::InvalidProof(observation) = malformed_result else {
            panic!("signed but malformed PRE share should produce a report observation");
        };
        let InvalidCryptoResponse::Pre { statement, .. } = &observation.evidence else {
            panic!("PRE observation must carry PRE evidence");
        };
        assert_eq!(statement.share, vec![1, 2, 3]);
        assert!(seen.contains(&fixture.from_node_id));

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

    /// An inline-sourced request's document was never posted to the bulletin, so
    /// `require_pre_proof_verification_failure` (`reporting/v0/registry.rs`) can't re-read it —
    /// instead the responder marks the statement `document_inline` and the coordinator carries the
    /// document out-of-band on the observation (`inline_document`) for the co-signers. A bad proof
    /// from such a request must still produce a full report, with that out-of-band evidence
    /// attached, exactly like a bulletin-sourced request would.
    #[test]
    fn invalid_pre_response_produces_a_self_verifying_report_when_document_is_inline() {
        let fixture = verify_fixture();
        let rdr_pk_bytes = CryptoSerialize::to_bytes(&fixture.rdr_pk).unwrap();
        let mut context = report_context(&fixture, &rdr_pk_bytes);
        let evidence = ReportedDocumentEvidence {
            document: "ciphertext-blob".to_string(),
            proof: "proof-blob".to_string(),
            policy_id: "policy-1".to_string(),
            resource: "document".to_string(),
            permission: "read".to_string(),
            tier: None,
        };
        context.timestamp = Some(1_700_000_000);
        context.inline_document = Some(evidence.clone());

        // Built by hand (not via `signed_response`) because the responder must sign over the
        // same `timestamp`/`document_inline` the coordinator's `report_context` carries, for the
        // reconstructed statement inside `verify_peer_response` to match this signature.
        let signed_at = unix_now();
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
            origin_protocol: "pre".to_string(),
            object_id: fixture.object_id.clone(),
            rdr_pk: rdr_pk_bytes.clone(),
            derivation: None,
            from_node_id: fixture.from_node_id,
            share: fixture.share.clone(),
            challenge: fixture.challenge.clone(),
            proof: fixture.invalid_proof.clone(),
            crypto_backend: PreImpl::name(),
            timestamp: Some(1_700_000_000),
            document_inline: true,
        };
        let response_signature =
            sign_node_message_with_hex_key(&fixture.signing_key_hex, &statement.canonical_bytes())
                .unwrap();
        let invalid_proof = PreMessage::ReencryptResponse {
            request_id: fixture.request_id.clone(),
            from_node_id: fixture.from_node_id,
            share: fixture.share.clone(),
            challenge: fixture.challenge.clone(),
            proof: fixture.invalid_proof.clone(),
            signed_at,
            response_signature,
        };

        let mut seen = HashSet::new();
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
            panic!("inline-sourced invalid PRE proof should still produce a report observation");
        };
        let InvalidCryptoResponse::Pre {
            statement: reported,
            ..
        } = &observation.evidence
        else {
            panic!("PRE observation must carry PRE evidence");
        };
        // The signed statement only marks the request inline — the ciphertext is not in it.
        assert!(reported.document_inline);
        // The document rides out-of-band on the observation for the co-signers.
        assert_eq!(observation.inline_document, Some(evidence));
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
