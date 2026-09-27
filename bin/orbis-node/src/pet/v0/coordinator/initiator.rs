//! Initiator-side threshold PET check.
//!
//! There is no separate "leader" concept here, exactly like PRE's own
//! reencryption round: whichever node received the external `StartPreRequest`
//! drives the check, fanning out directly to the whole ring committee and
//! computing its own contribution locally if it happens to be a member.

use super::PetCoordinator;
use crate::helpers::identity::{determine_session_node_id, is_self_peer_id};
use crate::helpers::node_routes::resolve_node_routes;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::helpers::response_manager::ResponseInitOutcome;
use crate::pet::v0::attestation::{PetCheckStatementContext, PetShareAttestation};
use crate::pet::v0::coordinator::verification::PetCheckResponseVerification;
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::{PetCheckContext, PetCheckRequest, PetMessage};
use crate::reporting::v0::observation::ReportObservation;
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::{ring_state_sha256, ReportedDocumentEvidence};
use crate::ring_state::RingShareBundle;
use authz::vera::ValidWindow;
use bulletin::r#trait::DocumentPayload;
use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, Pet, PriShare, PubShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{SigShareInner, SignImpl, SignaturePoint};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Duration;

/// Overall deadline for collecting threshold PET-check shares, mirroring
/// `PRE_COLLECTION_TIMEOUT`. A PET check runs at most once per PRE request
/// (never on a hot loop), so a generous bound is fine.
const PET_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine, PubPoly = D::PubPoly> + Send + Sync + 'static,
    SignImpl: ThresholdSigner<
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
    /// Run a threshold PET check for `document` against the owner registered
    /// on `audit_target_object_id`, returning the `threshold` signed
    /// attestations backing the check only when the tag genuinely matches
    /// that target. `check_pet_if_required` forwards these attestations to
    /// every PRE peer (via `PreRequestContext::pet_attestations`) so each one
    /// can independently verify the same check passed before releasing its
    /// reencryption share — see `verification::verify_pet_admission`. This
    /// function's own pass/fail result only ever gates whether PRE is
    /// attempted at all; it is not itself the security boundary anymore.
    ///
    /// Called only from PRE's own `start_pre` pipeline (`pre::v0::service::stages`),
    /// once per PET-gated request — see `pet/README.md`. Never called for a
    /// ring that doesn't require PET.
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_pet_check(
        &self,
        request_id: String,
        document: DocumentPayload,
        salt: Option<String>,
        object_id: String,
        document_evidence: Option<ReportedDocumentEvidence>,
        audit_target_object_id: String,
        actor_id: String,
        valid_window: Option<ValidWindow>,
    ) -> Result<Vec<PetShareAttestation>> {
        let document_inline = document_evidence.is_some();
        let ring_payload = read_ring_for_route(
            &*self.app_state.bulletin,
            &document.ring_id,
            self.routes.version,
        )
        .await
        .map_err(PetError::ProtocolError)?;
        if !ring_payload.requires_pet {
            return Err(PetError::ProtocolError(format!(
                "ring {} does not require a PET check",
                document.ring_id
            )));
        }

        // Authorization gate first — an unauthorized caller learns nothing
        // about whether the tag itself would have matched.
        super::verification::check_pet_permission(
            &*self.app_state.authz,
            &document,
            &audit_target_object_id,
            &actor_id,
            valid_window,
        )
        .await?;

        let threshold = ring_payload.threshold as usize;
        let committee_size = ring_payload.peer_node_keys.len();

        let ctx = PetCheckContext {
            document: document.clone(),
            salt: salt.clone(),
            object_id: object_id.clone(),
            document_inline,
        };
        // This node's own independent verification — matches
        // `Pet::verify_tag_knowledge`'s doc: "every PET participant,
        // including the initiator, must call this." The resolved
        // `ring_payload` here is discarded in favor of the one already
        // fetched above — same live read either way, no double-trust.
        let (tag, _pet_pk_hex, _digest, _) = self.verify_pet_check_request(&ctx).await?;

        // The one canonical statement every contribution in this round is
        // checked against — see `attestation`'s module doc comment for why
        // this is the same statement used for live verification, PRE-peer
        // admission, and (on failure) report evidence.
        let statement_ctx = PetCheckStatementContext {
            chain_id: self.app_state.bulletin.chain_id(),
            ring_id: document.ring_id.clone(),
            ring_pk: ring_payload.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(&ring_payload),
            protocol_version: self.routes.version,
            object_id: object_id.clone(),
            salt: salt.clone(),
            crypto_backend: P::name(),
            timestamp: document.timestamp,
            document_inline,
        };

        let node_id_opt =
            determine_session_node_id(&self.app_state.node_key, &ring_payload.peer_node_keys);

        // Per-share verification needs the checking key's own public
        // polynomial, not the main ring key's — loading it here also
        // enforces the pipeline's real, pre-existing invariant (see
        // `pet/README.md`) that whoever drives a `requires_pet` PRE round
        // must be a PET-committee (== main-ring) member, since PRE's own
        // later relay-setup stage already hard-requires this; failing here
        // instead just fails it earlier and more clearly.
        let bundle =
            RingShareBundle::load_by_pet_ring_key(&self.app_state.local_storage, &document.ring_id)
                .map_err(|e| {
                    PetError::Storage(format!("Failed to load PET share bundle: {}", e))
                })?;
        let pub_poly_bytes = hex::decode(&bundle.public_polynomial).map_err(|e| {
            PetError::Deserialization(format!("Failed to decode PET public polynomial hex: {}", e))
        })?;
        let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
            PetError::Deserialization(format!(
                "Failed to deserialize PET public polynomial: {}",
                e
            ))
        })?;

        let resolved = resolve_node_routes(&self.app_state.bulletin, &ring_payload.peer_node_keys)
            .await
            .map_err(PetError::ProtocolError)?;
        let expected_peer_ids: Vec<String> = resolved
            .iter()
            .map(|route| route.peer_id.clone())
            .filter(|peer_id| !is_self_peer_id(&self.app_state.network, peer_id))
            .collect();

        if self
            .app_state
            .pet_response_state
            .init_response_for_version(self.routes.version, request_id.clone(), &expected_peer_ids)
            .await
            == ResponseInitOutcome::AlreadyExists
        {
            return Err(PetError::ProtocolError(format!(
                "PET check request_id {} collided with an in-flight request",
                request_id
            )));
        }

        let mut shares: Vec<PubShare<G1Affine>> = Vec::with_capacity(committee_size);
        let mut attestations: Vec<PetShareAttestation> = Vec::with_capacity(committee_size);
        let mut seen_node_ids = HashSet::new();

        // This node's own local contribution — still individually
        // DLEQ-verified before being accepted, same as any peer's (defense
        // in depth: catches a local storage/computation bug, not just a
        // remote attacker).
        if let Some(node_id) = node_id_opt {
            let pri_share: PriShare<Fr> =
                PriShare::from_bytes(&bundle.share_bytes).map_err(|e| {
                    PetError::Deserialization(format!("Failed to deserialize PET share: {}", e))
                })?;
            let reply = P::partial_pet_check(&pri_share.v, node_id, &tag).map_err(|e| {
                PetError::Crypto(format!("Failed to compute PET check share: {}", e))
            })?;
            P::verify_partial_pet_check(&pub_poly, &tag, &reply).map_err(|e| {
                PetError::Crypto(format!(
                    "this node's own PET check contribution failed its own proof verification: {}",
                    e
                ))
            })?;
            let partial_bytes = CryptoSerialize::to_bytes(&reply.partial.v).map_err(|e| {
                PetError::Serialization(format!("Failed to serialize partial: {}", e))
            })?;
            let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).map_err(|e| {
                PetError::Serialization(format!("Failed to serialize challenge: {}", e))
            })?;
            let proof_bytes = CryptoSerialize::to_bytes(&reply.proof).map_err(|e| {
                PetError::Serialization(format!("Failed to serialize proof: {}", e))
            })?;
            let signed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| PetError::InvalidState(format!("Failed to get timestamp: {}", e)))?
                .as_secs();
            let statement = statement_ctx.statement_for(
                self.app_state.node_key.clone(),
                request_id.clone(),
                signed_at,
                node_id,
                partial_bytes.clone(),
                challenge_bytes.clone(),
                proof_bytes.clone(),
            );
            let signing_key = self
                .app_state
                .local_storage
                .get_encrypted(LocalStorageKeys::NodeSigningKey)
                .map_err(|e| PetError::Storage(format!("failed to read node signing key: {e}")))?
                .ok_or_else(|| {
                    PetError::Storage("node signing key is not configured".to_string())
                })?;
            let signing_key_hex = String::from_utf8(signing_key.to_vec()).map_err(|e| {
                PetError::Storage(format!("stored node signing key is not utf-8: {e}"))
            })?;
            let signature =
                sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
                    .map_err(|e| {
                        PetError::Crypto(format!("failed to sign PET check share: {e}"))
                    })?;
            seen_node_ids.insert(node_id);
            shares.push(PubShare {
                i: node_id,
                v: reply.partial.v,
            });
            attestations.push(PetShareAttestation {
                request_id: request_id.clone(),
                from_node_id: node_id,
                partial: partial_bytes,
                challenge: challenge_bytes,
                proof: proof_bytes,
                signed_at,
                signature,
            });
        }

        if shares.len() < threshold {
            let mut tasks = tokio::task::JoinSet::new();
            for peer_id in &expected_peer_ids {
                let peer_id = peer_id.clone();
                let request = PetMessage::CheckRequest(Box::new(PetCheckRequest {
                    request_id: request_id.clone(),
                    from_node_id: node_id_opt.unwrap_or(0),
                    context: ctx.clone(),
                }));
                let req_id = request_id.clone();
                let app_state = self.app_state.clone();
                let routes = self.routes;
                // A fresh coordinator per task is cheap: just `Arc<AppState>` +
                // a `'static` routes reference — mirrors PRE's own fan-out.
                tasks.spawn(async move {
                    let coordinator = PetCoordinator::<D, P>::with_routes(app_state, routes);
                    let result = coordinator
                        .send_check_request_and_receive_response(&peer_id, request, &req_id)
                        .await;
                    (peer_id, result)
                });
            }

            let collect = async {
                while let Some(joined) = tasks.join_next().await {
                    let (peer_id, result) = match joined {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "PET Coordinator: task join error");
                            continue;
                        }
                    };
                    match result {
                        Ok(Some(response @ PetMessage::CheckResponse { .. })) => {
                            // Required acceptance order (fixes a slot-preemption
                            // bug: a rejected response must never consume an
                            // honest participant's id) — see `pet/README.md`
                            // and `verify_check_response`'s own doc comment for
                            // the exact ordering this enforces.
                            match Self::verify_check_response(
                                response,
                                &peer_id,
                                &ring_payload,
                                &document.ring_id,
                                &pub_poly,
                                &tag,
                                &statement_ctx,
                                &request_id,
                                &document_evidence,
                                &mut seen_node_ids,
                            ) {
                                PetCheckResponseVerification::Verified(share, attestation) => {
                                    shares.push(share);
                                    attestations.push(*attestation);
                                }
                                PetCheckResponseVerification::InvalidProof(observation) => {
                                    let _ = queue_report::<D, SignImpl>(
                                        self.app_state.clone(),
                                        self.routes,
                                        ReportObservation::InvalidCryptoResponse(observation),
                                    )
                                    .await
                                    .inspect_err(|error| {
                                        tracing::warn!(
                                            peer = %peer_id,
                                            %error,
                                            "Failed to queue PET invalid-proof report observation"
                                        );
                                    });
                                }
                                PetCheckResponseVerification::Rejected => {}
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                peer = %peer_id,
                                %error,
                                "PET Coordinator: check request failed"
                            );
                        }
                    }
                    if shares.len() >= threshold {
                        break;
                    }
                }
            };
            if tokio::time::timeout(PET_COLLECTION_TIMEOUT, collect)
                .await
                .is_err()
            {
                tracing::warn!(
                    request_id = %request_id,
                    "PET Coordinator: collection deadline reached before threshold shares arrived"
                );
            }
        }

        self.app_state
            .pet_response_state
            .remove_response_for_version(self.routes.version, &request_id)
            .await;

        if shares.len() < threshold {
            return Err(PetError::InsufficientShares {
                got: shares.len(),
                need: threshold,
            });
        }

        let combined = P::combine_pet_check_shares(&shares, threshold, committee_size)
            .map_err(|e| PetError::Crypto(format!("Failed to combine PET check shares: {}", e)))?;

        // `audit_target_object_id` *is* the plaintext owner identity — see
        // `verification.rs`'s module doc comment for why no ACP identity
        // resolution step exists or is needed here.
        let target_fingerprint = P::owner_fingerprint(audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;

        P::verify_pet_match(&tag, &combined, &target_fingerprint)
            .map_err(|_| PetError::Mismatch)?;

        Ok(attestations)
    }
}
