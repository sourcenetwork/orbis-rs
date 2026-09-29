//! Initiator-side PET blind equality test (audit finding #2 — see
//! `docs/plans/pet-blind-equality-test-design.md`).
//!
//! There is no separate "leader" concept here, exactly like PRE's own
//! reencryption round: whichever node received the external `StartPreRequest`
//! drives the check, fanning out directly to the whole ring committee.
//!
//! Three sequential phases, each reusing the over-ask/timeout collection
//! pattern from `sign/v0/coordinator/rounds` with phase-specific acceptance
//! rules from the design doc's availability table:
//! - **Commit**: over-ask everyone, stop at `threshold`, freely
//!   substitutable (a late/dropped commit is simply not selected).
//! - **Reveal**: sent only to the exact `threshold` selected after commit.
//!   No substitution — any shortfall discards the whole attempt and returns
//!   an error; a fresh retry gets a brand-new `attempt_id` and entirely
//!   fresh randomness from every participant, per the design doc's
//!   cancellation-attack analysis.
//! - **Decrypt**: independent of reveal's participant set, over-ask again,
//!   freely substitutable, exactly like ordinary threshold decryption.
//!
//! This node's own local contribution, when it is itself a ring member, is
//! produced by calling the exact same handler methods
//! (`coordinator::handlers`) used for a live wire request, in-process with
//! this node's own peer id — so there is exactly one code path for each
//! phase's validation and crypto, not a second hand-duplicated one.

use super::verification::{
    build_and_verify_pet_blind_certificate, check_pet_permission, verify_commit_response,
    verify_decrypt_response, verify_reveal_response, PetCommitResponseVerification,
    PetDecryptResponseVerification, PetRevealResponseVerification,
};
use super::PetCoordinator;
use crate::constants::PET_COLLECTION_TIMEOUT;
use crate::helpers::identity::{determine_session_node_id, is_self_peer_id};
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, node_id_to_peer_id_from_routes,
    resolve_node_routes,
};
use crate::helpers::protocol_version::read_ring_for_route;
use crate::helpers::response_manager::ResponseInitOutcome;
use crate::pet::v0::attestation::{build_pet_blind_context, PetBlindEvidence};
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::{
    CommitRequest, DecryptRequest, PetCheckContext, PetMessage, RevealRequest,
};
use crate::reporting::v0::observation::{offline_observation_from_pet_error, ReportObservation};
use crate::reporting::v0::types::{
    pet_blind_selection_digest, PetBlindCertificate, PetBlindContext, PetBlindSignedDecrypt,
    PetBlindSignedReveal, ReportedDocumentEvidence,
};
use crate::reporting::v0::{queue_report, spawn_error_drain};
use crate::ring_state::RingShareBundle;
use authz::vera::ValidWindow;
use bulletin::r#trait::{DocumentPayload, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, Pet, PubShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{SigShareInner, SignImpl, SignaturePoint};
use std::collections::HashSet;

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
    /// Hand a phase's remaining in-flight peer tasks to the shared
    /// background drain (`reporting::v0::spawn_error_drain`) instead of
    /// letting them get silently cancelled when `tasks` is dropped — a late
    /// transport failure from a peer slower than this phase's collection
    /// deadline is still attributable as `node_offline`, exactly mirroring
    /// `sign/v0/coordinator/rounds`'s own drain — see the design doc's
    /// "Reuse the sign/v0/coordinator/rounds scheduling and background-drain
    /// pattern... Drain late responses for attribution" requirement.
    fn spawn_pet_offline_drain(
        &self,
        tasks: tokio::task::JoinSet<(String, Result<Option<PetMessage>>)>,
        ring_id: String,
        all_peer_ids: Vec<String>,
        peer_node_keys: Vec<String>,
        attempt_id: String,
    ) {
        let protocol_version = self.routes.version;
        spawn_error_drain::<D, SignImpl, _, _, _>(
            tasks,
            self.app_state.clone(),
            self.routes,
            PET_COLLECTION_TIMEOUT,
            move |peer_id, error| {
                offline_observation_from_pet_error(
                    &ring_id,
                    &all_peer_ids,
                    &peer_node_keys,
                    &peer_id,
                    &error,
                    protocol_version,
                    &attempt_id,
                )
                .map(ReportObservation::NodeOffline)
            },
        );
    }

    /// Decrypt-phase-specific variant of `spawn_pet_offline_drain`. Decrypt
    /// over-asks the whole committee and stops as soon as `threshold`
    /// genuine shares arrive (see this module's doc comment), so a
    /// still-in-flight task can resolve *successfully* — carrying a
    /// decryption proof that fails to verify — only after collection has
    /// already moved on. The plain error-only drain above would silently
    /// discard that response (`spawn_error_drain` only classifies `Err`
    /// outcomes; a late `Ok(_)` is dropped unconditionally), letting a
    /// misbehaving node dodge attribution purely by resolving after enough
    /// honest shares already arrived. This re-runs `verify_decrypt_response`
    /// on every late-but-successful response too, exactly as the live
    /// collection loop would have, queuing an `invalid_crypto_response`
    /// report when it fails. Reveal has no equivalent gap — it asks for
    /// exactly the selected `threshold`-sized set, so nothing "extra" can
    /// race past unexamined — and commit has nothing to misreport (a
    /// commitment carries no proof yet), so neither needs this.
    #[allow(clippy::too_many_arguments)]
    fn spawn_pet_decrypt_drain(
        &self,
        tasks: tokio::task::JoinSet<(String, Result<Option<PetMessage>>)>,
        ring_id: String,
        all_peer_ids: Vec<String>,
        peer_node_keys: Vec<String>,
        attempt_id: String,
        ring_payload: RingPayload,
        pub_poly: D::PubPoly,
        context_digest: [u8; 32],
        certificate_digest: [u8; 32],
        aggregate_r_bytes: Vec<u8>,
        aggregate_diff_bytes: Vec<u8>,
        blind_context: PetBlindContext,
        document_evidence: Option<ReportedDocumentEvidence>,
    ) {
        let protocol_version = self.routes.version;
        let app_state = self.app_state.clone();
        let routes = self.routes;
        let mut tasks = tasks;
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + PET_COLLECTION_TIMEOUT;
            let mut seen_node_ids = HashSet::new();
            while let Ok(Some(joined)) = tokio::time::timeout_at(deadline, tasks.join_next()).await
            {
                let (peer_id, result) = match joined {
                    Ok(pair) => pair,
                    Err(join_err) => {
                        tracing::error!(
                            error = ?join_err,
                            "PET decrypt drain: peer task panicked"
                        );
                        continue;
                    }
                };
                match result {
                    Ok(Some(response @ PetMessage::DecryptResponse { .. })) => {
                        if let PetDecryptResponseVerification::InvalidProof(observation) =
                            verify_decrypt_response::<P>(
                                response,
                                &ring_id,
                                &ring_payload,
                                &peer_id,
                                &pub_poly,
                                context_digest,
                                certificate_digest,
                                &attempt_id,
                                &aggregate_r_bytes,
                                &aggregate_diff_bytes,
                                &blind_context,
                                &document_evidence,
                                &mut seen_node_ids,
                            )
                        {
                            let _ = queue_report::<D, SignImpl>(
                                app_state.clone(),
                                routes,
                                ReportObservation::InvalidCryptoResponse(observation),
                            )
                            .await
                            .inspect_err(|error| {
                                tracing::warn!(
                                    peer_id = %peer_id,
                                    error = %error,
                                    "Failed to queue PET invalid-decrypt report observation \
                                     (post-threshold drain)"
                                );
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        if let Some(obs) = offline_observation_from_pet_error(
                            &ring_id,
                            &all_peer_ids,
                            &peer_node_keys,
                            &peer_id,
                            &error,
                            protocol_version,
                            &attempt_id,
                        )
                        .map(ReportObservation::NodeOffline)
                        {
                            let _ = queue_report::<D, SignImpl>(app_state.clone(), routes, obs)
                                .await
                                .inspect_err(|error| {
                                    tracing::warn!(
                                        peer_id = %peer_id,
                                        error = %error,
                                        "Failed to queue offline report observation \
                                         (post-threshold drain)"
                                    );
                                });
                        }
                    }
                }
            }
        });
    }

    /// Run the three-round blind equality test for `document` against the
    /// owner registered on `audit_target_object_id`, returning the portable
    /// [`PetBlindEvidence`] backing the check only when the tag genuinely
    /// matches that target. `check_pet_if_required` forwards this evidence
    /// to every PRE peer (via `PreRequestContext::pet_evidence`) so each one
    /// can independently verify the same check passed before releasing its
    /// reencryption share — see `verification::verify_pet_admission`.
    ///
    /// Called only from PRE's own `start_pre` pipeline
    /// (`pre::v0::service::stages`), once per PET-gated request. Never
    /// called for a ring that doesn't require PET.
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
        token_string: String,
    ) -> Result<PetBlindEvidence> {
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
        check_pet_permission(
            &*self.app_state.authz,
            &document,
            &audit_target_object_id,
            &actor_id,
            valid_window.clone(),
        )
        .await?;

        // Fresh per comparison, distinct from the outer PRE `request_id` —
        // phase-specific transport ids are derived from it below.
        let attempt_id = format!("{request_id}-{}", rand::random::<u64>());

        let ctx = PetCheckContext {
            document: document.clone(),
            salt: salt.clone(),
            object_id: object_id.clone(),
            document_inline,
            token_string,
            audit_target_object_id: audit_target_object_id.clone(),
            valid_window,
        };
        // This node's own independent verification of the underlying tag —
        // matches `Pet::verify_tag_knowledge`'s doc: "every PET participant,
        // including the initiator, must call this."
        let (tag, pet_pk_hex, _digest, _) = self.verify_pet_check_request(&ctx).await?;

        let threshold = ring_payload.threshold as usize;
        let committee_size = ring_payload.peer_node_keys.len();
        let node_id_opt =
            determine_session_node_id(&self.app_state.node_key, &ring_payload.peer_node_keys);
        let local_peer_id = self.app_state.network.local_peer_id();

        // This attempt's one canonical context — every response in every
        // phase is checked against this exact, self-computed digest, never
        // a value merely echoed back by a responder.
        let blind_context = build_pet_blind_context(
            self.app_state.bulletin.chain_id(),
            &ring_payload,
            &pet_pk_hex,
            self.routes.version,
            P::name(),
            &ctx,
            actor_id,
            self.app_state.node_key.clone(),
            attempt_id.clone(),
        );
        let context_digest = blind_context.context_digest();

        let resolved = resolve_node_routes(&self.app_state.bulletin, &ring_payload.peer_node_keys)
            .await
            .map_err(PetError::ProtocolError)?;
        // Index-aligned with `ring_payload.peer_node_keys` (unfiltered) — the
        // shape `offline_observation_from_pet_error` needs; `remote_peer_ids`
        // below is the same list with self removed for actually sending
        // requests, which breaks that alignment.
        let all_peer_ids: Vec<String> =
            resolved.iter().map(|route| route.peer_id.clone()).collect();
        let remote_peer_ids: Vec<String> = resolved
            .iter()
            .map(|route| route.peer_id.clone())
            .filter(|peer_id| !is_self_peer_id(&self.app_state.network, peer_id))
            .collect();
        let node_id_assignments =
            canonical_node_id_assignments_from_node_keys(&ring_payload.peer_node_keys)
                .map_err(PetError::ProtocolError)?;
        let node_id_to_peer_id = node_id_to_peer_id_from_routes(&resolved, &node_id_assignments)
            .map_err(PetError::ProtocolError)?;

        let target_fingerprint = P::owner_fingerprint(audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;

        // ===================== Round 1 — Commit =====================
        let mut commitments: Vec<(u32, [u8; 32])> = Vec::with_capacity(committee_size);
        let mut seen_commit_ids = HashSet::new();

        if let Some(node_id) = node_id_opt {
            let commit_req = CommitRequest {
                request_id: format!("commit-{attempt_id}"),
                attempt_id: attempt_id.clone(),
                from_node_id: node_id,
                context: ctx.clone(),
            };
            if let Ok(Some(response)) = self.handle_commit_request(commit_req, &local_peer_id).await
            {
                if let PetCommitResponseVerification::Verified {
                    node_id,
                    commitment,
                } = verify_commit_response(
                    response,
                    &ring_payload,
                    context_digest,
                    &mut seen_commit_ids,
                ) {
                    commitments.push((node_id, commitment));
                }
            }
        }

        if commitments.len() < threshold && !remote_peer_ids.is_empty() {
            let commit_request_id = format!("commit-{attempt_id}");
            if self
                .app_state
                .pet_response_state
                .init_response_for_version(
                    self.routes.version,
                    commit_request_id.clone(),
                    &remote_peer_ids,
                )
                .await
                == ResponseInitOutcome::AlreadyExists
            {
                return Err(PetError::ProtocolError(format!(
                    "PET commit request_id {commit_request_id} collided with an in-flight request"
                )));
            }

            let mut tasks = tokio::task::JoinSet::new();
            for peer_id in &remote_peer_ids {
                let peer_id = peer_id.clone();
                let request = PetMessage::CommitRequest(Box::new(CommitRequest {
                    request_id: commit_request_id.clone(),
                    attempt_id: attempt_id.clone(),
                    from_node_id: node_id_opt.unwrap_or(0),
                    context: ctx.clone(),
                }));
                let req_id = commit_request_id.clone();
                let app_state = self.app_state.clone();
                let routes = self.routes;
                tasks.spawn(async move {
                    let coordinator = PetCoordinator::<D, P>::with_routes(app_state, routes);
                    let result = coordinator
                        .send_pet_request_and_receive_response(&peer_id, request, &req_id)
                        .await;
                    (peer_id, result)
                });
            }

            let collect = async {
                while let Some(joined) = tasks.join_next().await {
                    let (peer_id, result) = match joined {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "PET Coordinator: commit task join error");
                            continue;
                        }
                    };
                    match result {
                        Ok(Some(response @ PetMessage::CommitResponse { .. })) => {
                            if let PetCommitResponseVerification::Verified {
                                node_id,
                                commitment,
                            } = verify_commit_response(
                                response,
                                &ring_payload,
                                context_digest,
                                &mut seen_commit_ids,
                            ) {
                                commitments.push((node_id, commitment));
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                peer = %peer_id,
                                %error,
                                "PET Coordinator: commit request failed"
                            );
                        }
                    }
                    if commitments.len() >= threshold {
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
                    "PET Coordinator: commit collection deadline reached before threshold shares arrived"
                );
            }
            self.spawn_pet_offline_drain(
                tasks,
                document.ring_id.clone(),
                all_peer_ids.clone(),
                ring_payload.peer_node_keys.clone(),
                attempt_id.clone(),
            );
            self.app_state
                .pet_response_state
                .remove_response_for_version(self.routes.version, &commit_request_id)
                .await;
        }

        if commitments.len() < threshold {
            return Err(PetError::InsufficientShares {
                got: commitments.len(),
                need: threshold,
            });
        }
        // Collection above stops as soon as `threshold` is reached, so this
        // is already exactly `threshold` entries — sort only for the
        // selected list's canonical order.
        commitments.sort_by_key(|(id, _)| *id);
        let selected_node_ids: HashSet<u32> = commitments.iter().map(|(id, _)| *id).collect();
        let all_commitments_wire: Vec<(u32, Vec<u8>)> = commitments
            .iter()
            .map(|(id, bytes)| (*id, bytes.to_vec()))
            .collect();
        let selection_digest =
            pet_blind_selection_digest(&attempt_id, &context_digest, &commitments);

        // ===================== Round 2 — Reveal =====================
        let mut reveals: Vec<PetBlindSignedReveal> = Vec::with_capacity(threshold);
        let mut seen_reveal_ids = HashSet::new();

        if let Some(node_id) = node_id_opt {
            if selected_node_ids.contains(&node_id) {
                let reveal_req = RevealRequest {
                    request_id: format!("reveal-{attempt_id}"),
                    attempt_id: attempt_id.clone(),
                    from_node_id: node_id,
                    all_commitments: all_commitments_wire.clone(),
                    context: ctx.clone(),
                };
                if let Ok(Some(response)) =
                    self.handle_reveal_request(reveal_req, &local_peer_id).await
                {
                    match verify_reveal_response::<P>(
                        response,
                        &document.ring_id,
                        &ring_payload,
                        &hex::encode(local_peer_id.as_bytes()),
                        &tag,
                        &target_fingerprint,
                        &commitments,
                        selection_digest,
                        &blind_context,
                        &document_evidence,
                        &mut seen_reveal_ids,
                    ) {
                        PetRevealResponseVerification::Verified(signed_reveal) => {
                            reveals.push(*signed_reveal);
                        }
                        PetRevealResponseVerification::InvalidProof(observation) => {
                            let _ = queue_report::<D, SignImpl>(
                                self.app_state.clone(),
                                self.routes,
                                ReportObservation::InvalidCryptoResponse(observation),
                            )
                            .await;
                        }
                        PetRevealResponseVerification::Rejected => {}
                    }
                }
            }
        }

        let selected_remote_ids: Vec<u32> = selected_node_ids
            .iter()
            .copied()
            .filter(|id| Some(*id) != node_id_opt)
            .collect();
        if reveals.len() < threshold && !selected_remote_ids.is_empty() {
            let reveal_request_id = format!("reveal-{attempt_id}");
            let mut expected_peers = Vec::with_capacity(selected_remote_ids.len());
            for id in &selected_remote_ids {
                let peer_id = node_id_to_peer_id.get(id).ok_or_else(|| {
                    PetError::ProtocolError(format!(
                        "could not resolve a peer route for selected reveal participant {id}"
                    ))
                })?;
                expected_peers.push(peer_id.clone());
            }

            if self
                .app_state
                .pet_response_state
                .init_response_for_version(
                    self.routes.version,
                    reveal_request_id.clone(),
                    &expected_peers,
                )
                .await
                == ResponseInitOutcome::AlreadyExists
            {
                return Err(PetError::ProtocolError(format!(
                    "PET reveal request_id {reveal_request_id} collided with an in-flight request"
                )));
            }

            let mut tasks = tokio::task::JoinSet::new();
            for peer_id in &expected_peers {
                let peer_id = peer_id.clone();
                let request = PetMessage::RevealRequest(Box::new(RevealRequest {
                    request_id: reveal_request_id.clone(),
                    attempt_id: attempt_id.clone(),
                    from_node_id: node_id_opt.unwrap_or(0),
                    all_commitments: all_commitments_wire.clone(),
                    context: ctx.clone(),
                }));
                let req_id = reveal_request_id.clone();
                let app_state = self.app_state.clone();
                let routes = self.routes;
                tasks.spawn(async move {
                    let coordinator = PetCoordinator::<D, P>::with_routes(app_state, routes);
                    let result = coordinator
                        .send_pet_request_and_receive_response(&peer_id, request, &req_id)
                        .await;
                    (peer_id, result)
                });
            }

            let ring_id = document.ring_id.clone();
            let collect = async {
                while let Some(joined) = tasks.join_next().await {
                    let (peer_id, result) = match joined {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "PET Coordinator: reveal task join error");
                            continue;
                        }
                    };
                    match result {
                        Ok(Some(response @ PetMessage::RevealResponse { .. })) => {
                            match verify_reveal_response::<P>(
                                response,
                                &ring_id,
                                &ring_payload,
                                &peer_id,
                                &tag,
                                &target_fingerprint,
                                &commitments,
                                selection_digest,
                                &blind_context,
                                &document_evidence,
                                &mut seen_reveal_ids,
                            ) {
                                PetRevealResponseVerification::Verified(signed_reveal) => {
                                    reveals.push(*signed_reveal);
                                }
                                PetRevealResponseVerification::InvalidProof(observation) => {
                                    let _ = queue_report::<D, SignImpl>(
                                        self.app_state.clone(),
                                        self.routes,
                                        ReportObservation::InvalidCryptoResponse(observation),
                                    )
                                    .await;
                                }
                                PetRevealResponseVerification::Rejected => {}
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                peer = %peer_id,
                                %error,
                                "PET Coordinator: reveal request failed"
                            );
                        }
                    }
                    if reveals.len() >= threshold {
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
                    "PET Coordinator: reveal collection deadline reached before every selected \
                     participant responded"
                );
            }
            self.spawn_pet_offline_drain(
                tasks,
                document.ring_id.clone(),
                all_peer_ids.clone(),
                ring_payload.peer_node_keys.clone(),
                attempt_id.clone(),
            );
            self.app_state
                .pet_response_state
                .remove_response_for_version(self.routes.version, &reveal_request_id)
                .await;
        }

        if reveals.len() < threshold {
            // No substitution — the whole attempt is discarded, per the
            // design doc's cancellation-attack analysis. A fresh retry (a
            // new call to this function) gets a brand-new `attempt_id` and
            // entirely fresh randomness from every participant.
            return Err(PetError::InsufficientShares {
                got: reveals.len(),
                need: threshold,
            });
        }

        let certificate = PetBlindCertificate {
            attempt_id: attempt_id.clone(),
            context_digest,
            all_commitments: all_commitments_wire,
            reveals,
        };
        let (_aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<D, P>(
            &certificate,
            &ring_payload,
            &tag,
            &target_fingerprint,
        )
        .map_err(|e| {
            PetError::Crypto(format!(
                "Failed to assemble a valid blinding certificate: {}",
                e
            ))
        })?;
        let aggregate_r_bytes = CryptoSerialize::to_bytes(&_aggregate_r).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize aggregate_r: {}", e))
        })?;
        let aggregate_diff_bytes = CryptoSerialize::to_bytes(&aggregate_diff).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize aggregate_diff: {}", e))
        })?;
        let certificate_digest = certificate.certificate_digest();

        // ===================== Round 3 — Decrypt =====================
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

        let mut shares: Vec<PubShare<G1Affine>> = Vec::with_capacity(threshold);
        let mut decrypt_responses: Vec<PetBlindSignedDecrypt> = Vec::with_capacity(threshold);
        let mut seen_decrypt_ids = HashSet::new();

        if let Some(node_id) = node_id_opt {
            let decrypt_req = DecryptRequest {
                request_id: format!("decrypt-{attempt_id}"),
                attempt_id: attempt_id.clone(),
                from_node_id: node_id,
                certificate: certificate.clone(),
                context: ctx.clone(),
            };
            if let Ok(Some(response)) = self
                .handle_decrypt_request(decrypt_req, &local_peer_id)
                .await
            {
                match verify_decrypt_response::<P>(
                    response,
                    &document.ring_id,
                    &ring_payload,
                    &hex::encode(local_peer_id.as_bytes()),
                    &pub_poly,
                    context_digest,
                    certificate_digest,
                    &attempt_id,
                    &aggregate_r_bytes,
                    &aggregate_diff_bytes,
                    &blind_context,
                    &document_evidence,
                    &mut seen_decrypt_ids,
                ) {
                    PetDecryptResponseVerification::Verified(signed_decrypt, share) => {
                        decrypt_responses.push(*signed_decrypt);
                        shares.push(share);
                    }
                    PetDecryptResponseVerification::InvalidProof(observation) => {
                        let _ = queue_report::<D, SignImpl>(
                            self.app_state.clone(),
                            self.routes,
                            ReportObservation::InvalidCryptoResponse(observation),
                        )
                        .await;
                    }
                    PetDecryptResponseVerification::Rejected => {}
                }
            }
        }

        if shares.len() < threshold && !remote_peer_ids.is_empty() {
            let decrypt_request_id = format!("decrypt-{attempt_id}");
            if self
                .app_state
                .pet_response_state
                .init_response_for_version(
                    self.routes.version,
                    decrypt_request_id.clone(),
                    &remote_peer_ids,
                )
                .await
                == ResponseInitOutcome::AlreadyExists
            {
                return Err(PetError::ProtocolError(format!(
                    "PET decrypt request_id {decrypt_request_id} collided with an in-flight request"
                )));
            }

            let mut tasks = tokio::task::JoinSet::new();
            for peer_id in &remote_peer_ids {
                let peer_id = peer_id.clone();
                let request = PetMessage::DecryptRequest(Box::new(DecryptRequest {
                    request_id: decrypt_request_id.clone(),
                    attempt_id: attempt_id.clone(),
                    from_node_id: node_id_opt.unwrap_or(0),
                    certificate: certificate.clone(),
                    context: ctx.clone(),
                }));
                let req_id = decrypt_request_id.clone();
                let app_state = self.app_state.clone();
                let routes = self.routes;
                tasks.spawn(async move {
                    let coordinator = PetCoordinator::<D, P>::with_routes(app_state, routes);
                    let result = coordinator
                        .send_pet_request_and_receive_response(&peer_id, request, &req_id)
                        .await;
                    (peer_id, result)
                });
            }

            let ring_id = document.ring_id.clone();
            let collect = async {
                while let Some(joined) = tasks.join_next().await {
                    let (peer_id, result) = match joined {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "PET Coordinator: decrypt task join error");
                            continue;
                        }
                    };
                    match result {
                        Ok(Some(response @ PetMessage::DecryptResponse { .. })) => {
                            match verify_decrypt_response::<P>(
                                response,
                                &ring_id,
                                &ring_payload,
                                &peer_id,
                                &pub_poly,
                                context_digest,
                                certificate_digest,
                                &attempt_id,
                                &aggregate_r_bytes,
                                &aggregate_diff_bytes,
                                &blind_context,
                                &document_evidence,
                                &mut seen_decrypt_ids,
                            ) {
                                PetDecryptResponseVerification::Verified(signed_decrypt, share) => {
                                    decrypt_responses.push(*signed_decrypt);
                                    shares.push(share);
                                }
                                PetDecryptResponseVerification::InvalidProof(observation) => {
                                    let _ = queue_report::<D, SignImpl>(
                                        self.app_state.clone(),
                                        self.routes,
                                        ReportObservation::InvalidCryptoResponse(observation),
                                    )
                                    .await;
                                }
                                PetDecryptResponseVerification::Rejected => {}
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                peer = %peer_id,
                                %error,
                                "PET Coordinator: decrypt request failed"
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
                    "PET Coordinator: decrypt collection deadline reached before threshold shares arrived"
                );
            }
            self.spawn_pet_decrypt_drain(
                tasks,
                document.ring_id.clone(),
                all_peer_ids.clone(),
                ring_payload.peer_node_keys.clone(),
                attempt_id.clone(),
                ring_payload.clone(),
                pub_poly.clone(),
                context_digest,
                certificate_digest,
                aggregate_r_bytes.clone(),
                aggregate_diff_bytes.clone(),
                blind_context.clone(),
                document_evidence.clone(),
            );
            self.app_state
                .pet_response_state
                .remove_response_for_version(self.routes.version, &decrypt_request_id)
                .await;
        }

        if shares.len() < threshold {
            return Err(PetError::InsufficientShares {
                got: shares.len(),
                need: threshold,
            });
        }

        let combined =
            P::combine_pet_check_shares(&shares, threshold, committee_size).map_err(|e| {
                PetError::Crypto(format!("Failed to combine PET decrypt shares: {}", e))
            })?;
        let combined_bytes = CryptoSerialize::to_bytes(&combined)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize combined: {}", e)))?;

        if combined_bytes != aggregate_diff_bytes {
            return Err(PetError::Mismatch);
        }

        Ok(PetBlindEvidence {
            certificate,
            decrypt_responses,
            coordinator_node_key: self.app_state.node_key.clone(),
        })
    }
}
