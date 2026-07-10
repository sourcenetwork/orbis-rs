use super::verification::{PeerResponseVerification, PreResponseReportContext};
use super::{PreCoordinator, PreResponse};
use crate::app_state::AppState;
use crate::constants::PRE_COLLECTION_TIMEOUT;
use crate::helpers::identity::{
    determine_ring_node_id_from_peer_id, determine_session_node_id, extract_node_part,
    is_self_peer_id,
};
use crate::helpers::response_manager::ResponseInitOutcome;
use crate::helpers::ring::{
    is_ring_reshare_in_progress, load_ring_pub_poly_and_bundle, RingConfig,
};
use crate::pre::v0::error::{PreError, Result};
use crate::pre::v0::messages::{PreMessage, PreRequestContext, ReencryptRequest};
use crate::reporting::v0::observation::{offline_observation_from_pre_error, ReportObservation};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::ring_state_sha256;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PriShare, PubShare, ReencryptReply,
    Secret, ThresholdDealer,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{PolynomialCommitmentImpl, PubPolyImpl, SigShareInner, SignImpl, SignaturePoint};
use std::collections::HashSet;
use std::sync::Arc;

struct PreResponseDrainArgs<D: Dkg> {
    set: tokio::task::JoinSet<(String, Result<Option<PreMessage>>)>,
    ring: RingConfig,
    report_binding: PreReportBinding,
    request_id: String,
    object_id: String,
    rdr_pk_bytes: Vec<u8>,
    derivation: Option<Vec<u8>>,
    rdr_pk: D::PublicKey,
    pub_poly: D::PubPoly,
    enc_cmt: D::PublicKey,
    seen_node_ids: HashSet<u32>,
}

impl<D, T> PreCoordinator<D, T>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
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
    SignImpl: crypto::r#trait::ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = PubPolyImpl,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    /// Initiate reencryption (initiator side)
    ///
    /// Sends reencryption requests to all ring nodes, collects responses,
    /// verifies them, and recovers the reencrypted commitment.
    ///
    /// Ring information is read from the bulletin by the service layer and
    /// provided via `ring`; the chain/ring binding for invalid-proof reports
    /// comes from the same payload fetch via `report_binding`. Request auth
    /// and object identity are in `ctx`.
    pub async fn initiate_reencryption(
        &self,
        request_id: String,
        ring: RingConfig,
        secret_bytes: Vec<u8>,
        ctx: PreRequestContext,
        report_binding: PreReportBinding,
    ) -> Result<Vec<u8>> {
        // Determine our node_id (if we're in the ring) - single source of truth
        let node_id_opt = determine_session_node_id(&self.app_state.node_key, &ring.peer_node_keys);

        // self_in_list derived from node_id - guarantees consistency
        let self_in_list = node_id_opt.is_some();

        // 0 is a safe sentinel: DKG node_ids are 1-indexed, so 0 means "external requester"
        let node_id = node_id_opt.unwrap_or(0);

        // Count how many peers we'll actually contact (excluding self)
        let actual_peer_count = if self_in_list {
            ring.peer_ids.len() - 1
        } else {
            ring.peer_ids.len()
        };

        tracing::info!(
            request_id = %request_id,
            peer_count = actual_peer_count,
            self_in_list = self_in_list,
            threshold = ring.threshold,
            "PRE Coordinator: Initiating reencryption"
        );

        // Build the list of peers we expect responses from (everyone except self)
        let expected_peers: Vec<String> = ring
            .peer_ids
            .iter()
            .filter(|pid| !is_self_peer_id(&self.app_state.network, pid))
            .cloned()
            .collect();

        // Initialize response collection before calling inner function
        // This allows us to guarantee cleanup regardless of how inner function exits
        let request_id_for_cleanup = request_id.clone();
        match self
            .app_state
            .pre_response_state
            .init_response_for_version(self.routes.version, request_id.clone(), &expected_peers)
            .await
        {
            ResponseInitOutcome::Created => {}
            ResponseInitOutcome::AlreadyExists => {
                return Err(PreError::ProtocolError(format!(
                    "PRE response state already exists for request {request_id}"
                )));
            }
            ResponseInitOutcome::LimitReached => {
                return Err(PreError::ProtocolError(
                    "PRE response limit exceeded, too many pending requests".to_string(),
                ));
            }
        }

        // Execute inner function and ensure cleanup happens regardless of result
        let result = self
            .initiate_reencryption_inner(
                request_id,
                ring,
                secret_bytes,
                node_id,
                self_in_list,
                actual_peer_count,
                ctx,
                report_binding,
            )
            .await;

        // Always cleanup response state regardless of success or failure.
        // Pool connections are permanent — no per-request eviction needed.
        self.app_state
            .pre_response_state
            .remove_response_for_version(self.routes.version, &request_id_for_cleanup)
            .await;

        result
    }

    /// Inner implementation of initiate_reencryption
    ///
    /// This is separated so that cleanup can be guaranteed by the outer function.
    /// Assumes init_pre_response has already been called.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn initiate_reencryption_inner(
        &self,
        request_id: String,
        ring: RingConfig,
        secret_bytes: Vec<u8>,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
        ctx: PreRequestContext,
        report_binding: PreReportBinding,
    ) -> Result<Vec<u8>> {
        // 1. Load the public polynomial and (when self_in_list) the local share bundle
        //    from a SINGLE atomic read of RingShareBundle.
        //
        //    Without this, there is a TOCTOU race: the service layer reads the polynomial
        //    in one bundle read, then `self_in_list` reads the share in a second bundle
        //    read.  If PSS Phase 4 fires between those two reads it updates the bundle
        //    atomically (new share + new polynomial together), so the two reads can see
        //    different generations.  A self-share from generation N+1 combined via
        //    Lagrange with peer shares from generation N produces a wrong xnc_cmt,
        //    which passes AES-GCM tag verification with a wrong key → "authentication
        //    failed".
        //
        //    Loading both fields from the same snapshot guarantees they are always from
        //    the same PSS generation, so Lagrange interpolation is correct.
        let (pub_poly, local_share_bundle) =
            load_ring_pub_poly_and_bundle::<D>(&self.app_state.local_storage, &ring, self_in_list)
                .map_err(PreError::Deserialization)?;

        // Validate we have enough potential shares to meet threshold
        // If we're in the list, we can contribute our own share locally
        let potential_shares = if self_in_list {
            actual_peer_count + 1 // peers + our local share
        } else {
            actual_peer_count
        };

        if potential_shares < ring.threshold {
            return Err(PreError::InsufficientShares {
                got: potential_shares,
                need: ring.threshold,
            });
        }

        // 2. Deserialize reader public key
        let rdr_pk = <D::PublicKey>::from_bytes(&ctx.rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize secret to get enc_cmt
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        let enc_cmt = <D::PublicKey>::from_bytes(&secret.enc_cmt[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize enc_cmt: {}", e))
        })?;

        let dealer = T::new();
        let mut verified_shares: Vec<PubShare<D::PublicKey>> = Vec::new();
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we're in the peer list, compute our own share locally before deciding
        // how many verified shares we still need from the network.
        if self_in_list {
            let bundle = local_share_bundle.ok_or_else(|| {
                PreError::Storage("Local share bundle missing for ring member".to_string())
            })?;
            let pri_share =
                PriShare::<D::ShareValue>::from_bytes(&bundle.share_bytes).map_err(|error| {
                    PreError::Deserialization(format!(
                        "Failed to deserialize local share: {}",
                        error
                    ))
                })?;
            let dist_key_share = DistKeyShare { pri_share };

            let reply = dealer
                .reencrypt(&dist_key_share, &secret, &rdr_pk, ctx.derivation.as_deref())
                .map_err(|error| {
                    PreError::Crypto(format!("Local reencryption failed: {}", error))
                })?;
            if dealer
                .verify(
                    &rdr_pk,
                    &pub_poly,
                    &enc_cmt,
                    &reply,
                    ctx.derivation.as_deref(),
                )
                .inspect_err(|error| {
                    tracing::error!(
                        from_node_id = reply.share.i,
                        error = %error,
                        "PRE Coordinator: Local share verification failed"
                    );
                })
                .is_ok()
            {
                tracing::debug!(
                    from_node_id = reply.share.i,
                    "PRE Coordinator: Added local share"
                );
                seen_node_ids.insert(reply.share.i);
                verified_shares.push(reply.share.clone());
            }
        }

        let min_needed_from_network = ring.threshold.saturating_sub(verified_shares.len());

        // 4. Send reencryption requests to all peers concurrently and receive responses
        // Note: init_pre_response is called by the outer function to ensure cleanup on all paths
        // node_id is already obtained from DKG session above
        let mut set = tokio::task::JoinSet::new();

        // Keep a copy of secret_bytes for later deserialization
        let secret_bytes_for_later = secret_bytes.clone();

        if min_needed_from_network > 0 {
            for peer_id_str in &ring.peer_ids {
                // Skip self - don't try to connect to ourselves
                if is_self_peer_id(&self.app_state.network, peer_id_str) {
                    tracing::debug!(peer_id = %peer_id_str, "Skipping self when sending reencrypt request");
                    continue;
                }

                let request = PreMessage::ReencryptRequest(ReencryptRequest {
                    request_id: request_id.clone(),
                    from_node_id: node_id,
                    context: ctx.clone(),
                });

                let peer_id = peer_id_str.clone();
                let req_id = request_id.clone();
                let app_state = self.app_state.clone();
                let routes = self.routes;

                // Spawn a task for each peer to send request and receive response
                // Note: Creating new coordinator is cheap (just holds Arc<AppState>)
                set.spawn(async move {
                    let coordinator = PreCoordinator::<D, T>::with_routes(app_state, routes);
                    let result = coordinator
                        .send_request_and_receive_response(&peer_id, request, &req_id)
                        .await;
                    (peer_id, result)
                });
            }
        }

        // Wait until we have enough verified shares from the network or the overall
        // deadline fires.
        let mut successful_responses = 0usize;
        if min_needed_from_network > 0 {
            match tokio::time::timeout(PRE_COLLECTION_TIMEOUT, async {
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok((peer_id, Ok(Some(response)))) => {
                            let Some(expected_node_id) =
                                determine_ring_node_id_from_peer_id(&peer_id, &ring)
                            else {
                                tracing::error!(
                                    peer_id = %peer_id,
                                    "PRE Coordinator: accepted response from peer outside ring"
                                );
                                continue;
                            };
                            let Some(accused_node_key) = node_key_for_peer(&ring, &peer_id) else {
                                tracing::error!(
                                    peer_id = %peer_id,
                                    "PRE Coordinator: accepted response from peer without node key"
                                );
                                continue;
                            };
                            let report_context = report_binding.response_report_context(
                                self.routes.version,
                                &request_id,
                                accused_node_key,
                                &peer_id,
                                &ctx.object_id,
                                ctx.rdr_pk_bytes.clone(),
                                ctx.derivation.clone(),
                            );
                            match Self::verify_peer_response(
                                &dealer,
                                response,
                                &rdr_pk,
                                &pub_poly,
                                &enc_cmt,
                                ctx.derivation.as_deref(),
                                expected_node_id,
                                &report_context,
                                &mut seen_node_ids,
                            ) {
                                PeerResponseVerification::Verified(share) => {
                                    verified_shares.push(share);
                                    successful_responses += 1;
                                    if successful_responses >= min_needed_from_network {
                                        break;
                                    }
                                }
                                PeerResponseVerification::InvalidProof(observation) => {
                                    let _ = queue_report::<D, SignImpl>(
                                        self.app_state.clone(),
                                        self.routes,
                                        ReportObservation::InvalidCryptoResponse(observation),
                                    )
                                    .await
                                    .inspect_err(|error| {
                                        tracing::warn!(
                                            peer_id = %peer_id,
                                            error = %error,
                                            "Failed to queue PRE invalid-proof report observation"
                                        );
                                    });
                                }
                                PeerResponseVerification::Rejected => {}
                            }
                        }
                        Ok((_, Ok(None))) => {}
                        Ok((peer_id, Err(e))) => {
                            tracing::warn!(
                                request_id = %request_id,
                                peer_id = %peer_id,
                                error = %e,
                                "PRE peer request failed"
                            );
                            if let Some(observation) = offline_observation_from_pre_error(
                                &ring,
                                &peer_id,
                                &e,
                                self.routes.version,
                                &request_id,
                            ) {
                                let _ = queue_report::<D, SignImpl>(
                                    self.app_state.clone(),
                                    self.routes,
                                    ReportObservation::NodeOffline(observation),
                                )
                                .await
                                .inspect_err(|error| {
                                    tracing::warn!(
                                        peer_id = %peer_id,
                                        error = %error,
                                        "Failed to queue offline report observation"
                                    );
                                });
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Peer reencrypt task panicked");
                        }
                    }
                }
                Ok::<(), PreError>(())
            })
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "PRE collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Drain remaining peer tasks in the background so results that arrive after
        // the collection loop broke early (threshold met or timeout) still trigger
        // reports: transport errors map to offline observations, and signed responses
        // whose proofs fail verification map to invalid-proof observations. Without
        // the latter, a bad proof that loses the race against threshold completion —
        // the common case in a healthy ring — would go unreported.
        self.spawn_response_drain(PreResponseDrainArgs {
            set,
            ring: ring.clone(),
            report_binding: report_binding.clone(),
            request_id: request_id.clone(),
            object_id: ctx.object_id.clone(),
            rdr_pk_bytes: ctx.rdr_pk_bytes.clone(),
            derivation: ctx.derivation.clone(),
            rdr_pk,
            pub_poly: pub_poly.clone(),
            enc_cmt,
            seen_node_ids: seen_node_ids.clone(),
        });

        // 5. Collect any responses that were already stored before cancellation and
        // verify the ones we have not counted yet.
        let collected_responses = self
            .app_state
            .pre_response_state
            .take_authenticated_responses_for_version(self.routes.version, &request_id)
            .await
            .ok_or_else(|| {
                PreError::Timeout(format!("No responses found for request {}", request_id))
            })?;

        for response in collected_responses {
            let Some(expected_node_id) =
                determine_ring_node_id_from_peer_id(&response.sender_peer_hex, &ring)
            else {
                tracing::error!(
                    sender_peer = %response.sender_peer_hex,
                    "PRE Coordinator: stored response from peer outside ring"
                );
                continue;
            };
            let Some(accused_node_key) = node_key_for_peer(&ring, &response.sender_peer_hex) else {
                tracing::error!(
                    sender_peer = %response.sender_peer_hex,
                    "PRE Coordinator: stored response from peer without node key"
                );
                continue;
            };
            let report_context = report_binding.response_report_context(
                self.routes.version,
                &request_id,
                accused_node_key,
                &response.sender_peer_hex,
                &ctx.object_id,
                ctx.rdr_pk_bytes.clone(),
                ctx.derivation.clone(),
            );
            match Self::verify_peer_response(
                &dealer,
                response.message,
                &rdr_pk,
                &pub_poly,
                &enc_cmt,
                ctx.derivation.as_deref(),
                expected_node_id,
                &report_context,
                &mut seen_node_ids,
            ) {
                PeerResponseVerification::Verified(share) => {
                    verified_shares.push(share);
                }
                PeerResponseVerification::InvalidProof(observation) => {
                    let _ = queue_report::<D, SignImpl>(
                        self.app_state.clone(),
                        self.routes,
                        ReportObservation::InvalidCryptoResponse(observation),
                    )
                    .await
                    .inspect_err(|error| {
                        tracing::warn!(
                            sender_peer = %response.sender_peer_hex,
                            error = %error,
                            "Failed to queue PRE invalid-proof report observation"
                        );
                    });
                }
                PeerResponseVerification::Rejected => {}
            }
        }

        // 6. Check if we have enough verified shares
        if verified_shares.len() < ring.threshold {
            if is_ring_reshare_in_progress(&ring.ring_pk_bytes, &self.app_state.dkg_session_state)
                .await
            {
                tracing::info!(
                    request_id = %request_id,
                    "PRE Coordinator: insufficient shares due to ongoing reshare"
                );
                return Err(PreError::ReshareInProgress);
            }
            return Err(PreError::InsufficientShares {
                got: verified_shares.len(),
                need: ring.threshold,
            });
        }

        // 7. Recover the reencrypted commitment
        let xnc_cmt_opt = dealer
            .recover(&verified_shares, ring.threshold, ring.total_participants)
            .map_err(|e| {
                PreError::RecoveryFailed(format!("Failed to recover commitment: {}", e))
            })?;

        let xnc_cmt = xnc_cmt_opt
            .ok_or_else(|| PreError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 8. Serialize xnc_cmt to bytes then hex using trait method
        let xnc_cmt_bytes = CryptoSerialize::to_bytes(&xnc_cmt)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize xnc_cmt: {}", e)))?;
        let xnc_cmt_hex = hex::encode(&xnc_cmt_bytes);

        // 9. Deserialize secret from bytes (use cloned version)
        let secret: Secret = serde_json::from_slice(&secret_bytes_for_later).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        // 10. Create response structure
        let pre_response = PreResponse {
            xnc_cmt: xnc_cmt_hex,
            secret,
        };

        // 11. Serialize response to JSON bytes
        let response_bytes = serde_json::to_vec(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        // Note: Cleanup is handled by the outer initiate_reencryption function

        tracing::info!(
            request_id = %request_id,
            "PRE Coordinator: Successfully recovered reencrypted commitment"
        );

        Ok(response_bytes)
    }

    /// Drain remaining peer tasks in the background so results that arrive
    /// after the collection loop broke early still reach `queue_report`:
    /// transport errors become offline observations and signed responses that
    /// fail proof verification become invalid-proof observations. Verified
    /// shares arriving here are simply logged — the request already completed.
    fn spawn_response_drain(&self, args: PreResponseDrainArgs<D>) {
        let app_state = self.app_state.clone();
        let routes = self.routes;
        tokio::spawn(async move {
            Self::run_pre_response_drain(app_state, routes, args).await;
        });
    }

    async fn run_pre_response_drain(
        app_state: Arc<AppState<D>>,
        routes: &'static network::ProtocolRoutes,
        mut args: PreResponseDrainArgs<D>,
    ) {
        let dealer = T::new();
        let deadline = tokio::time::Instant::now() + PRE_COLLECTION_TIMEOUT;
        while let Ok(Some(result)) = tokio::time::timeout_at(deadline, args.set.join_next()).await {
            Self::handle_pre_drain_result(&app_state, routes, &dealer, &mut args, result).await;
        }
    }

    async fn handle_pre_drain_result(
        app_state: &Arc<AppState<D>>,
        routes: &'static network::ProtocolRoutes,
        dealer: &T,
        args: &mut PreResponseDrainArgs<D>,
        result: std::result::Result<(String, Result<Option<PreMessage>>), tokio::task::JoinError>,
    ) {
        match result {
            Ok((peer_id, Ok(Some(response)))) => {
                Self::handle_pre_drain_response(app_state, routes, dealer, args, peer_id, response)
                    .await;
            }
            Ok((peer_id, Err(e))) => {
                tracing::warn!(
                    peer_id = %peer_id,
                    error = %e,
                    "PRE peer request failed (post-threshold drain)"
                );
                if let Some(observation) = offline_observation_from_pre_error(
                    &args.ring,
                    &peer_id,
                    &e,
                    routes.version,
                    &args.request_id,
                ) {
                    let _ = queue_report::<D, SignImpl>(
                        app_state.clone(),
                        routes,
                        ReportObservation::NodeOffline(observation),
                    )
                    .await
                    .inspect_err(|error| {
                        tracing::warn!(
                            peer_id = %peer_id,
                            error = %error,
                            "Failed to queue offline report observation (post-threshold drain)"
                        );
                    });
                }
            }
            Ok((_, Ok(None))) => {}
            Err(join_err) => {
                tracing::error!(
                    error = ?join_err,
                    "Peer reencrypt task panicked in response drain"
                );
            }
        }
    }

    async fn handle_pre_drain_response(
        app_state: &Arc<AppState<D>>,
        routes: &'static network::ProtocolRoutes,
        dealer: &T,
        args: &mut PreResponseDrainArgs<D>,
        peer_id: String,
        response: PreMessage,
    ) {
        let Some((expected_node_id, report_context)) =
            Self::build_pre_drain_report_context(routes, args, &peer_id)
        else {
            return;
        };

        match Self::verify_peer_response(
            dealer,
            response,
            &args.rdr_pk,
            &args.pub_poly,
            &args.enc_cmt,
            args.derivation.as_deref(),
            expected_node_id,
            &report_context,
            &mut args.seen_node_ids,
        ) {
            PeerResponseVerification::InvalidProof(observation) => {
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
                        "Failed to queue PRE invalid-proof report observation (post-threshold drain)"
                    );
                });
            }
            PeerResponseVerification::Verified(_) => {
                tracing::debug!(
                    peer_id = %peer_id,
                    "PRE Coordinator: valid share arrived after collection completed"
                );
            }
            PeerResponseVerification::Rejected => {}
        }
    }

    fn build_pre_drain_report_context(
        routes: &'static network::ProtocolRoutes,
        args: &PreResponseDrainArgs<D>,
        peer_id: &str,
    ) -> Option<(u32, PreResponseReportContext)> {
        let Some(expected_node_id) = determine_ring_node_id_from_peer_id(peer_id, &args.ring)
        else {
            tracing::error!(
                peer_id = %peer_id,
                "PRE Coordinator: late response from peer outside ring"
            );
            return None;
        };
        let Some(accused_node_key) = node_key_for_peer(&args.ring, peer_id) else {
            tracing::error!(
                peer_id = %peer_id,
                "PRE Coordinator: late response from peer without node key"
            );
            return None;
        };

        Some((
            expected_node_id,
            args.report_binding.response_report_context(
                routes.version,
                &args.request_id,
                accused_node_key,
                peer_id,
                &args.object_id,
                args.rdr_pk_bytes.clone(),
                args.derivation.clone(),
            ),
        ))
    }
}

/// Chain/ring context an invalid-proof report needs, captured from the same
/// bulletin payloads the service layer fetched to authorize the PRE request.
/// (Report envelope timing derives from the evidence's own `signed_at`, so no
/// timestamp is captured here.)
#[derive(Clone)]
pub(crate) struct PreReportBinding {
    chain_id: String,
    ring_id: String,
    ring_pk: String,
    ring_state_sha256: String,
}

impl PreReportBinding {
    pub(crate) fn new(
        chain_id: String,
        ring_id: String,
        ring_pk: String,
        ring_state_sha256: String,
    ) -> Self {
        Self {
            chain_id,
            ring_id,
            ring_pk,
            ring_state_sha256,
        }
    }

    /// Build the binding from the ring payload the caller already fetched.
    /// `ring_id` is the document's ring id (the value responders bind into
    /// their signed response statements).
    pub(crate) fn from_ring(chain_id: String, ring_id: String, ring_payload: &RingPayload) -> Self {
        Self::new(
            chain_id,
            ring_id,
            ring_payload.ring_pk.clone(),
            ring_state_sha256(ring_payload),
        )
    }

    /// Build the report context for one PRE response accused of an invalid proof.
    fn response_report_context(
        &self,
        protocol_version: u64,
        request_id: &str,
        accused_node_key: &str,
        accused_peer_id: &str,
        object_id: &str,
        rdr_pk: Vec<u8>,
        derivation: Option<Vec<u8>>,
    ) -> PreResponseReportContext {
        PreResponseReportContext {
            chain_id: self.chain_id.clone(),
            ring_id: self.ring_id.clone(),
            ring_pk: self.ring_pk.clone(),
            ring_state_sha256: self.ring_state_sha256.clone(),
            protocol_version,
            request_id: request_id.to_string(),
            accused_node_key: accused_node_key.to_string(),
            accused_peer_id: accused_peer_id.to_string(),
            object_id: object_id.to_string(),
            rdr_pk,
            derivation,
        }
    }
}

fn node_key_for_peer<'a>(ring: &'a RingConfig, peer_id: &str) -> Option<&'a str> {
    let peer_node_part = extract_node_part(peer_id).to_lowercase();
    ring.peer_node_keys
        .iter()
        .zip(ring.peer_ids.iter())
        .find(|(_, route)| extract_node_part(route).to_lowercase() == peer_node_part)
        .map(|(node_key, _)| node_key.as_str())
}
