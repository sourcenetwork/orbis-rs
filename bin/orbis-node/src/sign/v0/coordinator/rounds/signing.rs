use crate::constants::SIGN_COLLECTION_TIMEOUT;
use crate::helpers::identity::{
    determine_ring_node_id_from_peer_id, determine_session_node_id, is_self_peer_id,
};
use crate::helpers::response_manager::ResponseInitOutcome;
use crate::helpers::ring::{
    is_ring_reshare_in_progress, load_ring_pub_poly_and_bundle, RingConfig,
};
use crate::reporting::v0::observation::{InvalidCryptoResponseObservation, ReportObservation};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, InvalidCryptoResponse, NodeOffline, ReportEnvelope,
    INVALID_CRYPTO_RESPONSE_REPORT_TYPE, NODE_OFFLINE_REPORT_TYPE,
};
use crate::ring_state::RingIndexEntry;
use crate::sign::v0::coordinator::network::AuthenticatedSignMessage;
use crate::sign::v0::coordinator::rounds::queue_sign_offline_report;
use crate::sign::v0::coordinator::verification::{
    PeerSignatureVerification, SignResponseReportContext,
};
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse, SigningOptions};
use crate::sign::v0::error::{Result, SignError};
use crate::sign::v0::helpers::{serialize_commitments, validate_refresh_health_check_statement};
use crate::sign::v0::messages::{SignContext, SignMessage, SignRequest};
use bulletin::r#trait::{BulletinKind, DocumentPayload, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PubPoly as PubPolyTrait, PubShare,
    ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::collections::HashSet;

#[derive(Clone, Debug)]
struct SignResponseReportContextBase {
    chain_id: String,
    ring_id: String,
    ring_pk: String,
    ring_state_sha256: String,
    protocol_version: u64,
    request_id: String,
    origin_protocol: String,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
    message: Vec<u8>,
    signing_commitments: Vec<u8>,
    derivation: Option<Vec<u8>>,
    metadata: Option<Vec<u8>>,
}

impl SignResponseReportContextBase {
    fn from_ring(
        chain_id: String,
        ring_id: String,
        ring: &RingPayload,
        protocol_version: u64,
        request_id: String,
        origin_protocol: &'static str,
        accused_committee_scope: CommitteeScope,
        signing_committee_scope: CommitteeScope,
        message: Vec<u8>,
        signing_commitments: Vec<u8>,
        derivation: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> Self {
        Self {
            chain_id,
            ring_id,
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version,
            request_id,
            origin_protocol: origin_protocol.to_string(),
            accused_committee_scope,
            signing_committee_scope,
            message,
            signing_commitments,
            derivation,
            metadata,
        }
    }

    fn for_peer(
        &self,
        ring: &RingConfig,
        node_id: u32,
        accused_peer_id: String,
    ) -> Option<SignResponseReportContext> {
        Some(SignResponseReportContext {
            chain_id: self.chain_id.clone(),
            ring_id: self.ring_id.clone(),
            ring_pk: self.ring_pk.clone(),
            ring_state_sha256: self.ring_state_sha256.clone(),
            protocol_version: self.protocol_version,
            request_id: self.request_id.clone(),
            accused_node_key: node_key_for_session_node_id(node_id, &ring.peer_node_keys)?,
            accused_peer_id,
            origin_protocol: self.origin_protocol.clone(),
            accused_committee_scope: self.accused_committee_scope,
            signing_committee_scope: self.signing_committee_scope,
            message: self.message.clone(),
            signing_commitments: self.signing_commitments.clone(),
            derivation: self.derivation.clone(),
            metadata: self.metadata.clone(),
        })
    }
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
    /// Initiate signing (initiator side)
    ///
    /// Sends sign requests to all ring nodes, collects responses,
    /// verifies them, and recovers the full signature.
    ///
    /// For interactive schemes (FROST), performs nonce collection round first.
    /// Ring configuration from the bulletin is provided via `ring`.
    pub async fn initiate_signing(
        &self,
        request_id: String,
        ring: RingConfig,
        message: Vec<u8>,
        context: SignContext,
        options: SigningOptions,
    ) -> Result<Vec<u8>> {
        // Determine our node_id (if we're in the ring) - single source of truth
        let node_id_opt = determine_session_node_id(&self.app_state.node_key, &ring.peer_node_keys);

        // self_in_list derived from node_id - guarantees consistency
        let self_in_list = node_id_opt.is_some()
            && !options
                .excluded_node_keys
                .contains(&self.app_state.node_key);

        // 0 is a safe sentinel: DKG node_ids are 1-indexed, so 0 means "external requester"
        let node_id = node_id_opt.unwrap_or(0);

        // Count how many peers we'll actually contact (excluding self)
        let actual_peer_count = ring
            .peer_ids
            .iter()
            .filter(|peer_id| {
                !options.excludes_peer(peer_id, &ring)
                    && !is_self_peer_id(&self.app_state.network, peer_id)
            })
            .count();

        tracing::info!(
            request_id = %request_id,
            peer_count = actual_peer_count,
            self_in_list = self_in_list,
            threshold = ring.threshold,
            interactive = S::INTERACTIVE,
            "Sign Coordinator: Initiating signing"
        );
        // Build the list of peers we expect responses from (everyone except self)
        let expected_peers: Vec<String> = ring
            .peer_ids
            .iter()
            .filter(|pid| !is_self_peer_id(&self.app_state.network, pid))
            .filter(|pid| !options.excludes_peer(pid, &ring))
            .cloned()
            .collect();

        // Initialize response collection before calling inner function
        // This allows us to guarantee cleanup regardless of how inner function exits
        let request_id_for_cleanup = request_id.clone();
        match self
            .app_state
            .sign_response_state
            .init_response_for_version(self.routes.version, request_id.clone(), &expected_peers)
            .await
        {
            ResponseInitOutcome::Created => {}
            ResponseInitOutcome::AlreadyExists => {
                return Err(SignError::ProtocolError(format!(
                    "Sign response state already exists for request {request_id}"
                )));
            }
            ResponseInitOutcome::LimitReached => {
                return Err(SignError::ProtocolError(
                    "Sign response limit exceeded, too many pending requests".to_string(),
                ));
            }
        }

        // Execute inner function and ensure cleanup happens regardless of result
        let result = self
            .initiate_signing_inner(
                request_id,
                ring,
                message,
                node_id,
                self_in_list,
                actual_peer_count,
                context,
                options,
            )
            .await;

        // Always cleanup response state regardless of success or failure.
        // Pool connections are permanent — no per-request eviction needed.
        self.app_state
            .sign_response_state
            .remove_response_for_version(self.routes.version, &request_id_for_cleanup)
            .await;

        result
    }

    async fn read_ring_payload_unchecked_for_sign_report(
        &self,
        ring_id: &str,
    ) -> Result<RingPayload> {
        let post = self
            .app_state
            .bulletin
            .read(ring_id.to_string(), BulletinKind::Ring)
            .await
            .map_err(|error| {
                SignError::VerificationFailed(format!(
                    "Failed to read ring bulletin post '{}': {}",
                    ring_id, error
                ))
            })?;
        serde_json::from_slice(&post.payload).map_err(|error| {
            SignError::Deserialization(format!("Failed to parse RingPayload: {}", error))
        })
    }

    async fn read_document_payload_for_sign_report(
        &self,
        object_id: &str,
    ) -> Result<DocumentPayload> {
        let post = self
            .app_state
            .bulletin
            .read(object_id.to_string(), BulletinKind::Document)
            .await
            .map_err(|error| {
                SignError::VerificationFailed(format!(
                    "Failed to read signing object '{}': {}",
                    object_id, error
                ))
            })?;
        serde_json::from_slice(&post.payload).map_err(|error| {
            SignError::Deserialization(format!(
                "Failed to parse signing document '{}': {}",
                object_id, error
            ))
        })
    }

    async fn read_ring_payload_for_ring_pk_hex_for_sign_report(
        &self,
        ring_pk_hex: &str,
    ) -> Result<(String, RingPayload)> {
        let ring_pk_bytes = hex::decode(ring_pk_hex).map_err(|error| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", error))
        })?;
        let ring_pk = G1Affine::from_bytes(&ring_pk_bytes).map_err(|error| {
            SignError::Deserialization(format!("Failed to deserialize ring public key: {}", error))
        })?;
        let ring_key = ring_pk.to_string();
        let index_bytes = self
            .app_state
            .local_storage
            .get(LocalStorageKeys::RingIndex)
            .map_err(|error| SignError::Storage(format!("Failed to read RingIndex: {}", error)))?
            .ok_or_else(|| SignError::Storage("RingIndex is not configured".to_string()))?;
        let ring_index: Vec<RingIndexEntry> = serde_json::from_slice(&index_bytes)
            .map_err(|error| SignError::Storage(format!("Failed to parse RingIndex: {}", error)))?;
        let entry = ring_index
            .iter()
            .find(|entry| entry.ring_pk_str == ring_key || entry.ring_pk_str == ring_pk_hex)
            .ok_or_else(|| {
                SignError::Storage(format!(
                    "RingIndex has no entry for ring_pk {}",
                    ring_pk_hex
                ))
            })?;
        let ring = self
            .read_ring_payload_unchecked_for_sign_report(&entry.bulletin_post_id)
            .await?;
        Ok((entry.bulletin_post_id.clone(), ring))
    }

    fn report_signing_scope_from_envelope_for_sign_report(
        envelope: &ReportEnvelope,
    ) -> Result<CommitteeScope> {
        match envelope.report_type.as_str() {
            NODE_OFFLINE_REPORT_TYPE => {
                let payload = NodeOffline::from_canonical_bytes(&envelope.payload)
                    .map_err(|error| SignError::Unauthorized(error.to_string()))?;
                Ok(payload.signing_committee_scope)
            }
            INVALID_CRYPTO_RESPONSE_REPORT_TYPE => {
                let evidence = InvalidCryptoResponse::from_canonical_bytes(&envelope.payload)
                    .map_err(|error| SignError::Unauthorized(error.to_string()))?;
                Ok(evidence.signing_committee_scope())
            }
            _ => Ok(CommitteeScope::Current),
        }
    }

    async fn sign_response_report_context_base(
        &self,
        context: &SignContext,
        request_id: &str,
        message: &[u8],
        signing_commitments: &[u8],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<Option<SignResponseReportContextBase>> {
        let chain_id = self.app_state.bulletin.chain_id();
        let version = self.routes.version;
        let request_id = request_id.to_string();
        let message = message.to_vec();
        let signing_commitments = signing_commitments.to_vec();
        let derivation = derivation.map(ToOwned::to_owned);
        let metadata = metadata.map(ToOwned::to_owned);

        match context {
            SignContext::Policy(_) => Ok(None),
            SignContext::Bulletin { object_id } => {
                let document = self
                    .read_document_payload_for_sign_report(object_id)
                    .await?;
                let ring = self
                    .read_ring_payload_unchecked_for_sign_report(&document.ring_id)
                    .await?;
                Ok(Some(SignResponseReportContextBase::from_ring(
                    chain_id,
                    document.ring_id,
                    &ring,
                    version,
                    request_id,
                    "sign",
                    CommitteeScope::Current,
                    CommitteeScope::Current,
                    message,
                    signing_commitments,
                    derivation,
                    metadata,
                )))
            }
            SignContext::RingReshareUpdate(ctx) => {
                let ring = self
                    .read_ring_payload_unchecked_for_sign_report(&ctx.statement.ring_id)
                    .await?;
                Ok(Some(SignResponseReportContextBase::from_ring(
                    chain_id,
                    ctx.statement.ring_id.clone(),
                    &ring,
                    version,
                    request_id,
                    "pss_reshare",
                    CommitteeScope::PendingNew,
                    CommitteeScope::PendingNew,
                    message,
                    signing_commitments,
                    derivation,
                    metadata,
                )))
            }
            SignContext::RefreshHealthCheck(ctx) => {
                let (ring_id, ring) = self
                    .read_ring_payload_for_ring_pk_hex_for_sign_report(&ctx.statement.ring_pk)
                    .await?;
                Ok(Some(SignResponseReportContextBase::from_ring(
                    chain_id,
                    ring_id,
                    &ring,
                    version,
                    request_id,
                    "pss_refresh",
                    CommitteeScope::Current,
                    CommitteeScope::Current,
                    message,
                    signing_commitments,
                    derivation,
                    metadata,
                )))
            }
            SignContext::Report(ctx) => {
                let signing_scope =
                    Self::report_signing_scope_from_envelope_for_sign_report(&ctx.envelope)?;
                Ok(Some(SignResponseReportContextBase {
                    chain_id,
                    ring_id: ctx.envelope.ring_id.clone(),
                    ring_pk: ctx.envelope.ring_pk.clone(),
                    ring_state_sha256: ctx.envelope.ring_state_sha256.clone(),
                    protocol_version: version,
                    request_id,
                    origin_protocol: "report".to_string(),
                    accused_committee_scope: signing_scope,
                    signing_committee_scope: signing_scope,
                    message,
                    signing_commitments,
                    derivation,
                    metadata,
                }))
            }
        }
    }

    fn queue_sign_invalid_crypto_report(
        &self,
        observation: Box<InvalidCryptoResponseObservation>,
        peer_id: &str,
    ) {
        let app_state = self.app_state.clone();
        let routes = self.routes;
        let peer_id = peer_id.to_string();
        let _handle = tokio::spawn(async move {
            if let Err(error) = queue_report::<D, S>(
                app_state,
                routes,
                ReportObservation::InvalidCryptoResponse(observation),
            )
            .await
            {
                tracing::warn!(
                    peer_id = %peer_id,
                    error = %error,
                    "Failed to queue sign invalid_crypto_response report observation"
                );
            }
        });
    }

    /// Drain remaining peer tasks in the background so results that arrive
    /// after the collection loop broke early still reach `queue_report`:
    /// transport errors become offline observations and signed responses whose
    /// sig-shares fail verification become invalid-crypto observations. Verified
    /// shares arriving here are simply logged — the request already completed.
    #[allow(clippy::too_many_arguments)]
    fn spawn_response_drain(
        &self,
        mut set: tokio::task::JoinSet<(String, Result<Option<AuthenticatedSignMessage>>)>,
        ring: RingConfig,
        sign_report_context_base: Option<SignResponseReportContextBase>,
        context: SignContext,
        request_id: String,
        message: Vec<u8>,
        pub_poly: D::PubPoly,
        signing_commitments: Vec<(u32, S::NonceCommitment)>,
        derivation: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
        mut seen_node_ids: HashSet<u32>,
    ) {
        let app_state = self.app_state.clone();
        let routes = self.routes;
        tokio::spawn(async move {
            let signer = S::new();
            let deadline = tokio::time::Instant::now() + SIGN_COLLECTION_TIMEOUT;
            while let Ok(Some(res)) = tokio::time::timeout_at(deadline, set.join_next()).await {
                match res {
                    Ok((_, Ok(Some(response)))) => {
                        let Some(expected_node_id) =
                            determine_ring_node_id_from_peer_id(&response.sender_peer_hex, &ring)
                        else {
                            tracing::error!(
                                sender_peer = %response.sender_peer_hex,
                                "Sign Coordinator: late response from peer outside ring"
                            );
                            continue;
                        };
                        let sender_peer_hex = response.sender_peer_hex.clone();
                        let report_context = sign_report_context_base.as_ref().and_then(|base| {
                            base.for_peer(&ring, expected_node_id, sender_peer_hex.clone())
                        });
                        match Self::verify_peer_signature_response(
                            &signer,
                            response.message,
                            &message,
                            &pub_poly,
                            &signing_commitments,
                            derivation.as_deref(),
                            metadata.as_deref(),
                            expected_node_id,
                            report_context.as_ref(),
                            &mut seen_node_ids,
                        ) {
                            PeerSignatureVerification::InvalidCrypto(observation) => {
                                let _ = queue_report::<D, S>(
                                    app_state.clone(),
                                    routes,
                                    ReportObservation::InvalidCryptoResponse(observation),
                                )
                                .await
                                .inspect_err(|error| {
                                    tracing::warn!(
                                        peer_id = %sender_peer_hex,
                                        error = %error,
                                        "Failed to queue sign invalid_crypto_response report observation (post-threshold drain)"
                                    );
                                });
                            }
                            PeerSignatureVerification::Verified(_) => {
                                tracing::debug!(
                                    peer_id = %sender_peer_hex,
                                    "Sign Coordinator: valid share arrived after collection completed"
                                );
                            }
                            PeerSignatureVerification::Rejected => {}
                        }
                    }
                    Ok((peer_id, Err(e))) => {
                        tracing::warn!(
                            peer_id = %peer_id,
                            error = %e,
                            "Sign peer request failed (post-threshold drain)"
                        );
                        queue_sign_offline_report::<D, S>(
                            app_state.clone(),
                            routes,
                            &ring,
                            &peer_id,
                            &e,
                            &request_id,
                            &context,
                            "sign_share_round_drain",
                        );
                    }
                    Ok((_, Ok(None))) => {}
                    Err(join_err) => {
                        tracing::error!(error = ?join_err, "Peer sign task panicked in response drain");
                    }
                }
            }
        });
    }

    /// Inner implementation of initiate_signing
    ///
    /// This is separated so that cleanup can be guaranteed by the outer function.
    /// Assumes init_response has already been called.
    pub(crate) async fn initiate_signing_inner(
        &self,
        request_id: String,
        ring: RingConfig,
        message: Vec<u8>,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
        context: SignContext,
        options: SigningOptions,
    ) -> Result<Vec<u8>> {
        // 1. Load the public polynomial and (when self_in_list) the local dist_key_share
        //    from a SINGLE atomic read of RingShareBundle — same TOCTOU fix as PRE.
        //
        //    Without this there are two races:
        //    • BLS: service reads polynomial (P_old), PSS fires, signing round reads
        //      share (S_new).  self-share verified against P_old fails → dropped →
        //      InsufficientShares when we were one share short of threshold.
        //    • FROST: collect_nonces reads share (S_old) to generate nonce, PSS fires,
        //      signing round reads share (S_new).  Nonce bound to S_old, signing with
        //      S_new → wrong sig share → verify_share rejects it → same InsufficientShares.
        //
        //    Loading from the same bundle snapshot eliminates both races: pub_poly,
        //    nonce generation, and signing all use the same PSS generation.
        let (pub_poly, local_dist_key_share) =
            if let SignContext::RefreshHealthCheck(ctx) = &context {
                let (_, bundle) = validate_refresh_health_check_statement(
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    Some(&message),
                )
                .await?;
                let pub_poly_bytes = hex::decode(&bundle.public_polynomial).map_err(|e| {
                    SignError::Deserialization(format!(
                        "Failed to decode staged refresh public polynomial: {}",
                        e
                    ))
                })?;
                let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
                    SignError::Deserialization(format!(
                        "Failed to deserialize staged refresh public polynomial: {}",
                        e
                    ))
                })?;
                let dks = if self_in_list {
                    Some(DistKeyShare {
                        pri_share: bundle.pri_share().map_err(SignError::Deserialization)?,
                    })
                } else {
                    None
                };
                (pub_poly, dks)
            } else {
                let (poly, bundle) = load_ring_pub_poly_and_bundle::<D>(
                    &self.app_state.local_storage,
                    &ring,
                    self_in_list,
                )
                .map_err(SignError::Deserialization)?;
                let dks = match bundle {
                    Some(bundle) => Some(DistKeyShare {
                        pri_share: bundle.pri_share().map_err(SignError::Deserialization)?,
                    }),
                    None => None,
                };
                (poly, dks)
            };

        // Validate we have enough potential shares to meet threshold
        let potential_shares = if self_in_list {
            actual_peer_count + 1
        } else {
            actual_peer_count
        };

        if potential_shares < ring.threshold {
            return Err(SignError::InsufficientShares {
                got: potential_shares,
                need: ring.threshold,
            });
        }

        // Resolve derivation and metadata from bulletin for Policy context.
        // Always fetched regardless of self_in_list — needed for local signing, share
        // verification, AND final signature verification. Without this, an external
        // requester (self_in_list=false) would verify shares against the root key
        // instead of the derived key.
        let (derivation, metadata) = match &context {
            SignContext::Bulletin { .. } => (None, None),
            SignContext::Policy(ctx) => {
                let key_derivation = &ctx.key_derivation;
                let derivation = Some(key_derivation.derivation.clone().into_bytes());
                let meta = Some(S::encode_metadata(
                    &key_derivation.policy_id,
                    &key_derivation.resource,
                    &key_derivation.permission,
                ));
                (derivation, meta)
            }
            SignContext::RingReshareUpdate(_) => (None, None),
            SignContext::RefreshHealthCheck(_) => (None, None),
            SignContext::Report(_) => (None, None),
        };

        // =====================================================================
        // ROUND 1 (FROST only): Collect nonce commitments
        // =====================================================================
        let (all_commitments, local_signing_state) = if S::INTERACTIVE {
            self.collect_nonces(
                &request_id,
                &ring,
                node_id,
                self_in_list,
                &context,
                local_dist_key_share.as_ref(),
                &options,
            )
            .await?
        } else {
            (Vec::new(), None)
        };

        let signing_commitments = if S::INTERACTIVE {
            Self::select_signing_commitments(
                &all_commitments,
                ring.threshold,
                self_in_list.then_some(node_id),
            )?
        } else {
            all_commitments
        };
        let selected_signer_ids: HashSet<u32> =
            signing_commitments.iter().map(|(id, _)| *id).collect();
        let should_attempt_local_share = local_dist_key_share.is_some()
            && (!S::INTERACTIVE || selected_signer_ids.contains(&node_id));

        // Serialize commitments for the exact FROST signing set. FROST shares are
        // bound to this participant list, so the recovery step must use the same
        // list that responders signed over.
        let all_commitments_bytes = serialize_commitments::<S>(&signing_commitments)?;
        let sign_report_context_base = self
            .sign_response_report_context_base(
                &context,
                &request_id,
                &message,
                &all_commitments_bytes,
                derivation.as_deref(),
                metadata.as_deref(),
            )
            .await?;

        // =====================================================================
        // ROUND 2: Collect signature shares
        // =====================================================================

        let signer = S::new();
        let mut verified_shares: Vec<PubShare<SigShareInner>> = Vec::new();
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we are part of the signing set, compute our own share locally before
        // deciding how many verified shares we still need from the network.
        if should_attempt_local_share {
            if let Some(dist_key_share) = local_dist_key_share {
                if let Ok(sig_share) = signer
                    .sign(
                        &dist_key_share,
                        &message,
                        &pub_poly,
                        local_signing_state.as_ref(),
                        &signing_commitments,
                        derivation.as_deref(),
                        metadata.as_deref(),
                    )
                    .inspect_err(|error| {
                        tracing::error!(
                            error = %error,
                            "Sign Coordinator: Local signing failed"
                        );
                    })
                {
                    if signer
                        .verify_share(
                            &message,
                            &pub_poly,
                            &sig_share,
                            &signing_commitments,
                            derivation.as_deref(),
                            metadata.as_deref(),
                        )
                        .inspect_err(|error| {
                            tracing::error!(
                                error = %error,
                                "Sign Coordinator: Local share verification failed"
                            );
                        })
                        .is_ok()
                    {
                        tracing::debug!(
                            from_node_id = sig_share.i,
                            "Sign Coordinator: Added local share"
                        );
                        seen_node_ids.insert(sig_share.i);
                        verified_shares.push(sig_share);
                    }
                }
            }
        }

        let min_needed_from_network = ring.threshold.saturating_sub(verified_shares.len());

        // 2. Send sign requests to all peers concurrently and receive responses
        let mut set = tokio::task::JoinSet::new();

        if min_needed_from_network > 0 {
            for peer_id_str in &ring.peer_ids {
                if is_self_peer_id(&self.app_state.network, peer_id_str) {
                    tracing::debug!(
                        peer_id = %peer_id_str,
                        "Skipping self when sending sign request"
                    );
                    continue;
                }
                if options.excludes_peer(peer_id_str, &ring) {
                    tracing::debug!(
                        peer_id = %peer_id_str,
                        "Skipping peer excluded from signing"
                    );
                    continue;
                }
                if S::INTERACTIVE {
                    let peer_node_id = determine_ring_node_id_from_peer_id(peer_id_str, &ring);
                    if !peer_node_id
                        .map(|id| selected_signer_ids.contains(&id))
                        .unwrap_or(false)
                    {
                        tracing::debug!(
                            peer_id = %peer_id_str,
                            "Skipping peer outside selected FROST signing set"
                        );
                        continue;
                    }
                }

                let request = SignMessage::SignRequest(SignRequest {
                    request_id: request_id.clone(),
                    from_node_id: node_id,
                    message: message.clone(),
                    all_commitments: all_commitments_bytes.clone(),
                    context: context.clone(),
                });

                let peer_id = peer_id_str.clone();
                let req_id = request_id.clone();
                let app_state = self.app_state.clone();
                let routes = self.routes;

                set.spawn(async move {
                    let coordinator = SignCoordinator::<D, S>::with_routes(app_state, routes);
                    let result = coordinator
                        .send_request_and_receive_response(&peer_id, request, &req_id)
                        .await;
                    (peer_id, result)
                });
            }
        }

        // Wait until we have enough verified signature shares from the network or
        // the deadline fires.
        let mut successful_responses = 0usize;
        if min_needed_from_network > 0 {
            match tokio::time::timeout(SIGN_COLLECTION_TIMEOUT, async {
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok((_, Ok(Some(response)))) => {
                            let Some(expected_node_id) =
                                determine_ring_node_id_from_peer_id(&response.sender_peer_hex, &ring)
                            else {
                                tracing::error!(
                                    sender_peer = %response.sender_peer_hex,
                                    "Sign Coordinator: accepted signature response from peer outside ring"
                                );
                                continue;
                            };
                            let sender_peer_hex = response.sender_peer_hex.clone();
                            let report_context = sign_report_context_base
                                .as_ref()
                                .and_then(|base| {
                                    base.for_peer(&ring, expected_node_id, sender_peer_hex.clone())
                                });
                            match Self::verify_peer_signature_response(
                                &signer,
                                response.message,
                                &message,
                                &pub_poly,
                                &signing_commitments,
                                derivation.as_deref(),
                                metadata.as_deref(),
                                expected_node_id,
                                report_context.as_ref(),
                                &mut seen_node_ids,
                            ) {
                                PeerSignatureVerification::Verified(share) => {
                                    verified_shares.push(share);
                                    successful_responses += 1;
                                    if successful_responses >= min_needed_from_network {
                                        break;
                                    }
                                }
                                PeerSignatureVerification::InvalidCrypto(observation) => {
                                    self.queue_sign_invalid_crypto_report(
                                        observation,
                                        &sender_peer_hex,
                                    );
                                }
                                PeerSignatureVerification::Rejected => {}
                            }
                        }
                        Ok((_, Ok(None))) => {}
                        Ok((peer_id, Err(e))) => {
                            tracing::warn!(
                                request_id = %request_id,
                                peer_id = %peer_id,
                                error = %e,
                                "Sign peer request failed"
                            );
                            queue_sign_offline_report::<D, S>(
                                self.app_state.clone(),
                                self.routes,
                                &ring,
                                &peer_id,
                                &e,
                                &request_id,
                                &context,
                                "sign_share_round",
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Task failed");
                        }
                    }
                }
                Ok::<(), SignError>(())
            })
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "Sign collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Drain remaining peer tasks in the background so results that arrive after
        // the collection loop broke early (threshold met or timeout) still trigger
        // reports: transport errors map to offline observations, and signed responses
        // whose sig-shares fail verification map to invalid-crypto observations.
        // Without the latter, a bad share that loses the race against threshold
        // completion — the common case in a healthy ring — would go unreported.
        self.spawn_response_drain(
            set,
            ring.clone(),
            sign_report_context_base.clone(),
            context.clone(),
            request_id.clone(),
            message.clone(),
            pub_poly.clone(),
            signing_commitments.clone(),
            derivation.clone(),
            metadata.clone(),
            seen_node_ids.clone(),
        );

        // 3. Collect any responses that were already stored before cancellation and
        // verify the ones we have not counted yet.
        let collected_responses = self
            .app_state
            .sign_response_state
            .take_authenticated_responses_for_version(self.routes.version, &request_id)
            .await
            .ok_or_else(|| {
                SignError::Timeout(format!("No responses found for request {}", &request_id))
            })?;

        for response in collected_responses {
            let Some(expected_node_id) =
                determine_ring_node_id_from_peer_id(&response.sender_peer_hex, &ring)
            else {
                tracing::error!(
                    sender_peer = %response.sender_peer_hex,
                    "Sign Coordinator: stored signature response from peer outside ring"
                );
                continue;
            };
            let sender_peer_hex = response.sender_peer_hex.clone();
            let report_context = sign_report_context_base
                .as_ref()
                .and_then(|base| base.for_peer(&ring, expected_node_id, sender_peer_hex.clone()));
            match Self::verify_peer_signature_response(
                &signer,
                response.message,
                &message,
                &pub_poly,
                &signing_commitments,
                derivation.as_deref(),
                metadata.as_deref(),
                expected_node_id,
                report_context.as_ref(),
                &mut seen_node_ids,
            ) {
                PeerSignatureVerification::Verified(share) => verified_shares.push(share),
                PeerSignatureVerification::InvalidCrypto(observation) => {
                    self.queue_sign_invalid_crypto_report(observation, &sender_peer_hex);
                }
                PeerSignatureVerification::Rejected => {}
            }
        }

        // 4. Check if we have enough verified shares
        if verified_shares.len() < ring.threshold {
            if is_ring_reshare_in_progress(&ring.ring_pk_bytes, &self.app_state.dkg_session_state)
                .await
            {
                tracing::info!(
                    request_id = %request_id,
                    "Sign Coordinator: insufficient shares due to ongoing reshare"
                );
                return Err(SignError::ReshareInProgress);
            }
            return Err(SignError::InsufficientShares {
                got: verified_shares.len(),
                need: ring.threshold,
            });
        }

        // 5. Recover the full signature
        let signature_opt = signer
            .recover(
                &verified_shares,
                ring.threshold,
                ring.total_participants,
                &message,
                &signing_commitments,
            )
            .map_err(|e| {
                SignError::RecoveryFailed(format!("Failed to recover signature: {}", e))
            })?;

        let signature = signature_opt
            .ok_or_else(|| SignError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 6. Verify the final recovered signature before serializing. This catches
        // aggregation bugs before a silently bad signature reaches the caller.
        let aggregate_pk = pub_poly.eval(0);
        let verify_pk = if let Some(deriv) = derivation.as_deref() {
            S::derive_public_key(&aggregate_pk, deriv, metadata.as_deref()).map_err(|e| {
                SignError::Crypto(format!("Key derivation for verification failed: {}", e))
            })?
        } else {
            aggregate_pk
        };
        signer
            .verify(&verify_pk, &message, &signature)
            .map_err(|e| {
                SignError::RecoveryFailed(format!("Final signature verification failed: {}", e))
            })?;

        // 7. Serialize signature to bytes then hex
        let signature_bytes = CryptoSerialize::to_bytes(&signature).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signature: {}", e))
        })?;
        let signature_hex = hex::encode(&signature_bytes);

        // 8. Create response structure
        let sign_response = SignResponse {
            signature: signature_hex,
        };

        // 9. Serialize response to JSON bytes
        let response_bytes = serde_json::to_vec(&sign_response).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize response: {}", e))
        })?;

        tracing::info!(
            request_id = %request_id,
            "Sign Coordinator: Successfully recovered signature"
        );

        Ok(response_bytes)
    }
}

fn node_key_for_session_node_id(node_id: u32, peer_node_keys: &[String]) -> Option<String> {
    if node_id == 0 {
        return None;
    }
    let mut sorted = peer_node_keys.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.get(node_id as usize - 1).cloned()
}
