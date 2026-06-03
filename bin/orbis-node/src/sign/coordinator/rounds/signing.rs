use crate::constants::SIGN_COLLECTION_TIMEOUT;
use crate::helpers::helpers::{
    determine_ring_node_id_from_peer_id, determine_session_node_id, is_ring_reshare_in_progress,
    is_self_peer_id, load_ring_pub_poly_and_bundle, RingConfig,
};
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::error::{Result, SignError};
use crate::sign::helpers::{serialize_commitments, validate_refresh_health_check_statement};
use crate::sign::messages::{SignContext, SignMessage, SignRequest};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PubPoly as PubPolyTrait, PubShare,
    ThresholdSigner,
};
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
            interactive = S::INTERACTIVE,
            "Sign Coordinator: Initiating signing"
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
        if !self
            .app_state
            .sign_response_state
            .init_response(request_id.clone(), &expected_peers)
            .await
        {
            return Err(SignError::ProtocolError(
                "Sign response limit exceeded, too many pending requests".to_string(),
            ));
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
            )
            .await;

        // Always cleanup response state regardless of success or failure.
        // Pool connections are permanent — no per-request eviction needed.
        self.app_state
            .sign_response_state
            .remove_response(&request_id_for_cleanup)
            .await;

        result
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
            SignContext::Bulletin => (None, None),
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
                match signer.sign(
                    &dist_key_share,
                    &message,
                    &pub_poly,
                    local_signing_state.as_ref(),
                    &signing_commitments,
                    derivation.as_deref(),
                    metadata.as_deref(),
                ) {
                    Ok(sig_share) => match signer.verify_share(
                        &message,
                        &pub_poly,
                        &sig_share,
                        &signing_commitments,
                        derivation.as_deref(),
                        metadata.as_deref(),
                    ) {
                        Ok(_) => {
                            tracing::debug!(
                                from_node_id = sig_share.i,
                                "Sign Coordinator: Added local share"
                            );
                            seen_node_ids.insert(sig_share.i);
                            verified_shares.push(sig_share);
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "Sign Coordinator: Local share verification failed"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Sign Coordinator: Local signing failed"
                        );
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

                set.spawn(async move {
                    let coordinator = SignCoordinator::<D, S>::new(app_state);
                    coordinator
                        .send_request_and_receive_response(&peer_id, request, &req_id)
                        .await
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
                        Ok(Ok(Some(response))) => {
                            let Some(expected_node_id) =
                                determine_ring_node_id_from_peer_id(&response.sender_peer_hex, &ring)
                            else {
                                tracing::error!(
                                    sender_peer = %response.sender_peer_hex,
                                    "Sign Coordinator: accepted signature response from peer outside ring"
                                );
                                continue;
                            };
                            if let Some(share) = Self::verify_peer_signature_response(
                                &signer,
                                response.message,
                                &message,
                                &pub_poly,
                                &signing_commitments,
                                derivation.as_deref(),
                                metadata.as_deref(),
                                expected_node_id,
                                &mut seen_node_ids,
                            )? {
                                verified_shares.push(share);
                                successful_responses += 1;
                                if successful_responses >= min_needed_from_network {
                                    break;
                                }
                            }
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => {
                            tracing::warn!(
                                request_id = %request_id,
                                error = %e,
                                "Sign peer request failed"
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
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "Sign collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Cancel any stragglers once we have enough verified shares or stop waiting.
        drop(set);

        // 3. Collect any responses that were already stored before cancellation and
        // verify the ones we have not counted yet.
        let collected_responses = self
            .app_state
            .sign_response_state
            .take_authenticated_responses(&request_id)
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
            if let Some(share) = Self::verify_peer_signature_response(
                &signer,
                response.message,
                &message,
                &pub_poly,
                &signing_commitments,
                derivation.as_deref(),
                metadata.as_deref(),
                expected_node_id,
                &mut seen_node_ids,
            )? {
                verified_shares.push(share);
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
