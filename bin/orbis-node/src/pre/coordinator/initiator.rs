use super::{PreCoordinator, PreResponse};
use crate::constants::PRE_COLLECTION_TIMEOUT;
use crate::helpers::helpers::{
    determine_ring_node_id_from_peer_id, determine_session_node_id, is_ring_reshare_in_progress,
    is_self_peer_id, load_ring_pub_poly_and_bundle, RingConfig,
};
use crate::pre::error::{PreError, Result};
use crate::pre::messages::{PreMessage, PreRequestContext, ReencryptRequest};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PriShare, PubShare, ReencryptReply,
    Secret, ThresholdDealer,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use std::collections::HashSet;
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
    /// Initiate reencryption (initiator side)
    ///
    /// Sends reencryption requests to all ring nodes, collects responses,
    /// verifies them, and recovers the reencrypted commitment.
    ///
    /// Ring information is read from the bulletin by the service layer and
    /// provided via `ring`. Request auth and object identity are in `ctx`.
    pub async fn initiate_reencryption(
        &self,
        request_id: String,
        ring: RingConfig,
        secret_bytes: Vec<u8>,
        ctx: PreRequestContext,
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
        if !self
            .app_state
            .pre_response_state
            .init_response(request_id.clone(), &expected_peers)
            .await
        {
            return Err(PreError::ProtocolError(
                "PRE response limit exceeded, too many pending requests".to_string(),
            ));
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
            )
            .await;

        // Always cleanup response state regardless of success or failure.
        // Pool connections are permanent — no per-request eviction needed.
        self.app_state
            .pre_response_state
            .remove_response(&request_id_for_cleanup)
            .await;

        result
    }

    /// Inner implementation of initiate_reencryption
    ///
    /// This is separated so that cleanup can be guaranteed by the outer function.
    /// Assumes init_pre_response has already been called.
    pub(crate) async fn initiate_reencryption_inner(
        &self,
        request_id: String,
        ring: RingConfig,
        secret_bytes: Vec<u8>,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
        ctx: PreRequestContext,
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
                tracing::error!("PRE Coordinator: local share bundle missing for ring member");
                PreError::Storage("Local share bundle missing for ring member".to_string())
            })?;
            let pri_share =
                PriShare::<D::ShareValue>::from_bytes(&bundle.share_bytes).map_err(|e| {
                    tracing::error!(
                        error = %e,
                        "PRE Coordinator: Failed to deserialize local share"
                    );
                    PreError::Deserialization(format!("Failed to deserialize local share: {}", e))
                })?;
            let dist_key_share = DistKeyShare { pri_share };

            let reply = dealer
                .reencrypt(&dist_key_share, &secret, &rdr_pk, ctx.derivation.as_deref())
                .map_err(|e| {
                    tracing::error!(
                        error = %e,
                        "PRE Coordinator: Local reencryption failed"
                    );
                    PreError::Crypto(format!("Local reencryption failed: {}", e))
                })?;
            match dealer.verify(
                &rdr_pk,
                &pub_poly,
                &enc_cmt,
                &reply,
                ctx.derivation.as_deref(),
            ) {
                Ok(_) => {
                    tracing::debug!(
                        from_node_id = reply.share.i,
                        "PRE Coordinator: Added local share"
                    );
                    seen_node_ids.insert(reply.share.i);
                    verified_shares.push(reply.share.clone());
                }
                Err(e) => {
                    tracing::error!(
                        from_node_id = reply.share.i,
                        error = %e,
                        "PRE Coordinator: Local share verification failed"
                    );
                }
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

                // Spawn a task for each peer to send request and receive response
                // Note: Creating new coordinator is cheap (just holds Arc<AppState>)
                set.spawn(async move {
                    let coordinator = PreCoordinator::<D, T>::new(app_state);
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
                            if let Some(share) = Self::verify_peer_response(
                                &dealer,
                                response,
                                &rdr_pk,
                                &pub_poly,
                                &enc_cmt,
                                ctx.derivation.as_deref(),
                                Some(expected_node_id),
                                &mut seen_node_ids,
                            )? {
                                verified_shares.push(share);
                                successful_responses += 1;
                                if successful_responses >= min_needed_from_network {
                                    break;
                                }
                            }
                        }
                        Ok((_, Ok(None))) => {}
                        Ok((_, Err(e))) => {
                            tracing::warn!(
                                request_id = %request_id,
                                error = %e,
                                "PRE peer request failed"
                            );
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
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "PRE collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Cancel any stragglers once we have enough verified shares or stop waiting.
        drop(set);

        // 6. Collect any responses that were already stored before cancellation and
        // verify the ones we have not counted yet.
        let collected_responses = self
            .app_state
            .pre_response_state
            .take_authenticated_responses(&request_id)
            .await
            .ok_or_else(|| {
                PreError::Timeout(format!("No responses found for request {}", &request_id))
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
            if let Some(share) = Self::verify_peer_response(
                &dealer,
                response.message,
                &rdr_pk,
                &pub_poly,
                &enc_cmt,
                ctx.derivation.as_deref(),
                Some(expected_node_id),
                &mut seen_node_ids,
            )? {
                verified_shares.push(share);
            }
        }

        // 7. Check if we have enough verified shares
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

        // 8. Recover the reencrypted commitment
        let xnc_cmt_opt = dealer
            .recover(&verified_shares, ring.threshold, ring.total_participants)
            .map_err(|e| {
                PreError::RecoveryFailed(format!("Failed to recover commitment: {}", e))
            })?;

        let xnc_cmt = xnc_cmt_opt
            .ok_or_else(|| PreError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 10. Serialize xnc_cmt to bytes then hex using trait method
        let xnc_cmt_bytes = CryptoSerialize::to_bytes(&xnc_cmt)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize xnc_cmt: {}", e)))?;
        let xnc_cmt_hex = hex::encode(&xnc_cmt_bytes);

        // 11. Deserialize secret from bytes (use cloned version)
        let secret: Secret = serde_json::from_slice(&secret_bytes_for_later).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        // 12. Create response structure
        let pre_response = PreResponse {
            xnc_cmt: xnc_cmt_hex,
            secret,
        };

        // 13. Serialize response to JSON bytes
        let response_bytes = serde_json::to_vec(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        // Note: Cleanup is handled by the outer initiate_reencryption function

        tracing::info!(
            request_id = %request_id,
            "PRE Coordinator: Successfully recovered reencrypted commitment"
        );

        Ok(response_bytes)
    }
}
